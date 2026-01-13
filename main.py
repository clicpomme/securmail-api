"""
SecurMail API - Backend pour l'audit de sÃ©curitÃ© email
45 Nord Sec
"""

import os
import json
import asyncio
import subprocess
import tempfile
import io
from datetime import datetime
from typing import Optional, AsyncGenerator
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse
from pydantic import BaseModel, field_validator
import dns.resolver
import httpx
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Configuration
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "2a1fbd560278460290efbb182bc7253b")
DNS_TIMEOUT = 5
HTTP_TIMEOUT = 10
REPORTS_DIR = Path("/tmp/securmail_reports")
REPORTS_DIR.mkdir(exist_ok=True)

# FastAPI app
app = FastAPI(
    title="SecurMail API",
    description="API d'audit de sécurité email par 45 Nord Sec",
    version="2.0.0"
)

# CORS - Version SIMPLE qui fonctionne TOUJOURS
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Accepter TOUTES les origines (debug mode)
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ModÃ¨les
class AuditRequest(BaseModel):
    domain: str
    skip_typo: bool = False
    check_hibp: bool = True

    @field_validator('domain')
    @classmethod
    def validate_domain(cls, v):
        v = v.strip().lower()
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
        if not re.match(pattern, v):
            raise ValueError('Format de domaine invalide')
        return v


class GenerateReportRequest(BaseModel):
    domain: str
    score: int
    results: list = []
    reportType: str = "free"


class PremiumRequestModel(BaseModel):
    name: str
    email: str
    company: str = ""
    domain: str
    score: int
    message: str = ""
    userEmail: str = ""


# Utilitaires
def dns_query(domain: str, record_type: str, prefix: str = None) -> Optional[str]:
    """Effectue une requÃªte DNS."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        
        query_domain = f"{prefix}.{domain}" if prefix else domain
        answers = resolver.resolve(query_domain, record_type)
        
        results = []
        for rdata in answers:
            results.append(str(rdata))
        
        return "\n".join(results) if results else None
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return None
    except Exception as e:
        return None


async def check_spf(domain: str) -> dict:
    """VÃ©rifie l'enregistrement SPF."""
    result = {"check": "spf", "found": False, "raw": "", "alert": None, "score": 0, "quality": None}
    
    try:
        records = dns_query(domain, "TXT")
        if records:
            for line in records.split("\n"):
                if "v=spf1" in line.lower():
                    result["found"] = True
                    result["raw"] = line.replace('"', '')
                    
                    # Analyser la qualitÃ©
                    if "-all" in line:
                        result["score"] = 25
                        result["quality"] = "Strict (-all)"
                    elif "~all" in line:
                        result["score"] = 25
                        result["quality"] = "ModÃ©rÃ© (~all)"
                    elif "?all" in line:
                        result["score"] = 5
                        result["quality"] = "Faible (?all)"
                    elif "+all" in line:
                        result["score"] = 0
                        result["quality"] = "Dangereux (+all)"
                        result["alert"] = "SPF avec +all permet Ã  tout le monde d'envoyer des emails!"
                    else:
                        result["score"] = 12
                        result["quality"] = "PrÃ©sent"
                    
                    result["raw"] += f"\nQualitÃ©: {result['quality']}"
                    break
        
        if not result["found"]:
            result["raw"] = "Aucun enregistrement SPF trouvÃ©"
            result["alert"] = "Aucun enregistrement SPF dÃ©tectÃ©"
    except Exception as e:
        result["raw"] = f"Erreur: {str(e)}"
        result["alert"] = "Erreur lors de la vÃ©rification SPF"
    
    return result


async def check_dkim(domain: str) -> dict:
    """VÃ©rifie les enregistrements DKIM."""
    result = {"check": "dkim", "found": False, "raw": "", "alert": None, "score": 0}
    
    selectors = [
        "default", "s1", "s2", "mail", "dkim", "email",
        "selector1", "selector2",  # Microsoft 365
        "google", "20161025", "20210112",  # Google
        "k1", "k2", "k3",
        "mandrill", "mailchimp", "mc",
        "smtp", "smtpapi",
        "amazonses", "ses",
        "protonmail", "protonmail2", "protonmail3",
        "mailjet", "dkim1", "dkim2",
        "hornet", "mimecast", "fm1", "fm2", "fm3"
    ]
    
    found_selectors = []
    raw_lines = []
    
    for selector in selectors:
        record = dns_query(domain, "TXT", f"{selector}._domainkey")
        if record:
            found_selectors.append(selector)
            raw_lines.append(f"â†’ {selector}._domainkey.{domain}")
            raw_lines.append(record.replace('"', '')[:200] + "...")
            raw_lines.append("")
    
    if found_selectors:
        result["found"] = True
        result["score"] = 25
        raw_lines.insert(0, f"SÃ©lecteurs trouvÃ©s: {', '.join(found_selectors)}\n")
        result["raw"] = "\n".join(raw_lines)
    else:
        result["raw"] = "Aucun enregistrement DKIM dÃ©tectÃ©\n(SÃ©lecteurs testÃ©s: default, google, selector1, selector2, etc.)"
        result["alert"] = "Aucun enregistrement DKIM dÃ©tectÃ©"
    
    return result


async def check_dmarc(domain: str) -> dict:
    """VÃ©rifie l'enregistrement DMARC."""
    result = {"check": "dmarc", "found": False, "raw": "", "alert": None, "score": 0, "policy": None}
    
    try:
        record = dns_query(domain, "TXT", "_dmarc")
        
        if record:
            result["found"] = True
            result["raw"] = record.replace('"', '')
            
            # Analyser la politique
            if "p=reject" in record:
                result["score"] = 25
                result["policy"] = "Reject (strict)"
            elif "p=quarantine" in record:
                result["score"] = 25
                result["policy"] = "Quarantine (modere)"
            elif "p=none" in record:
                result["score"] = 25
                result["policy"] = "None (surveillance)"
                result["alert"] = "DMARC en mode surveillance (p=none) - pas de protection active"
            else:
                result["score"] = 20
                result["policy"] = "Present"
            
            result["raw"] += f"\nPolitique: {result['policy']}"
            
            # VÃ©rifier pct
            pct_match = re.search(r'pct=(\d+)', record)
            if pct_match:
                pct = int(pct_match.group(1))
                if pct < 100:
                    result["raw"] += f"\nâš  Attention: seulement {pct}% des messages couverts"
        else:
            result["raw"] = "Aucun enregistrement DMARC trouvÃ©"
            result["alert"] = "Aucun enregistrement DMARC dÃ©tectÃ©"
    except Exception as e:
        result["raw"] = f"Erreur: {str(e)}"
    
    return result


async def check_bimi(domain: str) -> dict:
    """VÃ©rifie l'enregistrement BIMI."""
    result = {"check": "bimi", "found": False, "raw": "", "alert": None, "score": 0}
    
    record = dns_query(domain, "TXT", "default._bimi")
    
    if record:
        result["found"] = True
        result["score"] = 25
        result["raw"] = record.replace('"', '')
        
        if "l=" in record:
            result["raw"] += "\nâœ“ Logo BIMI configurÃ©"
    else:
        result["raw"] = "Aucun enregistrement BIMI trouvÃ©\n(Optionnel - amÃ©liore la visibilitÃ© de marque)"
    
    return result


async def check_mtasts(domain: str) -> dict:
    """VÃ©rifie MTA-STS."""
    result = {"check": "mtasts", "found": False, "raw": "", "alert": None, "score": 0}
    
    lines = []
    
    # Enregistrement DNS
    record = dns_query(domain, "TXT", "_mta-sts")
    if record:
        result["score"] += 8
        lines.append("[DNS MTA-STS]")
        lines.append(record.replace('"', ''))
        lines.append("")
    else:
        lines.append("[DNS MTA-STS]")
        lines.append("Non trouvÃ©")
        lines.append("")
    
    # Politique HTTPS
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            response = await client.get(f"https://mta-sts.{domain}/.well-known/mta-sts.txt")
            if response.status_code == 200:
                result["score"] += 7
                result["found"] = True
                lines.append("[Politique HTTPS]")
                lines.append(response.text[:500])
                
                if "mode: enforce" in response.text:
                    lines.append("\nâœ“ Mode enforce (strict)")
                elif "mode: testing" in response.text:
                    lines.append("\nâš  Mode testing (surveillance)")
    except:
        lines.append("[Politique HTTPS]")
        lines.append("Non accessible")
    
    result["raw"] = "\n".join(lines)
    result["found"] = result["score"] > 0
    
    return result


async def check_tlsrpt(domain: str) -> dict:
    """VÃ©rifie TLS-RPT."""
    result = {"check": "tlsrpt", "found": False, "raw": "", "alert": None, "score": 0}
    
    record = dns_query(domain, "TXT", "_smtp._tls")
    
    if record:
        result["found"] = True
        result["score"] = 15
        result["raw"] = record.replace('"', '')
    else:
        result["raw"] = "Aucun enregistrement TLS-RPT trouvÃ©"
    
    return result


async def check_dnssec(domain: str) -> dict:
    """VÃ©rifie DNSSEC."""
    result = {"check": "dnssec", "found": False, "raw": "", "alert": None, "score": 0}
    
    dnskey = dns_query(domain, "DNSKEY")
    
    if dnskey:
        result["found"] = True
        result["score"] = 5
        result["raw"] = "DNSSEC activÃ© âœ“\n\n" + dnskey[:300]
    else:
        result["raw"] = "DNSSEC non activÃ©\n(RecommandÃ© pour protÃ©ger contre l'usurpation DNS)"
    
    return result


async def check_caa(domain: str) -> dict:
    """VÃ©rifie CAA."""
    result = {"check": "caa", "found": False, "raw": "", "alert": None, "score": 0}
    
    record = dns_query(domain, "CAA")
    
    if record:
        result["found"] = True
        result["score"] = 5
        result["raw"] = record
    else:
        result["raw"] = "Aucun enregistrement CAA trouvÃ©\n(RecommandÃ© pour limiter les CA autorisÃ©es)"
    
    return result


async def check_hibp(domain: str) -> dict:
    """VÃ©rifie Have I Been Pwned."""
    result = {"check": "hibp", "found": False, "raw": "", "alert": None, "score": 0}
    
    prefixes = ["contact", "info", "admin", "support", "rich"]
    lines = []
    total_breaches = 0
    
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        for prefix in prefixes:
            email = f"{prefix}@{domain}"
            lines.append(f"\nâ†’ {email}:")
            
            try:
                response = await client.get(
                    f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                    params={"truncateResponse": "false"},
                    headers={
                        "hibp-api-key": HIBP_API_KEY,
                        "user-agent": "SecurMail-45NordSec/2.0"
                    }
                )
                
                if response.status_code == 200:
                    breaches = response.json()
                    breach_names = [b["Name"] for b in breaches]
                    total_breaches += len(breaches)
                    lines.append(f"  âš  TrouvÃ© dans {len(breaches)} fuite(s): {', '.join(breach_names[:5])}")
                elif response.status_code == 404:
                    lines.append("  âœ“ Aucune fuite connue")
                elif response.status_code == 401:
                    lines.append("  Erreur: clÃ© API invalide")
                    break
                elif response.status_code == 429:
                    lines.append("  Erreur: limite de requÃªtes atteinte")
                    break
                else:
                    lines.append(f"  Erreur HTTP {response.status_code}")
                    
            except Exception as e:
                lines.append(f"  Erreur: {str(e)}")
            
            # Rate limit HIBP
            await asyncio.sleep(1.6)
    
    result["raw"] = "\n".join(lines)
    
    if total_breaches > 0:
        result["found"] = True
        result["alert"] = f"{total_breaches} data breach(es) detected"
        result["score"] = 0
    else:
        result["score"] = 15
    
    return result


async def check_typosquatting(domain: str) -> dict:
    """VÃ©rifie le typosquatting avec dnstwist."""
    result = {"check": "typosquatting", "found": False, "raw": "", "alert": None, "score": 0}
    
    try:
        # ExÃ©cuter dnstwist
        process = await asyncio.create_subprocess_exec(
            "dnstwist", "--registered", "--format", "json", domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120)
        
        if process.returncode == 0:
            data = json.loads(stdout.decode())
            # Filtrer pour ne garder que les domaines enregistrÃ©s
            registered = [d for d in data if d.get("dns_a") or d.get("dns_mx")]
            
            if registered:
                result["found"] = True
                result["score"] = 15
                
                lines = [f"Domaines similaires enregistrÃ©s: {len(registered)}\n"]
                for d in registered[:20]:  # Limiter Ã  20
                    line = f"â€¢ {d.get('domain', 'N/A')} ({d.get('fuzzer', '')})"
                    if d.get('dns_a'):
                        line += f" - IP: {d['dns_a'][0]}"
                    lines.append(line)
                
                if len(registered) > 20:
                    lines.append(f"\n... et {len(registered) - 20} autres")
                
                result["raw"] = "\n".join(lines)
                
                if len(registered) > 10:
                    result["alert"] = f"{len(registered)} domaines similaires dÃ©tectÃ©s - risque Ã©levÃ©"
            else:
                result["raw"] = "Aucun domaine similaire enregistrÃ© dÃ©tectÃ©"
        else:
            result["raw"] = f"Erreur dnstwist: {stderr.decode()}"
            
    except asyncio.TimeoutError:
        result["raw"] = "Timeout - l'analyse typosquatting a pris trop de temps"
    except FileNotFoundError:
        result["raw"] = "dnstwist non disponible sur ce serveur"
    except Exception as e:
        result["raw"] = f"Erreur: {str(e)}"
    
    return result


async def run_audit(domain: str, skip_typo: bool, check_hibp_flag: bool) -> AsyncGenerator[str, None]:
    """ExÃ©cute l'audit complet avec streaming."""
    
    total_score = 0
    results = {}
    
    # Liste des checks
    checks = [
        ("hibp", check_hibp) if check_hibp_flag else None,
        ("spf", check_spf),
        ("dkim", check_dkim),
        ("dmarc", check_dmarc),
        ("bimi", check_bimi),
        ("mtasts", check_mtasts),
        ("tlsrpt", check_tlsrpt),
        ("dnssec", check_dnssec),
        ("caa", check_caa),
    ]
    
    # Retirer None (si HIBP pas demandé)
    checks = [c for c in checks if c is not None]
    
    # ExÃ©cuter chaque check
    scoring_checks = {"spf", "dkim", "dmarc", "bimi"}  # Seulement ces 4 pour le score
    
    for check_name, check_func in checks:
        # Progress: running
        yield f"data: {json.dumps({'type': 'progress', 'check': check_name, 'status': 'running'})}\n\n"
        
        try:
            result = await check_func(domain)
            results[check_name] = result
            
            # Ajouter au score SEULEMENT si c'est SPF, DKIM, DMARC ou BIMI
            if check_name in scoring_checks:
                total_score += result.get("score", 0)
            
            # Progress: done
            yield f"data: {json.dumps({'type': 'progress', 'check': check_name, 'status': 'done'})}\n\n"
            
            # Result
            yield f"data: {json.dumps({'type': 'result', 'check': check_name, 'data': result})}\n\n"
            
        except Exception as e:
            yield f"data: {json.dumps({'type': 'progress', 'check': check_name, 'status': 'error'})}\n\n"
            yield f"data: {json.dumps({'type': 'result', 'check': check_name, 'data': {'found': False, 'raw': str(e), 'alert': 'Erreur'}})}\n\n"
    
    # Plafonner le score a 100
    total_score = min(total_score, 100)
    
    # Score final
    yield f"data: {json.dumps({'type': 'score', 'domain': domain, 'score': total_score})}\n\n"
    
    # GÃ©nÃ©rer PDF (optionnel)
    pdf_url = None
    try:
        pdf_path = await generate_pdf_report(domain, total_score, results)
        if pdf_path:
            pdf_url = f"/api/report/{domain}/pdf"
    except:
        pass
    
    # Complet
    yield f"data: {json.dumps({'type': 'complete', 'domain': domain, 'score': total_score, 'pdf_url': pdf_url})}\n\n"


async def generate_pdf_report(domain: str, score: int, results: dict) -> Optional[Path]:
    """GÃ©nÃ¨re un rapport PDF."""
    # Pour l'instant, on retourne None
    # Tu peux implÃ©menter la gÃ©nÃ©ration PDF avec WeasyPrint si nÃ©cessaire
    return None


# Routes API
@app.get("/")
async def root():
    return {"status": "ok", "service": "SecurMail API", "version": "2.0.0"}


@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


@app.post("/api/audit")
async def audit(request: AuditRequest):
    """Lance un audit de sÃ©curitÃ© email."""
    return StreamingResponse(
        run_audit(request.domain, request.skip_typo, request.check_hibp),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


@app.get("/api/report/{domain}/pdf")
async def get_pdf_report(domain: str):
    """Télécharge le rapport PDF."""
    pdf_path = REPORTS_DIR / f"rapport_{domain}.pdf"
    
    if not pdf_path.exists():
        raise HTTPException(status_code=404, detail="Rapport non trouvé")
    
    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename=f"securmail_rapport_{domain}.pdf"
    )


@app.post("/api/generate-report")
async def generate_report(request: GenerateReportRequest):
    """Génère un rapport PDF avec Claude API."""
    try:
        # For now, return a simple placeholder PDF
        # In production, integrate with Claude API and WeasyPrint/reportlab
        
        # Create a simple text file report (replace with actual PDF generation)
        report_content = f"""
SecurMail Security Report
========================

Domain: {request.domain}
Score: {request.score}/100
Report Type: {request.reportType}

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Summary:
--------
This is a free report analyzing your domain's email security configuration.

For a comprehensive analysis, please request our Premium Report service.
        """.encode('utf-8')
        
        return FileResponse(
            io.BytesIO(report_content),
            media_type="application/pdf",
            filename=f"securmail_report_{request.domain}.pdf"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/premium-request")
async def submit_premium_request(request: PremiumRequestModel):
    """Enregistre une demande de rapport premium."""
    try:
        # Send email to info@clicpomme.com
        await send_premium_email(request)
        
        return {
            "status": "success",
            "message": "Premium request received",
            "email": "info@clicpomme.com"
        }
    except Exception as e:
        print(f"Error submitting premium request: {str(e)}")
        raise HTTPException(status_code=500, detail="Error processing request")


async def send_premium_email(request: PremiumRequestModel):
    """Envoie un email de demande premium à info@clicpomme.com."""
    try:
        # Configuration SMTP (à remplacer avec vos paramètres réels)
        smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        sender_email = os.getenv("SMTP_FROM", "noreply@clicpomme.com")
        sender_password = os.getenv("SMTP_PASSWORD", "")
        
        # Create email
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = "info@clicpomme.com"
        msg['Subject'] = f"Premium Report Request - {request.domain}"
        
        body = f"""
Premium Security Report Request
================================

Client Information:
- Name: {request.name}
- Email: {request.email}
- Company: {request.company}

Analysis Details:
- Domain: {request.domain}
- Security Score: {request.score}/100
- Client's Email: {request.userEmail}

Additional Notes:
{request.message if request.message else "No additional notes"}

---
Please contact the client at {request.email} to discuss the premium report.
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Send email (async wrapper around sync operation)
        if smtp_server and sender_password:
            try:
                with smtplib.SMTP(smtp_server, smtp_port) as server:
                    server.starttls()
                    server.login(sender_email, sender_password)
                    server.send_message(msg)
            except Exception as e:
                print(f"Email sending failed: {str(e)}")
                # Don't fail the request even if email fails
        else:
            print("SMTP not configured, skipping email")
            
    except Exception as e:
        print(f"Error in send_premium_email: {str(e)}")
        # Don't raise, just log


# Point d'entrée
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
