"""
SecurMail API - Email Security Audit Backend
45 Nord Sec
"""

import os
import json
import asyncio
import subprocess
import tempfile
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

# Configuration
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "2a1fbd560278460290efbb182bc7253b")
DNS_TIMEOUT = 5
HTTP_TIMEOUT = 10
REPORTS_DIR = Path("/tmp/securmail_reports")
REPORTS_DIR.mkdir(exist_ok=True)

# FastAPI app
app = FastAPI(
    title="SecurMail API",
    description="Email security audit API by 45 Nord Sec",
    version="2.6.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://clicpomme.com",
        "https://www.clicpomme.com",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Models
class AuditRequest(BaseModel):
    domain: str
    email: Optional[str] = None
    skip_typo: bool = False
    check_hibp: bool = True

    @field_validator('domain')
    @classmethod
    def validate_domain(cls, v):
        v = v.strip().lower()
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
        if not re.match(pattern, v):
            raise ValueError('Invalid domain format')
        return v


# Utilities
def dns_query(domain: str, record_type: str, prefix: str = None) -> Optional[str]:
    """Perform DNS query."""
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
    """Check SPF record."""
    result = {"check": "spf", "found": False, "raw": "", "alert": None, "score": 0, "quality": None}
    
    try:
        records = dns_query(domain, "TXT")
        if records:
            for line in records.split("\n"):
                if "v=spf1" in line.lower():
                    result["found"] = True
                    result["raw"] = line.replace('"', '')
                    
                    if "-all" in line:
                        result["score"] = 25
                        result["quality"] = "Strict (-all)"
                    elif "~all" in line:
                        result["score"] = 25
                        result["quality"] = "Moderate (~all)"
                    elif "?all" in line:
                        result["score"] = 0
                        result["quality"] = "Weak (?all)"
                    elif "+all" in line:
                        result["score"] = 0
                        result["quality"] = "Dangerous (+all)"
                        result["alert"] = "SPF with +all allows anyone to send emails!"
                    else:
                        result["score"] = 25
                        result["quality"] = "Configured"
                    
                    result["raw"] += f"\nQuality: {result['quality']}"
                    break
        
        if not result["found"]:
            result["raw"] = "No SPF record found"
            result["alert"] = "No SPF record detected"
    except Exception as e:
        result["raw"] = f"Error: {str(e)}"
        result["alert"] = "Error checking SPF"
    
    return result


async def check_dkim(domain: str) -> dict:
    """Check DKIM records."""
    result = {"check": "dkim", "found": False, "raw": "", "alert": None, "score": 0}
    
    selectors = [
        "default", "s1", "s2", "mail", "dkim", "email",
        "selector1", "selector2",
        "google", "20161025", "20210112",
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
            raw_lines.append(f"-> {selector}._domainkey.{domain}")
            raw_lines.append(record.replace('"', '')[:200] + "...")
            raw_lines.append("")
    
    if found_selectors:
        result["found"] = True
        result["score"] = 25
        raw_lines.insert(0, f"Selectors found: {', '.join(found_selectors)}\n")
        result["raw"] = "\n".join(raw_lines)
    else:
        result["raw"] = "No DKIM records detected\n(Selectors tested: default, google, selector1, selector2, etc.)"
        result["alert"] = "No DKIM records detected"
    
    return result


async def check_dmarc(domain: str) -> dict:
    """Check DMARC record."""
    result = {"check": "dmarc", "found": False, "raw": "", "alert": None, "score": 0, "policy": None}
    
    try:
        record = dns_query(domain, "TXT", "_dmarc")
        
        if record:
            result["found"] = True
            result["raw"] = record.replace('"', '')
            
            if "p=reject" in record:
                result["score"] = 25
                result["policy"] = "Reject (strict)"
            elif "p=quarantine" in record:
                result["score"] = 25
                result["policy"] = "Quarantine (moderate)"
            elif "p=none" in record:
                result["score"] = 0
                result["policy"] = "None (monitoring)"
                result["alert"] = "DMARC in monitoring mode (p=none) - no active protection"
            else:
                result["score"] = 25
                result["policy"] = "Configured"
            
            result["raw"] += f"\nPolicy: {result['policy']}"
            
            pct_match = re.search(r'pct=(\d+)', record)
            if pct_match:
                pct = int(pct_match.group(1))
                if pct < 100:
                    result["raw"] += f"\nWarning: only {pct}% of messages covered"
        else:
            result["raw"] = "No DMARC record found"
            result["alert"] = "No DMARC record detected"
    except Exception as e:
        result["raw"] = f"Error: {str(e)}"
    
    return result


async def check_bimi(domain: str) -> dict:
    """Check BIMI record."""
    result = {"check": "bimi", "found": False, "raw": "", "alert": None, "score": 0}
    
    record = dns_query(domain, "TXT", "default._bimi")
    
    if record:
        result["found"] = True
        result["score"] = 25
        result["raw"] = record.replace('"', '')
        
        if "l=" in record:
            result["raw"] += "\n✓ Logo BIMI configured"
    else:
        result["raw"] = "No BIMI record found\n(Optional - improves brand visibility)"
    
    return result


async def check_mtasts(domain: str) -> dict:
    """Check MTA-STS."""
    result = {"check": "mtasts", "found": False, "raw": "", "alert": None, "score": 0}
    
    lines = []
    
    record = dns_query(domain, "TXT", "_mta-sts")
    if record:
        result["score"] = 0
        lines.append("[DNS MTA-STS]")
        lines.append(record.replace('"', ''))
        lines.append("")
    else:
        lines.append("[DNS MTA-STS]")
        lines.append("Not found")
        lines.append("")
    
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            response = await client.get(f"https://mta-sts.{domain}/.well-known/mta-sts.txt")
            if response.status_code == 200:
                result["score"] = 0
                result["found"] = True
                lines.append("[HTTPS Policy]")
                lines.append(response.text[:500])
                
                if "mode: enforce" in response.text:
                    lines.append("\n✓ Mode enforce (strict)")
                elif "mode: testing" in response.text:
                    lines.append("\nWarning: Mode testing (monitoring)")
    except:
        lines.append("[HTTPS Policy]")
        lines.append("Not accessible")
    
    result["raw"] = "\n".join(lines)
    result["found"] = result["score"] > 0
    
    return result


async def check_tlsrpt(domain: str) -> dict:
    """Check TLS-RPT."""
    result = {"check": "tlsrpt", "found": False, "raw": "", "alert": None, "score": 0}
    
    record = dns_query(domain, "TXT", "_smtp._tls")
    
    if record:
        result["found"] = True
        result["score"] = 0
        result["raw"] = record.replace('"', '')
    else:
        result["raw"] = "No TLS-RPT record found"
    
    return result


async def check_dnssec(domain: str) -> dict:
    """Check DNSSEC."""
    result = {"check": "dnssec", "found": False, "raw": "", "alert": None, "score": 0}
    
    dnskey = dns_query(domain, "DNSKEY")
    
    if dnskey:
        result["found"] = True
        result["score"] = 0
        result["raw"] = "DNSSEC enabled\n\n" + dnskey[:300]
    else:
        result["raw"] = "DNSSEC not enabled\n(Recommended to protect against DNS spoofing)"
    
    return result


async def check_caa(domain: str) -> dict:
    """Check CAA."""
    result = {"check": "caa", "found": False, "raw": "", "alert": None, "score": 0}
    
    record = dns_query(domain, "CAA")
    
    if record:
        result["found"] = True
        result["score"] = 0
        result["raw"] = record
    else:
        result["raw"] = "No CAA record found\n(Recommended to limit authorized CAs)"
    
    return result


async def check_hibp(domain: str, custom_email: Optional[str] = None) -> dict:
    """Check Have I Been Pwned for a specific email."""
    result = {"check": "hibp", "found": False, "raw": "", "alert": None, "score": 0}
    
    if not custom_email:
        result["raw"] = "No email provided for breach checking"
        return result
    
    email = custom_email
    lines = []
    total_breaches = 0
    
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            try:
                response = await client.get(
                    f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                    params={"truncateResponse": "false"},
                    headers={
                        "hibp-api-key": HIBP_API_KEY,
                        "user-agent": "SecurMail-45NordSec/2.6"
                    }
                )
                
                if response.status_code == 200:
                    breaches = response.json()
                    total_breaches = len(breaches)
                    
                    lines.append(f"Email: {email}")
                    lines.append(f"Status: Found in {total_breaches} breach(es)")
                    lines.append("")
                    lines.append("Breach sources:")
                    for breach in breaches[:10]:
                        breach_name = breach.get("Name", "Unknown")
                        breach_date = breach.get("BreachDate", "Unknown date")
                        breach_count = breach.get("PwnCount", 0)
                        lines.append(f"  • {breach_name} ({breach_date}) - {breach_count:,} records")
                    
                    if len(breaches) > 10:
                        lines.append(f"\n  ... and {len(breaches) - 10} more breaches")
                    
                elif response.status_code == 404:
                    lines.append(f"Email: {email}")
                    lines.append("Status: No known breaches found")
                    lines.append("")
                    lines.append("This email address has not been found in known data breaches.")
                    
                elif response.status_code == 401:
                    lines.append("Error: Invalid HIBP API key")
                    result["alert"] = "HIBP API key validation failed"
                    
                elif response.status_code == 429:
                    lines.append("Error: HIBP rate limit exceeded")
                    lines.append("Please try again in a few minutes")
                    result["alert"] = "HIBP rate limit exceeded. Please try again later"
                    
                else:
                    lines.append(f"Error: HTTP {response.status_code}")
                    lines.append("Could not check email with HIBP service")
                    result["alert"] = f"HIBP service error: HTTP {response.status_code}"
                    
            except Exception as e:
                lines.append(f"Error: {str(e)}")
                lines.append("Could not connect to HIBP service")
                result["alert"] = f"Error checking email: {str(e)}"
    
    except Exception as e:
        lines.append(f"Error: {str(e)}")
        result["alert"] = f"Error: {str(e)}"
    
    result["raw"] = "\n".join(lines)
    
    if total_breaches > 0:
        result["found"] = True
        result["score"] = 0
        result["alert"] = f"Email found in {total_breaches} data breach(es)"
    
    return result


async def check_typosquatting(domain: str) -> dict:
    """Check typosquatting with dnstwist."""
    result = {"check": "typosquatting", "found": False, "raw": "", "alert": None, "score": 0}
    
    try:
        process = await asyncio.create_subprocess_exec(
            "dnstwist", "--registered", "--format", "json", domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120)
        
        if process.returncode == 0:
            data = json.loads(stdout.decode())
            registered = [d for d in data if d.get("dns_a") or d.get("dns_mx")]
            
            if registered:
                result["found"] = True
                result["score"] = 0
                
                lines = [f"Similar domains registered: {len(registered)}\n"]
                for d in registered[:20]:
                    line = f"• {d.get('domain', 'N/A')} ({d.get('fuzzer', '')})"
                    if d.get('dns_a'):
                        line += f" - IP: {d['dns_a'][0]}"
                    lines.append(line)
                
                if len(registered) > 20:
                    lines.append(f"\n... and {len(registered) - 20} others")
                
                result["raw"] = "\n".join(lines)
                
                if len(registered) > 10:
                    result["alert"] = f"{len(registered)} similar domains detected - high risk"
            else:
                result["raw"] = "No similar domains detected"
        else:
            result["raw"] = f"Dnstwist error: {stderr.decode()}"
            
    except asyncio.TimeoutError:
        result["raw"] = "Timeout - typosquatting analysis took too long"
    except FileNotFoundError:
        result["raw"] = "Dnstwist not available on this server"
    except Exception as e:
        result["raw"] = f"Error: {str(e)}"
    
    return result


async def run_audit(domain: str, skip_typo: bool, check_hibp_flag: bool, email: Optional[str] = None) -> AsyncGenerator[str, None]:
    """Run complete security audit with streaming."""
    
    total_score = 0
    results = {}
    
    # Core checks (critical)
    checks = [
        ("spf", check_spf),
        ("dkim", check_dkim),
        ("dmarc", check_dmarc),
        ("bimi", check_bimi),
    ]
    
    # Optional checks (informational, 0 points)
    optional_checks = [
        ("mtasts", check_mtasts),
        ("tlsrpt", check_tlsrpt),
        ("dnssec", check_dnssec),
        ("caa", check_caa),
    ]
    checks.extend(optional_checks)
    
    # Only add typosquatting if requested
    if not skip_typo:
        checks.append(("typosquatting", check_typosquatting))
    
    # Only add HIBP if email is provided
    if email:
        checks.append(("hibp", lambda d=domain, e=email: check_hibp(d, e)))
    
    # Execute each check
    for check_name, check_func in checks:
        yield f"data: {json.dumps({'type': 'progress', 'check': check_name, 'status': 'running'})}\n\n"
        
        try:
            result = await check_func(domain)
            results[check_name] = result
            total_score += result.get("score", 0)
            
            yield f"data: {json.dumps({'type': 'progress', 'check': check_name, 'status': 'done'})}\n\n"
            yield f"data: {json.dumps({'type': 'result', 'check': check_name, 'data': result})}\n\n"
            
        except Exception as e:
            yield f"data: {json.dumps({'type': 'progress', 'check': check_name, 'status': 'error'})}\n\n"
            yield f"data: {json.dumps({'type': 'result', 'check': check_name, 'data': {'found': False, 'raw': str(e), 'alert': 'Error'}})}\n\n"
    
    # Cap score at 100
    total_score = min(total_score, 100)
    
    # Final score
    yield f"data: {json.dumps({'type': 'score', 'domain': domain, 'score': total_score})}\n\n"
    
    # Generate PDF (optional)
    pdf_url = None
    try:
        pdf_path = await generate_pdf_report(domain, total_score, results)
        if pdf_path:
            pdf_url = f"/api/report/{domain}/pdf"
    except:
        pass
    
    # Complete
    yield f"data: {json.dumps({'type': 'complete', 'domain': domain, 'score': total_score, 'pdf_url': pdf_url})}\n\n"


async def generate_pdf_report(domain: str, score: int, results: dict) -> Optional[Path]:
    """Generate PDF report."""
    return None


# Routes
@app.get("/")
async def root():
    return {"status": "ok", "service": "SecurMail API", "version": "2.6.0"}


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.post("/api/audit")
async def audit(request: AuditRequest):
    """Run email security audit."""
    return StreamingResponse(
        run_audit(request.domain, request.skip_typo, request.check_hibp, request.email),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


@app.get("/api/report/{domain}/pdf")
async def get_pdf_report(domain: str):
    """Download PDF report."""
    pdf_path = REPORTS_DIR / f"rapport_{domain}.pdf"
    
    if not pdf_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    
    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename=f"securmail_report_{domain}.pdf"
    )


# Entry point
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
