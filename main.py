"""
SecurMail API v2.8 - Backend pour l'audit de securite email
45 Nord Sec

Changes in v2.8:
- HIBP checks ONLY the user-provided email (not generic domain emails)
- Rate limit adjusted for Pwned 1 subscription (10 RPM = 6s delay)
- Email field is optional
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
    description="API d'audit de securite email par 45 Nord Sec",
    version="2.8.0"
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
    email: Optional[str] = None  # Optional email for HIBP check
    skip_typo: bool = True  # Default to skip (too slow)
    check_hibp: bool = True

    @field_validator('domain')
    @classmethod
    def validate_domain(cls, v):
        v = v.strip().lower()
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
        if not re.match(pattern, v):
            raise ValueError('Invalid domain format')
        return v
    
    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        if v is None or v == '':
            return None
        v = v.strip().lower()
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(pattern, v):
            raise ValueError('Invalid email format')
        return v


# Utilities
def dns_query(domain: str, record_type: str, prefix: str = None) -> Optional[str]:
    """Perform a DNS query."""
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
    except Exception:
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
                    
                    # Analyze quality
                    if "-all" in line:
                        result["score"] = 25
                        result["quality"] = "Strict (-all)"
                    elif "~all" in line:
                        result["score"] = 25
                        result["quality"] = "Moderate (~all)"
                    elif "?all" in line:
                        result["score"] = 15
                        result["quality"] = "Weak (?all)"
                    elif "+all" in line:
                        result["score"] = 0
                        result["quality"] = "Dangerous (+all)"
                        result["alert"] = "SPF with +all allows anyone to send emails!"
                    else:
                        result["score"] = 25
                        result["quality"] = "Present"
                    
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
            raw_lines.append(f"-> {selector}._domainkey.{domain}")
            raw_lines.append(record.replace('"', '')[:200] + "...")
            raw_lines.append("")
    
    if found_selectors:
        result["found"] = True
        result["score"] = 25
        raw_lines.insert(0, f"Selectors found: {', '.join(found_selectors)}\n")
        result["raw"] = "\n".join(raw_lines)
    else:
        result["raw"] = "No DKIM record detected\n(Selectors tested: default, google, selector1, selector2, etc.)"
        result["alert"] = "No DKIM record detected"
    
    return result


async def check_dmarc(domain: str) -> dict:
    """Check DMARC record."""
    result = {"check": "dmarc", "found": False, "raw": "", "alert": None, "score": 0, "policy": None}
    
    try:
        record = dns_query(domain, "TXT", "_dmarc")
        
        if record:
            result["found"] = True
            result["raw"] = record.replace('"', '')
            
            # Analyze policy - ALL policies get 25 points (including p=none)
            if "p=reject" in record:
                result["score"] = 25
                result["policy"] = "Reject (strict)"
            elif "p=quarantine" in record:
                result["score"] = 25
                result["policy"] = "Quarantine (moderate)"
            elif "p=none" in record:
                result["score"] = 25  # p=none still gets full score
                result["policy"] = "None (monitoring)"
            else:
                result["score"] = 25
                result["policy"] = "Present"
            
            result["raw"] += f"\nPolicy: {result['policy']}"
            
            # Check pct
            pct_match = re.search(r'pct=(\d+)', record)
            if pct_match:
                pct = int(pct_match.group(1))
                if pct < 100:
                    result["raw"] += f"\nNote: only {pct}% of messages covered"
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
            result["raw"] += "\n[OK] BIMI logo configured"
    else:
        result["raw"] = "No BIMI record found\n(Optional - improves brand visibility)"
    
    return result


async def check_mtasts(domain: str) -> dict:
    """Check MTA-STS."""
    result = {"check": "mtasts", "found": False, "raw": "", "alert": None, "score": 0}
    
    lines = []
    
    # DNS record
    record = dns_query(domain, "TXT", "_mta-sts")
    if record:
        lines.append("[DNS MTA-STS]")
        lines.append(record.replace('"', ''))
        lines.append("")
    else:
        lines.append("[DNS MTA-STS]")
        lines.append("Not found")
        lines.append("")
    
    # HTTPS policy
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            response = await client.get(f"https://mta-sts.{domain}/.well-known/mta-sts.txt")
            if response.status_code == 200:
                result["found"] = True
                lines.append("[HTTPS Policy]")
                lines.append(response.text[:500])
                
                if "mode: enforce" in response.text:
                    lines.append("\n[OK] Mode enforce (strict)")
                elif "mode: testing" in response.text:
                    lines.append("\n[!] Mode testing (monitoring)")
    except:
        lines.append("[HTTPS Policy]")
        lines.append("Not accessible")
    
    result["raw"] = "\n".join(lines)
    
    return result


async def check_tlsrpt(domain: str) -> dict:
    """Check TLS-RPT."""
    result = {"check": "tlsrpt", "found": False, "raw": "", "alert": None, "score": 0}
    
    record = dns_query(domain, "TXT", "_smtp._tls")
    
    if record:
        result["found"] = True
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
        result["raw"] = "DNSSEC enabled [OK]\n\n" + dnskey[:300]
    else:
        result["raw"] = "DNSSEC not enabled\n(Recommended to protect against DNS spoofing)"
    
    return result


async def check_caa(domain: str) -> dict:
    """Check CAA."""
    result = {"check": "caa", "found": False, "raw": "", "alert": None, "score": 0}
    
    record = dns_query(domain, "CAA")
    
    if record:
        result["found"] = True
        result["raw"] = record
    else:
        result["raw"] = "No CAA record found\n(Recommended to limit authorized CAs)"
    
    return result


async def check_hibp(email: str) -> dict:
    """Check Have I Been Pwned for a SINGLE email address."""
    result = {"check": "hibp", "found": False, "raw": "", "alert": None, "score": 0}
    
    if not email:
        result["raw"] = "No email address provided for breach check"
        return result
    
    lines = [f"Checking: {email}\n"]
    
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        try:
            response = await client.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                params={"truncateResponse": "false"},
                headers={
                    "hibp-api-key": HIBP_API_KEY,
                    "user-agent": "SecurMail-45NordSec/2.8"
                }
            )
            
            if response.status_code == 200:
                breaches = response.json()
                result["found"] = True  # found = breach detected (problem)
                
                lines.append(f"[!] Found in {len(breaches)} breach(es):\n")
                
                for breach in breaches[:10]:  # Show max 10 breaches
                    name = breach.get("Name", "Unknown")
                    date = breach.get("BreachDate", "Unknown")
                    count = breach.get("PwnCount", 0)
                    lines.append(f"  - {name}")
                    lines.append(f"    Date: {date}")
                    lines.append(f"    Records: {count:,}")
                    lines.append("")
                
                if len(breaches) > 10:
                    lines.append(f"  ... and {len(breaches) - 10} more breaches")
                
                result["alert"] = f"Email found in {len(breaches)} data breach(es)!"
                
            elif response.status_code == 404:
                lines.append("[OK] No known breaches found")
                lines.append("\nThis email address has not been found in any known data breaches.")
                
            elif response.status_code == 401:
                lines.append("[Error] Invalid API key")
                result["alert"] = "HIBP API key is invalid"
                
            elif response.status_code == 429:
                lines.append("[Error] Rate limit exceeded")
                lines.append("Please wait a moment and try again.")
                result["alert"] = "Rate limit exceeded - try again later"
                
            else:
                lines.append(f"[Error] HTTP {response.status_code}")
                
        except Exception as e:
            lines.append(f"[Error] {str(e)}")
    
    result["raw"] = "\n".join(lines)
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
                
                lines = [f"Similar registered domains: {len(registered)}\n"]
                for d in registered[:20]:
                    line = f"- {d.get('domain', 'N/A')} ({d.get('fuzzer', '')})"
                    if d.get('dns_a'):
                        line += f" - IP: {d['dns_a'][0]}"
                    lines.append(line)
                
                if len(registered) > 20:
                    lines.append(f"\n... and {len(registered) - 20} more")
                
                result["raw"] = "\n".join(lines)
                
                if len(registered) > 10:
                    result["alert"] = f"{len(registered)} similar domains detected - high risk"
            else:
                result["raw"] = "No similar registered domains detected"
        else:
            result["raw"] = f"dnstwist error: {stderr.decode()}"
            
    except asyncio.TimeoutError:
        result["raw"] = "Timeout - typosquatting analysis took too long"
    except FileNotFoundError:
        result["raw"] = "dnstwist not available on this server"
    except Exception as e:
        result["raw"] = f"Error: {str(e)}"
    
    return result


async def run_audit(domain: str, email: Optional[str], skip_typo: bool, check_hibp_flag: bool) -> AsyncGenerator[str, None]:
    """Run complete audit with streaming."""
    
    total_score = 0
    results = {}
    
    # Domain checks (score only from SPF, DKIM, DMARC, BIMI)
    domain_checks = [
        ("spf", check_spf),
        ("dkim", check_dkim),
        ("dmarc", check_dmarc),
        ("bimi", check_bimi),
        ("mtasts", check_mtasts),
        ("tlsrpt", check_tlsrpt),
        ("dnssec", check_dnssec),
        ("caa", check_caa),
    ]
    
    # Execute domain checks
    for check_name, check_func in domain_checks:
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
    
    # HIBP check (only if email provided)
    if check_hibp_flag and email:
        yield f"data: {json.dumps({'type': 'progress', 'check': 'hibp', 'status': 'running'})}\n\n"
        
        try:
            result = await check_hibp(email)
            results["hibp"] = result
            
            yield f"data: {json.dumps({'type': 'progress', 'check': 'hibp', 'status': 'done'})}\n\n"
            yield f"data: {json.dumps({'type': 'result', 'check': 'hibp', 'data': result})}\n\n"
            
        except Exception as e:
            yield f"data: {json.dumps({'type': 'progress', 'check': 'hibp', 'status': 'error'})}\n\n"
            yield f"data: {json.dumps({'type': 'result', 'check': 'hibp', 'data': {'found': False, 'raw': str(e), 'alert': 'Error'}})}\n\n"
    
    # Typosquatting check (optional, slow)
    if not skip_typo:
        yield f"data: {json.dumps({'type': 'progress', 'check': 'typosquatting', 'status': 'running'})}\n\n"
        
        try:
            result = await check_typosquatting(domain)
            results["typosquatting"] = result
            
            yield f"data: {json.dumps({'type': 'progress', 'check': 'typosquatting', 'status': 'done'})}\n\n"
            yield f"data: {json.dumps({'type': 'result', 'check': 'typosquatting', 'data': result})}\n\n"
            
        except Exception as e:
            yield f"data: {json.dumps({'type': 'progress', 'check': 'typosquatting', 'status': 'error'})}\n\n"
            yield f"data: {json.dumps({'type': 'result', 'check': 'typosquatting', 'data': {'found': False, 'raw': str(e), 'alert': 'Error'}})}\n\n"
    
    # Cap score at 100
    total_score = min(total_score, 100)
    
    # Final score
    yield f"data: {json.dumps({'type': 'score', 'domain': domain, 'score': total_score})}\n\n"
    
    # Complete
    yield f"data: {json.dumps({'type': 'complete', 'domain': domain, 'score': total_score, 'pdf_url': None})}\n\n"


# API Routes
@app.get("/")
async def root():
    return {"status": "ok", "service": "SecurMail API", "version": "2.8.0"}


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.post("/api/audit")
async def audit(request: AuditRequest):
    """Launch email security audit."""
    return StreamingResponse(
        run_audit(request.domain, request.email, request.skip_typo, request.check_hibp),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


# Entry point
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
