"""
DNS, WHOIS, and IP intelligence module.
All lookups are best-effort with short timeouts — never block analysis.
"""

from __future__ import annotations
import ipaddress
import socket
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Dict

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class DNSRecord:
    domain: str
    a_records: List[str] = field(default_factory=list)
    aaaa_records: List[str] = field(default_factory=list)
    mx_records: List[str] = field(default_factory=list)
    ns_records: List[str] = field(default_factory=list)
    error: str = ""

@dataclass
class WHOISRecord:
    domain: str
    registrar: str = ""
    creation_date: str = ""
    expiration_date: str = ""
    updated_date: str = ""
    country: str = ""
    days_old: Optional[int] = None
    is_new: bool = False          # < 90 days old
    privacy_protected: bool = False
    error: str = ""

@dataclass
class IPIntelRecord:
    ip: str
    is_private: bool = False
    country: str = ""
    org: str = ""
    asn: str = ""
    hosting_provider: str = ""
    is_datacenter: bool = False
    is_tor: bool = False
    reverse_dns: str = ""
    risk_flags: List[str] = field(default_factory=list)

@dataclass
class IntelligenceResult:
    dns_records: List[DNSRecord] = field(default_factory=list)
    whois_records: List[WHOISRecord] = field(default_factory=list)
    ip_intel: List[IPIntelRecord] = field(default_factory=list)
    intel_score: int = 0
    intel_warnings: List[str] = field(default_factory=list)

# ---------------------------------------------------------------------------
# Datacenter / bulletproof ASN keywords
# ---------------------------------------------------------------------------

DATACENTER_KEYWORDS = [
    "amazon", "google", "microsoft", "digitalocean", "linode", "vultr",
    "ovh", "hetzner", "contabo", "hostinger", "cloudflare", "fastly",
    "akamai", "serverius", "alexhost", "ddos-guard", "combahton",
    "frantech", "shinjiru", "psychz", "m247", "hostkey", "serverius",
]

BULLETPROOF_ORGS = [
    "frantech", "shinjiru", "m247", "combahton", "psychz", "hostkey",
    "vdsina", "alexhost", "ddos-guard",
]

# ---------------------------------------------------------------------------
# DNS Resolution
# ---------------------------------------------------------------------------

def _resolve_dns(domain: str, timeout: float = 3.0) -> DNSRecord:
    rec = DNSRecord(domain=domain)
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout

        for qtype, attr in [("A", "a_records"), ("AAAA", "aaaa_records"),
                             ("MX", "mx_records"), ("NS", "ns_records")]:
            try:
                answers = resolver.resolve(domain, qtype)
                if qtype == "MX":
                    getattr(rec, attr).extend(
                        f"{r.preference} {r.exchange.to_text().rstrip('.')}"
                        for r in answers
                    )
                elif qtype == "NS":
                    getattr(rec, attr).extend(
                        r.target.to_text().rstrip('.') for r in answers
                    )
                else:
                    getattr(rec, attr).extend(r.address for r in answers)
            except Exception:
                pass
    except ImportError:
        rec.error = "dnspython not installed"
    except Exception as e:
        rec.error = str(e)[:80]
    return rec


def _reverse_dns(ip: str, timeout: float = 2.0) -> str:
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# WHOIS
# ---------------------------------------------------------------------------

def _whois_lookup(domain: str) -> WHOISRecord:
    rec = WHOISRecord(domain=domain)
    try:
        import whois
        w = whois.whois(domain)
        rec.registrar = str(w.registrar or "")[:80]
        rec.country   = str(w.country  or "")[:5].upper()

        def _fmt_date(d):
            if isinstance(d, list):
                d = d[0]
            if isinstance(d, datetime):
                return d.strftime("%Y-%m-%d")
            return str(d)[:10] if d else ""

        rec.creation_date   = _fmt_date(w.creation_date)
        rec.expiration_date = _fmt_date(w.expiration_date)
        rec.updated_date    = _fmt_date(w.updated_date)

        # Age calculation
        if w.creation_date:
            cd = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            if isinstance(cd, datetime):
                if cd.tzinfo is None:
                    cd = cd.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                rec.days_old = (now - cd).days
                rec.is_new = rec.days_old < 90

        # Privacy detection
        reg_str = (str(w.name or "") + str(w.org or "") + str(w.registrar or "")).lower()
        rec.privacy_protected = any(k in reg_str for k in
            ["privacy", "whoisguard", "redacted", "withheld", "protected"])

    except Exception as e:
        rec.error = str(e)[:120]
    return rec


# ---------------------------------------------------------------------------
# IP Intelligence (using ip-api.com free tier — no key needed)
# ---------------------------------------------------------------------------

def _ip_intel(ip: str) -> IPIntelRecord:
    rec = IPIntelRecord(ip=ip)

    # Check private
    try:
        obj = ipaddress.ip_address(ip)
        if obj.is_private or obj.is_loopback or obj.is_link_local:
            rec.is_private = True
            rec.risk_flags.append("Private/internal IP hardcoded in APK")
            return rec
    except ValueError:
        pass

    # Reverse DNS
    rec.reverse_dns = _reverse_dns(ip)

    # Free geo/ASN lookup via ip-api.com (no key, 45 req/min)
    try:
        import urllib.request, json
        url = f"http://ip-api.com/json/{ip}?fields=status,country,org,as,isp,hosting"
        with urllib.request.urlopen(url, timeout=4) as resp:
            data = json.loads(resp.read().decode())
        if data.get("status") == "success":
            rec.country          = data.get("country", "")
            rec.org              = data.get("org", "")
            rec.asn              = data.get("as", "")
            rec.hosting_provider = data.get("isp", "")
            rec.is_datacenter    = bool(data.get("hosting", False))
    except Exception:
        pass  # offline / rate-limited — graceful degradation

    # Flag datacenter/bulletproof by keyword even if API failed
    org_lower = (rec.org + rec.hosting_provider).lower()
    if rec.is_datacenter or any(k in org_lower for k in DATACENTER_KEYWORDS):
        rec.is_datacenter = True
        rec.risk_flags.append(f"Datacenter/cloud-hosted IP ({rec.hosting_provider or rec.org})")

    if any(k in org_lower for k in BULLETPROOF_ORGS):
        rec.risk_flags.append(
            f"Possible bulletproof hosting provider: {rec.hosting_provider or rec.org}"
        )

    return rec


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

def run_intelligence(
    domains: List[str],
    ips: List[str],
    max_domains: int = 10,
    max_ips: int = 10,
) -> IntelligenceResult:
    """
    Run DNS + WHOIS + IP intel on extracted indicators.
    Limits are enforced to keep total time under ~30s.
    """
    result = IntelligenceResult()
    score = 0
    warnings: List[str] = []

    # DNS + WHOIS per domain (cap to avoid timeout)
    for domain in domains[:max_domains]:
        dns_rec = _resolve_dns(domain)
        result.dns_records.append(dns_rec)

        whois_rec = _whois_lookup(domain)
        result.whois_records.append(whois_rec)

        if whois_rec.is_new:
            score += 20
            warnings.append(
                f"Newly registered domain: {domain} "
                f"(registered {whois_rec.days_old} days ago)"
            )
        if whois_rec.privacy_protected:
            score += 5
            warnings.append(f"WHOIS privacy enabled: {domain}")

    # IP intel
    for ip in ips[:max_ips]:
        ip_rec = _ip_intel(ip)
        result.ip_intel.append(ip_rec)
        if ip_rec.is_datacenter:
            score += 10
        if ip_rec.risk_flags:
            warnings.extend(ip_rec.risk_flags)

    result.intel_score   = score
    result.intel_warnings = warnings
    return result
