"""
Static string extraction and threat-indicator analysis.
Works on decompiled smali/java/kotlin source text.
No network calls — pure regex-based extraction.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Set
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

RE_IP = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

RE_DOMAIN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:com|net|org|in|io|xyz|top|club|live|online|site|'
    r'store|shop|info|biz|co|me|app|dev|tech|ru|cn|tk|ml|ga|cf)\b',
    re.IGNORECASE,
)

RE_URL = re.compile(
    r'https?://[^\s\'"<>]{10,200}',
    re.IGNORECASE,
)

RE_API_KEY = re.compile(
    r'''(?x)
    (?:
        (?P<google_api>AIza[0-9A-Za-z\-_]{35})                              # Google API Key
      | (?P<firebase>AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140})              # Firebase Cloud Messaging
      | (?P<aws_access>(?:AKIA|AGPA|AROA|ASIA)[0-9A-Z]{16})                 # AWS Access Key
      | (?P<aws_secret>[0-9a-zA-Z/+]{40})                                    # AWS Secret (40-char base64)
      | (?P<razorpay>rzp_(?:live|test)_[A-Za-z0-9]{14,})                   # Razorpay
      | (?P<paytm>PAYTM_[A-Z0-9]{16,})                                      # Paytm merchant key
      | (?P<stripe>sk_(?:live|test)_[A-Za-z0-9]{24,})                       # Stripe secret
      | (?P<sendgrid>SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{43,})           # SendGrid
      | (?P<jwt>eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}) # JWT
      | (?P<telegram_bot>bot[0-9]{8,10}:[A-Za-z0-9_-]{35,})                # Telegram Bot Token
    )
    ''',
)

RE_PHONE = re.compile(r'\b(?:\+91|0)?[6-9]\d{9}\b')
RE_EMAIL = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,7}\b')

# Known legitimate Android / Google domains to reduce false positives
WHITELIST_DOMAINS: Set[str] = {
    "google.com", "googleapis.com", "android.com", "gstatic.com",
    "firebase.com", "firebaseio.com", "crashlytics.com", "fabric.io",
    "github.com", "stackoverflow.com", "developer.android.com",
    "play.google.com", "fonts.googleapis.com", "maps.googleapis.com",
    "schema.org", "w3.org", "apache.org", "mozilla.org",
}

# Private/loopback IP ranges — usually interesting if hardcoded
PRIVATE_IP_PREFIXES = ("192.168.", "10.", "172.16.", "172.17.",
                       "172.18.", "172.19.", "172.20.", "172.21.",
                       "172.22.", "172.23.", "172.24.", "172.25.",
                       "172.26.", "172.27.", "172.28.", "172.29.",
                       "172.30.", "172.31.", "127.", "0.0.0.0")

# C2-associated TLDs / suspicious patterns
SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".top", ".xyz",
                   ".club", ".online", ".site", ".live", ".work"}
SUSPICIOUS_KEYWORDS = ["panel", "bot", "c2", "cmd", "command",
                       "payload", "agent", "exfil", "upload", "collect"]

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ExtractedURL:
    url: str
    domain: str
    is_suspicious: bool
    reason: str = ""

@dataclass
class ExtractedKey:
    key_type: str
    value: str
    is_active: bool = False          # set by validator later
    risk_note: str = ""

@dataclass
class StringAnalysisResult:
    urls: List[ExtractedURL]
    hardcoded_ips: List[str]
    api_keys: List[ExtractedKey]
    phone_numbers: List[str]
    emails: List[str]
    suspicious_urls: List[ExtractedURL]
    string_score: int                # additive risk contribution

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_suspicious_domain(domain: str) -> Tuple[bool, str]:
    domain_lower = domain.lower()
    # Whitelist check
    for wl in WHITELIST_DOMAINS:
        if domain_lower == wl or domain_lower.endswith("." + wl):
            return False, ""
    # TLD
    for tld in SUSPICIOUS_TLDS:
        if domain_lower.endswith(tld):
            return True, f"Suspicious TLD ({tld})"
    # Keyword in hostname
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in domain_lower:
            return True, f"C2-indicative keyword '{kw}' in hostname"
    # Very short domain with no recognizable brand — weak signal
    parts = domain_lower.split(".")
    if len(parts[0]) <= 5 and not any(c.isalpha() and c.isdigit() for c in parts[0]):
        pass  # too noisy to flag alone
    return False, ""


def _domain_from_url(url: str) -> str:
    try:
        parsed = urlparse(url)
        return parsed.netloc.split(":")[0].lower()
    except Exception:
        return ""

# ---------------------------------------------------------------------------
# Main function
# ---------------------------------------------------------------------------

def analyze_strings(source_text: str) -> StringAnalysisResult:
    """
    source_text: concatenated smali/java/kotlin decompiled content
    Returns structured findings.
    """
    score = 0
    seen_urls: Set[str] = set()
    seen_ips: Set[str] = set()
    seen_keys: Set[str] = set()
    seen_phones: Set[str] = set()
    seen_emails: Set[str] = set()

    urls: List[ExtractedURL] = []
    hardcoded_ips: List[str] = []
    api_keys: List[ExtractedKey] = []
    phone_numbers: List[str] = []
    emails: List[str] = []
    suspicious_urls: List[ExtractedURL] = []

    # --- URLs ---
    for match in RE_URL.finditer(source_text):
        raw = match.group().rstrip(".,;)")
        if raw in seen_urls:
            continue
        seen_urls.add(raw)
        domain = _domain_from_url(raw)
        is_susp, reason = _is_suspicious_domain(domain)
        eu = ExtractedURL(url=raw, domain=domain,
                          is_suspicious=is_susp, reason=reason)
        urls.append(eu)
        if is_susp:
            suspicious_urls.append(eu)
            score += 15

    # --- Bare domains not already in a URL ---
    for match in RE_DOMAIN.finditer(source_text):
        d = match.group().lower()
        fake_url = f"http://{d}"
        if fake_url in seen_urls or d in seen_urls:
            continue
        seen_urls.add(d)
        is_susp, reason = _is_suspicious_domain(d)
        eu = ExtractedURL(url=d, domain=d,
                          is_suspicious=is_susp, reason=reason)
        urls.append(eu)
        if is_susp:
            suspicious_urls.append(eu)
            score += 10

    # --- IPs ---
    for match in RE_IP.finditer(source_text):
        ip = match.group()
        if ip in seen_ips:
            continue
        seen_ips.add(ip)
        # Skip common placeholders
        if ip in ("0.0.0.0", "255.255.255.255", "127.0.0.1"):
            continue
        hardcoded_ips.append(ip)
        # Private IPs hardcoded in APK are interesting
        if any(ip.startswith(p) for p in PRIVATE_IP_PREFIXES):
            score += 5
        else:
            score += 12   # public IP hardcoded = C2 candidate

    # --- API Keys ---
    for match in RE_API_KEY.finditer(source_text):
        matched_groups = {k: v for k, v in match.groupdict().items() if v}
        for key_type, value in matched_groups.items():
            if value in seen_keys:
                continue
            seen_keys.add(value)
            note = ""
            if key_type == "telegram_bot":
                note = "Telegram bot token often used for C2 exfiltration"
                score += 20
            elif key_type in ("aws_access", "aws_secret"):
                note = "AWS credentials — potential for cloud resource abuse"
                score += 25
            elif key_type == "firebase":
                note = "FCM key — can be used for push notification abuse"
                score += 15
            elif key_type == "razorpay":
                note = "Payment gateway key — financial fraud risk"
                score += 20
            else:
                score += 10
            api_keys.append(ExtractedKey(
                key_type=key_type.replace("_", " ").title(),
                value=value[:12] + "..." + value[-4:],  # partial redact
                risk_note=note,
            ))

    # --- Phone numbers ---
    for match in RE_PHONE.finditer(source_text):
        ph = match.group()
        if ph not in seen_phones:
            seen_phones.add(ph)
            phone_numbers.append(ph)
            score += 5

    # --- Emails ---
    for match in RE_EMAIL.finditer(source_text):
        em = match.group().lower()
        if em in seen_emails:
            continue
        seen_emails.add(em)
        # Filter out common lib emails (apache, etc.)
        if any(wl in em for wl in ("apache.org", "example.com", "schema.org")):
            continue
        emails.append(em)
        score += 3

    return StringAnalysisResult(
        urls=urls,
        hardcoded_ips=hardcoded_ips,
        api_keys=api_keys,
        phone_numbers=phone_numbers,
        emails=emails,
        suspicious_urls=suspicious_urls,
        string_score=score,
    )
