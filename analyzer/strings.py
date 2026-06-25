"""
Static string extraction and threat-indicator analysis.
Works on decompiled smali/java/kotlin source text.
No network calls — pure regex-based extraction.
"""

import re
from dataclasses import dataclass, field
from typing import List, Set
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

RE_IP = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

RE_IPV6 = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    r'|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b'
    r'|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b'
)

RE_DOMAIN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:com|net|org|in|io|xyz|top|club|live|online|site|'
    r'store|shop|info|biz|co|me|app|dev|tech|ru|cn|tk|ml|ga|cf)\\b',
    re.IGNORECASE,
)

RE_URL = re.compile(
    r'https?://[^\s\'"<>]{10,200}',
    re.IGNORECASE,
)

RE_WEBSOCKET = re.compile(
    r'wss?://[^\s\'"<>]{5,200}',
    re.IGNORECASE,
)

RE_API_ENDPOINT = re.compile(
    r'(?:"|\')/(?:api|v\d|rest|graphql|webhook|ws)/[^\s\'"<>]{3,100}(?:"|\')',
    re.IGNORECASE,
)

RE_API_KEY = re.compile(
    r'''(?x)
    (?:
        (?P<google_api>AIza[0-9A-Za-z\-_]{35})                              # Google API Key
      | (?P<firebase>AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140})              # Firebase Cloud Messaging
      | (?P<aws_access>(?:AKIA|AGPA|AROA|ASIA)[0-9A-Z]{16})                 # AWS Access Key (precise prefix)
      | (?P<razorpay>rzp_(?:live|test)_[A-Za-z0-9]{14,})                   # Razorpay
      | (?P<paytm>PAYTM_[A-Z0-9]{16,})                                      # Paytm merchant key
      | (?P<stripe>sk_(?:live|test)_[A-Za-z0-9]{24,})                       # Stripe secret
      | (?P<sendgrid>SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{43,})           # SendGrid
      | (?P<jwt>eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}) # JWT
      | (?P<telegram_bot>bot[0-9]{8,10}:[A-Za-z0-9_-]{35,})                # Telegram Bot Token
      | (?P<discord_webhook>https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]{60,}) # Discord Webhook
      | (?P<firebase_url>https://[a-z0-9-]+\.firebaseio\.com)               # Firebase Realtime DB
    )
    ''',
)

RE_PHONE = re.compile(r'\b(?:\+91|0)?[6-9]\d{9}\b')
RE_EMAIL = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,7}\b')

# Cryptocurrency addresses
RE_BTC = re.compile(r'\b(?:1|3)[A-HJ-NP-Za-km-z1-9]{25,34}\b|bc1[a-zA-HJ-NP-Z0-9]{25,39}\b')
RE_ETH = re.compile(r'\b0x[a-fA-F0-9]{40}\b')
RE_USDT_TRON = re.compile(r'\bT[A-Za-z1-9]{33}\b')

# Cloud storage patterns
RE_CLOUD_STORAGE = re.compile(
    r'(?:s3\.amazonaws\.com|storage\.googleapis\.com|'
    r'blob\.core\.windows\.net|[a-z0-9-]+\.s3\.[a-z0-9-]+\.amazonaws\.com)'
    r'(?:/[^\s\'"<>]{0,100})?',
    re.IGNORECASE,
)

# Known legitimate Android / Google domains to reduce false positives
WHITELIST_DOMAINS: Set[str] = {
    "google.com", "googleapis.com", "android.com", "gstatic.com",
    "firebase.com", "firebaseio.com", "crashlytics.com", "fabric.io",
    "github.com", "stackoverflow.com", "developer.android.com",
    "play.google.com", "fonts.googleapis.com", "maps.googleapis.com",
    "schema.org", "w3.org", "apache.org", "mozilla.org",
}

PRIVATE_IP_PREFIXES = ("192.168.", "10.", "172.16.", "172.17.",
                       "172.18.", "172.19.", "172.20.", "172.21.",
                       "172.22.", "172.23.", "172.24.", "172.25.",
                       "172.26.", "172.27.", "172.28.", "172.29.",
                       "172.30.", "172.31.", "127.", "0.0.0.0")

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
    is_active: bool = False
    risk_note: str = ""

@dataclass
class CryptoWallet:
    wallet_type: str   # BTC / ETH / USDT-TRC20
    address: str

@dataclass
class StringAnalysisResult:
    urls: List[ExtractedURL]
    websocket_endpoints: List[str]
    api_endpoints: List[str]
    hardcoded_ips: List[str]
    ipv6_addresses: List[str]
    api_keys: List[ExtractedKey]
    phone_numbers: List[str]
    emails: List[str]
    crypto_wallets: List[CryptoWallet]
    cloud_storage_urls: List[str]
    suspicious_urls: List[ExtractedURL]
    string_score: int

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_suspicious_domain(domain: str):
    domain_lower = domain.lower()
    for wl in WHITELIST_DOMAINS:
        if domain_lower == wl or domain_lower.endswith("." + wl):
            return False, ""
    for tld in SUSPICIOUS_TLDS:
        if domain_lower.endswith(tld):
            return True, f"Suspicious TLD ({tld})"
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in domain_lower:
            return True, f"C2-indicative keyword '{kw}' in hostname"
    return False, ""


def _domain_from_url(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Main function
# ---------------------------------------------------------------------------

def analyze_strings(source_text: str) -> StringAnalysisResult:
    score = 0
    seen_urls: Set[str] = set()
    seen_ips: Set[str] = set()
    seen_ipv6: Set[str] = set()
    seen_keys: Set[str] = set()
    seen_phones: Set[str] = set()
    seen_emails: Set[str] = set()
    seen_ws: Set[str] = set()
    seen_api: Set[str] = set()
    seen_crypto: Set[str] = set()
    seen_cloud: Set[str] = set()

    urls: List[ExtractedURL] = []
    hardcoded_ips: List[str] = []
    ipv6_addresses: List[str] = []
    api_keys: List[ExtractedKey] = []
    phone_numbers: List[str] = []
    emails: List[str] = []
    suspicious_urls: List[ExtractedURL] = []
    websocket_endpoints: List[str] = []
    api_endpoints: List[str] = []
    crypto_wallets: List[CryptoWallet] = []
    cloud_storage_urls: List[str] = []

    # --- URLs ---
    for match in RE_URL.finditer(source_text):
        raw = match.group().rstrip(".,;)")
        if raw in seen_urls:
            continue
        seen_urls.add(raw)
        domain = _domain_from_url(raw)
        is_susp, reason = _is_suspicious_domain(domain)
        eu = ExtractedURL(url=raw, domain=domain, is_suspicious=is_susp, reason=reason)
        urls.append(eu)
        if is_susp:
            suspicious_urls.append(eu)
            score += 15

    # --- Bare domains ---
    for match in RE_DOMAIN.finditer(source_text):
        d = match.group().lower()
        if d in seen_urls:
            continue
        seen_urls.add(d)
        is_susp, reason = _is_suspicious_domain(d)
        eu = ExtractedURL(url=d, domain=d, is_suspicious=is_susp, reason=reason)
        urls.append(eu)
        if is_susp:
            suspicious_urls.append(eu)
            score += 10

    # Deduplicate suspicious_urls by domain
    seen_susp_d: Set[str] = set()
    deduped_susp = []
    for su in suspicious_urls:
        if su.domain not in seen_susp_d:
            seen_susp_d.add(su.domain)
            deduped_susp.append(su)

    # --- WebSocket endpoints ---
    for match in RE_WEBSOCKET.finditer(source_text):
        raw = match.group().rstrip(".,;)")
        if raw not in seen_ws:
            seen_ws.add(raw)
            websocket_endpoints.append(raw)
            score += 8

    # --- API endpoints ---
    for match in RE_API_ENDPOINT.finditer(source_text):
        ep = match.group().strip("'\"")
        if ep not in seen_api:
            seen_api.add(ep)
            api_endpoints.append(ep)

    # --- IPv4 ---
    for match in RE_IP.finditer(source_text):
        ip = match.group()
        if ip in seen_ips or ip in ("0.0.0.0", "255.255.255.255", "127.0.0.1"):
            continue
        seen_ips.add(ip)
        hardcoded_ips.append(ip)
        if any(ip.startswith(p) for p in PRIVATE_IP_PREFIXES):
            score += 5
        else:
            score += 12

    # --- IPv6 ---
    for match in RE_IPV6.finditer(source_text):
        ip6 = match.group()
        if ip6 not in seen_ipv6 and ip6 != "::1":
            seen_ipv6.add(ip6)
            ipv6_addresses.append(ip6)
            score += 8

    # --- API Keys / Credentials ---
    for match in RE_API_KEY.finditer(source_text):
        for key_type, value in match.groupdict().items():
            if not value or value in seen_keys:
                continue
            seen_keys.add(value)
            note = ""
            if key_type == "telegram_bot":
                note = "Telegram bot token — often used for C2 data exfiltration"
                score += 20
            elif key_type == "discord_webhook":
                note = "Discord webhook — used for C2 notifications / data exfil"
                score += 18
            elif key_type == "aws_access":
                note = "AWS access key — potential cloud resource abuse"
                score += 25
            elif key_type == "firebase":
                note = "FCM key — can be abused for push notification spam"
                score += 15
            elif key_type == "firebase_url":
                note = "Firebase Realtime DB URL — possible data exfil endpoint"
                score += 12
            elif key_type == "razorpay":
                note = "Razorpay payment key — financial fraud risk"
                score += 20
            elif key_type == "stripe":
                note = "Stripe secret key — financial fraud risk"
                score += 22
            else:
                score += 10
            api_keys.append(ExtractedKey(
                key_type=key_type.replace("_", " ").title(),
                value=value[:12] + "..." + value[-4:],
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
        if any(wl in em for wl in ("apache.org", "example.com", "schema.org")):
            continue
        emails.append(em)
        score += 3

    # --- Crypto wallets ---
    for match in RE_BTC.finditer(source_text):
        addr = match.group()
        if addr not in seen_crypto and len(addr) >= 26:
            seen_crypto.add(addr)
            crypto_wallets.append(CryptoWallet("BTC", addr))
            score += 20

    for match in RE_ETH.finditer(source_text):
        addr = match.group()
        if addr not in seen_crypto:
            seen_crypto.add(addr)
            crypto_wallets.append(CryptoWallet("ETH", addr))
            score += 20

    for match in RE_USDT_TRON.finditer(source_text):
        addr = match.group()
        if addr not in seen_crypto:
            seen_crypto.add(addr)
            crypto_wallets.append(CryptoWallet("USDT-TRC20", addr))
            score += 20

    # --- Cloud storage ---
    for match in RE_CLOUD_STORAGE.finditer(source_text):
        url = match.group()
        if url not in seen_cloud:
            seen_cloud.add(url)
            cloud_storage_urls.append(url)
            score += 8

    return StringAnalysisResult(
        urls=urls,
        websocket_endpoints=websocket_endpoints,
        api_endpoints=api_endpoints,
        hardcoded_ips=hardcoded_ips,
        ipv6_addresses=ipv6_addresses,
        api_keys=api_keys,
        phone_numbers=phone_numbers,
        emails=emails,
        crypto_wallets=crypto_wallets,
        cloud_storage_urls=cloud_storage_urls,
        suspicious_urls=deduped_susp,
        string_score=score,
    )
