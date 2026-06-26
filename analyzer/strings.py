"""
Static string extraction and threat-indicator analysis.
Works on decompiled smali/java/kotlin source text.
No network calls — pure regex-based extraction.

v2: Reduced false positives per spec:
- Private IPs scored 0 (not flagged as C2)
- Phone numbers validated for country format / length / exclusion of resource IDs
- Emails validated for proper domain + TLD structure
- Crypto wallets require strict format matching
- Confidence levels on all findings
"""

import re
import ipaddress
from dataclasses import dataclass, field
from typing import List, Set, Optional
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Known legitimate / whitelisted TLDs for email validation
# ---------------------------------------------------------------------------

VALID_TLDS = {
    "com", "net", "org", "in", "io", "co", "me", "app", "dev", "tech",
    "gov", "edu", "int", "mil", "uk", "us", "ca", "au", "de", "fr",
    "jp", "cn", "br", "ru", "it", "es", "nl", "se", "no", "fi", "dk",
    "pl", "ch", "at", "be", "nz", "sg", "hk", "info", "biz", "name",
    "pro", "mobi", "tel", "travel", "museum", "coop", "aero", "jobs",
    "xyz", "top", "club", "live", "online", "site", "store", "shop",
    "tk", "ml", "ga", "cf", "gq", "pw", "cc",
}

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

RE_IP = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

RE_IPV6 = re.compile(
    # Full 8-group IPv6 (no compression) — most reliable
    r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    # Compressed forms — require at least one full hex group on both sides to avoid
    # matching things like ::9, ::1 (loopback), :: in CSS, etc.
    r'|\b(?:[0-9a-fA-F]{1,4}:){2,7}:\b'
    r'|\b::(?:[0-9a-fA-F]{1,4}:){1,6}[0-9a-fA-F]{1,4}\b'
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
      | (?P<aws_access>(?:AKIA|AGPA|AROA|ASIA)[0-9A-Z]{16})                 # AWS Access Key
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

# Indian phone numbers — stricter: must be 10 digits starting with 6-9
# Not preceded/followed by digits (avoid resource IDs, hashes)
RE_PHONE_STRICT = re.compile(r'(?<!\d)(\+91[\-\s]?|0)?([6-9]\d{9})(?!\d)')

RE_EMAIL = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,7}\b')

# Cryptocurrency addresses — strict patterns
# BTC: P2PKH (1...), P2SH (3...), or bech32 (bc1...)
RE_BTC = re.compile(
    r'\b(?:(?:1[A-HJ-NP-Za-km-z1-9]{25,33})|(?:3[A-HJ-NP-Za-km-z1-9]{25,33})|(?:bc1[a-z0-9]{25,39}))\b'
)

# ETH: 0x + exactly 40 hex chars
RE_ETH = re.compile(r'\b0x[a-fA-F0-9]{40}\b')

# TRON: T + exactly 33 base58 chars (total 34 chars)
# Requires at least 2 digits in the body to distinguish from Java class names
# like "ThirdPartyDeviceManagementRequired" (pure-alpha, ~34 chars).
# Real TRON addresses are pseudo-random and always contain multiple digits.
RE_TRON = re.compile(
    r'\bT'
    r'(?=[A-Za-z1-9]{33}\b)'            # 33 more chars then word boundary
    r'(?=[A-Za-z1-9]{0,32}\d.*\b)'     # at least 1 digit in body
    r'(?=[A-Za-z1-9]{0,25}\d.*\d.*\b)' # at least 2 digits in body
    r'[A-HJ-NP-Za-km-z1-9]{33}'         # base58 body (no 0/O/I/l)
    r'\b'
)


# Cloud storage patterns
RE_CLOUD_STORAGE = re.compile(
    r'(?:s3\.amazonaws\.com|storage\.googleapis\.com|'
    r'blob\.core\.windows\.net|[a-z0-9-]+\.s3\.[a-z0-9-]+\.amazonaws\.com)'
    r'(?:/[^\s\'"<>]{0,100})?',
    re.IGNORECASE,
)

# Known legitimate Android / Google domains
WHITELIST_DOMAINS: Set[str] = {
    "google.com", "googleapis.com", "android.com", "gstatic.com",
    "firebase.com", "firebaseio.com", "crashlytics.com", "fabric.io",
    "github.com", "stackoverflow.com", "developer.android.com",
    "play.google.com", "fonts.googleapis.com", "maps.googleapis.com",
    "schema.org", "w3.org", "apache.org", "mozilla.org",
}

SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".top", ".xyz",
                   ".club", ".online", ".site", ".live", ".work"}
SUSPICIOUS_KEYWORDS = ["panel", "bot", "c2", "cmd", "command",
                       "payload", "agent", "exfil", "upload", "collect"]

# Known developer/SDK email domains to suppress as noise
SDK_EMAIL_DOMAINS = {
    "android.com", "google.com", "apache.org", "example.com",
    "schema.org", "w3.org", "mozilla.org", "ietf.org",
    "github.com", "stackoverflow.com",
}

# Known SDK/library email prefixes (false positive indicators)
SDK_EMAIL_PREFIXES = {
    "noreply", "no-reply", "support", "info", "contact",
    "hello", "help", "admin", "webmaster", "postmaster",
    "donotreply", "do-not-reply",
}

# ---------------------------------------------------------------------------
# Private IP detection
# ---------------------------------------------------------------------------

def _is_private_ip(ip: str) -> bool:
    """Return True if the IP is private, loopback, or emulator-special."""
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_unspecified
            or addr.is_multicast
            or ip == "10.0.2.2"  # Android emulator gateway
        )
    except ValueError:
        return False


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
    confidence: str = "HIGH"  # HIGH / MEDIUM / LOW

@dataclass
class PhoneNumber:
    number: str
    confidence: str  # HIGH / MEDIUM / LOW
    country: str = "IN"

@dataclass
class EmailAddress:
    address: str
    category: str  # "Application Contact" / "Developer Contact" / "Third-Party Library Contact"
    confidence: str = "MEDIUM"  # HIGH / MEDIUM / LOW

@dataclass
class StringAnalysisResult:
    urls: List[ExtractedURL]
    websocket_endpoints: List[str]
    api_endpoints: List[str]
    hardcoded_ips: List[str]           # only public IPs
    private_ips: List[str]             # informational only, not scored
    ipv6_addresses: List[str]
    api_keys: List[ExtractedKey]
    phone_numbers: List[PhoneNumber]
    emails: List[EmailAddress]
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


def _validate_phone(raw: str) -> Optional[PhoneNumber]:
    """
    Validate a candidate phone number match.
    Returns PhoneNumber with confidence level or None if invalid.

    Rules:
    - Strip country code (+91 / 0)
    - Must be exactly 10 digits starting with 6-9
    - Must not look like a resource ID (e.g. 0x1234567890)
    - Must not be a hash fragment (all same digit, sequential, etc.)
    """
    # Remove common prefix formats
    digits = re.sub(r'[\s\-\+]', '', raw)
    digits = re.sub(r'^(?:91|0091|\+91|0)', '', digits)
    digits = re.sub(r'\D', '', digits)

    if len(digits) != 10:
        return None
    if not re.match(r'^[6-9]\d{9}$', digits):
        return None

    # Reject obvious non-phone patterns
    # - All same digit: 9999999999
    if len(set(digits)) == 1:
        return None
    # - Sequential: 1234567890, 9876543210
    if digits in ("1234567890", "9876543210", "0123456789"):
        return None
    # - Too many repeating groups (resource ID smell)
    if re.match(r'^(\d{2,3})\1{2,}', digits):
        return None

    formatted = f"+91 {digits[:5]} {digits[5:]}"
    return PhoneNumber(number=formatted, confidence="HIGH", country="IN")


def _validate_email(raw: str) -> Optional[EmailAddress]:
    """
    Validate and categorize an email address.
    Returns EmailAddress or None if invalid / noise.
    """
    em = raw.lower().strip()

    # Must have exactly one @
    parts = em.split("@")
    if len(parts) != 2:
        return None

    local, domain = parts[0], parts[1]

    # Domain must have at least one dot and a valid TLD
    domain_parts = domain.split(".")
    if len(domain_parts) < 2:
        return None

    tld = domain_parts[-1]
    if tld not in VALID_TLDS:
        return None

    # Domain must be at least 4 chars total
    if len(domain) < 4:
        return None

    # Suppress SDK / library noise domains
    base_domain = ".".join(domain_parts[-2:])
    if base_domain in SDK_EMAIL_DOMAINS or domain in SDK_EMAIL_DOMAINS:
        return None

    # Categorize
    if base_domain in SDK_EMAIL_DOMAINS or any(sdk in domain for sdk in SDK_EMAIL_DOMAINS):
        category = "Third-Party Library Contact"
    elif local in SDK_EMAIL_PREFIXES:
        category = "Application Contact"
    else:
        category = "Developer Contact"

    # Confidence: high if domain looks real, medium otherwise
    confidence = "HIGH" if len(domain_parts[-2]) >= 3 else "MEDIUM"

    return EmailAddress(address=em, category=category, confidence=confidence)


def _validate_btc(addr: str) -> bool:
    """Strict BTC address validation."""
    if addr.startswith("bc1"):
        # bech32: bc1 + 25-39 lowercase alphanumeric
        return bool(re.match(r'^bc1[a-z0-9]{25,39}$', addr))
    elif addr.startswith("1") or addr.startswith("3"):
        # Base58: 26-34 chars, no 0/O/I/l
        return bool(re.match(r'^[13][A-HJ-NP-Za-km-z1-9]{25,33}$', addr)) and \
               len(addr) >= 26 and len(addr) <= 34
    return False


def _validate_eth(addr: str) -> bool:
    """Strict ETH address: 0x + exactly 40 hex chars."""
    return bool(re.match(r'^0x[a-fA-F0-9]{40}$', addr))


def _validate_tron(addr: str) -> bool:
    """Strict TRON address: T + exactly 33 base58 chars = 34 total."""
    return bool(re.match(r'^T[A-Za-z1-9]{33}$', addr)) and len(addr) == 34


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
    hardcoded_ips: List[str] = []    # public IPs only
    private_ips: List[str] = []       # informational only
    ipv6_addresses: List[str] = []
    api_keys: List[ExtractedKey] = []
    phone_numbers: List[PhoneNumber] = []
    emails: List[EmailAddress] = []
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
    # Private IPs (10.x, 192.168.x, 172.16-31.x, 127.x, 10.0.2.2) → informational, score=0
    # Public IPs → scored
    for match in RE_IP.finditer(source_text):
        ip = match.group()
        if ip in seen_ips or ip in ("0.0.0.0", "255.255.255.255", "127.0.0.1"):
            continue
        seen_ips.add(ip)
        if _is_private_ip(ip):
            private_ips.append(ip)
            # score += 0  # Private IPs are NOT suspicious
        else:
            hardcoded_ips.append(ip)
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

    # --- Phone numbers (HIGH confidence only) ---
    for match in RE_PHONE_STRICT.finditer(source_text):
        raw = match.group()
        if raw in seen_phones:
            continue
        seen_phones.add(raw)
        phone = _validate_phone(raw)
        if phone and phone.confidence == "HIGH":
            phone_numbers.append(phone)
            score += 5

    # --- Emails (validated, no SDK noise) ---
    for match in RE_EMAIL.finditer(source_text):
        em = match.group().lower()
        if em in seen_emails:
            continue
        seen_emails.add(em)
        email_obj = _validate_email(em)
        if email_obj:
            emails.append(email_obj)
            score += 3

    # --- Crypto wallets (strict validation) ---
    for match in RE_BTC.finditer(source_text):
        addr = match.group()
        if addr in seen_crypto:
            continue
        if _validate_btc(addr):
            seen_crypto.add(addr)
            crypto_wallets.append(CryptoWallet("BTC", addr, confidence="HIGH"))
            score += 20

    for match in RE_ETH.finditer(source_text):
        addr = match.group()
        if addr in seen_crypto:
            continue
        if _validate_eth(addr):
            seen_crypto.add(addr)
            crypto_wallets.append(CryptoWallet("ETH", addr, confidence="HIGH"))
            score += 20

    for match in RE_TRON.finditer(source_text):
        addr = match.group()
        if addr in seen_crypto:
            continue
        if _validate_tron(addr):
            seen_crypto.add(addr)
            crypto_wallets.append(CryptoWallet("USDT-TRC20", addr, confidence="HIGH"))
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
        private_ips=private_ips,
        ipv6_addresses=ipv6_addresses,
        api_keys=api_keys,
        phone_numbers=phone_numbers,
        emails=emails,
        crypto_wallets=crypto_wallets,
        cloud_storage_urls=cloud_storage_urls,
        suspicious_urls=deduped_susp,
        string_score=score,
    )
