"""
Permission risk analysis engine.
Detects fake loan app patterns, spyware signatures, and permission abuse.
"""

from dataclasses import dataclass, field
from typing import List, Dict

# ---------------------------------------------------------------------------
# Risk-weighted permission catalogue
# ---------------------------------------------------------------------------

PERMISSION_WEIGHTS: Dict[str, int] = {
    # Surveillance / data harvesting
    "android.permission.READ_SMS":                  9,
    "android.permission.RECEIVE_SMS":               8,
    "android.permission.SEND_SMS":                  8,
    "android.permission.READ_CONTACTS":             7,
    "android.permission.WRITE_CONTACTS":            6,
    "android.permission.READ_CALL_LOG":             8,
    "android.permission.WRITE_CALL_LOG":            6,
    "android.permission.PROCESS_OUTGOING_CALLS":    7,
    "android.permission.RECORD_AUDIO":              7,
    "android.permission.CAMERA":                    5,
    "android.permission.READ_MEDIA_IMAGES":         5,
    "android.permission.READ_EXTERNAL_STORAGE":     5,
    "android.permission.WRITE_EXTERNAL_STORAGE":    4,

    # Location tracking
    "android.permission.ACCESS_FINE_LOCATION":      7,
    "android.permission.ACCESS_COARSE_LOCATION":    5,
    "android.permission.ACCESS_BACKGROUND_LOCATION":9,

    # Financial / device control
    "android.permission.BIND_DEVICE_ADMIN":         10,
    "android.permission.REQUEST_INSTALL_PACKAGES":  8,
    "android.permission.SYSTEM_ALERT_WINDOW":       7,
    "android.permission.DISABLE_KEYGUARD":          7,
    "android.permission.RECEIVE_BOOT_COMPLETED":    6,
    "android.permission.FOREGROUND_SERVICE":        4,
    "android.permission.WAKE_LOCK":                 3,

    # Account / credential access
    "android.permission.GET_ACCOUNTS":              7,
    "android.permission.MANAGE_ACCOUNTS":           8,
    "android.permission.USE_CREDENTIALS":           8,
    "android.permission.AUTHENTICATE_ACCOUNTS":     8,

    # Accessibility abuse
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 9,
    "android.permission.WRITE_SETTINGS":            6,
    "android.permission.WRITE_SECURE_SETTINGS":     8,
    "android.permission.CHANGE_CONFIGURATION":      5,

    # Screen capture / overlay
    "android.permission.CAPTURE_VIDEO_OUTPUT":      8,
    "android.permission.MEDIA_PROJECTION":          8,
    "android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION": 7,

    # Network surveillance
    "android.permission.INTERNET":                  2,
    "android.permission.CHANGE_NETWORK_STATE":      5,
    "android.permission.CHANGE_WIFI_STATE":         5,
    "android.permission.ACCESS_WIFI_STATE":         3,

    # Package / app control
    "android.permission.QUERY_ALL_PACKAGES":        5,
    "android.permission.DELETE_PACKAGES":           7,
    "android.permission.INSTALL_PACKAGES":          9,
}

# ---------------------------------------------------------------------------
# Fraud / malware permission clusters
# ---------------------------------------------------------------------------

FRAUD_CLUSTERS: List[Dict] = [
    {
        "name": "Fake Loan App (Classic)",
        "description": "Harvests contacts, SMS OTPs, and location for blackmail and identity fraud",
        "permissions": [
            "android.permission.READ_CONTACTS",
            "android.permission.READ_SMS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_CALL_LOG",
        ],
        "threshold": 3,
        "severity": "CRITICAL",
    },
    {
        "name": "Device Takeover / Stalkerware",
        "description": "Records audio, tracks location in background, reads messages — full surveillance",
        "permissions": [
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_BOOT_COMPLETED",
        ],
        "threshold": 3,
        "severity": "CRITICAL",
    },
    {
        "name": "Credential Harvester",
        "description": "Targets banking credentials via account access and overlay attacks",
        "permissions": [
            "android.permission.GET_ACCOUNTS",
            "android.permission.USE_CREDENTIALS",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_DEVICE_ADMIN",
        ],
        "threshold": 2,
        "severity": "HIGH",
    },
    {
        "name": "Silent Installer / Dropper",
        "description": "Downloads and silently installs secondary payloads",
        "permissions": [
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.FOREGROUND_SERVICE",
            "android.permission.INTERNET",
        ],
        "threshold": 3,
        "severity": "HIGH",
    },
    {
        "name": "SMS Interceptor",
        "description": "Classic OTP and banking SMS interception pattern",
        "permissions": [
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
        ],
        "threshold": 2,
        "severity": "CRITICAL",
    },
    {
        "name": "Accessibility Service Abuser",
        "description": "Uses Accessibility Service for keylogging, UI scraping, or overlay attacks",
        "permissions": [
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.WRITE_SECURE_SETTINGS",
        ],
        "threshold": 2,
        "severity": "CRITICAL",
    },
    {
        "name": "Screen Capture / Spyware",
        "description": "Captures screen content or records device display",
        "permissions": [
            "android.permission.MEDIA_PROJECTION",
            "android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAPTURE_VIDEO_OUTPUT",
        ],
        "threshold": 2,
        "severity": "HIGH",
    },
    {
        "name": "Call Monitor",
        "description": "Monitors outgoing calls and call logs — phone surveillance pattern",
        "permissions": [
            "android.permission.PROCESS_OUTGOING_CALLS",
            "android.permission.READ_CALL_LOG",
            "android.permission.RECORD_AUDIO",
        ],
        "threshold": 2,
        "severity": "HIGH",
    },
]

# ---------------------------------------------------------------------------
# Malware behavior indicators in DEX strings
# ---------------------------------------------------------------------------

MALWARE_PATTERNS: List[Dict] = [
    {
        "name": "Dynamic Code Loading",
        "patterns": ["DexClassLoader", "PathClassLoader", "loadDex", "InMemoryDexClassLoader"],
        "description": "Loads code dynamically at runtime — evasion or payload delivery technique",
        "severity": "HIGH",
        "score": 15,
    },
    {
        "name": "Java Reflection Abuse",
        "patterns": ["java.lang.reflect", "getDeclaredMethod", "setAccessible(true)", "invoke("],
        "description": "Heavy use of reflection to hide API calls from static analysis",
        "severity": "MEDIUM",
        "score": 10,
    },
    {
        "name": "Root / Shell Execution",
        "patterns": ["su\x00", "/system/xbin/su", "Runtime.getRuntime().exec", "ProcessBuilder"],
        "description": "Attempts to execute shell commands or escalate to root",
        "severity": "CRITICAL",
        "score": 25,
    },
    {
        "name": "Emulator Detection",
        "patterns": ["Build.FINGERPRINT", "generic_x86", "Genymotion", "ro.kernel.qemu",
                     "isEmulator", "getDeviceId() == \"000000000000000\""],
        "description": "Checks for emulator environment to evade sandbox analysis",
        "severity": "HIGH",
        "score": 12,
    },
    {
        "name": "Anti-Debug / Anti-Analysis",
        "patterns": ["Debug.isDebuggerConnected()", "ptrace", "TracerPid", "JDWP", "frida"],
        "description": "Detects and evades debuggers and dynamic analysis tools",
        "severity": "HIGH",
        "score": 15,
    },
    {
        "name": "Obfuscation Indicators",
        "patterns": ["base64_decode", "Base64.decode", "AES/CBC/PKCS", "Cipher.getInstance",
                     "SecretKeySpec"],
        "description": "String encryption / obfuscation techniques that hide payload or C2 config",
        "severity": "MEDIUM",
        "score": 8,
    },
    {
        "name": "Root Detection",
        "patterns": ["/system/app/Superuser.apk", "/sbin/su", "which su", "test-keys",
                     "RootBeer", "isRooted"],
        "description": "Checks for root — may behave differently on rooted devices",
        "severity": "MEDIUM",
        "score": 8,
    },
    {
        "name": "Accessibility Service Abuse",
        "patterns": ["AccessibilityService", "onAccessibilityEvent", "performGlobalAction",
                     "findAccessibilityNodeInfosByText"],
        "description": "Uses Accessibility API for keylogging, click injection, or credential theft",
        "severity": "CRITICAL",
        "score": 20,
    },
    {
        "name": "SMS Sending / Premium",
        "patterns": ["SmsManager.sendTextMessage", "sendMultipartTextMessage",
                     "SEND_TO_PREMIUM_SMS"],
        "description": "Sends SMS programmatically — may be used for OTP relay or premium SMS fraud",
        "severity": "HIGH",
        "score": 15,
    },
    {
        "name": "Contact / Media Harvesting",
        "patterns": ["ContactsContract", "MediaStore.Images", "getContentResolver().query",
                     "Telephony.Sms.Inbox"],
        "description": "Reads contacts, media files, or SMS inbox via Content Providers",
        "severity": "HIGH",
        "score": 12,
    },
]

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class PermissionFinding:
    permission: str
    risk_weight: int
    category: str

@dataclass
class ClusterMatch:
    cluster_name: str
    description: str
    severity: str
    matched_permissions: List[str]
    match_ratio: float

@dataclass
class MalwareIndicator:
    name: str
    description: str
    severity: str
    matched_patterns: List[str]
    score_contribution: int

@dataclass
class PermissionAnalysisResult:
    total_permissions: int
    risky_permissions: List[PermissionFinding]
    cluster_matches: List[ClusterMatch]
    malware_indicators: List[MalwareIndicator]
    permission_score: int
    normalized_score: float
    verdict: str

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def categorize_permission(perm: str) -> str:
    if any(k in perm for k in ("SMS", "CALL_LOG", "CONTACTS", "RECORD_AUDIO")):
        return "Surveillance"
    if "LOCATION" in perm:
        return "Location Tracking"
    if any(k in perm for k in ("ACCOUNTS", "CREDENTIALS", "AUTHENTICATE")):
        return "Credential Access"
    if any(k in perm for k in ("INSTALL", "DEVICE_ADMIN", "SYSTEM_ALERT", "ACCESSIBILITY")):
        return "Device Control"
    if any(k in perm for k in ("STORAGE", "CAMERA", "MEDIA", "PROJECTION")):
        return "Data Access"
    if any(k in perm for k in ("INTERNET", "NETWORK", "WIFI")):
        return "Network"
    if "SETTINGS" in perm:
        return "System Settings"
    return "Other"

# ---------------------------------------------------------------------------
# Main analyser
# ---------------------------------------------------------------------------

def analyze_permissions(permissions: List[str], source_text: str = "") -> PermissionAnalysisResult:
    permissions_set = set(permissions)

    # Score risky permissions
    risky: List[PermissionFinding] = []
    raw_score = 0
    for perm in permissions:
        weight = PERMISSION_WEIGHTS.get(perm, 0)
        if weight >= 4:
            risky.append(PermissionFinding(
                permission=perm,
                risk_weight=weight,
                category=categorize_permission(perm),
            ))
            raw_score += weight

    # Cluster matching
    cluster_matches: List[ClusterMatch] = []
    for cluster in FRAUD_CLUSTERS:
        matched = [p for p in cluster["permissions"] if p in permissions_set]
        if len(matched) >= cluster["threshold"]:
            cluster_matches.append(ClusterMatch(
                cluster_name=cluster["name"],
                description=cluster["description"],
                severity=cluster["severity"],
                matched_permissions=matched,
                match_ratio=len(matched) / len(cluster["permissions"]),
            ))
            raw_score += 20 * len(matched)

    # Malware behavior indicators (from DEX strings)
    malware_indicators: List[MalwareIndicator] = []
    if source_text:
        for mp in MALWARE_PATTERNS:
            matched_pats = [p for p in mp["patterns"] if p in source_text]
            if matched_pats:
                malware_indicators.append(MalwareIndicator(
                    name=mp["name"],
                    description=mp["description"],
                    severity=mp["severity"],
                    matched_patterns=matched_pats[:3],  # show up to 3
                    score_contribution=mp["score"],
                ))
                raw_score += mp["score"]

    # Normalize to 0-100
    max_possible = 180
    normalized = min(100.0, (raw_score / max_possible) * 100)

    # Verdict
    has_critical = any(c.severity == "CRITICAL" for c in cluster_matches) or \
                   any(m.severity == "CRITICAL" for m in malware_indicators)
    has_high = any(c.severity == "HIGH" for c in cluster_matches) or \
               any(m.severity == "HIGH" for m in malware_indicators)

    if has_critical or normalized >= 70:
        verdict = "MALICIOUS"
    elif has_high or normalized >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "BENIGN"

    return PermissionAnalysisResult(
        total_permissions=len(permissions),
        risky_permissions=risky,
        cluster_matches=cluster_matches,
        malware_indicators=malware_indicators,
        permission_score=raw_score,
        normalized_score=round(normalized, 1),
        verdict=verdict,
    )
