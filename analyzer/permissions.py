"""
Permission risk analysis engine.
Detects fake loan app patterns, spyware signatures, and permission abuse.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Tuple

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

    # Network surveillance
    "android.permission.INTERNET":                  2,  # alone: fine
    "android.permission.CHANGE_NETWORK_STATE":      5,
    "android.permission.CHANGE_WIFI_STATE":         5,
    "android.permission.ACCESS_WIFI_STATE":         3,
}

# ---------------------------------------------------------------------------
# Known fraud / fake-loan-app permission clusters
# Clusters are named pattern groups; hitting most of a cluster = high risk
# ---------------------------------------------------------------------------

FRAUD_CLUSTERS: List[Dict] = [
    {
        "name": "Fake Loan App (Classic)",
        "description": "Harvests contacts + SMS OTPs for blackmail and identity fraud",
        "permissions": [
            "android.permission.READ_CONTACTS",
            "android.permission.READ_SMS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_CALL_LOG",
        ],
        "threshold": 3,   # how many of these must match
        "severity": "CRITICAL",
    },
    {
        "name": "Device Takeover / Stalkerware",
        "description": "Can record audio, track location, read messages in background",
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
        "description": "Targets banking credentials via account access permissions",
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
        "description": "Downloads and installs secondary payloads silently",
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
        "description": "Classic OTP/banking SMS interception pattern",
        "permissions": [
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
        ],
        "threshold": 2,
        "severity": "CRITICAL",
    },
]

# ---------------------------------------------------------------------------
# Dataclasses for structured output
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
    match_ratio: float            # matched / total in cluster

@dataclass
class PermissionAnalysisResult:
    total_permissions: int
    risky_permissions: List[PermissionFinding]
    cluster_matches: List[ClusterMatch]
    permission_score: int          # raw sum of weights
    normalized_score: float        # 0-100
    verdict: str                   # BENIGN / SUSPICIOUS / MALICIOUS

# ---------------------------------------------------------------------------
# Main analyser
# ---------------------------------------------------------------------------

def categorize_permission(perm: str) -> str:
    if any(k in perm for k in ("SMS", "CALL_LOG", "CONTACTS", "RECORD_AUDIO")):
        return "Surveillance"
    if "LOCATION" in perm:
        return "Location Tracking"
    if any(k in perm for k in ("ACCOUNTS", "CREDENTIALS", "AUTHENTICATE")):
        return "Credential Access"
    if any(k in perm for k in ("INSTALL", "DEVICE_ADMIN", "SYSTEM_ALERT")):
        return "Device Control"
    if any(k in perm for k in ("STORAGE", "CAMERA", "MEDIA")):
        return "Data Access"
    if any(k in perm for k in ("INTERNET", "NETWORK", "WIFI")):
        return "Network"
    return "Other"


def analyze_permissions(permissions: List[str]) -> PermissionAnalysisResult:
    permissions_set = set(permissions)

    # Score risky perms
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
            # Boost score for cluster hits
            raw_score += 20 * len(matched)

    # Normalize to 0-100
    max_possible = 150
    normalized = min(100.0, (raw_score / max_possible) * 100)

    # Verdict
    has_critical = any(c.severity == "CRITICAL" for c in cluster_matches)
    has_high = any(c.severity == "HIGH" for c in cluster_matches)
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
        permission_score=raw_score,
        normalized_score=round(normalized, 1),
        verdict=verdict,
    )
