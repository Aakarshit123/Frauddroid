"""
Permission risk analysis engine.
Detects fake loan app patterns, spyware signatures, and permission abuse.

v2: Reduced false positives per spec:
- Accessibility abuse requires manifest declaration + implementation (not string alone)
- Dynamic code loading requires active instantiation (not class reference)
- Reflection alone is low severity (+2)
- Root detection is informational (+0 to +2)
- Standard crypto APIs (AES/CBC, SecretKeySpec) NOT classified as obfuscation
- Only string decryption routines flagged (+10)
- ContactsContract requires READ_CONTACTS permission + query code
- Evidence Correlation Engine: correlated patterns score higher than individual findings
- New 5-tier verdict system: BENIGN / LOW RISK / SUSPICIOUS / HIGHLY SUSPICIOUS / LIKELY MALICIOUS
- Confidence scoring on all findings
- Framework detection to reduce false positives from framework code
"""

from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional

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
# Malware behavior indicators — v2 with confidence and context requirements
# ---------------------------------------------------------------------------

MALWARE_PATTERNS: List[Dict] = [
    # Dynamic Code Loading — requires ACTIVE instantiation, not just class reference
    {
        "name": "Dynamic Code Loading",
        "description": "Loads code dynamically at runtime — evasion or payload delivery technique",
        "severity": "HIGH",
        "score": 0,  # Base score; actual score determined by context analysis below
        "confidence": "LOW",  # Updated per context
        # Patterns graded by evidence level:
        "class_ref_patterns": ["DexClassLoader", "PathClassLoader", "InMemoryDexClassLoader"],
        "active_patterns": ["new DexClassLoader(", "new PathClassLoader(", "loadDex(", ".loadClass("],
        "external_patterns": [".apk", "sdcard", "/data/local/tmp", "Environment.getExternalStorageDirectory"],
        # Scoring: class ref only = 0, active loading = +10, external APK = +25
    },

    # Java Reflection — very common, very low score unless combined with obfuscation
    {
        "name": "Java Reflection",
        "patterns": ["java.lang.reflect", "getDeclaredMethod", "setAccessible(true)", "invoke("],
        "description": "Use of Java reflection — common in legitimate apps; only suspicious with other indicators",
        "severity": "LOW",
        "score": 2,   # Reflection alone = +2 (was 10)
        "confidence": "LOW",
    },

    # Root / Shell Execution
    {
        "name": "Root / Shell Execution",
        "patterns": ["su\x00", "/system/xbin/su", "Runtime.getRuntime().exec", "ProcessBuilder"],
        "description": "Attempts to execute shell commands or escalate to root",
        "severity": "CRITICAL",
        "score": 25,
        "confidence": "HIGH",
    },

    # Emulator Detection
    {
        "name": "Emulator Detection",
        "patterns": ["Build.FINGERPRINT", "generic_x86", "Genymotion", "ro.kernel.qemu",
                     "isEmulator", 'getDeviceId() == "000000000000000"'],
        "description": "Checks for emulator environment to evade sandbox analysis",
        "severity": "MEDIUM",
        "score": 12,
        "confidence": "MEDIUM",
    },

    # Anti-Debug / Anti-Analysis
    {
        "name": "Anti-Debug / Anti-Analysis",
        "patterns": ["Debug.isDebuggerConnected()", "ptrace", "TracerPid", "JDWP", "frida"],
        "description": "Detects and evades debuggers and dynamic analysis tools",
        "severity": "HIGH",
        "score": 15,
        "confidence": "HIGH",
    },

    # String Decryption (NOT standard crypto APIs — those are normal)
    # Only flag runtime string decryption routines, not use of AES/CBC/etc.
    {
        "name": "Runtime String Decryption",
        "patterns": ["decrypt(", "decryptString(", "xorDecrypt", "rc4decrypt",
                     "deobfuscate(", "StringObfuscator", "ObfuscatedString"],
        "description": "Runtime string decryption routines that hide payload or C2 config",
        "severity": "MEDIUM",
        "score": 10,   # Was 8 for all crypto; now only for actual decryption routines
        "confidence": "MEDIUM",
    },

    # Root Detection — informational only
    {
        "name": "Root Detection",
        "patterns": ["/system/app/Superuser.apk", "/sbin/su", "which su", "test-keys",
                     "RootBeer", "isRooted"],
        "description": "Checks for root — common in security apps; informational only",
        "severity": "INFO",
        "score": 1,   # Was 8; now +1 max (informational)
        "confidence": "LOW",
    },

    # Accessibility Service Abuse — requires ACTIVE implementation, not string presence
    {
        "name": "Accessibility Service Abuse",
        "description": "Uses Accessibility API for keylogging, click injection, or credential theft",
        "severity": "CRITICAL",
        "score": 0,  # Scored contextually below
        "confidence": "LOW",
        # Scoring tiers:
        # string only = 0
        # manifest declaration = +10
        # active implementation (extends AccessibilityService + onAccessibilityEvent) = +20
        # credential theft indicators = +40
        "string_patterns": ["AccessibilityService", "findAccessibilityNodeInfosByText"],
        "impl_patterns": ["onAccessibilityEvent", "performGlobalAction", "getSource()"],
        "theft_patterns": ["getPassword", "getText()", "InputType.TYPE_CLASS_NUMBER",
                           "InputType.TYPE_TEXT_VARIATION_PASSWORD"],
    },

    # SMS Sending / Premium
    {
        "name": "SMS Sending / Premium",
        "patterns": ["SmsManager.sendTextMessage", "sendMultipartTextMessage",
                     "SEND_TO_PREMIUM_SMS"],
        "description": "Sends SMS programmatically — may be used for OTP relay or premium SMS fraud",
        "severity": "HIGH",
        "score": 15,
        "confidence": "HIGH",
    },

    # Contact / Media Harvesting — requires READ_CONTACTS permission + actual query
    {
        "name": "Contact Harvesting",
        "description": "Reads contacts via Content Providers — requires READ_CONTACTS permission",
        "severity": "HIGH",
        "score": 0,  # Scored contextually below
        "confidence": "LOW",
        "string_patterns": ["ContactsContract", "Telephony.Sms.Inbox", "MediaStore.Images"],
        "query_patterns": ["getContentResolver().query", "managedQuery(", ".query(ContactsContract"],
    },
]

# ---------------------------------------------------------------------------
# Framework detection patterns (reduce false positives from framework code)
# ---------------------------------------------------------------------------

FRAMEWORK_PATTERNS: Dict[str, List[str]] = {
    "React Native": [
        "com.facebook.react", "ReactNativeHost", "ReactApplication",
        "ReactInstanceManager", "com.facebook.soloader",
    ],
    "Flutter": [
        "io.flutter", "FlutterActivity", "FlutterEngine",
        "FlutterMain", "GeneratedPluginRegistrant",
    ],
    "Cordova": [
        "org.apache.cordova", "CordovaActivity", "CordovaPlugin",
        "CordovaWebView", "cordova.js",
    ],
    "Unity": [
        "com.unity3d.player", "UnityPlayer", "UnityPlayerActivity",
        "unity.aar", "libunity.so",
    ],
    "Xamarin": [
        "Xamarin.Android", "mono.android", "Xamarin.Forms",
        "MonoRuntimeProvider", "android.runtime.DexLoader",
    ],
}

# ---------------------------------------------------------------------------
# Evidence Correlation Patterns
# ---------------------------------------------------------------------------

CORRELATION_PATTERNS: List[Dict] = [
    {
        "name": "Credential Theft Pattern",
        "description": "Accessibility + Overlay + SMS interception = credential theft toolkit",
        "required_indicators": {
            "malware_indicators": ["Accessibility Service Abuse"],
            "cluster_matches": [],
            "permission_names": ["android.permission.SYSTEM_ALERT_WINDOW"],
            "string_patterns": [],
        },
        "supporting_permissions": ["android.permission.READ_SMS", "android.permission.RECEIVE_SMS"],
        "bonus_score": 25,
        "confidence": "HIGH",
    },
    {
        "name": "C2 Communication Pattern",
        "description": "Telegram/Discord bot + hardcoded IP + dynamic loading = likely C2",
        "api_key_types": ["Telegram Bot", "Discord Webhook"],
        "requires_hardcoded_ip": True,
        "requires_dynamic_loading": True,
        "bonus_score": 30,
        "confidence": "HIGH",
    },
    {
        "name": "Malware Evasion Pattern",
        "description": "Dynamic loading + anti-debug + string decryption = evasion toolkit",
        "required_malware_indicators": ["Dynamic Code Loading", "Anti-Debug / Anti-Analysis", "Runtime String Decryption"],
        "requires_count": 2,
        "bonus_score": 20,
        "confidence": "HIGH",
    },
    {
        "name": "Financial Fraud Pattern",
        "description": "SMS intercept + contacts + location = fake loan app",
        "required_clusters": ["Fake Loan App (Classic)", "SMS Interceptor"],
        "requires_count": 1,
        "bonus_score": 15,
        "confidence": "HIGH",
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
    confidence: str = "MEDIUM"

@dataclass
class CorrelationMatch:
    pattern_name: str
    description: str
    bonus_score: int
    confidence: str

@dataclass
class DetectedFramework:
    name: str
    matched_indicators: List[str]

@dataclass
class PermissionAnalysisResult:
    total_permissions: int
    risky_permissions: List[PermissionFinding]
    cluster_matches: List[ClusterMatch]
    malware_indicators: List[MalwareIndicator]
    correlation_matches: List[CorrelationMatch]
    detected_frameworks: List[DetectedFramework]
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


def _detect_frameworks(source_text: str) -> List[DetectedFramework]:
    """Identify cross-platform frameworks from source strings."""
    found = []
    for fw_name, patterns in FRAMEWORK_PATTERNS.items():
        matched = [p for p in patterns if p in source_text]
        if len(matched) >= 2:  # Require at least 2 indicators to avoid single-string FP
            found.append(DetectedFramework(name=fw_name, matched_indicators=matched[:3]))
    return found


def _analyze_accessibility_abuse(source_text: str, permissions: Set[str],
                                   has_manifest_declaration: bool) -> Optional[MalwareIndicator]:
    """
    Context-aware accessibility abuse detection.
    Scoring:
      - string only = 0
      - manifest declaration = +10
      - active implementation = +20
      - credential theft indicators = +40
    """
    mp = next(p for p in MALWARE_PATTERNS if p["name"] == "Accessibility Service Abuse")

    has_string = any(p in source_text for p in mp["string_patterns"])
    if not has_string:
        return None

    # String only — no score, LOW confidence
    score = 0
    confidence = "LOW"
    matched = [p for p in mp["string_patterns"] if p in source_text]

    if has_manifest_declaration:
        score += 10
        confidence = "MEDIUM"

    has_impl = any(p in source_text for p in mp["impl_patterns"])
    if has_impl:
        score += 20
        confidence = "HIGH"
        matched += [p for p in mp["impl_patterns"] if p in source_text]

    has_theft = any(p in source_text for p in mp["theft_patterns"])
    if has_theft:
        score += 40
        confidence = "HIGH"
        matched += [p for p in mp["theft_patterns"] if p in source_text]

    if score == 0:
        return None  # String-only, no manifest — don't report

    return MalwareIndicator(
        name="Accessibility Service Abuse",
        description=mp["description"],
        severity=mp["severity"] if score >= 20 else "MEDIUM",
        matched_patterns=matched[:3],
        score_contribution=score,
        confidence=confidence,
    )


def _analyze_dynamic_loading(source_text: str) -> Optional[MalwareIndicator]:
    """
    Context-aware dynamic code loading detection.
    Scoring:
      - class ref only = 0
      - active loading = +10
      - external APK loading = +25
    """
    mp = next(p for p in MALWARE_PATTERNS if p["name"] == "Dynamic Code Loading")

    has_class_ref = any(p in source_text for p in mp["class_ref_patterns"])
    if not has_class_ref:
        return None

    has_active = any(p in source_text for p in mp["active_patterns"])
    has_external = any(p in source_text for p in mp["external_patterns"])

    if not has_active and not has_external:
        return None  # Class reference only — skip

    score = 0
    confidence = "LOW"
    matched = [p for p in mp["class_ref_patterns"] if p in source_text]

    if has_active:
        score += 10
        confidence = "MEDIUM"
        matched += [p for p in mp["active_patterns"] if p in source_text]

    if has_external:
        score += 25
        confidence = "HIGH"
        matched += [p for p in mp["external_patterns"] if p in source_text]

    return MalwareIndicator(
        name="Dynamic Code Loading",
        description=mp["description"],
        severity="HIGH" if score >= 25 else "MEDIUM",
        matched_patterns=matched[:3],
        score_contribution=score,
        confidence=confidence,
    )


def _analyze_contact_harvesting(source_text: str, permissions: Set[str]) -> Optional[MalwareIndicator]:
    """
    Contact harvesting requires READ_CONTACTS permission + actual query code.
    String-only presence of ContactsContract = 0 score.
    """
    mp = next(p for p in MALWARE_PATTERNS if p["name"] == "Contact Harvesting")

    has_string = any(p in source_text for p in mp["string_patterns"])
    if not has_string:
        return None

    has_permission = "android.permission.READ_CONTACTS" in permissions
    has_query = any(p in source_text for p in mp["query_patterns"])

    if not (has_permission and has_query):
        return None  # String only or missing permission — not flagged

    matched = [p for p in mp["string_patterns"] if p in source_text]
    matched += [p for p in mp["query_patterns"] if p in source_text]

    return MalwareIndicator(
        name="Contact Harvesting",
        description=mp["description"],
        severity=mp["severity"],
        matched_patterns=matched[:3],
        score_contribution=20,
        confidence="HIGH",
    )


def _run_correlation_engine(
    cluster_matches: List[ClusterMatch],
    malware_indicators: List[MalwareIndicator],
    permissions: Set[str],
    api_key_types: Set[str],
    has_hardcoded_ip: bool,
) -> List[CorrelationMatch]:
    """
    Evidence correlation: correlated patterns contribute more than individual findings.
    """
    results: List[CorrelationMatch] = []
    indicator_names = {m.name for m in malware_indicators}
    cluster_names = {c.cluster_name for c in cluster_matches}

    # Credential Theft Pattern
    if "Accessibility Service Abuse" in indicator_names and \
       "android.permission.SYSTEM_ALERT_WINDOW" in permissions:
        has_sms = "android.permission.READ_SMS" in permissions or \
                  "android.permission.RECEIVE_SMS" in permissions
        results.append(CorrelationMatch(
            pattern_name="Credential Theft Pattern",
            description="Accessibility + Overlay" + (" + SMS" if has_sms else "") + " = credential theft toolkit",
            bonus_score=25,
            confidence="HIGH",
        ))

    # C2 Communication Pattern
    has_tg_dc = bool(api_key_types & {"Telegram Bot", "Discord Webhook"})
    has_dyn = "Dynamic Code Loading" in indicator_names
    if has_tg_dc and (has_hardcoded_ip or has_dyn):
        results.append(CorrelationMatch(
            pattern_name="C2 Communication Pattern",
            description="Telegram/Discord C2 token + " +
                        ("hardcoded IP" if has_hardcoded_ip else "") +
                        (" + dynamic loading" if has_dyn else ""),
            bonus_score=30,
            confidence="HIGH",
        ))

    # Malware Evasion Pattern
    evasion_indicators = {"Dynamic Code Loading", "Anti-Debug / Anti-Analysis", "Runtime String Decryption"}
    matched_evasion = indicator_names & evasion_indicators
    if len(matched_evasion) >= 2:
        results.append(CorrelationMatch(
            pattern_name="Malware Evasion Pattern",
            description=f"Evasion combo: {', '.join(sorted(matched_evasion))}",
            bonus_score=20,
            confidence="HIGH",
        ))

    # Financial Fraud Pattern
    fraud_clusters = {"Fake Loan App (Classic)", "SMS Interceptor"}
    if cluster_names & fraud_clusters:
        results.append(CorrelationMatch(
            pattern_name="Financial Fraud Pattern",
            description=f"Fraud cluster match: {', '.join(cluster_names & fraud_clusters)}",
            bonus_score=15,
            confidence="HIGH",
        ))

    return results


# ---------------------------------------------------------------------------
# Main analyser
# ---------------------------------------------------------------------------

def analyze_permissions(permissions: List[str], source_text: str = "",
                         has_accessibility_manifest: bool = False) -> PermissionAnalysisResult:
    permissions_set = set(permissions)

    # --- Framework detection ---
    detected_frameworks = _detect_frameworks(source_text) if source_text else []
    framework_names = {f.name for f in detected_frameworks}

    # --- Score risky permissions ---
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

    # --- Cluster matching ---
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

    # --- Malware behavior indicators (from DEX strings) ---
    malware_indicators: List[MalwareIndicator] = []
    if source_text:
        for mp in MALWARE_PATTERNS:
            # Context-aware handlers for special cases
            if mp["name"] == "Accessibility Service Abuse":
                indicator = _analyze_accessibility_abuse(
                    source_text, permissions_set, has_accessibility_manifest
                )
                if indicator:
                    malware_indicators.append(indicator)
                    raw_score += indicator.score_contribution
                continue

            if mp["name"] == "Dynamic Code Loading":
                indicator = _analyze_dynamic_loading(source_text)
                if indicator:
                    malware_indicators.append(indicator)
                    raw_score += indicator.score_contribution
                continue

            if mp["name"] == "Contact Harvesting":
                indicator = _analyze_contact_harvesting(source_text, permissions_set)
                if indicator:
                    malware_indicators.append(indicator)
                    raw_score += indicator.score_contribution
                continue

            # Standard pattern matching for other indicators
            patterns_key = "patterns"
            if patterns_key not in mp:
                continue
            matched_pats = [p for p in mp["patterns"] if p in source_text]
            if matched_pats:
                # Framework context: lower confidence if framework detected
                confidence = mp.get("confidence", "MEDIUM")
                score_contribution = mp["score"]

                # Root detection: informational only
                if mp["name"] == "Root Detection":
                    score_contribution = min(2, score_contribution)

                # Reflection alone: very low score
                if mp["name"] == "Java Reflection":
                    score_contribution = 2

                # If we're in a framework context, lower confidence
                if detected_frameworks and mp["name"] in (
                    "Dynamic Code Loading", "Java Reflection",
                    "Emulator Detection", "Root Detection"
                ):
                    confidence = "LOW"
                    score_contribution = max(0, score_contribution - 5)

                malware_indicators.append(MalwareIndicator(
                    name=mp["name"],
                    description=mp["description"],
                    severity=mp["severity"],
                    matched_patterns=matched_pats[:3],
                    score_contribution=score_contribution,
                    confidence=confidence,
                ))
                raw_score += score_contribution

    # --- Evidence Correlation Engine ---
    api_key_types: Set[str] = set()  # Would be passed from string analysis in real integration
    has_hardcoded_ip = False  # Would be passed from string analysis

    correlation_matches = _run_correlation_engine(
        cluster_matches, malware_indicators, permissions_set,
        api_key_types, has_hardcoded_ip,
    )
    for cm in correlation_matches:
        raw_score += cm.bonus_score

    # --- Normalize to 0-100 ---
    max_possible = 200
    normalized = min(100.0, (raw_score / max_possible) * 100)

    # --- 5-tier Verdict System ---
    # 0-15: BENIGN
    # 16-35: LOW RISK
    # 36-55: SUSPICIOUS
    # 56-75: HIGHLY SUSPICIOUS
    # 76-100: LIKELY MALICIOUS
    #
    # Critical rule: LIKELY MALICIOUS requires multiple correlated indicators
    # A single critical cluster is "HIGHLY SUSPICIOUS" unless corroborated

    has_critical_cluster = any(c.severity == "CRITICAL" for c in cluster_matches)
    has_critical_indicator = any(m.severity == "CRITICAL" for m in malware_indicators)
    has_correlation = len(correlation_matches) > 0
    critical_count = (
        sum(1 for c in cluster_matches if c.severity == "CRITICAL") +
        sum(1 for m in malware_indicators if m.severity == "CRITICAL")
    )

    if normalized >= 76 or (critical_count >= 2 and has_correlation):
        verdict = "LIKELY MALICIOUS"
    elif normalized >= 56 or (has_critical_cluster and has_critical_indicator):
        verdict = "HIGHLY SUSPICIOUS"
    elif normalized >= 36 or has_critical_cluster or has_critical_indicator:
        verdict = "SUSPICIOUS"
    elif normalized >= 16:
        verdict = "LOW RISK"
    else:
        verdict = "BENIGN"

    return PermissionAnalysisResult(
        total_permissions=len(permissions),
        risky_permissions=risky,
        cluster_matches=cluster_matches,
        malware_indicators=malware_indicators,
        correlation_matches=correlation_matches,
        detected_frameworks=detected_frameworks,
        permission_score=raw_score,
        normalized_score=round(normalized, 1),
        verdict=verdict,
    )
