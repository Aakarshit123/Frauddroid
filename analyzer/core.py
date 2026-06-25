"""
Main APK analysis orchestrator.
Coordinates manifest, permission, string, and intelligence analysis
and produces a unified FraudReport.

v2: Updated for reduced false positives:
- 5-tier verdict system (BENIGN / LOW RISK / SUSPICIOUS / HIGHLY SUSPICIOUS / LIKELY MALICIOUS)
- Private IPs not flagged as C2
- Evidence correlation engine integrated
- Framework detection context passed through
- Accessibility manifest declaration passed to permissions analyser
"""

from __future__ import annotations

import hashlib
import os
import re
import time
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Set

from analyzer.manifest import analyze_manifest, ManifestAnalysisResult
from analyzer.permissions import analyze_permissions, PermissionAnalysisResult
from analyzer.strings import analyze_strings, StringAnalysisResult
from analyzer.intelligence import run_intelligence, IntelligenceResult

# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------

DEX_READ_LIMIT     = 5 * 1024 * 1024
DEX_TOTAL_LIMIT    = 15 * 1024 * 1024
ASSET_SIZE_LIMIT   = 256 * 1024
MAX_CHUNK_SIZE     = 65536

_RE_STRINGS  = re.compile(rb'[ -~]{6,}')
_RE_SKIP_EXT = frozenset([
    '.png','.jpg','.jpeg','.gif','.webp','.mp4','.mp3',
    '.ogg','.wav','.ttf','.otf','.woff','.woff2',
    '.so','.db','.sqlite','.keystore','.jks',
])

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class FraudReport:
    filename: str
    file_size_bytes: int
    sha256: str
    md5: str
    analysis_timestamp: str
    manifest: ManifestAnalysisResult
    permissions: PermissionAnalysisResult
    strings: StringAnalysisResult
    intelligence: IntelligenceResult
    total_score: float
    verdict: str
    verdict_color: str
    risk_summary: List[str]
    recommended_action: str
    analysis_time_ms: int

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hash_file(path: str):
    sha = hashlib.sha256()
    md5 = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(MAX_CHUNK_SIZE), b""):
            sha.update(chunk)
            md5.update(chunk)
    return sha.hexdigest(), md5.hexdigest()


def _extract_printable_fast(data: bytes) -> str:
    return b"\n".join(_RE_STRINGS.findall(data)).decode("ascii", errors="ignore")


def _extract_smali_strings(apk_path: str) -> str:
    chunks = []
    dex_bytes_read = 0

    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            entries = z.infolist()

            # Pass 1: text/config files
            for info in entries:
                name = info.filename.lower()
                ext  = os.path.splitext(name)[1]
                if ext in _RE_SKIP_EXT:
                    continue
                if not any(name.endswith(e) for e in
                           (".xml", ".json", ".txt", ".js", ".html",
                            ".properties", ".cfg", ".yaml", ".yml",
                            ".smali", ".kt", ".java")):
                    continue
                if info.file_size > ASSET_SIZE_LIMIT:
                    continue
                try:
                    data = z.read(info.filename)
                    chunks.append(data.decode("utf-8", errors="ignore"))
                except Exception:
                    pass

            # Pass 2: DEX files
            dex_entries = sorted(
                [e for e in entries if e.filename.lower().endswith(".dex")],
                key=lambda e: e.filename
            )
            for info in dex_entries:
                if dex_bytes_read >= DEX_TOTAL_LIMIT:
                    break
                try:
                    with z.open(info.filename) as dex_f:
                        data = dex_f.read(DEX_READ_LIMIT)
                    dex_bytes_read += len(data)
                    chunks.append(_extract_printable_fast(data))
                except Exception:
                    pass

    except zipfile.BadZipFile:
        pass

    return "\n".join(chunks)


def _has_accessibility_in_manifest(manifest_result: ManifestAnalysisResult) -> bool:
    """Check if AccessibilityService is declared in the manifest."""
    for comp in manifest_result.components:
        if comp.component_type == "service":
            if "accessibility" in comp.name.lower():
                return True
            for f in comp.intent_filters:
                if "accessibility" in f.lower():
                    return True
    for perm in manifest_result.permissions:
        if "ACCESSIBILITY" in perm:
            return True
    return False


VERDICT_COLORS = {
    "BENIGN": "green",
    "LOW RISK": "blue",
    "SUSPICIOUS": "orange",
    "HIGHLY SUSPICIOUS": "darkorange",
    "LIKELY MALICIOUS": "red",
}


def _compute_verdict(
    perm_result: PermissionAnalysisResult,
    string_result: StringAnalysisResult,
    manifest_result: ManifestAnalysisResult,
    intel_result: IntelligenceResult,
) -> tuple:

    perm_score     = perm_result.normalized_score
    str_score      = min(100.0, string_result.string_score)
    manifest_score = min(100.0, manifest_result.manifest_score * 5)
    intel_score    = min(100.0, intel_result.intel_score)

    # Weighted composite
    total = (perm_score * 0.50 + str_score * 0.28 + manifest_score * 0.12 + intel_score * 0.10)
    total = round(min(100.0, total), 1)

    reasons: List[str] = []

    for cm in perm_result.cluster_matches:
        reasons.append(
            f"[{cm.severity}] Matches '{cm.cluster_name}' pattern "
            f"({len(cm.matched_permissions)} permissions matched)"
        )

    for mi in perm_result.malware_indicators:
        reasons.append(
            f"[{mi.severity}][Confidence: {mi.confidence}] {mi.name} — {mi.description}"
        )

    for corr in perm_result.correlation_matches:
        reasons.append(
            f"[CORRELATED][Confidence: {corr.confidence}] {corr.pattern_name}: {corr.description}"
        )

    if perm_result.detected_frameworks:
        fw_names = ", ".join(f.name for f in perm_result.detected_frameworks)
        reasons.append(f"Framework detected: {fw_names} — generic indicators have lower weight")

    seen_domains = set()
    for su in string_result.suspicious_urls:
        if su.domain not in seen_domains:
            seen_domains.add(su.domain)
            reasons.append(f"Suspicious domain: {su.domain} ({su.reason})")

    # Only flag PUBLIC IPs as possible C2
    if string_result.hardcoded_ips:
        reasons.append(
            f"{len(string_result.hardcoded_ips)} hardcoded public IP address(es) — possible C2"
        )

    # Private IPs: informational only
    if string_result.private_ips:
        reasons.append(
            f"{len(string_result.private_ips)} private/loopback IP(s) found — informational only (not C2)"
        )

    if string_result.crypto_wallets:
        wallet_types = list({w.wallet_type for w in string_result.crypto_wallets})
        reasons.append(
            f"Cryptocurrency wallets found: {', '.join(wallet_types)} — "
            "possible ransom/fraud payment collection"
        )

    seen_keys = set()
    for k in string_result.api_keys:
        if k.key_type not in seen_keys:
            seen_keys.add(k.key_type)
            reasons.append(f"Hardcoded credential: {k.key_type} — {k.risk_note}")

    # Telegram/Discord C2 boost (only with other indicators)
    tg_keys = [k for k in string_result.api_keys if "Telegram" in k.key_type]
    if tg_keys and (string_result.hardcoded_ips or perm_result.correlation_matches):
        total = min(100.0, total + 15)

    dc_keys = [k for k in string_result.api_keys if "Discord" in k.key_type]
    if dc_keys and (string_result.hardcoded_ips or perm_result.correlation_matches):
        total = min(100.0, total + 12)

    for w in intel_result.intel_warnings[:5]:
        reasons.append(f"Threat Intel: {w}")

    for w in manifest_result.warnings[:3]:
        reasons.append(f"Manifest: {w}")

    for dc in manifest_result.dangerous_components[:2]:
        reasons.append(f"Exposed component: {dc.name} — {dc.danger_reason}")

    # --- 5-tier Verdict ---
    # Use permission-level verdict as primary signal, but override with composite score
    perm_verdict = perm_result.verdict

    # Map to composite score thresholds
    if total >= 76 or perm_verdict == "LIKELY MALICIOUS":
        verdict = "LIKELY MALICIOUS"
        color = VERDICT_COLORS["LIKELY MALICIOUS"]
        action = (
            "Escalate immediately. Collect APK hash for FIR/CFSL submission. "
            "Notify victims not to grant further permissions. "
            "Trace C2 domains/IPs via CERT-In / ISP coordination (Section 69B IT Act)."
        )
    elif total >= 56 or perm_verdict == "HIGHLY SUSPICIOUS":
        verdict = "HIGHLY SUSPICIOUS"
        color = VERDICT_COLORS["HIGHLY SUSPICIOUS"]
        action = (
            "High likelihood of malicious behavior. Requires urgent manual review. "
            "Test in isolated device for dynamic behavior confirmation. "
            "Cross-check with known malware hashes. Consider escalation."
        )
    elif total >= 36 or perm_verdict == "SUSPICIOUS":
        verdict = "SUSPICIOUS"
        color = VERDICT_COLORS["SUSPICIOUS"]
        action = (
            "Requires manual review. Cross-check package name against Play Store. "
            "Trace developer email/phone numbers found. "
            "Test in isolated device for dynamic behavior confirmation."
        )
    elif total >= 16 or perm_verdict == "LOW RISK":
        verdict = "LOW RISK"
        color = VERDICT_COLORS["LOW RISK"]
        action = (
            "Some elevated permissions or indicators detected but no strong malware patterns. "
            "Verify app source and review permissions with the complainant. "
            "May be a legitimate app with broad permissions."
        )
    else:
        verdict = "BENIGN"
        color = VERDICT_COLORS["BENIGN"]
        action = (
            "No strong indicators of fraud detected in static analysis. "
            "Still verify app source and review permissions with the complainant."
        )

    if not reasons:
        reasons.append("No high-confidence indicators found in static analysis.")

    return total, verdict, color, reasons, action


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def analyze_apk(apk_path: str) -> FraudReport:
    t_start = time.time()
    filename  = os.path.basename(apk_path)
    file_size = os.path.getsize(apk_path)

    sha, md5 = _hash_file(apk_path)

    manifest_result = analyze_manifest(apk_path)
    source_text     = _extract_smali_strings(apk_path)

    # Detect accessibility manifest declaration for context-aware analysis
    has_accessibility_manifest = _has_accessibility_in_manifest(manifest_result)

    perm_result     = analyze_permissions(
        manifest_result.permissions, source_text,
        has_accessibility_manifest=has_accessibility_manifest,
    )
    string_result   = analyze_strings(source_text)

    # Collect unique domains and PUBLIC IPs for intelligence lookups
    all_domains = list({
        su.domain for su in string_result.suspicious_urls if su.domain
    })
    all_ips = list({ip for ip in string_result.hardcoded_ips})  # public IPs only

    # Run threat intelligence (DNS/WHOIS/IP — network-dependent, best-effort)
    intel_result = run_intelligence(all_domains, all_ips, max_domains=8, max_ips=8)

    total, verdict, color, reasons, action = _compute_verdict(
        perm_result, string_result, manifest_result, intel_result
    )

    return FraudReport(
        filename=filename,
        file_size_bytes=file_size,
        sha256=sha,
        md5=md5,
        analysis_timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        manifest=manifest_result,
        permissions=perm_result,
        strings=string_result,
        intelligence=intel_result,
        total_score=total,
        verdict=verdict,
        verdict_color=color,
        risk_summary=reasons,
        recommended_action=action,
        analysis_time_ms=int((time.time() - t_start) * 1000),
    )
