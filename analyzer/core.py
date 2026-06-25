"""
Main APK analysis orchestrator.
Coordinates manifest, permission, string, and intelligence analysis
and produces a unified FraudReport.
"""

from __future__ import annotations

import hashlib
import os
import re
import time
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict

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
            f"[{mi.severity}] Malware behavior: {mi.name} — {mi.description}"
        )

    seen_domains = set()
    for su in string_result.suspicious_urls:
        if su.domain not in seen_domains:
            seen_domains.add(su.domain)
            reasons.append(f"Suspicious domain: {su.domain} ({su.reason})")

    if string_result.hardcoded_ips:
        reasons.append(
            f"{len(string_result.hardcoded_ips)} hardcoded IP address(es) — possible C2"
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

    # Telegram bot → score boost
    tg_keys = [k for k in string_result.api_keys if "Telegram" in k.key_type]
    if tg_keys:
        total = min(100.0, total + 15)

    # Discord webhook → score boost
    dc_keys = [k for k in string_result.api_keys if "Discord" in k.key_type]
    if dc_keys:
        total = min(100.0, total + 12)

    for w in intel_result.intel_warnings[:5]:
        reasons.append(f"Threat Intel: {w}")

    for w in manifest_result.warnings[:3]:
        reasons.append(f"Manifest: {w}")

    for dc in manifest_result.dangerous_components[:2]:
        reasons.append(f"Exposed component: {dc.name} — {dc.danger_reason}")

    has_critical = any(c.severity == "CRITICAL" for c in perm_result.cluster_matches) or \
                   any(m.severity == "CRITICAL" for m in perm_result.malware_indicators)

    if has_critical or total >= 65:
        verdict, color = "MALICIOUS", "red"
        action = (
            "Escalate immediately. Collect APK hash for FIR/CFSL submission. "
            "Notify victims not to grant further permissions. "
            "Trace C2 domains/IPs via CERT-In / ISP coordination (Section 69B IT Act)."
        )
    elif total >= 35:
        verdict, color = "SUSPICIOUS", "orange"
        action = (
            "Requires manual review. Cross-check package name against Play Store. "
            "Trace developer email/phone numbers found. "
            "Test in isolated device for dynamic behavior confirmation."
        )
    else:
        verdict, color = "BENIGN", "green"
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
    perm_result     = analyze_permissions(manifest_result.permissions, source_text)
    string_result   = analyze_strings(source_text)

    # Collect unique domains and IPs for intelligence lookups
    all_domains = list({
        su.domain for su in string_result.suspicious_urls if su.domain
    })
    all_ips = list({ip for ip in string_result.hardcoded_ips})

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
