"""
Main APK analysis orchestrator.
Coordinates manifest, permission, and string analysis
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

# ---------------------------------------------------------------------------
# Limits — tuned for 300MB APKs, keeps analysis under ~45s
# ---------------------------------------------------------------------------

DEX_READ_LIMIT     = 12 * 1024 * 1024  # read first 12MB of each .dex file
DEX_TOTAL_LIMIT    = 40 * 1024 * 1024  # stop after 40MB total DEX content
ASSET_SIZE_LIMIT   = 1 * 1024 * 1024   # skip asset files > 1MB
MAX_CHUNK_SIZE     = 65536             # streaming chunk size for hashing

# Precompiled patterns — all run at C speed via re engine
_RE_STRINGS  = re.compile(rb'[ -~]{6,}')     # printable ASCII strings
_RE_SKIP_EXT = frozenset([                    # binary/media entries to skip entirely
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
    """Compute SHA-256 and MD5 in a single streaming pass."""
    sha = hashlib.sha256()
    md5 = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(MAX_CHUNK_SIZE), b""):
            sha.update(chunk)
            md5.update(chunk)
    return sha.hexdigest(), md5.hexdigest()


def _extract_printable_fast(data: bytes) -> str:
    """
    Extract printable ASCII strings using compiled regex (C speed).
    ~50x faster than the byte-by-byte Python loop for large DEX files.
    """
    return b"\n".join(_RE_STRINGS.findall(data)).decode("ascii", errors="ignore")


def _extract_smali_strings(apk_path: str) -> str:
    """
    Pull readable strings from APK entries with size limits to cap analysis time.
    Priority order: text assets first (richest IOC source), then DEX.
    """
    chunks = []
    dex_bytes_read = 0

    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            entries = z.infolist()

            # ---- Pass 1: text/config files ----
            for info in entries:
                name = info.filename.lower()
                ext  = os.path.splitext(name)[1]
                # Skip known binary/media formats immediately
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

            # ---- Pass 2: DEX files ----
            # Sort by filename so classes.dex (most important) is read first
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
) -> tuple[float, str, str, List[str], str]:

    perm_score   = perm_result.normalized_score
    str_score    = min(100.0, string_result.string_score)
    manifest_score = min(100.0, manifest_result.manifest_score * 5)

    total = (perm_score * 0.55 + str_score * 0.30 + manifest_score * 0.15)
    total = round(min(100.0, total), 1)

    reasons: List[str] = []

    for cm in perm_result.cluster_matches:
        reasons.append(
            f"[{cm.severity}] Matches '{cm.cluster_name}' pattern "
            f"({len(cm.matched_permissions)} permissions matched)"
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

    seen_keys = set()
    for k in string_result.api_keys:
        if k.key_type not in seen_keys:
            seen_keys.add(k.key_type)
            reasons.append(f"Hardcoded credential: {k.key_type} — {k.risk_note}")

    tg_keys = [k for k in string_result.api_keys if "Telegram" in k.key_type]
    if tg_keys:
        total = min(100.0, total + 15)

    for w in manifest_result.warnings[:3]:
        reasons.append(f"Manifest: {w}")

    for dc in manifest_result.dangerous_components[:2]:
        reasons.append(f"Exposed component: {dc.name} — {dc.danger_reason}")

    has_critical = any(c.severity == "CRITICAL" for c in perm_result.cluster_matches)

    if has_critical or total >= 65:
        verdict, color = "MALICIOUS", "red"
        action = (
            "Escalate immediately. Collect APK hash for FIR/CFSL submission. "
            "Notify victims not to grant further permissions. "
            "Trace C2 domains/IPs via CERT-In / ISP coordination."
        )
    elif total >= 35:
        verdict, color = "SUSPICIOUS", "orange"
        action = (
            "Requires manual review. Cross-check package name against Play Store. "
            "Trace developer email/phone numbers found. "
            "Test in isolated device for dynamic behavior."
        )
    else:
        verdict, color = "BENIGN", "green"
        action = (
            "No strong indicators of fraud. "
            "Still verify app source and review permissions with complainant."
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
    perm_result     = analyze_permissions(manifest_result.permissions)
    source_text     = _extract_smali_strings(apk_path)
    string_result   = analyze_strings(source_text)

    total, verdict, color, reasons, action = _compute_verdict(
        perm_result, string_result, manifest_result
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
        total_score=total,
        verdict=verdict,
        verdict_color=color,
        risk_summary=reasons,
        recommended_action=action,
        analysis_time_ms=int((time.time() - t_start) * 1000),
    )
