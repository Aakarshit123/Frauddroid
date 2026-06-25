"""
APK manifest analysis.
Uses androguard (pip install androguard) when available,
falls back to raw XML parsing for basic manifest extraction.

androguard gives us:
  - parsed AndroidManifest.xml
  - permission lists
  - activities / services / receivers / providers
  - app metadata (package name, version, min SDK, target SDK)
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
import zipfile
import xml.etree.ElementTree as ET
import re

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ComponentInfo:
    name: str
    component_type: str       # activity | service | receiver | provider
    exported: Optional[bool]
    intent_filters: List[str] = field(default_factory=list)
    is_dangerous: bool = False
    danger_reason: str = ""

@dataclass
class ManifestAnalysisResult:
    package_name: str
    version_name: str
    version_code: str
    min_sdk: str
    target_sdk: str
    permissions: List[str]
    components: List[ComponentInfo]
    dangerous_components: List[ComponentInfo]
    uses_cleartext_traffic: bool
    debuggable: bool
    backup_allowed: bool
    manifest_score: int
    warnings: List[str] = field(default_factory=list)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _attr(elem: ET.Element, name: str, default="") -> str:
    return elem.attrib.get(f"{{{ANDROID_NS}}}{name}", 
           elem.attrib.get(name, default))


def _parse_manifest_xml(xml_text: str) -> ET.Element:
    """Parse manifest XML, stripping namespace declarations if needed."""
    try:
        return ET.fromstring(xml_text)
    except ET.ParseError:
        # Strip namespace and try again
        cleaned = re.sub(r'\s+xmlns[^"]*"[^"]*"', "", xml_text)
        return ET.fromstring(cleaned)


def _check_dangerous_component(comp: ComponentInfo) -> ComponentInfo:
    """Flag components that are exported but probably shouldn't be."""
    if comp.exported is True:
        if comp.component_type == "provider":
            comp.is_dangerous = True
            comp.danger_reason = (
                "Exported ContentProvider — may expose app data to other apps"
            )
        elif comp.component_type == "receiver":
            dangerous_actions = [
                "android.provider.Telephony.SMS_RECEIVED",
                "android.intent.action.BOOT_COMPLETED",
                "android.intent.action.PACKAGE_ADDED",
            ]
            matched = [a for a in comp.intent_filters 
                       if any(d in a for d in dangerous_actions)]
            if matched:
                comp.is_dangerous = True
                comp.danger_reason = (
                    f"Exported receiver listening for sensitive broadcast(s): "
                    f"{', '.join(matched)}"
                )
        elif comp.component_type == "service":
            bind_actions = [a for a in comp.intent_filters if "BIND" in a]
            if bind_actions:
                comp.is_dangerous = True
                comp.danger_reason = (
                    f"Exported bindable service: {', '.join(bind_actions)}"
                )
    return comp

# ---------------------------------------------------------------------------
# Pure-Python fallback parser (raw binary manifest via zipfile)
# ---------------------------------------------------------------------------

def _extract_manifest_bytes(apk_path: str) -> bytes:
    with zipfile.ZipFile(apk_path, "r") as z:
        return z.read("AndroidManifest.xml")


def _try_androguard(apk_path: str) -> Optional[ManifestAnalysisResult]:
    """Use androguard if available — best-quality parse."""
    try:
        from androguard.misc import AnalyzeAPK
        a, d, dx = AnalyzeAPK(apk_path)

        permissions = list(a.get_permissions() or [])
        warnings: List[str] = []
        components: List[ComponentInfo] = []

        # Activities
        for act in (a.get_activities() or []):
            c = ComponentInfo(
                name=act,
                component_type="activity",
                exported=None,
                intent_filters=[],
            )
            components.append(c)

        # Services
        for svc in (a.get_services() or []):
            c = ComponentInfo(name=svc, component_type="service", exported=None)
            components.append(c)

        # Receivers
        for recv in (a.get_receivers() or []):
            c = ComponentInfo(name=recv, component_type="receiver", exported=None)
            components.append(c)

        # Providers
        for prov in (a.get_providers() or []):
            c = ComponentInfo(name=prov, component_type="provider", exported=None)
            components.append(c)

        # Flags
        debuggable = a.get_attribute_value("application", "debuggable") in ("true", "True", True)
        backup_allowed = a.get_attribute_value("application", "allowBackup") not in ("false", "False", False)
        cleartext = a.get_attribute_value("application", "usesCleartextTraffic") in ("true", "True", True)

        if debuggable:
            warnings.append("App is marked debuggable — must not ship to production")
        if backup_allowed:
            warnings.append("allowBackup=true — app data can be extracted via adb backup")
        if cleartext:
            warnings.append("usesCleartextTraffic=true — transmits unencrypted HTTP traffic")

        # Score
        score = 0
        if debuggable: score += 10
        if cleartext: score += 15

        dangerous = [_check_dangerous_component(c) for c in components]
        dangerous = [c for c in dangerous if c.is_dangerous]
        score += len(dangerous) * 10

        return ManifestAnalysisResult(
            package_name=a.get_package() or "",
            version_name=a.get_androidversion_name() or "",
            version_code=str(a.get_androidversion_code() or ""),
            min_sdk=str(a.get_min_sdk_version() or ""),
            target_sdk=str(a.get_target_sdk_version() or ""),
            permissions=permissions,
            components=components,
            dangerous_components=dangerous,
            uses_cleartext_traffic=cleartext,
            debuggable=debuggable,
            backup_allowed=backup_allowed,
            manifest_score=score,
            warnings=warnings,
        )

    except ImportError:
        return None
    except Exception as e:
        return None


def _fallback_parse(apk_path: str) -> ManifestAnalysisResult:
    """
    Fallback: read manifest XML directly from the zip.
    Binary AndroidManifest.xml in a real APK is AXML-encoded (not plain XML).
    For the fallback, we attempt plain XML (works for testing with manually
    crafted APKs) or return an empty-but-valid result.
    """
    warnings = ["androguard not installed — install with: pip install androguard"]
    permissions: List[str] = []
    components: List[ComponentInfo] = []
    meta: Dict[str, str] = {}

    try:
        raw = _extract_manifest_bytes(apk_path)
        # Try plain XML first (test APKs)
        text = raw.decode("utf-8", errors="ignore")
        root = _parse_manifest_xml(text)

        meta = {
            "package": root.attrib.get("package", ""),
            "version_name": _attr(root, "versionName"),
            "version_code": _attr(root, "versionCode"),
        }

        for uses_perm in root.iter("uses-permission"):
            name = _attr(uses_perm, "name")
            if name:
                permissions.append(name)

        uses_sdk = root.find("uses-sdk")
        min_sdk = _attr(uses_sdk, "minSdkVersion") if uses_sdk is not None else ""
        tgt_sdk = _attr(uses_sdk, "targetSdkVersion") if uses_sdk is not None else ""

        app = root.find("application")
        debuggable = False
        backup_allowed = True
        cleartext = False
        if app is not None:
            debuggable = _attr(app, "debuggable") == "true"
            backup_allowed = _attr(app, "allowBackup") != "false"
            cleartext = _attr(app, "usesCleartextTraffic") == "true"

            for tag, ctype in [("activity", "activity"), ("service", "service"),
                               ("receiver", "receiver"), ("provider", "provider")]:
                for elem in app.findall(tag):
                    name = _attr(elem, "name")
                    exported_str = _attr(elem, "exported", "")
                    exported = (exported_str == "true") if exported_str else None
                    filters = []
                    for f in elem.findall("intent-filter"):
                        for action in f.findall("action"):
                            a = _attr(action, "name")
                            if a:
                                filters.append(a)
                    comp = ComponentInfo(
                        name=name, component_type=ctype,
                        exported=exported, intent_filters=filters,
                    )
                    _check_dangerous_component(comp)
                    components.append(comp)

        if debuggable:
            warnings.append("App is marked debuggable")
        if cleartext:
            warnings.append("usesCleartextTraffic=true — plain HTTP allowed")
        if backup_allowed:
            warnings.append("allowBackup=true — data extractable via adb")

        score = 0
        if debuggable: score += 10
        if cleartext: score += 15
        dangerous = [c for c in components if c.is_dangerous]
        score += len(dangerous) * 10

        return ManifestAnalysisResult(
            package_name=meta.get("package", ""),
            version_name=meta.get("version_name", ""),
            version_code=meta.get("version_code", ""),
            min_sdk=min_sdk,
            target_sdk=tgt_sdk,
            permissions=permissions,
            components=components,
            dangerous_components=dangerous,
            uses_cleartext_traffic=cleartext,
            debuggable=debuggable,
            backup_allowed=backup_allowed,
            manifest_score=score,
            warnings=warnings,
        )

    except Exception as exc:
        warnings.append(f"Manifest parse failed: {exc}")
        return ManifestAnalysisResult(
            package_name="", version_name="", version_code="",
            min_sdk="", target_sdk="", permissions=[],
            components=[], dangerous_components=[],
            uses_cleartext_traffic=False, debuggable=False,
            backup_allowed=True, manifest_score=0, warnings=warnings,
        )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def analyze_manifest(apk_path: str) -> ManifestAnalysisResult:
    result = _try_androguard(apk_path)
    if result is not None:
        return result
    return _fallback_parse(apk_path)
