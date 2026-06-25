"""
Test suite for FraudDroid.
Generates synthetic .apk files with fake manifests + dex strings
so tests run without needing real malware samples.
"""

import io
import os
import sys
import zipfile
import unittest
import tempfile

# Make sure we can import from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.permissions import analyze_permissions, FRAUD_CLUSTERS
from analyzer.strings import analyze_strings
from analyzer.manifest import analyze_manifest
from analyzer.core import analyze_apk

# ---------------------------------------------------------------------------
# Synthetic APK builder
# ---------------------------------------------------------------------------

FAKE_LOAN_APP_MANIFEST = """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.quickloan.instant"
    android:versionCode="5"
    android:versionName="2.1.0">

    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33"/>

    <!-- Core fraud permissions -->
    <uses-permission android:name="android.permission.READ_SMS"/>
    <uses-permission android:name="android.permission.RECEIVE_SMS"/>
    <uses-permission android:name="android.permission.READ_CONTACTS"/>
    <uses-permission android:name="android.permission.READ_CALL_LOG"/>
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
    <uses-permission android:name="android.permission.ACCESS_BACKGROUND_LOCATION"/>
    <uses-permission android:name="android.permission.RECORD_AUDIO"/>
    <uses-permission android:name="android.permission.CAMERA"/>
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>
    <uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE"/>

    <application
        android:debuggable="true"
        android:allowBackup="true"
        android:usesCleartextTraffic="true"
        android:label="QuickLoan">

        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
            </intent-filter>
        </activity>

        <receiver android:name=".SmsReceiver" android:exported="true">
            <intent-filter>
                <action android:name="android.provider.Telephony.SMS_RECEIVED"/>
            </intent-filter>
        </receiver>

        <receiver android:name=".BootReceiver" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED"/>
            </intent-filter>
        </receiver>

        <service android:name=".UploadService" android:exported="true">
            <intent-filter>
                <action android:name="com.quickloan.BIND_UPLOAD"/>
            </intent-filter>
        </service>

    </application>
</manifest>
"""

CLEAN_APP_MANIFEST = """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.calculator"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33"/>
    <uses-permission android:name="android.permission.INTERNET"/>

    <application
        android:debuggable="false"
        android:allowBackup="false"
        android:usesCleartextTraffic="false"
        android:label="Calculator">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
"""

FAKE_LOAN_STRINGS = """
https://panel.quickloan-collect.tk/api/upload
https://cmd.botserver123.xyz/c2/receive
192.168.10.50
185.220.101.44
AIzaSyD3x4fakeGoogleAPIkeyForTesting1234
bot5583921749:AAGfaketelegrambottoken12345XXXXXXX
+919876543210
+918800001234
admin@quickloan-fraud.ml
sms_collect@phishing.top
https://fonts.googleapis.com/css2?family=Roboto
https://firebase.google.com/docs
"""

CLEAN_APP_STRINGS = """
https://fonts.googleapis.com/css2?family=Inter
https://developer.android.com/guide
https://www.w3.org/2001/XMLSchema
"""


def make_apk(manifest_xml: str, extra_strings: str = "") -> str:
    """Create a minimal synthetic APK (ZIP) with the given manifest XML."""
    tmp = tempfile.NamedTemporaryFile(suffix=".apk", delete=False)
    tmp.close()

    with zipfile.ZipFile(tmp.name, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", manifest_xml)
        if extra_strings:
            z.writestr("assets/config.json", extra_strings)
        # Fake empty dex
        z.writestr("classes.dex", b"\x64\x65\x78\x0a\x30\x33\x35\x00" + extra_strings.encode())

    return tmp.name

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestPermissionAnalyzer(unittest.TestCase):

    def test_fake_loan_app_detected_as_malicious(self):
        perms = [
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.RECORD_AUDIO",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.INTERNET",
        ]
        result = analyze_permissions(perms)
        self.assertEqual(result.verdict, "MALICIOUS",
                         f"Expected MALICIOUS, got {result.verdict} "
                         f"(score={result.normalized_score})")
        self.assertGreater(len(result.cluster_matches), 0,
                           "Should match at least one fraud cluster")
        # Must hit the fake loan cluster
        cluster_names = [c.cluster_name for c in result.cluster_matches]
        self.assertTrue(
            any("Loan" in n or "SMS" in n for n in cluster_names),
            f"Expected Loan or SMS cluster match, got: {cluster_names}"
        )
        print(f"  [PASS] Fake loan app — score={result.normalized_score}, "
              f"clusters={cluster_names}, verdict={result.verdict}")

    def test_clean_app_benign(self):
        perms = ["android.permission.INTERNET"]
        result = analyze_permissions(perms)
        self.assertEqual(result.verdict, "BENIGN",
                         f"Expected BENIGN, got {result.verdict}")
        self.assertEqual(len(result.cluster_matches), 0)
        print(f"  [PASS] Clean app — score={result.normalized_score}, "
              f"verdict={result.verdict}")

    def test_sms_interceptor_cluster(self):
        perms = [
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.SEND_SMS",
        ]
        result = analyze_permissions(perms)
        self.assertEqual(result.verdict, "MALICIOUS")
        names = [c.cluster_name for c in result.cluster_matches]
        self.assertTrue(any("SMS" in n for n in names))
        print(f"  [PASS] SMS interceptor cluster — verdict={result.verdict}")

    def test_permission_score_increases_with_more_perms(self):
        few  = analyze_permissions(["android.permission.READ_SMS"])
        many = analyze_permissions([
            "android.permission.READ_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.RECORD_AUDIO",
        ])
        self.assertGreater(many.permission_score, few.permission_score)
        print(f"  [PASS] Score scaling — few={few.permission_score}, "
              f"many={many.permission_score}")


class TestStringAnalyzer(unittest.TestCase):

    def test_c2_domain_detected(self):
        text = "https://panel.collect.tk/upload\nhttps://cmd.c2.xyz/receive"
        result = analyze_strings(text)
        self.assertGreater(len(result.suspicious_urls), 0,
                           "Should detect .tk/.xyz C2 domains")
        print(f"  [PASS] C2 domains detected: "
              f"{[u.domain for u in result.suspicious_urls]}")

    def test_google_api_key_extracted(self):
        text = "apiKey = 'AIzaSyD3x4fakeGoogleAPIkeyForTesting1234'"
        result = analyze_strings(text)
        keys = [k.key_type for k in result.api_keys]
        self.assertTrue(any("Google" in k for k in keys),
                        f"Expected Google Api key, got: {keys}")
        print(f"  [PASS] Google API key extracted — types={keys}")

    def test_telegram_bot_detected(self):
        text = "token = 'bot5583921749:AAGfaketelegrambottoken12345XXXXXXX'"
        result = analyze_strings(text)
        keys = [k.key_type for k in result.api_keys]
        self.assertTrue(any("Telegram" in k for k in keys),
                        f"Expected Telegram bot key, got: {keys}")
        print(f"  [PASS] Telegram bot token detected")

    def test_hardcoded_ip_found(self):
        text = "serverIP = '185.220.101.44'\nbackupIP = '192.168.10.50'"
        result = analyze_strings(text)
        self.assertGreater(len(result.hardcoded_ips), 0)
        self.assertIn("185.220.101.44", result.hardcoded_ips)
        print(f"  [PASS] IPs found: {result.hardcoded_ips}")

    def test_phone_number_extraction(self):
        text = "contactUs: +919876543210, support: 9800001234"
        result = analyze_strings(text)
        self.assertGreater(len(result.phone_numbers), 0)
        print(f"  [PASS] Phone numbers: {result.phone_numbers}")

    def test_whitelist_domains_not_flagged(self):
        text = "https://fonts.googleapis.com/css2?family=Roboto\nhttps://firebase.google.com/docs"
        result = analyze_strings(text)
        susp_domains = [u.domain for u in result.suspicious_urls]
        self.assertEqual(susp_domains, [],
                         f"Whitelisted domains incorrectly flagged: {susp_domains}")
        print(f"  [PASS] Google/Firebase domains correctly whitelisted")

    def test_string_score_zero_for_clean_text(self):
        text = "Hello world. This is a clean app description."
        result = analyze_strings(text)
        self.assertEqual(result.string_score, 0)
        print(f"  [PASS] Clean text → string_score=0")


class TestManifestParser(unittest.TestCase):

    def setUp(self):
        self.fraud_apk = make_apk(FAKE_LOAN_APP_MANIFEST, FAKE_LOAN_STRINGS)
        self.clean_apk = make_apk(CLEAN_APP_MANIFEST, CLEAN_APP_STRINGS)

    def tearDown(self):
        for p in (self.fraud_apk, self.clean_apk):
            try: os.unlink(p)
            except: pass

    def test_fraud_manifest_package_name(self):
        result = analyze_manifest(self.fraud_apk)
        self.assertEqual(result.package_name, "com.quickloan.instant")
        print(f"  [PASS] Package name parsed: {result.package_name}")

    def test_fraud_manifest_permissions_extracted(self):
        result = analyze_manifest(self.fraud_apk)
        self.assertIn("android.permission.READ_SMS", result.permissions)
        self.assertIn("android.permission.RECEIVE_BOOT_COMPLETED", result.permissions)
        print(f"  [PASS] {len(result.permissions)} permissions extracted")

    def test_debuggable_flag_detected(self):
        result = analyze_manifest(self.fraud_apk)
        self.assertTrue(result.debuggable)
        self.assertTrue(result.uses_cleartext_traffic)
        self.assertTrue(result.backup_allowed)
        print(f"  [PASS] Security flags detected — debuggable, cleartext, backup")

    def test_clean_app_no_bad_flags(self):
        result = analyze_manifest(self.clean_apk)
        self.assertFalse(result.debuggable)
        self.assertFalse(result.uses_cleartext_traffic)
        self.assertFalse(result.backup_allowed)
        print(f"  [PASS] Clean app — no bad flags")


class TestFullPipeline(unittest.TestCase):

    def setUp(self):
        self.fraud_apk = make_apk(FAKE_LOAN_APP_MANIFEST, FAKE_LOAN_STRINGS)
        self.clean_apk = make_apk(CLEAN_APP_MANIFEST, CLEAN_APP_STRINGS)

    def tearDown(self):
        for p in (self.fraud_apk, self.clean_apk):
            try: os.unlink(p)
            except: pass

    def test_fraud_apk_full_analysis_malicious(self):
        report = analyze_apk(self.fraud_apk)
        self.assertEqual(report.verdict, "MALICIOUS",
                         f"Expected MALICIOUS, got {report.verdict} "
                         f"(score={report.total_score})")
        self.assertGreater(report.total_score, 60)
        self.assertGreater(len(report.risk_summary), 0)
        print(f"\n  [PASS] FULL PIPELINE — MALICIOUS")
        print(f"         Score    : {report.total_score}/100")
        print(f"         Clusters : {[c.cluster_name for c in report.permissions.cluster_matches]}")
        print(f"         IOC IPs  : {report.strings.hardcoded_ips}")
        print(f"         Susp URLs: {[u.domain for u in report.strings.suspicious_urls]}")
        print(f"         Action   : {report.recommended_action[:80]}...")

    def test_clean_apk_full_analysis_benign(self):
        report = analyze_apk(self.clean_apk)
        self.assertEqual(report.verdict, "BENIGN",
                         f"Expected BENIGN, got {report.verdict} "
                         f"(score={report.total_score})")
        print(f"\n  [PASS] FULL PIPELINE — BENIGN")
        print(f"         Score    : {report.total_score}/100")

    def test_sha256_and_md5_present(self):
        report = analyze_apk(self.fraud_apk)
        self.assertEqual(len(report.sha256), 64)
        self.assertEqual(len(report.md5), 32)
        print(f"  [PASS] Hashes generated — SHA256={report.sha256[:16]}...")

    def test_analysis_time_recorded(self):
        report = analyze_apk(self.fraud_apk)
        self.assertGreater(report.analysis_time_ms, 0)
        self.assertLess(report.analysis_time_ms, 30000)
        print(f"  [PASS] Analysis time: {report.analysis_time_ms}ms")


if __name__ == "__main__":
    print("=" * 60)
    print("  FraudDroid — Test Suite")
    print("=" * 60)
    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()
    for cls in [TestPermissionAnalyzer, TestStringAnalyzer,
                TestManifestParser, TestFullPipeline]:
        suite.addTests(loader.loadTestsFromTestCase(cls))
        print(f"\n▶ {cls.__name__}")
        print("-" * 40)

    runner = unittest.TextTestRunner(verbosity=0, stream=sys.stdout)
    result = runner.run(suite)
    print("\n" + "=" * 60)
    if result.wasSuccessful():
        print(f"  ✓ ALL {result.testsRun} TESTS PASSED")
    else:
        print(f"  ✗ {len(result.failures)} failures, {len(result.errors)} errors")
    print("=" * 60)
