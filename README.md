# FraudDroid — APK Threat Analyzer

**Cybersecurity Internship Project | UP Police Cyber Cell | MIET Jammu**

A static analysis tool for law enforcement to rapidly triage potentially fraudulent
Android APKs (fake loan apps, stalkerware, SMS interceptors) without needing expensive
commercial tools or sending suspect samples to the cloud.

---

## What it detects

| Category | Examples |
|---|---|
| Fake Loan App patterns | READ_SMS + READ_CONTACTS + LOCATION cluster |
| SMS Interceptors | OTP harvesting via RECEIVE_SMS + SEND_SMS |
| Device Takeover / Stalkerware | RECORD_AUDIO + ACCESS_BACKGROUND_LOCATION |
| Credential Harvesters | GET_ACCOUNTS + SYSTEM_ALERT_WINDOW overlays |
| Silent Dropper/Installer | REQUEST_INSTALL_PACKAGES + BOOT_COMPLETED |
| C2 Infrastructure | Hardcoded IPs, suspicious TLD domains (.tk .xyz .top) |
| Telegram Bot C2 | Bot tokens used for data exfiltration |
| Payment Key Exposure | Razorpay, Paytm, Stripe hardcoded keys |
| Manifest Misconfigs | debuggable=true, cleartext HTTP, adb backup enabled |
| Exported Components | Dangerous receivers/providers exposed to other apps |

---

## Architecture

```
fraud-apk-analyzer/
├── app.py                      # Flask web application
├── analyzer/
│   ├── core.py                 # Orchestrator — ties all modules together
│   ├── permissions.py          # Permission risk engine + cluster matching
│   ├── strings.py              # IOC extraction (URLs, IPs, API keys, phones)
│   └── manifest.py             # AndroidManifest.xml parser (androguard + fallback)
├── templates/
│   └── index.html              # Dark forensics-themed dashboard
├── static/
│   ├── css/style.css
│   └── js/app.js
├── tests/
│   └── test_analyzer.py        # 19 tests with synthetic APK generator
└── requirements.txt
```

### Analysis pipeline

```
APK Upload
    │
    ├── SHA256 + MD5 hash (for FIR/CFSL submission)
    │
    ├── [1] Manifest Parser (androguard → fallback XML parser)
    │       └── Package name, SDK versions, permissions list,
    │           exported components, security flags
    │
    ├── [2] Permission Analyzer
    │       └── Risk-weighted scoring (15+ dangerous permissions)
    │           Fraud cluster matching (5 pattern groups)
    │
    ├── [3] String Extractor (from .dex, assets, XML resources)
    │       └── C2 domain detection (suspicious TLDs + keywords)
    │           Hardcoded IP extraction
    │           API key / credential detection (Telegram, Google, AWS, Razorpay...)
    │           Phone number + email extraction
    │
    └── [4] Composite Scorer
            └── Weighted: Permissions 55% + Strings 30% + Manifest 15%
                Verdict: BENIGN / SUSPICIOUS / MALICIOUS
                Recommended investigator action
```

---

## Setup

```bash
# Clone / copy project
cd fraud-apk-analyzer

# Install dependencies (Fedora / any Linux)
pip install -r requirements.txt

# Run tests first to verify everything works
python3 tests/test_analyzer.py

# Start the web server
python3 app.py
# → Open http://localhost:5000
```

For production / deployment on Render:
```bash
gunicorn app:app --bind 0.0.0.0:10000
```

---

## Usage

1. Open `http://localhost:5000` in browser
2. Drag-and-drop or browse to select a `.apk` file (max 100 MB)
3. Wait 2–10 seconds for analysis
4. Review:
   - **Verdict banner** — MALICIOUS / SUSPICIOUS / BENIGN with risk score 0–100
   - **Permissions tab** — matched fraud clusters + all risky permissions
   - **Strings & IOCs tab** — C2 domains, IPs, hardcoded credentials, contacts
   - **Manifest tab** — security misconfigs, dangerous exported components
   - **Action tab** — investigator recommended next steps + file hashes for FIR

---

## Scoring

| Component | Weight | What drives it |
|---|---|---|
| Permission analysis | 55% | Cluster hits, raw weight sum |
| String / IOC analysis | 30% | C2 domains, hardcoded keys, IPs |
| Manifest analysis | 15% | Debuggable, cleartext, exported components |

| Score range | Verdict |
|---|---|
| 0–34 | BENIGN |
| 35–64 | SUSPICIOUS |
| 65–100 or any CRITICAL cluster | MALICIOUS |

---

## Notes for investigators

- **All analysis is offline** — the APK never leaves your server
- **APK is deleted immediately** after analysis completes
- Use **SHA256 hash** from the Action tab for FIR documentation and CFSL submissions
- **Trace C2 domains/IPs** via CERT-In portal or ISP coordination (Section 69B IT Act)
- Static analysis only — for dynamic behavior, test in an isolated Android device or emulator
- For confirmed malicious samples, cross-reference package name on Google Play and report via [Play Protect](https://support.google.com/googleplay/android-developer/answer/9888076)

---

## Extending

**Add a new fraud cluster** → edit `FRAUD_CLUSTERS` list in `analyzer/permissions.py`

**Add a new API key pattern** → add named group to `RE_API_KEY` regex in `analyzer/strings.py`

**Add a new suspicious TLD** → add to `SUSPICIOUS_TLDS` set in `analyzer/strings.py`

---

*Built for the UP Police Cyber Cell as part of MIET Jammu B.Tech CSE Internship Program.*
