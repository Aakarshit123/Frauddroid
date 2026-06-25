"""
FraudDroid — APK Threat Analyzer
UP Police Cyber Cell / MIET Jammu | APCSIP 2026
Intern: Aakarshit Bargotra | APCSIP/2026/003
"""

import os
import logging
import sys

# Suppress androguard debug/info/warning spam before any androguard import.
logging.getLogger("androguard").setLevel(logging.CRITICAL)
for _name in list(logging.root.manager.loggerDict):
    if "androguard" in _name:
        logging.getLogger(_name).setLevel(logging.CRITICAL)

try:
    from loguru import logger as _loguru
    _loguru.remove()
    _loguru.add(sys.stderr, level="CRITICAL")
except Exception:
    pass

import json
import dataclasses
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename

from analyzer.core import analyze_apk

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
ALLOWED    = {"apk"}
MAX_UPLOAD = 300 * 1024 * 1024   # 300 MB
ANALYSIS_TIMEOUT = 120           # seconds — thread-safe, works in Flask threaded mode

os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD
app.config["UPLOAD_FOLDER"]      = UPLOAD_DIR

_executor = ThreadPoolExecutor(max_workers=4)


def allowed(fname):
    return "." in fname and fname.rsplit(".", 1)[1].lower() in ALLOWED


def to_dict(obj):
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: to_dict(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, list):
        return [to_dict(i) for i in obj]
    return obj


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": f"File too large. Maximum is {MAX_UPLOAD//(1024*1024)} MB."}), 413

@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": "Bad request: " + str(e)}), 400

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Server error: " + str(e)}), 500


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    if "apk" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    f = request.files["apk"]
    if not f.filename or not allowed(f.filename):
        return jsonify({"error": "Only .apk files accepted"}), 400

    filename  = secure_filename(f.filename)
    save_path = os.path.join(UPLOAD_DIR, filename)
    f.save(save_path)

    try:
        # Thread-safe timeout — works in Flask threaded mode and gunicorn.
        # signal.SIGALRM only works in main thread; ThreadPoolExecutor works anywhere.
        future = _executor.submit(analyze_apk, save_path)
        try:
            report = future.result(timeout=ANALYSIS_TIMEOUT)
            return jsonify(to_dict(report))
        except FuturesTimeout:
            future.cancel()
            return jsonify({
                "error": (
                    f"Analysis timed out after {ANALYSIS_TIMEOUT}s. "
                    "APK may be too large — try running FraudDroid locally."
                )
            }), 504
        except Exception as e:
            app.logger.exception("Analysis failed for %s", filename)
            return jsonify({"error": str(e)}), 500
    finally:
        try:
            os.remove(save_path)
        except OSError:
            pass


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "FraudDroid", "intern": "APCSIP/2026/003"})


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)
