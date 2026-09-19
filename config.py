from pathlib import Path

# Directory holding the fixed synthetic demo evidence set
SAMPLE_DIR = Path(__file__).resolve().parent / "data" / "sample"

# Known evidence filenames -> classification type
SUPPORTED_FILES = {
    "file_access_log.csv": "file_access",
    "usb_log.csv": "usb",
    "browser_activity_log.csv": "browser",
    "system_login_log.csv": "login",
}

# Required CSV columns per evidence type (used for validation)
REQUIRED_COLUMNS = {
    "file_access": {"timestamp", "user", "host", "file", "action"},
    "usb": {"timestamp", "user", "host", "device", "action"},
    "browser": {"timestamp", "user", "host", "url", "action"},
    "login": {"timestamp", "user", "host", "action"},
}

# Correlation window (minutes) used to link related events
CORRELATION_WINDOW_MINUTES = 30

# Sensitive file markers used by the correlation engine
SENSITIVE_FILE_KEYWORDS = ("confidential", "roadmap", "secret")

# Severity scoring weights (Stage 6)
SEVERITY_WEIGHTS = {
    "SENSITIVE_FILE_ACCESS": 20,
    "FILE_COPY": 20,
    "USB_CONNECTION": 25,
    "EXTERNAL_UPLOAD": 30,
    "KNOWN_BAD_HASH": 40,
}

SEVERITY_BANDS = (
    (80, "CRITICAL"),
    (60, "HIGH"),
    (30, "MEDIUM"),
    (0, "LOW"),
)


def score_to_severity(score: int) -> str:
    for threshold, label in SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "LOW"


# Small deterministic "known bad hash" list (Stage 9 style demo mechanism)
KNOWN_BAD_HASHES = {
    "a84f7c2e9d13f3568e8c4472b6aa11ffdeadbeefcafefeed0011223344556677",
}
