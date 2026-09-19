from datetime import timedelta

from .config import (
    CORRELATION_WINDOW_MINUTES,
    KNOWN_BAD_HASHES,
    SENSITIVE_FILE_KEYWORDS,
    SEVERITY_WEIGHTS,
    score_to_severity,
)
from .models import Alert, Event

WINDOW = timedelta(minutes=CORRELATION_WINDOW_MINUTES)


def _is_sensitive_file_event(event: Event) -> bool:
    if event.source != "file_access":
        return False
    filename = str(event.details.get("file", "")).lower()
    return any(keyword in filename for keyword in SENSITIVE_FILE_KEYWORDS)


def _is_copy_event(event: Event) -> bool:
    return event.source == "file_access" and event.event_type == "FILE_COPIED"


def _is_usb_connect(event: Event) -> bool:
    return event.source == "usb" and event.event_type == "USB_CONNECTED"


def _is_external_upload(event: Event) -> bool:
    return event.source == "browser" and event.event_type == "FILE_UPLOADED"


def _score_chain(events: list[Event], extra: dict[str, int] | None = None):
    breakdown = []
    score = 0

    for event in events:
        if _is_sensitive_file_event(event):
            breakdown.append({"reason": "Sensitive file access", "points": SEVERITY_WEIGHTS["SENSITIVE_FILE_ACCESS"]})
            score += SEVERITY_WEIGHTS["SENSITIVE_FILE_ACCESS"]
        if _is_copy_event(event):
            breakdown.append({"reason": "File copied", "points": SEVERITY_WEIGHTS["FILE_COPY"]})
            score += SEVERITY_WEIGHTS["FILE_COPY"]
        if _is_usb_connect(event):
            breakdown.append({"reason": "USB connection", "points": SEVERITY_WEIGHTS["USB_CONNECTION"]})
            score += SEVERITY_WEIGHTS["USB_CONNECTION"]
        if _is_external_upload(event):
            breakdown.append({"reason": "External upload", "points": SEVERITY_WEIGHTS["EXTERNAL_UPLOAD"]})
            score += SEVERITY_WEIGHTS["EXTERNAL_UPLOAD"]

        file_hash = str(event.details.get("hash", ""))
        if file_hash and file_hash in KNOWN_BAD_HASHES:
            breakdown.append({"reason": "Known-bad file hash", "points": SEVERITY_WEIGHTS["KNOWN_BAD_HASH"]})
            score += SEVERITY_WEIGHTS["KNOWN_BAD_HASH"]

    if extra:
        for reason, points in extra.items():
            breakdown.append({"reason": reason, "points": points})
            score += points

    return score, breakdown


def correlate(events: list[Event]) -> list[Alert]:
    alerts: list[Alert] = []
    alert_counter = 0

    sensitive_events = [e for e in events if _is_sensitive_file_event(e) or _is_copy_event(e)]
    usb_events = [e for e in events if _is_usb_connect(e)]
    upload_events = [e for e in events if _is_external_upload(e)]

    used_usb: set[str] = set()
    used_upload: set[str] = set()

    # Rule 1 — USB exfiltration
    for sensitive in sensitive_events:
        for usb in usb_events:
            if usb.id in used_usb:
                continue
            delta = usb.timestamp - sensitive.timestamp
            if timedelta(0) <= delta <= WINDOW:
                alert_counter += 1
                chain = [e for e in events if e.id in {sensitive.id, usb.id}]
                score, breakdown = _score_chain(chain)
                alerts.append(Alert(
                    id=f"ALERT-{alert_counter:03d}",
                    severity=score_to_severity(score),
                    type="USB_EXFILTRATION",
                    reason=(
                        f"Sensitive file activity ({sensitive.event_type}) followed by USB "
                        f"connection within {CORRELATION_WINDOW_MINUTES} minutes "
                        f"({int(delta.total_seconds() // 60)} min apart)"
                    ),
                    events=[sensitive.id, usb.id],
                    score=score,
                    breakdown=breakdown,
                    timestamp=usb.timestamp,
                ))
                used_usb.add(usb.id)
                break

    # Rule 2 — External upload (browser / Gmail)
    for sensitive in sensitive_events:
        for upload in upload_events:
            if upload.id in used_upload:
                continue
            delta = upload.timestamp - sensitive.timestamp
            if timedelta(0) <= delta <= WINDOW:
                alert_counter += 1
                chain = [e for e in events if e.id in {sensitive.id, upload.id}]
                score, breakdown = _score_chain(chain)
                alerts.append(Alert(
                    id=f"ALERT-{alert_counter:03d}",
                    severity=score_to_severity(score),
                    type="EXTERNAL_UPLOAD",
                    reason=(
                        f"Sensitive file activity ({sensitive.event_type}) followed by an "
                        f"external browser upload within {CORRELATION_WINDOW_MINUTES} minutes "
                        f"({int(delta.total_seconds() // 60)} min apart)"
                    ),
                    events=[sensitive.id, upload.id],
                    score=score,
                    breakdown=breakdown,
                    timestamp=upload.timestamp,
                ))
                used_upload.add(upload.id)
                break

    alerts.sort(key=lambda a: a.timestamp or a.id)
    return alerts
