from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .classifier import classify_file
from .models import Event
from .parser import PARSERS


def _timestamp(value: str, filename: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Unable to parse {filename}: invalid timestamp '{value}'") from exc


def _event_type(kind: str, row: dict[str, Any]) -> str:
    action = str(row.get("action", "")).strip().lower()

    if kind == "file_access":
        mapping = {
            "open": "FILE_OPENED",
            "opened": "FILE_OPENED",
            "copy": "FILE_COPIED",
            "copied": "FILE_COPIED",
        }
        return mapping.get(action, "FILE_ACTIVITY")

    if kind == "usb":
        if "connect" in action:
            return "USB_CONNECTED"
        if "disconnect" in action:
            return "USB_DISCONNECTED"
        return "USB_ACTIVITY"

    if kind == "browser":
        if "upload" in action:
            return "FILE_UPLOADED"
        if "open" in action:
            return "BROWSER_OPENED"
        return "BROWSER_ACTIVITY"

    if "success" in action:
        return "LOGIN_SUCCESS"
    if "fail" in action:
        return "LOGIN_FAILURE"
    return "LOGIN_ACTIVITY"


def normalize_file(filename: str, path: str | Path) -> list[Event]:
    kind = classify_file(filename)
    if not isinstance(kind, str):
        return []

    events: list[Event] = []
    for row in PARSERS[kind](path):
        details = {
            key: value
            for key, value in row.items()
            if key not in {"timestamp", "user", "host"} and value not in (None, "")
        }

        event = Event(
            id="",
            timestamp=_timestamp(str(row["timestamp"]), filename),
            source=kind,
            event_type=_event_type(kind, row),
            user=str(row.get("user", "")),
            host=str(row.get("host", "")),
            details=details,
        )
        events.append(event)

    for index, event in enumerate(events, start=1):
        event.id = f"EV-{index:03d}"

    return events


def normalize_directory(directory: str | Path) -> list[Event]:
    directory = Path(directory)
    all_events: list[Event] = []

    for filename in sorted(directory.iterdir()):
        if not filename.is_file():
            continue
        kind = classify_file(filename.name)
        if isinstance(kind, str):
            all_events.extend(normalize_file(filename.name, filename))

    all_events.sort(key=lambda event: event.timestamp)

    for index, event in enumerate(all_events, start=1):
        event.id = f"EV-{index:03d}"

    return all_events