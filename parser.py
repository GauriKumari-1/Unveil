import csv
from pathlib import Path
from typing import Any

from .classifier import validate_columns


def _read(path: str | Path) -> list[dict[str, Any]]:
    path = Path(path)
    try:
        with path.open(newline="", encoding="utf-8-sig") as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames:
                raise ValueError(f"Unable to parse {path.name}: CSV header is missing")
            validate_columns(path.name, reader.fieldnames)
            return [dict(row) for row in reader]
    except UnicodeDecodeError as exc:
        raise ValueError(f"Unable to parse {path.name}: file is not valid UTF-8") from exc
    except csv.Error as exc:
        raise ValueError(f"Unable to parse {path.name}: malformed CSV ({exc})") from exc


def parse_file_access(path: str | Path):
    return _read(path)


def parse_usb(path: str | Path):
    return _read(path)


def parse_browser(path: str | Path):
    return _read(path)


def parse_login(path: str | Path):
    return _read(path)


PARSERS = {
    "file_access": parse_file_access,
    "usb": parse_usb,
    "browser": parse_browser,
    "login": parse_login,
}