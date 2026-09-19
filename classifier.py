from .config import REQUIRED_COLUMNS, SUPPORTED_FILES


def classify_file(filename: str):
    """Classify an evidence file by its filename.

    Returns the evidence-type string (e.g. "file_access") for a known file,
    or a dict describing an unsupported file instead of raising.
    """
    kind = SUPPORTED_FILES.get(filename)
    if kind is None:
        return {"status": "unsupported", "filename": filename}
    return kind


def validate_columns(filename: str, fieldnames: list[str]) -> None:
    """Raise ValueError with a clear message if required columns are missing."""
    kind = SUPPORTED_FILES.get(filename)
    if kind is None:
        return

    required = REQUIRED_COLUMNS.get(kind, set())
    present = {name.strip() for name in fieldnames if name}
    missing = required - present

    if missing:
        missing_list = ", ".join(sorted(missing))
        raise ValueError(
            f"Unable to parse {filename}: missing required column(s): {missing_list}"
        )
