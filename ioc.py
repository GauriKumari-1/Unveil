import re

from .models import Event, IOC

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE = re.compile(r"\bhttps?://[^\s,;\"']+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")


def _domain_from_url(url: str) -> str | None:
    match = re.match(r"https?://([^/]+)/?", url, re.IGNORECASE)
    return match.group(1) if match else None


def extract_iocs(events: list[Event]) -> list[IOC]:
    iocs: list[IOC] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str, event_id: str):
        key = (kind, value)
        if key in seen:
            return
        seen.add(key)
        iocs.append(IOC(type=kind, value=value, source_event_id=event_id))

    for event in events:
        text_parts = [str(v) for v in event.details.values()]
        blob = " ".join(text_parts)

        for ip in IP_RE.findall(blob):
            add("IP", ip, event.id)

        for url in URL_RE.findall(blob):
            add("URL", url, event.id)
            domain = _domain_from_url(url)
            if domain:
                add("DOMAIN", domain, event.id)

        for h in HASH_RE.findall(blob):
            add("HASH", h, event.id)

        if event.user:
            add("USERNAME", event.user, event.id)

    return iocs
