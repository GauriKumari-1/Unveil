from fastapi.testclient import TestClient

from backend.app import app
from backend.classifier import classify_file

client = TestClient(app)


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_demo_timeline_sorted():
    resp = client.get("/timeline")
    assert resp.status_code == 200
    data = resp.json()
    events = data["events"]
    assert len(events) > 0
    assert [e["timestamp"] for e in events] == sorted(e["timestamp"] for e in events)


def test_demo_alerts_exist():
    resp = client.get("/alerts")
    assert resp.status_code == 200
    alerts = resp.json()["alerts"]
    assert len(alerts) >= 2
    assert {a["type"] for a in alerts} >= {"USB_EXFILTRATION", "EXTERNAL_UPLOAD"}


def test_iocs_extracted():
    resp = client.get("/iocs")
    assert resp.status_code == 200
    iocs = resp.json()["iocs"]
    assert len(iocs) > 0
    assert any(item["type"] in {"IP", "URL", "HASH", "USERNAME", "DOMAIN"} for item in iocs)


def test_classifier_unknown_file():
    assert classify_file("random.txt") == {"status": "unsupported", "filename": "random.txt"}