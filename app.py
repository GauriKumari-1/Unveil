import shutil
import tempfile
import uuid
import zipfile
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .classifier import classify_file
from .config import SAMPLE_DIR, SUPPORTED_FILES
from .correlation import correlate
from .ioc import extract_iocs
from .models import CaseResult
from .normalizer import normalize_directory

app = FastAPI(title="Cyber Triage", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

CASES: dict[str, CaseResult] = {}


def process_case(case_id: str, directory: Path, files: list[dict[str, str]]) -> CaseResult:
    result = CaseResult(case_id=case_id, files=files)
    try:
        result.events = normalize_directory(directory)
        result.iocs = extract_iocs(result.events)
        result.alerts = correlate(result.events)
    except ValueError as exc:
        result.errors.append(str(exc))
    except Exception as exc:  # never leak a raw traceback to the jury
        result.errors.append(f"Unexpected error while processing evidence: {exc}")
    CASES[case_id] = result
    return result


def get_demo_case() -> CaseResult:
    if "CASE-DEMO" not in CASES:
        files = [{"filename": name, "type": kind} for name, kind in SUPPORTED_FILES.items()]
        process_case("CASE-DEMO", SAMPLE_DIR, files)
    return CASES["CASE-DEMO"]


def get_case(case_id: str | None) -> CaseResult:
    if case_id is None or case_id == "CASE-DEMO":
        return get_demo_case()

    if case_id not in CASES:
        raise HTTPException(404, f"Case '{case_id}' not found")

    return CASES[case_id]


@app.get("/health")
def health():
    return {"status": "ok", "service": "cyber-triage"}


@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(400, "Please upload a ZIP evidence bundle")

    case_id = "CASE-" + uuid.uuid4().hex[:8].upper()
    work_dir = Path(tempfile.mkdtemp(prefix="cyber-triage-"))
    archive_path = work_dir / "evidence.zip"
    archive_path.write_bytes(await file.read())

    try:
        with zipfile.ZipFile(archive_path) as zf:
            extract_dir = work_dir / "data"
            extract_dir.mkdir(exist_ok=True)

            for member in zf.infolist():
                if member.is_dir():
                    continue

                target = (extract_dir / Path(member.filename).name).resolve()

                if not str(target).startswith(str(extract_dir.resolve())):
                    raise HTTPException(400, f"Unsafe zip entry: {member.filename}")

                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member) as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst)

    except zipfile.BadZipFile as exc:
        shutil.rmtree(work_dir, ignore_errors=True)
        raise HTTPException(400, "Uploaded file is not a valid ZIP") from exc

    files: list[dict[str, str]] = []
    for path in sorted((work_dir / "data").rglob("*")):
        if path.is_file():
            result = classify_file(path.name)
            files.append({
                "filename": path.name,
                "type": result if isinstance(result, str) else "unsupported"
            })

    process_case(case_id, work_dir / "data", files)
    return {
        "case_id": case_id,
        "files": files,
        "errors": CASES[case_id].errors,
    }


@app.post("/analyze/{case_id}")
def analyze(case_id: str):
    return get_case(case_id)


@app.get("/timeline")
def timeline(case_id: str | None = None):
    case = get_case(case_id)
    return {"case_id": case.case_id, "events": case.events, "errors": case.errors}


@app.get("/alerts")
def alerts(case_id: str | None = None):
    case = get_case(case_id)
    return {"case_id": case.case_id, "alerts": case.alerts, "errors": case.errors}


@app.get("/iocs")
def iocs(case_id: str | None = None):
    case = get_case(case_id)
    return {"case_id": case.case_id, "iocs": case.iocs, "errors": case.errors}


@app.get("/cases/{case_id}")
def case_detail(case_id: str):
    return get_case(case_id)


@app.get("/summary")
def summary(case_id: str | None = None):
    case = get_case(case_id)
    highest = "NONE"
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    for alert in case.alerts:
        if alert.severity in order and (highest == "NONE" or order.index(alert.severity) > order.index(highest)):
            highest = alert.severity
    return {
        "case_id": case.case_id,
        "evidence_files": len(case.files),
        "events_extracted": len(case.events),
        "iocs_found": len(case.iocs),
        "suspicious_chains": len(case.alerts),
        "highest_severity": highest,
        "errors": case.errors,
    }


# ---------------------------------------------------------------------------
# Frontend (served by this same server so one process runs the whole demo)
# ---------------------------------------------------------------------------
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

if FRONTEND_DIR.exists():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_DIR)), name="assets")

    @app.get("/", include_in_schema=False)
    def root():
        index = FRONTEND_DIR / "index.html"
        if index.exists():
            return FileResponse(index)
        return {"message": "Cyber Triage backend is running"}
else:
    @app.get("/", include_in_schema=False)
    def root():
        return {"message": "Cyber Triage backend is running"}
