"""SBOMSight 웹 서버.

PC 한 대(Windows 11 또는 Rocky Linux 10)에서 도는 단독 도구를 전제로 한다.
기본 바인딩은 127.0.0.1이며, 업로드된 SBOM과 스캔 결과에는 내부 자산 정보가
담기므로 외부에 노출하지 않는 것을 기본값으로 삼는다.

프론트엔드(web/)는 GitHub Pages 데모와 **같은 코드**다. 다른 것은 스캔
제공자뿐이며, 여기서는 이 API를 호출한다.
"""

from __future__ import annotations

import json
import shutil
import uuid
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from core import grype_runner, sbom as sbom_mod, syft_runner
from core.cli import _load_scan_result
from core.config import get_config
from core.models import to_jsonable
from core.policy import load as load_policy
from core.render import to_html, to_markdown
from core.report import ReportBuilder
from core.ruleengine import RuleEngine
from core.store import Store

from .jobs import JobRegistry
from .pipeline import run_scan

config = get_config()
config.ensure_dirs()

app = FastAPI(
    title="SBOMSight",
    description="SBOM 기반 취약점 대응 검토 · 근거 정리",
    version="0.4.0",
)

registry = JobRegistry()
WEB_DIR = config.repo_root / "web"


def _store() -> Store:
    return Store(config.db_path)


# ---------------------------------------------------------------------------
# 상태
# ---------------------------------------------------------------------------


@app.get("/api/health")
def health() -> dict[str, Any]:
    """외부 도구와 정책 상태. UI가 시작 시 확인해 안내 문구를 띄운다."""
    grype_version = grype_runner.version(config)
    policy = load_policy(config.rules_dir / "priority.json", config.config_dir / "priority.local.json")
    return {
        "ok": bool(grype_version),
        "tools": {
            "syft": syft_runner.version(config),
            "grype": grype_version,
            "grype_db": grype_runner.db_status(config),
        },
        "offline": config.offline,
        # AI는 기본적으로 꺼져 있다. 켜져 있어도 공개 취약점 데이터만 전달된다.
        "ai": {"enabled": config.ai_enabled, "ready": config.ai_ready()},
        "policy": {
            "version": policy.version,
            "sha256": policy.sha256,
            "sources": list(policy.sources),
            "label": policy.label,
        },
    }


@app.get("/api/policy")
def policy() -> dict[str, Any]:
    """적용 중인 우선순위 정책 전문. UI가 판정 근거를 설명할 때 쓴다."""
    loaded = load_policy(config.rules_dir / "priority.json", config.config_dir / "priority.local.json")
    return {
        "version": loaded.version,
        "sha256": loaded.sha256,
        "sources": list(loaded.sources),
        "label": loaded.label,
        "policy": loaded.data,
    }


# ---------------------------------------------------------------------------
# 업로드 · 스캔
# ---------------------------------------------------------------------------


@app.post("/api/upload")
async def upload(file: UploadFile = File(...)) -> dict[str, Any]:
    """SBOM JSON을 받아 저장하고 형식·컴포넌트 수를 알려 준다."""
    upload_id = uuid.uuid4().hex[:12]
    target = config.upload_dir / f"{upload_id}.json"
    limit = config.max_upload_mb * 1024 * 1024

    size = 0
    with target.open("wb") as out:
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > limit:
                out.close()
                target.unlink(missing_ok=True)
                raise HTTPException(413, f"업로드 크기가 {config.max_upload_mb}MB를 넘습니다.")
            out.write(chunk)

    try:
        _, fmt, packages, digest = sbom_mod.load(target)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        target.unlink(missing_ok=True)
        raise HTTPException(400, f"JSON으로 읽을 수 없는 파일입니다: {exc}") from exc

    return {
        "upload_id": upload_id,
        "filename": file.filename or f"{upload_id}.json",
        "format": fmt,
        "component_count": len(packages),
        "sha256": digest,
        "size": size,
    }


@app.post("/api/scan")
def start_scan(
    background: BackgroundTasks,
    upload_id: str = Query(...),
    filename: str = Query(""),
    enrich: bool = Query(True),
    nvd_budget: int = Query(40, ge=0, le=500),
) -> dict[str, Any]:
    """업로드된 SBOM에 대해 스캔을 시작한다. 진행 상황은 /api/scan/{job_id}."""
    path = config.upload_dir / f"{upload_id}.json"
    if not path.is_file():
        raise HTTPException(404, "업로드를 찾을 수 없습니다. 다시 업로드해 주세요.")

    job = registry.create()
    background.add_task(
        run_scan,
        job=job,
        registry=registry,
        sbom_path=path,
        original_name=filename or path.name,
        config=config,
        enrich=enrich,
        nvd_budget=nvd_budget,
    )
    return {"job_id": job.job_id, "steps": job.to_dict()["steps"]}


@app.get("/api/scan/{job_id}")
def scan_status(job_id: str) -> dict[str, Any]:
    job = registry.get(job_id)
    if job is None:
        raise HTTPException(404, "작업을 찾을 수 없습니다.")
    return job.to_dict()


# ---------------------------------------------------------------------------
# 결과 조회
# ---------------------------------------------------------------------------


@app.get("/api/scans")
def list_scans(limit: int = Query(50, ge=1, le=200)) -> dict[str, Any]:
    return {"scans": _store().list_scans(limit=limit)}


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str) -> dict[str, Any]:
    scan = _store().get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, "스캔을 찾을 수 없습니다.")
    return scan


@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: str) -> dict[str, Any]:
    if _store().get_scan(scan_id) is None:
        raise HTTPException(404, "스캔을 찾을 수 없습니다.")
    _store().delete_scan(scan_id)
    return {"deleted": scan_id}


@app.get("/api/scans/{scan_id}/report")
def get_report(
    scan_id: str,
    format: str = Query("json", pattern="^(json|markdown|html)$"),
) -> Any:
    """보고서를 생성해 돌려준다.

    AI는 사용하지 않는다(Mode B). AI 서술은 M5에서 별도 엔드포인트로 붙는다.
    """
    if _store().get_scan(scan_id) is None:
        raise HTTPException(404, "스캔을 찾을 수 없습니다.")

    result = _load_scan_result(scan_id)
    report = ReportBuilder(config, engine=RuleEngine.from_config(config)).build(result)

    if format == "markdown":
        return PlainTextResponse(to_markdown(report), media_type="text/markdown; charset=utf-8")
    if format == "html":
        return HTMLResponse(to_html(report))
    return JSONResponse(to_jsonable(report))


# ---------------------------------------------------------------------------
# 정적 프론트엔드 — GitHub Pages 데모와 동일한 코드
# ---------------------------------------------------------------------------

if WEB_DIR.is_dir():
    app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
