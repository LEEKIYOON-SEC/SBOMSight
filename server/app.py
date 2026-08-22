"""SBOMSight 웹 서버.

PC 한 대(Windows 11 또는 Rocky Linux 10)에서 도는 단독 도구를 전제로 한다.
기본 바인딩은 127.0.0.1이며, 업로드된 SBOM과 스캔 결과에는 내부 자산 정보가
담기므로 외부에 노출하지 않는 것을 기본값으로 삼는다.

프론트엔드(web/)는 GitHub Pages 데모와 **같은 코드**다. 다른 것은 스캔
제공자뿐이며, 여기서는 이 API를 호출한다.
"""

from __future__ import annotations

import dataclasses
import uuid
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, Body, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from core import (
    artifacts, findingview, grype_runner, selection as selection_mod, syft_runner,
)
from core.ai_narrative import narrative_from_dict, narrative_to_dict, run_narratives
from core.cli import _load_scan_result
from core.config import get_config
from core.models import ScanResult, to_jsonable
from core.policy import load as load_policy
from core.audit import AuditLog
from core.prompt import build_full_text
from core.render import to_html, to_markdown
from core.report import ReportBuilder
from core.ruleengine import RuleEngine
from core.sanitizer import EgressBlocked, EgressGuard
from core.store import Store
from core.vulnfact import build_batch

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


def _find_upload(upload_id: str) -> Path | None:
    """업로드본을 찾는다. 압축 저장이 켜졌다 꺼졌다 해도 둘 다 찾아 준다."""
    if not upload_id.isalnum():          # 경로 조작 차단
        return None
    for name in (f"{upload_id}.json.gz", f"{upload_id}.json"):
        candidate = config.upload_dir / name
        if candidate.is_file():
            return candidate
    return None


def _scoped(scan_id: str, select: list[str] | None) -> tuple[ScanResult, selection_mod.Selection]:
    """스캔을 불러와 선택 범위를 적용한다.

    선택이 비어 있으면 전체를 뜻한다. 이그레스 미리보기·보고서·AI 호출이 전부
    이 한 함수를 거치므로, 화면에 보여 준 범위와 실제로 처리되는 범위가
    어긋날 수 없다.
    """
    if _store().get_scan(scan_id) is None:
        raise HTTPException(404, "스캔을 찾을 수 없습니다.")
    result = _load_scan_result(scan_id)
    picked = selection_mod.apply(result.findings, select)
    if picked.requested and not picked.findings:
        raise HTTPException(400, "선택한 항목이 이 스캔에 없습니다.")
    return result, picked


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
        # AI는 기본적으로 꺼져 있다. 켜져 있어도 공개 취약점 데이터만 전달되며,
        # 키는 서버 환경변수에만 있고 여기로도 브라우저로도 나가지 않는다.
        "ai": {
            "enabled": config.ai_enabled,
            "ready": config.ai_ready(),
            "model": config.gemini_model,
            "fallback_model": config.gemini_fallback_model,
            "key_source": "server-env",
        },
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
async def upload(request: Request, filename: str = Query("")) -> dict[str, Any]:
    """SBOM JSON을 받아 저장하고 형식·컴포넌트 수를 알려 준다.

    **multipart 를 쓰지 않는다.** Starlette 의 `MultiPartParser` 는 파트 하나를
    1MB(`max_part_size`)로 제한하고 FastAPI 의 `UploadFile = File(...)` 로는 그
    값을 넘길 방법이 없다. 실 서버 SBOM 은 100MB를 넘으므로 그 경로로는 애초에
    올릴 수 없었다. 그래서 요청 본문을 그대로 받는다.

        POST /api/upload?filename=sbom.json
        Content-Type: application/json
        body: 파일 바이트 그대로

    받는 즉시 gzip 으로 흘려 쓰면서 같은 통과에서 해시·형식·컴포넌트 수를
    계산한다. 파일 크기와 무관하게 메모리는 청크 하나에 머문다.
    """
    upload_id = uuid.uuid4().hex[:12]

    try:
        stored, info = await artifacts.store_stream(
            request.stream(),
            config.upload_dir,
            f"{upload_id}.json",
            compress=config.compress_storage,
            limit_mb=config.max_upload_mb,
        )
    except artifacts.UploadTooLarge as exc:
        raise HTTPException(413, str(exc)) from exc

    if not stored.original_bytes:
        stored.path.unlink(missing_ok=True)
        raise HTTPException(400, "빈 파일입니다.")

    return {
        "upload_id": upload_id,
        "filename": filename or f"{upload_id}.json",
        "format": info.format,
        "component_count": info.component_count,
        "sha256": info.sha256,
        "size": info.size,
        "stored_bytes": stored.stored_bytes,
        "compressed": stored.compressed,
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
    path = _find_upload(upload_id)
    if path is None:
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
    store = _store()
    scan = store.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, "스캔을 찾을 수 없습니다.")
    scan["selection"] = {"keys": store.get_selection(scan_id)}
    scan["narratives"] = store.narrative_meta(scan_id)
    return scan


@app.get("/api/scans/{scan_id}/findings")
def list_findings(
    scan_id: str,
    sort: str = Query("priority"),
    order: str = Query("asc", pattern="^(asc|desc)$"),
    priority: str = Query("", pattern="^(P0|P1|P2|P3|)$"),
    package_type: str = Query(""),
    status: str = Query(""),
    q: str = Query(""),
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
) -> dict[str, Any]:
    """탐지 결과를 정렬·필터해 한 페이지만 돌려준다.

    서버 한 대가 수천 건을 내므로 전체를 내려보내지 않는다. 정렬에서
    **미확인 값은 방향과 무관하게 항상 뒤로** 간다 — 데이터가 없는 것을
    "낮음"으로 줄 세우면 거짓말이 된다.
    """
    if sort not in findingview.SORT_KEYS:
        raise HTTPException(400, f"정렬 키가 올바르지 않습니다: {sort}")
    if status and status not in findingview.FILTER_KEYS:
        raise HTTPException(400, f"상태 필터가 올바르지 않습니다: {status}")

    if _store().get_scan(scan_id) is None:
        raise HTTPException(404, "스캔을 찾을 수 없습니다.")

    result = _load_scan_result(scan_id, config)
    page = findingview.apply(
        result.findings,
        sort=sort, order=order, priority=priority, package_type=package_type,
        status=status, query=q, offset=offset, limit=limit,
    )
    return {
        "scan_id": scan_id,
        "total": page.total,
        "scan_total": page.scan_total,
        "offset": page.offset,
        "limit": page.limit,
        "has_more": page.has_more,
        "package_types": findingview.package_types(result.findings),
        "findings": [to_jsonable(f) for f in page.findings],
    }


@app.put("/api/scans/{scan_id}/selection")
def put_selection(scan_id: str, body: dict[str, Any] = Body(default={})) -> dict[str, Any]:
    """담당자가 고른 항목을 기록한다.

    보고서를 만들 때마다 범위를 다시 고르게 하지 않기 위한 것이자, 나중에
    `core.cli export` 가 "이 보고서는 무엇을 대상으로 만들어졌는가"를 그대로
    옮길 수 있게 하기 위한 기록이다.
    """
    raw = body.get("selection")
    if not isinstance(raw, list):
        raise HTTPException(400, "selection은 문자열 배열이어야 합니다.")

    _, picked = _scoped(scan_id, [str(x) for x in raw])
    _store().save_selection(scan_id, [f.key for f in picked.findings] if picked.requested else [])
    return {"scan_id": scan_id, "selection": picked.to_dict()}


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
    select: list[str] = Query(default=[]),
) -> Any:
    """보고서를 생성해 돌려준다.

    `select`로 항목을 고르면 그 항목만 담긴다. 고르지 않으면 전체다.

    AI 서술은 이 엔드포인트가 만들지 않는다. 이미 생성해 둔 것이 있으면
    얹을 뿐이며, 없으면 전 항목이 룰 문장으로 채워진다 — AI 없이도 보고서가
    완결된다는 전제는 여기서도 그대로다.
    """
    result, picked = _scoped(scan_id, select)
    scoped = dataclasses.replace(result, findings=picked.findings)

    stored = _store().get_narratives(scan_id)
    narratives = {cve: narrative_from_dict(payload) for cve, payload in stored.items()}

    report = ReportBuilder(config, engine=RuleEngine.from_config(config)).build(
        scoped, narratives=narratives
    )

    if format == "markdown":
        return PlainTextResponse(to_markdown(report), media_type="text/markdown; charset=utf-8")
    if format == "html":
        return HTMLResponse(to_html(report))
    payload = to_jsonable(report)
    payload["selection"] = picked.to_dict()
    return JSONResponse(payload)


# ---------------------------------------------------------------------------
# 이그레스 — AI로 나갈 내용을 사람이 먼저 본다
# ---------------------------------------------------------------------------


@app.get("/api/egress/policy")
def egress_policy() -> dict[str, Any]:
    """적용 중인 외부 전송 허용 정책 전문."""
    guard = EgressGuard.from_config(config)
    return {
        "version": guard.policy.version,
        "sha256": guard.policy.sha256,
        "label": guard.policy.label,
        "policy": guard.policy.data,
    }


@app.get("/api/scans/{scan_id}/egress/preview")
def egress_preview(
    scan_id: str,
    select: list[str] = Query(default=[]),
    limit: int = Query(0, ge=0, le=500),
) -> dict[str, Any]:
    """AI에게 전송될 내용 전체를 그대로 돌려준다.

    "공개 데이터만 보냅니다"라는 주장은 검증할 수 있어야 의미가 있다.
    실제 전송에 쓰이는 것과 **같은 조립기·같은 가드**를 통과시킨 결과와,
    프롬프트 원문을 함께 낸다. 사람이 눈으로 확인한 뒤 보낼 수 있게 하기
    위한 것이며, 이 호출 자체는 외부로 아무것도 보내지 않는다.

    `select`로 고른 항목만 조립한다. 미리보기와 실제 전송이 같은 범위여야
    하므로 AI 호출부도 같은 선택 키를 받아 같은 방식으로 조립한다.
    """
    result, picked = _scoped(scan_id, select)
    guard = EgressGuard.from_config(config)
    facts = build_batch(picked.findings)
    if limit:
        facts = facts[:limit]

    checked = guard.check(facts)

    # 미리보기도 감사 로그에 남긴다 — 언제 무엇을 확인했는지가 기록되어야 한다.
    AuditLog(config.audit_dir).record(
        action="preview",
        outcome="allowed" if checked.ok else "blocked",
        facts=facts,
        policy_version=guard.policy.version,
        policy_sha256=guard.policy.sha256,
        scan_id=scan_id,
        violations=[v.to_dict() for v in checked.violations],
    )

    return {
        "scan_id": scan_id,
        "finding_count": len(picked.findings),
        "scan_finding_count": len(result.findings),
        "selection": picked.to_dict(),
        "fact_count": len(facts),
        "deduplicated": len(picked.findings) - len(facts),
        "ok": checked.ok,
        "violations": [v.to_dict() for v in checked.violations],
        "policy": {
            "version": guard.policy.version,
            "sha256": guard.policy.sha256,
            "label": guard.policy.label,
        },
        "facts": facts,
        "prompt": build_full_text(facts),
        "would_send": config.ai_ready(),
        "model": config.gemini_model if config.ai_ready() else "",
        "note": (
            "이 내용이 AI에게 전달되는 전부입니다. 자산명·호스트명·IP·파일 경로·"
            "설치 버전·취약 여부 판정·대응 우선순위는 포함되지 않습니다."
        ),
    }


# ---------------------------------------------------------------------------
# AI 서술 — 고른 항목만, 서버가 쥔 키로
# ---------------------------------------------------------------------------


@app.post("/api/scans/{scan_id}/narratives")
def make_narratives(scan_id: str, body: dict[str, Any] = Body(default={})) -> dict[str, Any]:
    """선택한 항목에 대해서만 AI 서술을 생성해 저장한다.

    키는 서버 환경변수(`GEMINI_API_KEY`)에서 읽으며 브라우저로 내려가지
    않는다. 전송되는 내용은 같은 선택 키로 egress/preview가 보여 준 것과
    동일하고, 같은 가드를 통과해야만 호출이 일어난다.
    """
    raw = body.get("selection") or []
    if not isinstance(raw, list):
        raise HTTPException(400, "selection은 문자열 배열이어야 합니다.")
    select = [str(x) for x in raw]

    _, picked = _scoped(scan_id, select)

    if not config.ai_enabled:
        raise HTTPException(
            409,
            "AI 사용이 꺼져 있습니다. SBOMSIGHT_AI_ENABLED=1 로 켜 주세요. "
            "AI 없이도 보고서는 룰 기반으로 완결됩니다.",
        )
    if not config.gemini_api_key:
        raise HTTPException(
            409,
            "GEMINI_API_KEY가 설정되어 있지 않습니다. .env 에 키를 넣고 서버를 다시 시작하세요.",
        )

    try:
        run = run_narratives(picked.findings, config=config, scan_id=scan_id)
    except EgressBlocked as blocked:
        # 가드가 막았다면 전송은 일어나지 않았다. 무엇이 걸렸는지 그대로 알린다.
        raise HTTPException(
            422,
            {
                "message": "이그레스 정책 위반으로 전송이 차단되었습니다.",
                "violations": [v.to_dict() for v in blocked.violations],
            },
        ) from blocked

    store = _store()
    store.save_narratives(
        scan_id,
        {cve: narrative_to_dict(n) for cve, n in run.narratives.items()},
        model=run.model,
    )
    # 실제로 전송한 범위를 남긴다. 이것이 나중에 전시 자료의 근거가 된다.
    store.save_selection(scan_id, [f.key for f in picked.findings] if picked.requested else [])

    return {
        "scan_id": scan_id,
        "selection": picked.to_dict(),
        **run.to_dict(),
        "stored": store.narrative_meta(scan_id),
    }


@app.delete("/api/scans/{scan_id}/narratives")
def drop_narratives(scan_id: str) -> dict[str, Any]:
    """저장된 AI 서술을 지운다. 보고서는 다시 룰 문장으로 돌아간다."""
    if _store().get_scan(scan_id) is None:
        raise HTTPException(404, "스캔을 찾을 수 없습니다.")
    _store().clear_narratives(scan_id)
    return {"scan_id": scan_id, "cleared": True}


@app.get("/api/egress/audit")
def egress_audit(limit: int = Query(50, ge=1, le=500)) -> dict[str, Any]:
    """이그레스 감사 로그. 무엇이 언제 나갔는지(또는 차단됐는지)."""
    return {"records": AuditLog(config.audit_dir).tail(limit=limit)}


# ---------------------------------------------------------------------------
# 정적 프론트엔드 — GitHub Pages 데모와 동일한 코드
# ---------------------------------------------------------------------------

POLICY_DIR = config.policy_dir
RULES_DIR = config.rules_dir

# 적용 중인 정책·룰 파일을 그대로 노출한다. UI가 "어떤 기준으로 판정했는가"를
# 보여 줄 때 사본이 아니라 실제로 적용된 파일을 가리켜야 하기 때문이다.
if POLICY_DIR.is_dir():
    app.mount("/policy", StaticFiles(directory=POLICY_DIR), name="policy")
if RULES_DIR.is_dir():
    app.mount("/rules", StaticFiles(directory=RULES_DIR), name="rules")

if WEB_DIR.is_dir():
    app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
