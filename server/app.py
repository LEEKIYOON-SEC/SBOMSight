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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, Body, FastAPI, HTTPException, Query, Request
from fastapi.responses import (
    HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse,
)
from fastapi.staticfiles import StaticFiles

from core import (
    artifacts, assets as assets_mod, csvexport, escalation, findingview, grype_runner,
    selection as selection_mod, syft_runner, versioning,
)
from core.accounts import AccountError, VIEWER
from core.assets import Asset, AssetError, Assets
from core.ai_narrative import (
    build_chain_groups, build_vuln_fact_from_payload, narrative_from_dict, narrative_to_dict,
    run_chain_analysis, run_escalation_analysis, run_narratives,
)
from core.cli import _load_scan_result, revive_finding, revive_metadata
from core.config import get_config
from core.models import Priority, ScanResult, to_jsonable
from core.netacl import Allowlist
from core.policy import load as load_policy
from core.audit import AuditLog
from core.prompt import build_chain_full_text, build_escalation_full_text, build_full_text
from core.render import to_html, to_markdown
from core.report import ReportBuilder, _highest_version
from core.ruleengine import RuleEngine
from core.sanitizer import EgressBlocked, EgressGuard
from core.store import Store, package_key, split_package_key
from core.vulnfact import build_batch

from .jobs import JobRegistry
from .pipeline import run_scan
from .security import (
    AccessControl, AccessMiddleware, clear_session_cookie, client_ip, set_session_cookie,
)

config = get_config()
config.ensure_dirs()

app = FastAPI(
    title="SBOMSight",
    description="SBOM 기반 취약점 대응 검토 · 근거 정리",
    version="0.4.0",
)

registry = JobRegistry()
WEB_DIR = config.repo_root / "web"

access = AccessControl(config)
app.add_middleware(AccessMiddleware, access=access)


def _require_admin(request: Request) -> None:
    """미들웨어가 이미 쓰기 요청을 걸러 주지만, 여기서 한 번 더 본다.

    권한 판단이 미들웨어 한 곳에만 있으면, 나중에 누군가 경로 예외를 하나
    추가하는 순간 그 경로 전체가 조용히 열린다. 계정 관리처럼 되돌리기 어려운
    것은 라우트에서도 확인한다.
    """
    user = getattr(request.state, "user", None)
    if user is None:
        raise HTTPException(401, "로그인이 필요합니다.")
    if user.role != "admin":
        raise HTTPException(403, "관리자만 할 수 있습니다.")


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
# 로그인 · 계정 · 접근 IP
# ---------------------------------------------------------------------------


@app.get("/api/auth/state")
def auth_state(request: Request) -> dict[str, Any]:
    """로그인 화면이 시작할 때 묻는 것. 인증 없이 닿는 유일한 조회다."""
    user = getattr(request.state, "user", None)
    account = access.accounts.get(user.username) if user else None
    return {
        "needs_setup": access.needs_setup(),
        "authenticated": user is not None,
        "username": user.username if user else "",
        "role": user.role if user else "",
        # 초기화된 계정은 바꾸기 전에는 아무 화면도 열리지 않는다.
        "must_change": bool(account.must_change) if account else False,
        "client_ip": client_ip(request),
    }


@app.post("/api/auth/setup")
def auth_setup(request: Request, body: dict[str, Any] = Body(default={})) -> Any:
    """최초 관리자 하나를 만든다. 계정이 이미 있으면 거부한다."""
    if not access.needs_setup():
        raise HTTPException(409, "이미 계정이 있습니다. 관리자로 로그인해 주세요.")

    try:
        user = access.accounts.create(
            str(body.get("username", "")), str(body.get("password", "")), role="admin"
        )
    except AccountError as exc:
        raise HTTPException(400, str(exc)) from exc

    session = access.accounts.open_session(user.username, ttl_hours=config.session_ttl_hours)
    response = JSONResponse({"username": user.username, "role": user.role})
    set_session_cookie(response, session.token, max_age=config.session_ttl_hours * 3600)
    return response


@app.post("/api/auth/login")
def auth_login(request: Request, body: dict[str, Any] = Body(default={})) -> Any:
    ip = client_ip(request)
    wait = access.throttle.blocked_for(ip)
    if wait:
        raise HTTPException(429, f"로그인 시도가 너무 많습니다. {wait}초 후 다시 시도하세요.")

    username = str(body.get("username", "")).strip()
    user = access.accounts.authenticate(username, str(body.get("password", "")))
    if user is None:
        access.throttle.fail(ip)
        # 어느 쪽이 틀렸는지 말하지 않는다. 계정 존재 여부를 알려 주는 셈이 된다.
        raise HTTPException(401, "계정 또는 비밀번호가 올바르지 않습니다.")

    access.throttle.succeed(ip)
    session = access.accounts.open_session(user.username, ttl_hours=config.session_ttl_hours)
    response = JSONResponse({
        "username": user.username, "role": user.role,
        "must_change": bool(user.must_change),
    })
    set_session_cookie(response, session.token, max_age=config.session_ttl_hours * 3600)
    return response


@app.post("/api/auth/logout")
def auth_logout(request: Request) -> Any:
    user = getattr(request.state, "user", None)
    if user is not None:
        access.accounts.close_session(user.token)
    response = JSONResponse({"ok": True})
    clear_session_cookie(response)
    return response


@app.post("/api/auth/password")
def auth_change_password(request: Request, body: dict[str, Any] = Body(default={})) -> Any:
    """자기 비밀번호를 바꾼다. 현재 비밀번호를 확인한다."""
    user = getattr(request.state, "user", None)
    if user is None:
        raise HTTPException(401, "로그인이 필요합니다.")
    if access.accounts.authenticate(user.username, str(body.get("current", ""))) is None:
        raise HTTPException(403, "현재 비밀번호가 올바르지 않습니다.")

    try:
        access.accounts.set_password(
            user.username, str(body.get("password", "")), must_change=False
        )
    except AccountError as exc:
        raise HTTPException(400, str(exc)) from exc

    # set_password가 기존 세션을 전부 끊었다. 방금 바꾼 본인은 다시 열어 준다.
    session = access.accounts.open_session(user.username, ttl_hours=config.session_ttl_hours)
    response = JSONResponse({"ok": True})
    set_session_cookie(response, session.token, max_age=config.session_ttl_hours * 3600)
    return response


@app.get("/api/users")
def list_users(request: Request) -> dict[str, Any]:
    _require_admin(request)
    return {"users": [u.to_dict() for u in access.accounts.list_users()]}


@app.post("/api/users")
def create_user(request: Request, body: dict[str, Any] = Body(default={})) -> dict[str, Any]:
    _require_admin(request)
    try:
        user = access.accounts.create(
            str(body.get("username", "")),
            str(body.get("password", "")),
            str(body.get("role", VIEWER)),
        )
    except AccountError as exc:
        raise HTTPException(400, str(exc)) from exc
    return user.to_dict()


@app.put("/api/users/{username}")
def update_user(request: Request, username: str, body: dict[str, Any] = Body(default={})) -> dict[str, Any]:
    """비밀번호 변경·초기화와 권한 변경. 관리자만.

    둘은 다른 동작이다.

    - `password` — 관리자가 **정한** 새 비밀번호로 바꾼다.
    - `reset: true` — 계정 **이름과 같은** 비밀번호로 되돌리고, 그 계정이
      다음 로그인에서 반드시 바꾸게 한다.

    예전에는 이 둘이 "초기화" 하나로 묶여 있었는데, 실제로 하는 일은 관리자가
    새 비밀번호를 지어내는 것이라 이름과 동작이 어긋나 있었다.
    """
    _require_admin(request)
    if access.accounts.get(username) is None:
        raise HTTPException(404, f"'{username}' 계정이 없습니다.")

    try:
        if body.get("reset"):
            access.accounts.reset_password(username)
        elif body.get("password"):
            access.accounts.set_password(username, str(body["password"]))
        if body.get("role"):
            access.accounts.set_role(username, str(body["role"]))
    except AccountError as exc:
        raise HTTPException(400, str(exc)) from exc

    user = access.accounts.get(username)
    return user.to_dict() if user else {}


@app.delete("/api/users/{username}")
def delete_user(request: Request, username: str) -> dict[str, Any]:
    _require_admin(request)
    actor = getattr(request.state, "user", None)
    if actor is not None and actor.username == username:
        raise HTTPException(400, "자기 계정은 삭제할 수 없습니다.")
    try:
        access.accounts.delete(username)
    except AccountError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"deleted": username}


@app.get("/api/access/ips")
def get_allowed_ips(request: Request) -> dict[str, Any]:
    _require_admin(request)
    allowlist = access.allowlist()
    return {
        "entries": list(allowlist.entries),
        "active": allowlist.active,
        "client_ip": client_ip(request),
        "note": (
            "비워 두면 IP 제한이 없습니다(로그인은 여전히 필요합니다). "
            "판단은 소켓 상대 주소로만 하며 X-Forwarded-For 헤더는 보지 않습니다."
        ),
    }


@app.put("/api/access/ips")
def put_allowed_ips(request: Request, body: dict[str, Any] = Body(default={})) -> dict[str, Any]:
    """허용 목록을 저장한다. **자기 자신을 잠그는 저장은 막는다.**

    목록을 잘못 넣어 스스로 못 들어오게 되면 서버 PC 앞으로 가서 DB를 손봐야
    한다. 저장 직전에 지금 접속 중인 주소가 새 목록에 들어가는지 확인한다.
    """
    _require_admin(request)
    raw = body.get("entries", "")
    try:
        allowlist = Allowlist.parse(raw if isinstance(raw, (list, tuple)) else str(raw))
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

    ip = client_ip(request)
    if allowlist.active and not allowlist.permits(ip):
        raise HTTPException(
            400,
            f"지금 접속 중인 주소({ip})가 목록에 없습니다. "
            f"이대로 저장하면 다시 들어올 수 없습니다.",
        )

    access.save_allowlist(allowlist)
    return {"entries": list(allowlist.entries), "active": allowlist.active}


# ---------------------------------------------------------------------------
# 상태
# ---------------------------------------------------------------------------


@app.get("/api/health")
def health(request: Request) -> dict[str, Any]:
    """외부 도구와 정책 상태. UI가 시작 시 확인해 안내 문구를 띄운다."""
    grype_version = grype_runner.version(config)
    policy = load_policy(config.rules_dir / "priority.json", config.config_dir / "priority.local.json")
    user = getattr(request.state, "user", None)
    return {
        "ok": bool(grype_version),
        "user": {"username": user.username, "role": user.role} if user else None,
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
# 자산 — 이 도구의 관리 단위는 스캔이 아니라 서버 한 대다
# ---------------------------------------------------------------------------


def _assets() -> Assets:
    return Assets(config.db_path)


def _asset_or_404(asset_id: str) -> Asset:
    asset = _assets().get(asset_id)
    if asset is None:
        raise HTTPException(404, "자산을 찾을 수 없습니다.")
    return asset


@app.get("/api/assets")
def list_assets() -> dict[str, Any]:
    """자산 목록에 마지막 스캔 정보를 붙여 돌려준다.

    "마지막 스캔이 언제였나"가 대시보드에서 가장 먼저 봐야 하는 값이다 —
    석 달 전에 한 번 올리고 잊은 서버가 목록에 조용히 섞여 있으면 안 된다.
    """
    store = _store()
    summary = store.asset_summary()
    assets = _assets().list()

    rows = []
    for asset in assets:
        row = asset.to_dict()
        row.update(summary.get(asset.asset_id, {
            "scan_count": 0, "last_scan_at": "", "last_scan_id": "",
            "last_finding_count": 0, "last_sbom_filename": "",
        }))
        rows.append(row)

    unassigned = summary.get(assets_mod.UNASSIGNED, {})
    return {
        "assets": rows,
        # 자산 개념 이전에 만들어진 스캔들. 화면에서 배정할 수 있게 개수를 알린다.
        "unassigned_scans": unassigned.get("scan_count", 0),
    }


@app.post("/api/assets")
def create_asset(request: Request, body: dict[str, Any] = Body(default={})) -> dict[str, Any]:
    _require_admin(request)
    try:
        asset = _assets().create(
            str(body.get("name", "")),
            group_name=str(body.get("group_name", "")),
            os=str(body.get("os", "")),
            note=str(body.get("note", "")),
        )
    except AssetError as exc:
        raise HTTPException(400, str(exc)) from exc
    return asset.to_dict()


@app.get("/api/assets/{asset_id}")
def get_asset(asset_id: str, limit: int = Query(50, ge=1, le=500)) -> dict[str, Any]:
    asset = _asset_or_404(asset_id)
    return {
        **asset.to_dict(),
        "scans": _store().list_scans(limit=limit, asset_id=asset_id),
    }


@app.put("/api/assets/{asset_id}")
def update_asset(request: Request, asset_id: str, body: dict[str, Any] = Body(default={})) -> dict[str, Any]:
    _require_admin(request)
    _asset_or_404(asset_id)
    try:
        asset = _assets().update(asset_id, **{
            k: body[k] for k in ("name", "group_name", "os", "note") if k in body
        })
    except AssetError as exc:
        raise HTTPException(400, str(exc)) from exc
    return asset.to_dict()


@app.delete("/api/assets/{asset_id}")
def delete_asset(request: Request, asset_id: str) -> dict[str, Any]:
    """자산을 지운다. **그 자산의 스캔과 보관 파일도 함께 지운다.**

    자산이 사라졌는데 결과만 남으면 어디에도 속하지 않는 데이터가 쌓이고,
    그것을 되살릴 길도 없다. DB 행과 디스크의 Grype 원본을 같이 정리한다.
    """
    _require_admin(request)
    asset = _asset_or_404(asset_id)
    try:
        removed = _assets().delete(asset_id)
    except AssetError as exc:
        raise HTTPException(400, str(exc)) from exc

    # 디스크에 남은 산출물. 지우지 못해도 자산 삭제 자체는 되돌리지 않는다 —
    # DB 는 이미 정리됐고, 남은 파일은 고아라 다음에 지워도 된다.
    import shutil

    for scan_id in removed:
        directory = config.scan_dir(scan_id)
        if directory.is_dir():
            shutil.rmtree(directory, ignore_errors=True)

    return {"deleted": asset_id, "name": asset.name, "scans_deleted": len(removed)}


@app.put("/api/scans/{scan_id}/asset")
def assign_scan(request: Request, scan_id: str, body: dict[str, Any] = Body(default={})) -> dict[str, Any]:
    """스캔을 다른 자산으로 옮긴다. 자산 없는 상태로는 되돌릴 수 없다."""
    _require_admin(request)
    if _store().get_scan(scan_id) is None:
        raise HTTPException(404, "스캔을 찾을 수 없습니다.")

    asset_id = str(body.get("asset_id", ""))
    if not asset_id:
        raise HTTPException(400, "옮길 자산을 골라 주세요.")
    _asset_or_404(asset_id)
    _store().assign_scan(scan_id, asset_id)
    return {"scan_id": scan_id, "asset_id": asset_id}


def _history_scope(asset_id: str, base: str, head: str) -> dict[str, Any]:
    """비교할 두 스캔을 정한다. 지정이 없으면 최근 두 건."""
    store = _store()
    _asset_or_404(asset_id)
    scans = store.list_scans(limit=500, asset_id=asset_id)
    known = {s["scan_id"] for s in scans}

    if not base and not head:
        if len(scans) < 2:
            return {
                "asset_id": asset_id,
                "comparable": False,
                "detail": "비교하려면 이 자산에 스캔이 2건 이상 있어야 합니다.",
                "scans": scans,
            }
        head, base = scans[0]["scan_id"], scans[1]["scan_id"]

    for scan_id in (base, head):
        if scan_id not in known:
            raise HTTPException(404, f"이 자산의 스캔이 아닙니다: {scan_id}")

    at = {s["scan_id"]: s["created_at"] for s in scans}
    return {
        "asset_id": asset_id, "comparable": True, "scans": scans,
        "base_scan_id": base, "head_scan_id": head,
        "base_created_at": at.get(base, ""), "head_created_at": at.get(head, ""),
    }


@app.get("/api/assets/{asset_id}/history")
def asset_history(
    asset_id: str,
    base: str = Query(""),
    head: str = Query(""),
) -> dict[str, Any]:
    """같은 자산의 두 스캔을 대조한다 — **건수만.** 지정이 없으면 최근 두 건.

    비교 축은 `(cve, 설치 패키지명)` 이다. `Finding.key` 는 설치 버전을
    포함하므로 패치하면 키가 바뀐다 — 그것으로 비교하면 "패치했더니 하나
    사라지고 하나 생겼다" 가 되어 무엇이 달라졌는지 알 수 없다.

    **줄은 싣지 않는다.** 예전에는 두 스캔의 payload 를 전부 되살려 세 갈래를
    통째로 내려보냈다. 48,923건짜리 스캔 둘이면 그 한 번이 20초가 넘고, 화면은
    수만 줄을 그리다 멈췄다. 줄은 `/history/changes` 가 쪽으로 낸다.
    """
    scope = _history_scope(asset_id, base, head)
    if not scope["comparable"]:
        return scope
    return {**scope, "counts": _store().diff_counts(scope["base_scan_id"], scope["head_scan_id"])}


@app.get("/api/assets/{asset_id}/history/changes")
def asset_history_changes(
    asset_id: str,
    kind: str = Query("added"),
    base: str = Query(""),
    head: str = Query(""),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
) -> dict[str, Any]:
    """변화 한 갈래의 한 쪽 — 신규 · 해소 · 유지."""
    if kind not in Store.DIFF_KINDS:
        raise HTTPException(400, f"갈래는 {' · '.join(Store.DIFF_KINDS)} 중 하나여야 합니다.")
    scope = _history_scope(asset_id, base, head)
    if not scope["comparable"]:
        raise HTTPException(400, scope["detail"])
    return _store().diff_page(
        scope["base_scan_id"], scope["head_scan_id"], kind, offset=offset, limit=limit
    )


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
    asset_id: str = Query(""),
) -> dict[str, Any]:
    """업로드된 SBOM에 대해 스캔을 시작한다. 진행 상황은 /api/scan/{job_id}.

    **자산은 필수다.** 어느 서버의 SBOM 인지 정해지지 않은 채로 결과가 쌓이면
    나중에 파일명으로 추측하게 되고, 이력 비교도 성립하지 않는다. 등록이 먼저다.
    """
    if not asset_id:
        raise HTTPException(400, "어느 서버의 SBOM 인지 먼저 골라 주세요. 자산 등록이 먼저입니다.")
    _asset_or_404(asset_id)

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
        asset_id=asset_id,
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


@app.get("/api/scans/{scan_id}/meta")
def get_scan_meta(scan_id: str) -> dict[str, Any]:
    """스캔 머리말. **findings 는 들어 있지 않다.**

    보고서 화면이 시작할 때 필요한 것은 시각·SBOM·정책·보강 상태뿐이다.
    그것을 위해 48,923건을 내려보내면 첫 화면이 8초가 된다.
    """
    store = _store()
    meta = store.get_scan_meta(scan_id)
    if meta is None:
        raise HTTPException(404, "스캔을 찾을 수 없습니다.")
    meta["narratives"] = store.narrative_meta(scan_id)
    # 선택 키는 싣지 않는다. 48,923건짜리 스캔에서 이 한 줄이 머리말을 4MB로
    # 불렸다. 필요한 화면은 /selection 을 따로 부른다.
    meta["selection"] = {"count": len(store.get_selection(scan_id))}
    return meta


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
    if sort not in Store.SORT_KEYS:
        raise HTTPException(400, f"정렬 키가 올바르지 않습니다: {sort}")
    if status and status not in Store.FILTER_KEYS:
        raise HTTPException(400, f"상태 필터가 올바르지 않습니다: {status}")

    store = _store()
    if store.get_scan_meta(scan_id) is None:
        raise HTTPException(404, "스캔을 찾을 수 없습니다.")

    page = store.page_findings(
        scan_id,
        sort=sort, order=order, priority=priority, package_type=package_type,
        status=status, query=q, offset=offset, limit=limit,
    )
    return {"scan_id": scan_id, **page}


@app.get("/api/scans/{scan_id}/summary")
def scan_summary(scan_id: str) -> dict[str, Any]:
    """요약 타일 값. SQL 로 센다 — 세려고 48,923건을 내려보내지 않는다."""
    store = _store()
    if store.get_scan_meta(scan_id) is None:
        raise HTTPException(404, "스캔을 찾을 수 없습니다.")
    return {"scan_id": scan_id, **store.scan_summary(scan_id)}


@app.get("/api/scans/{scan_id}/finding-keys")
def list_finding_keys(
    scan_id: str,
    priority: str = Query("", pattern="^(P0|P1|P2|P3|)$"),
    package_type: str = Query(""),
    status: str = Query(""),
    q: str = Query(""),
) -> dict[str, Any]:
    """필터에 맞는 선택 키 전부. "필터 전체 선택" 이 쓴다.

    상한을 넘으면 목록은 잘리고 건수는 그대로 온다 — 화면이 "N건 중 M건만
    선택했다"고 말할 수 있어야 한다.
    """
    store = _store()
    if store.get_scan_meta(scan_id) is None:
        raise HTTPException(404, "스캔을 찾을 수 없습니다.")

    keys, total = store.finding_keys(
        scan_id, priority=priority, package_type=package_type,
        status=status, query=q, limit=limit,
    )
    return {"scan_id": scan_id, "keys": keys, "total": total, "truncated": len(keys) < total}


@app.get("/api/scans/{scan_id}/findings/{finding_key:path}")
def get_finding_detail(scan_id: str, finding_key: str) -> dict[str, Any]:
    """항목 하나의 상세. 보고서 절과 권고 절차를 그 한 건에 대해서만 조립한다.

    상세를 열자고 48,923건짜리 보고서를 통째로 만들 이유가 없다.
    """
    store = _store()
    payload = store.get_finding(scan_id, finding_key)
    if payload is None:
        raise HTTPException(404, "항목을 찾을 수 없습니다.")

    finding = revive_finding(payload)
    stored = store.get_narratives(scan_id).get(finding.intel.cve)
    narratives = {finding.intel.cve: narrative_from_dict(stored)} if stored else {}

    meta = store.get_scan_meta(scan_id) or {}
    result = ScanResult(
        metadata=revive_metadata(meta.get("metadata") or {}),
        findings=(finding,),
        policy=meta.get("policy") or {},
    )
    report = ReportBuilder(config, engine=RuleEngine.from_config(config)).build(
        result, narratives=narratives
    )
    return to_jsonable(report.findings[0]) if report.findings else {}


@app.get("/api/scans/{scan_id}/findings.csv")
def export_findings_csv(
    scan_id: str,
    priority: str = Query("", pattern="^(P0|P1|P2|P3|)$"),
    package_type: str = Query(""),
    status: str = Query(""),
    q: str = Query(""),
) -> Any:
    """지금 필터에 맞는 항목 전부를 CSV 로. 청크로 흘려 보낸다.

    화면은 100건씩 보지만 내려받는 것은 조건에 맞는 전부여야 한다 — 결재에
    올릴 목록이 화면 한 페이지일 리 없다.
    """
    store = _store()
    if store.get_scan_meta(scan_id) is None:
        raise HTTPException(404, "스캔을 찾을 수 없습니다.")

    stream = csvexport.rows(
        store.iter_findings(
            scan_id, priority=priority, package_type=package_type, status=status, query=q
        )
    )
    return StreamingResponse(
        stream,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="sbomsight-{scan_id}.csv"'},
    )


@app.get("/api/scans/{scan_id}/selection")
def get_selection(scan_id: str, keys: bool = Query(False)) -> dict[str, Any]:
    """기록된 선택. **findings 는 읽지 않는다.**

    화면이 시작할 때 선택을 되살리려고 스캔 전체(48,923건 · 82MB)를 받으면
    첫 화면이 12초가 된다.

    화면은 패키지를 고르지만 보고서·이그레스는 finding 단위로 돈다. 양쪽을
    함께 돌려준다 — 저장된 것은 finding 키이고, 그것이 속한 묶음 키를 여기서
    되돌린다.
    """
    store = _store()
    if store.get_scan_meta(scan_id) is None:
        raise HTTPException(404, "스캔을 찾을 수 없습니다.")
    # 화면이 되살리는 것은 **체크된 패키지**다. finding 키 48,923개를 내려보내면
    # 그 한 번이 2.4초에 4MB 이고, 화면은 그것을 쓰지도 않는다.
    packages = store.selected_packages(scan_id)
    payload: dict[str, Any] = {
        "scan_id": scan_id,
        "packages": packages,
        "count": len(packages),
    }
    if keys:
        payload["keys"] = store.get_selection(scan_id)
    return payload


@app.put("/api/scans/{scan_id}/selection")
def put_selection(scan_id: str, body: dict[str, Any] = Body(default={})) -> dict[str, Any]:
    """담당자가 고른 범위를 기록한다.

    보고서를 만들 때마다 범위를 다시 고르게 하지 않기 위한 것이자, 나중에
    `core.cli export` 가 "이 보고서는 무엇을 대상으로 만들어졌는가"를 그대로
    옮길 수 있게 하기 위한 기록이다.

    `packages` 로 묶음 키를 주면 그 안의 finding 을 전부 편다. 화면이 고르는
    단위가 패키지이기 때문이다. 옛 방식대로 `selection` 에 finding 키를 직접
    줄 수도 있다.

    **스캔 전체를 되살리지 않는다.** 8,154개를 고른 뒤 저장하는데 48,923건을
    파이썬 객체로 만들면 그 저장 한 번이 12초다.
    """
    store = _store()
    if store.get_scan_meta(scan_id) is None:
        raise HTTPException(404, "스캔을 찾을 수 없습니다.")

    packages = body.get("packages")
    raw = body.get("selection")
    if isinstance(packages, list):
        picked = [str(x) for x in packages]
        keys = store.finding_keys_for_packages(scan_id, picked)
    elif isinstance(raw, list):
        # 존재하지 않는 키는 조용히 버린다 — 스캔이 바뀐 뒤의 옛 선택이다.
        keys = store.existing_finding_keys(scan_id, [str(x) for x in raw])
        picked = store.packages_for_finding_keys(scan_id, keys)
    else:
        raise HTTPException(400, "selection 또는 packages 는 문자열 배열이어야 합니다.")

    store.save_selection(scan_id, keys)
    return {"scan_id": scan_id, "count": len(keys), "packages": picked}


@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: str) -> dict[str, Any]:
    if _store().get_scan(scan_id) is None:
        raise HTTPException(404, "스캔을 찾을 수 없습니다.")
    _store().delete_scan(scan_id)
    return {"deleted": scan_id}


@app.get("/api/scans/{scan_id}/packages")
def list_packages(
    scan_id: str,
    sort: str = Query("priority"),
    order: str = Query("asc", pattern="^(asc|desc)$"),
    priority: str = Query("", pattern="^(P0|P1|P2|P3|)$"),
    package_type: str = Query(""),
    status: str = Query(""),
    q: str = Query(""),
    scoped: bool = Query(False),
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
) -> dict[str, Any]:
    """결과 표 한 쪽. **패키지 하나가 한 줄이다.**

    조치가 패키지당 한 번이므로 세는 단위도 그렇다 — 48,923건은 조치 대상
    8,154개다. 목표 버전은 이 쪽에 실린 묶음에 대해서만 계산한다: 버전 비교는
    SQL 이 못 하고, 8,154개를 다 비교할 이유도 없다.
    """
    store = _store()
    if store.get_scan_meta(scan_id) is None:
        raise HTTPException(404, "스캔을 찾을 수 없습니다.")
    if sort not in Store.PACKAGE_SORT_KEYS:
        sort = "priority"

    page = store.page_packages(
        scan_id, sort=sort, order=order, priority=priority, package_type=package_type,
        status=status, query=q, scoped=scoped, offset=offset, limit=limit,
    )
    engine = RuleEngine.from_config(config)
    for group in page["packages"]:
        comparator = versioning.comparator_for(group["package_type"])
        group["target_version"] = _highest_version(group.pop("fixed_versions"), comparator)
        level = engine.describe_level(Priority(group["priority"] or "P3"))
        group["priority_label"] = level.get("label", group["priority"] or "")
        group["key"] = package_key(group["package"], group["installed_version"])

    return {
        "scan_id": scan_id,
        **page,
        "totals": store.package_totals(scan_id),
        "package_types": store.package_types(scan_id),
    }


@app.get("/api/scans/{scan_id}/package-keys")
def list_package_keys(
    scan_id: str,
    priority: str = Query("", pattern="^(P0|P1|P2|P3|)$"),
    package_type: str = Query(""),
    status: str = Query(""),
    q: str = Query(""),
) -> dict[str, Any]:
    """지금 조건에 맞는 묶음 키 전부. "전체 선택" 이 쓴다. **상한은 없다.**

    담당자가 전체라고 했으면 전체여야 한다. 키는 `이름@버전` 짧은 문자열이라
    8,154개라도 수백 KB 이고, 한 번만 오간다.
    """
    store = _store()
    if store.get_scan_meta(scan_id) is None:
        raise HTTPException(404, "스캔을 찾을 수 없습니다.")
    keys = store.package_keys(
        scan_id, priority=priority, package_type=package_type, status=status, query=q
    )
    return {"scan_id": scan_id, "keys": keys, "total": len(keys)}


@app.get("/api/scans/{scan_id}/package/findings")
def get_package_findings(
    scan_id: str,
    name: str = Query(...),
    version: str = Query(""),
    limit: int = Query(500, ge=1, le=2000),
) -> dict[str, Any]:
    """묶음 하나에 속한 취약점 목록. **표에서 패키지를 눌렀을 때만 부른다.**

    패키지 이름은 **경로가 아니라 쿼리로 받는다.** 경로에 두면 이름에 `/` 가
    들어가는 패키지가 404 가 된다 — Go 모듈(`github.com/gogo/protobuf`), npm
    스코프(`@babel/core`) 가 전부 그렇다. uvicorn 이 `%2F` 를 실제 슬래시로
    되돌려 놓기 때문에 `{package}` 세그먼트가 그것을 넘지 못한다.

    보고서 절이 아니라 표의 줄들이라 payload 를 그대로 낸다 — 서술을 조립하지
    않으므로 밀리초다. 상세는 그중 하나를 다시 눌렀을 때 따로 가져온다.
    """
    store = _store()
    if store.get_scan_meta(scan_id) is None:
        raise HTTPException(404, "스캔을 찾을 수 없습니다.")
    findings = store.package_findings(scan_id, name, version)
    if not findings:
        raise HTTPException(404, f"'{name}' 패키지를 찾을 수 없습니다.")
    return {
        "scan_id": scan_id,
        "package": name,
        "installed_version": version,
        "total": len(findings),
        "findings": findings[:limit],
    }


@app.get("/api/scans/{scan_id}/package")
def get_package_detail(
    scan_id: str,
    name: str = Query(...),
    version: str = Query(""),
    ai: bool = Query(False),
) -> dict[str, Any]:
    """묶음 하나의 상세. **펼쳤을 때만 부른다.**

    이름은 쿼리로 받는다 — 경로에 두면 `/` 가 든 패키지가 404 가 된다.

    보고서 전체를 만들면 48,923건에 20초가 걸리고 JSON 은 수십 MB 다.
    펼친 묶음 하나만 조립하면 밀리초다.
    """
    store = _store()
    meta = store.get_scan_meta(scan_id)
    if meta is None:
        raise HTTPException(404, "스캔을 찾을 수 없습니다.")

    payloads = store.package_findings(scan_id, name, version)
    if not payloads:
        raise HTTPException(404, f"'{name}' 패키지를 찾을 수 없습니다.")

    findings = tuple(revive_finding(p) for p in payloads)
    narratives, chains = {}, {}
    if ai:
        stored = store.get_narratives(scan_id)
        narratives = {cve: narrative_from_dict(v) for cve, v in stored.items()}
        chains = store.get_chains(scan_id)

    result = ScanResult(
        metadata=revive_metadata(meta.get("metadata") or {}),
        findings=findings,
        policy=meta.get("policy") or {},
    )
    report = ReportBuilder(config, engine=RuleEngine.from_config(config)).build(
        result, narratives=narratives, chains=chains
    )
    return to_jsonable(report.packages[0]) if report.packages else {}


@app.get("/api/scans/{scan_id}/report")
def get_report(
    scan_id: str,
    format: str = Query("json", pattern="^(json|markdown|html)$"),
    select: list[str] = Query(default=[]),
    saved: bool = Query(False),
    ai: bool = Query(True),
    package: str = Query(""),
    version: str = Query(""),
    cve: str = Query(""),
) -> Any:
    """보고서를 생성해 돌려준다.

    범위를 정하는 방법이 넷이다.

    - `package`(+`version`) — 묶음 하나. 조치 단위 하나가 문서 하나다.
    - `package` + `cve` — 그 묶음의 한 건. 근거 팝업이 내려받는 것.
    - `saved=true` — 서버에 기록해 둔 선택. **화면은 이것을 쓴다.**
    - `select` — finding 키를 직접. 스크립트용이다.

    `select` 를 화면에서 쓰지 않는 이유가 있다. 5,000건을 고르면 URL 이
    250KB 가 되고, uvicorn 의 HTTP 파서가 요청 줄 길이 상한에 걸려
    ``Invalid HTTP request received`` 로 끊는다. 선택은 이미 서버에
    기록되어 있으므로 그것을 가리키기만 하면 된다.

    AI 서술은 이 엔드포인트가 만들지 않는다. 이미 생성해 둔 것이 있으면
    얹을 뿐이며, 없으면 전 항목이 룰 문장으로 채워진다 — AI 없이도 보고서가
    완결된다는 전제는 여기서도 그대로다.

    `ai=false` 는 **생성해 둔 서술까지 빼고** 뽑는다. 결재 문서를 AI 없이
    내야 하는 경우가 있고, 그때는 AI 관련 문구가 한 줄도 없어야 한다.
    """
    store = _store()

    if package:
        # 패키지 하나만. 48,923건짜리 문서를 만들어 그중 한 절만 읽을 이유가 없다.
        meta = store.get_scan_meta(scan_id)
        if meta is None:
            raise HTTPException(404, "스캔을 찾을 수 없습니다.")
        payloads = store.package_findings(scan_id, package, version)
        if cve:
            payloads = [p for p in payloads if (p.get("intel") or {}).get("cve") == cve]
        if not payloads:
            raise HTTPException(404, "패키지를 찾을 수 없습니다.")
        scoped = ScanResult(
            metadata=revive_metadata(meta.get("metadata") or {}),
            findings=tuple(revive_finding(p) for p in payloads),
            policy=meta.get("policy") or {},
        )
        picked = selection_mod.apply(scoped.findings, None)
    else:
        keys = store.get_selection(scan_id) if saved else [str(k) for k in select]
        result, picked = _scoped(scan_id, keys)
        scoped = dataclasses.replace(result, findings=picked.findings)

    narratives: dict[str, Any] = {}
    chains: dict[str, str] = {}
    if ai:
        stored = store.get_narratives(scan_id)
        narratives = {cve: narrative_from_dict(payload) for cve, payload in stored.items()}
        chains = store.get_chains(scan_id)

    report = ReportBuilder(config, engine=RuleEngine.from_config(config)).build(
        scoped, narratives=narratives, chains=chains
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
    saved: bool = Query(False),
    limit: int = Query(0, ge=0, le=500),
) -> dict[str, Any]:
    """AI에게 전송될 내용 전체를 그대로 돌려준다.

    "공개 데이터만 보냅니다"라는 주장은 검증할 수 있어야 의미가 있다.
    실제 전송에 쓰이는 것과 **같은 조립기·같은 가드**를 통과시킨 결과와,
    프롬프트 원문을 함께 낸다. 사람이 눈으로 확인한 뒤 보낼 수 있게 하기
    위한 것이며, 이 호출 자체는 외부로 아무것도 보내지 않는다.

    `select`로 고른 항목만 조립한다. 미리보기와 실제 전송이 같은 범위여야
    하므로 AI 호출부도 같은 선택 키를 받아 같은 방식으로 조립한다.

    `saved=true` 는 서버에 기록해 둔 선택을 쓴다. 화면은 이것을 쓴다 — 고른
    키를 전부 주소창에 실으면 URL 이 수백 KB 가 되어 HTTP 파서가 요청을 끊는다.

    **한 번에 조립하는 양은 실제 전송 상한과 같다.** 미리보기가 48,923건을
    조립하면 그 한 번이 9초인데, 정작 전송은 그만큼 되지 않는다 — 보여 주는
    범위와 나가는 범위가 다르면 이 화면의 존재 이유가 없어진다.
    """
    store = _store()
    if store.get_scan_meta(scan_id) is None:
        raise HTTPException(404, "스캔을 찾을 수 없습니다.")

    keys = store.get_selection(scan_id) if saved else [str(k) for k in select]
    cap = config.ai_max_findings
    scan_total = store.scan_summary(scan_id)["total"]
    selected_total = len(keys) if keys else scan_total

    # 스캔 전체를 파이썬 객체로 되살리지 않는다. 상한만큼만 payload 를 읽는다.
    if keys:
        payloads = store.findings_by_keys(scan_id, keys[:cap])
        if not payloads:
            # 고른 것이 이 스캔에 하나도 없다. 조용히 전체로 넓히면 화면이
            # 보여 준 범위와 나가는 범위가 달라진다.
            raise HTTPException(400, "선택한 항목이 이 스캔에 없습니다.")
        selected_total = len(store.existing_finding_keys(scan_id, keys))
    else:
        payloads = store.page_findings(scan_id, limit=cap)["findings"]
    findings = tuple(revive_finding(p) for p in payloads)

    guard = EgressGuard.from_config(config)
    facts = build_batch(findings)
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
        "finding_count": selected_total,
        "scan_finding_count": scan_total,
        # 상한에 걸렸으면 그렇다고 말한다. 조용히 자르면 "확인한 것"과 "나가는
        # 것"이 달라진다.
        "capped": selected_total > cap,
        "cap": cap,
        "selection": {
            "count": selected_total,
            "requested": bool(keys),
            "scope": "selection" if keys else "all",
        },
        "fact_count": len(facts),
        "deduplicated": len(findings) - len(facts),
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
    """**패키지 하나**에 대해 AI 서술과 연계 분석을 생성해 저장한다.

    한 번에 하나만 받는다. 서술은 CVE 한 건마다 모델을 한 번 부르는데,
    범위를 넓게 잡으면 분당 토큰(TPM) 한도를 첫 요청에서 넘겨 버려 그 뒤가
    전부 실패한다 — 실제로 그래서 생성해도 달라지는 것이 없었다. 조치 단위가
    패키지이므로 생성 단위도 패키지로 맞춘다: 담당자가 필요한 것부터 하나씩
    누르면 호출 속도도 사람 손에 맞춰진다.

    키는 서버 환경변수(`GEMINI_API_KEY`)에서 읽으며 브라우저로 내려가지
    않는다. 전송되는 내용은 egress/preview 가 보여 준 것과 동일하고, 같은
    가드를 통과해야만 호출이 일어난다.
    """
    store = _store()
    if store.get_scan_meta(scan_id) is None:
        raise HTTPException(404, "스캔을 찾을 수 없습니다.")

    name = str(body.get("package", "")).strip()
    if not name:
        raise HTTPException(400, "어느 패키지의 해설을 만들지 지정해 주세요.")
    version = str(body.get("version", ""))

    payloads = store.package_findings(scan_id, name, version)
    if not payloads:
        raise HTTPException(404, f"'{name}' 패키지를 찾을 수 없습니다.")
    findings = tuple(revive_finding(p) for p in payloads)

    if len(findings) > config.ai_max_findings:
        raise HTTPException(
            400,
            f"이 패키지에는 취약점이 {len(findings):,}건 있습니다. "
            f"한 번에 {config.ai_max_findings:,}건까지 만듭니다.",
        )

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
        run = run_narratives(findings, config=config, scan_id=scan_id)
    except EgressBlocked as blocked:
        # 가드가 막았다면 전송은 일어나지 않았다. 무엇이 걸렸는지 그대로 알린다.
        raise HTTPException(
            422,
            {
                "message": "이그레스 정책 위반으로 전송이 차단되었습니다.",
                "violations": [v.to_dict() for v in blocked.violations],
            },
        ) from blocked

    store.save_narratives(
        scan_id,
        {cve: narrative_to_dict(n) for cve, n in run.narratives.items()},
        model=run.model,
    )

    # 연계 분석도 같은 묶음에 대해 한 번. 낮은 등급 여러 건이 서로의 전제를
    # 충족시키는지는 그 묶음 안에서만 볼 수 있는 판단이다.
    chains: dict[str, str] = {}
    if len(findings) > 1:
        result = ScanResult(
            metadata=revive_metadata((store.get_scan_meta(scan_id) or {}).get("metadata") or {}),
            findings=findings,
            policy={},
        )
        report = ReportBuilder(config, engine=RuleEngine.from_config(config)).build(result)
        try:
            chain_run = run_chain_analysis(report.packages, config=config, scan_id=scan_id)
            chains = dict(chain_run.analyses)
            if chains:
                store.save_chains(scan_id, chains, model=chain_run.model)
        except EgressBlocked:
            # 서술은 이미 저장했다. 연계 분석만 빠진다.
            chains = {}

    return {
        "scan_id": scan_id,
        "package": name,
        "installed_version": version,
        "requested": len(findings),
        **run.to_dict(),
        "chained": len(chains),
        "stored": store.narrative_meta(scan_id),
    }


# ---------------------------------------------------------------------------
# 연계 상승 — 저위험 조합이 고위험으로 올라서는 경로
# ---------------------------------------------------------------------------
#
# 이 도구에서 AI 가 실제로 값을 더하는 자리다. CVE 하나를 풀어 설명하는 것은
# 룰 문장으로도 되지만, "이 두 개가 이어지면 각각일 때와 다른 결과에 도달한다"는
# 판단은 벡터를 읽고 관계를 세워야 나온다.
#
# 후보 선정은 **우리가** 한다(core/escalation.py). CVSS 벡터에서 발판(PR:N)과
# 상승(PR:L/H + 높은 영향)을 갈라 상한만큼 고르고, AI 는 그 사이의 연쇄 논리를
# 서술한다. 48,923건을 보내는 것이 아니라 40건을 보낸다.


def _escalation_payloads(scan_id: str) -> tuple[list[dict[str, Any]], int, bool]:
    """분석 대상 payload. 고른 범위가 있으면 그 안에서, 없으면 스캔 전체에서.

    상한을 넘으면 우선순위 순으로 앞에서부터 읽는다 — 후보 선정이 다시 한 번
    거르므로, 여기서는 "볼 만한 것을 충분히 본다" 정도면 된다.
    """
    store = _store()
    keys = store.get_selection(scan_id)
    cap = config.escalation_scan_limit
    if keys:
        payloads = store.findings_by_keys(scan_id, keys[:cap])
        return payloads, len(keys), True
    total = store.scan_summary(scan_id)["total"]
    return store.page_findings(scan_id, limit=cap)["findings"], total, False


@app.get("/api/scans/{scan_id}/escalation")
def get_escalation(scan_id: str) -> dict[str, Any]:
    """저장된 연계 상승 분석. 없으면 후보만 세어 돌려준다.

    **이 호출은 외부로 아무것도 보내지 않는다.** 후보 선정은 CVSS 벡터를 읽는
    우리 코드이고, 화면은 생성 전에 "무엇을 보낼 것인가"를 먼저 보여 준다.
    """
    store = _store()
    if store.get_scan_meta(scan_id) is None:
        raise HTTPException(404, "스캔을 찾을 수 없습니다.")

    saved = store.get_escalation(scan_id)
    payloads, scoped_total, scoped = _escalation_payloads(scan_id)
    picked = escalation.pick(payloads, limit=config.escalation_limit)
    scope = escalation.summarize(picked)

    return {
        "scan_id": scan_id,
        "generated": saved is not None,
        "result": saved,
        "candidates": scope,
        "scanned": len(payloads),
        "scoped": scoped,
        "scope_total": scoped_total,
        "ai_ready": config.ai_ready(),
        "model": config.gemini_model if config.ai_ready() else "",
    }


@app.get("/api/scans/{scan_id}/escalation/preview")
def preview_escalation(scan_id: str) -> dict[str, Any]:
    """연계 상승 요청에서 실제로 나갈 내용 전체. 여기서도 아무것도 보내지 않는다."""
    store = _store()
    if store.get_scan_meta(scan_id) is None:
        raise HTTPException(404, "스캔을 찾을 수 없습니다.")

    payloads, _, _ = _escalation_payloads(scan_id)
    picked = escalation.pick(payloads, limit=config.escalation_limit)
    by_cve = {(p.get("intel") or {}).get("cve"): p for p in payloads}

    def facts_for(role: str) -> list[dict[str, Any]]:
        return [build_vuln_fact_from_payload(by_cve[c.cve])
                for c in picked[role] if c.cve in by_cve]

    footholds, escalations = facts_for(escalation.FOOTHOLD), facts_for(escalation.ESCALATION)
    guard = EgressGuard.from_config(config)
    checked = guard.check([*footholds, *escalations])

    return {
        "scan_id": scan_id,
        "ok": checked.ok,
        "violations": [v.to_dict() for v in checked.violations],
        "candidates": escalation.summarize(picked),
        "facts": {"footholds": footholds, "escalations": escalations},
        "prompt": build_escalation_full_text(footholds, escalations),
        "note": (
            "이 내용이 AI에게 전달되는 전부입니다. 자산명·호스트명·IP·파일 경로·"
            "설치 버전·취약 여부 판정·대응 우선순위는 포함되지 않습니다."
        ),
    }


@app.post("/api/scans/{scan_id}/escalation")
def make_escalation(scan_id: str) -> dict[str, Any]:
    """연계 상승 분석을 생성해 저장한다. **스캔당 한 번**이다.

    묻는 것이 "이 취약점들 사이의 관계"라 한 번에 한 묶음으로 물어야 답이
    나온다 — 쪼개 보내면 모델이 서로를 볼 수 없다. 대신 보내는 양을 후보
    선정으로 40건 남짓까지 줄여, 분당 토큰 한도 안에서 한 번에 끝낸다.
    """
    store = _store()
    if store.get_scan_meta(scan_id) is None:
        raise HTTPException(404, "스캔을 찾을 수 없습니다.")

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

    payloads, _, _ = _escalation_payloads(scan_id)
    try:
        run = run_escalation_analysis(
            payloads, limit=config.escalation_limit, config=config, scan_id=scan_id
        )
    except EgressBlocked as blocked:
        raise HTTPException(
            422,
            {
                "message": "이그레스 정책 위반으로 전송이 차단되었습니다.",
                "violations": [v.to_dict() for v in blocked.violations],
            },
        ) from blocked

    payload = run.to_dict()
    payload["created_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    store.save_escalation(scan_id, payload)
    return {"scan_id": scan_id, **payload}


@app.delete("/api/scans/{scan_id}/escalation")
def drop_escalation(scan_id: str) -> dict[str, Any]:
    _store().clear_escalation(scan_id)
    return {"scan_id": scan_id, "cleared": True}


@app.post("/api/scans/{scan_id}/chains")
def make_chains(scan_id: str, body: dict[str, Any] = Body(default={})) -> dict[str, Any]:
    """패키지 묶음별 연계 분석을 생성해 저장한다.

    낮은 등급 여러 건이 서로의 전제를 충족시키면 파급력이 커진다 — 그 판단에
    필요한 재료(CVSS 벡터·CWE)는 전부 공개 데이터이므로 이그레스 원칙은
    그대로다. 같은 가드를 통과한 VulnFact 만 나가고, 묶음은 `group-1` 같은
    번호로 부른다.
    """
    raw = body.get("selection") or []
    if not isinstance(raw, list):
        raise HTTPException(400, "selection은 문자열 배열이어야 합니다.")

    _, picked = _scoped(scan_id, [str(x) for x in raw])

    if not config.ai_enabled:
        raise HTTPException(409, "AI 사용이 꺼져 있습니다. SBOMSIGHT_AI_ENABLED=1 로 켜 주세요.")
    if not config.gemini_api_key:
        raise HTTPException(409, "GEMINI_API_KEY가 설정되어 있지 않습니다.")

    scoped = dataclasses.replace(_load_scan_result(scan_id, config), findings=picked.findings)
    report = ReportBuilder(config, engine=RuleEngine.from_config(config)).build(scoped)

    try:
        run = run_chain_analysis(report.packages, config=config, scan_id=scan_id)
    except EgressBlocked as blocked:
        raise HTTPException(
            422,
            {
                "message": "이그레스 정책 위반으로 전송이 차단되었습니다.",
                "violations": [v.to_dict() for v in blocked.violations],
            },
        ) from blocked

    _store().save_chains(scan_id, run.analyses, model=run.model)
    return {"scan_id": scan_id, **run.to_dict()}


@app.get("/api/scans/{scan_id}/chains/preview")
def chains_preview(scan_id: str, select: list[str] = Query(default=[])) -> dict[str, Any]:
    """연계 분석에서 전송될 내용 전체. 보내기 전에 사람이 눈으로 확인한다."""
    _, picked = _scoped(scan_id, select)
    scoped = dataclasses.replace(_load_scan_result(scan_id, config), findings=picked.findings)
    report = ReportBuilder(config, engine=RuleEngine.from_config(config)).build(scoped)

    groups, index = build_chain_groups(report.packages)
    guard = EgressGuard.from_config(config)
    facts = [fact for group in groups for fact in group["vulnerabilities"]]
    checked = guard.check(facts)

    return {
        "scan_id": scan_id,
        "group_count": len(groups),
        "fact_count": len(facts),
        # 묶음 번호 → 패키지명. **이 표는 전송되지 않는다.**
        "local_index": index,
        "ok": checked.ok,
        "violations": [v.to_dict() for v in checked.violations],
        "prompt": build_chain_full_text(groups),
        "note": (
            "이 내용이 AI에게 전달되는 전부입니다. 묶음은 group-1 같은 번호로만 "
            "불리며, 자산명·호스트명·IP·파일 경로·설치 버전·판정 결과는 포함되지 않습니다."
        ),
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
