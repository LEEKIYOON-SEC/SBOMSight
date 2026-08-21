"""실제 스캔 결과를 정적 전시물로 내보낸다.

GitHub Pages에는 서버가 없다. Grype는 Go 바이너리와 취약점 DB를 요구하고,
AI 호출에 쓰는 키는 정적 페이지에 담을 수 없다. 그래서 Pages는 **전시장**이고,
판정은 담당자 PC에서 일어난다. 이 모듈은 그 PC에서 실제로 일어난 일을
그대로 옮겨 담는다 — 탐지 결과, 담당자가 고른 항목, AI에 전송된 내용,
그리고 그 결과로 나온 보고서.

    python -m core.cli export --out results
    python -m core.cli export --out results --scan 20260821T...-ab12cd34

⚠ 내보낸 파일에는 **내부 자산 정보가 들어 있다.** 설치 패키지명과 설치 버전은
전시의 요점이라 남기지만, 파일 경로·SBOM 파일명·스캔 대상 문자열은 기본으로
지운다(`--no-redact` 로 끌 수 있다). 공개 리포에 커밋하기 전에 무엇이 담겼는지
직접 확인하라 — 이 모듈은 그 확인을 대신해 주지 않는다.
"""

from __future__ import annotations

import dataclasses
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import selection as selection_mod
from .ai_narrative import narrative_from_dict
from .audit import AuditLog
from .config import Config, get_config
from .models import ScanResult, to_jsonable
from .prompt import build_full_text
from .render import to_html, to_markdown
from .report import ReportBuilder
from .ruleengine import RuleEngine
from .sanitizer import EgressGuard
from .store import Store
from .vulnfact import build_batch

# 기본으로 지우는 필드. 어느 것도 판정에 쓰이지 않으며, 전시에도 필요 없다.
REDACTED = "(비공개 처리됨)"


def _redact_scan(payload: dict[str, Any]) -> dict[str, Any]:
    """전시용으로 내부 식별 정보를 지운다.

    지우는 것: 파일 경로(locations), SBOM 파일명·해시, 스캔 대상 문자열,
    Grype 탐지의 search_criteria(설치 패키지명·버전이 그대로 들어 있다).

    남기는 것: 설치 패키지명과 설치 버전. 이것을 지우면 "설치 버전 대 Fixed
    Version 비교"라는 전시의 요점이 사라진다.
    """
    meta = dict(payload.get("metadata") or {})
    for field in ("sbom_filename", "sbom_sha256", "source"):
        if meta.get(field):
            meta[field] = REDACTED
    payload["metadata"] = meta

    findings = []
    for raw in payload.get("findings") or []:
        finding = json.loads(json.dumps(raw))          # 원본을 건드리지 않는다
        installed = finding.get("installed") or {}
        installed["locations"] = []
        installed["sbom_ref"] = ""
        finding["installed"] = installed
        detection = finding.get("detection") or {}
        detection["search_criteria"] = {}
        finding["detection"] = detection
        findings.append(finding)
    payload["findings"] = findings
    return payload


def _egress_record(
    result: ScanResult,
    picked: selection_mod.Selection,
    config: Config,
    *,
    ai_used: bool,
    model: str,
) -> dict[str, Any]:
    """AI에 전송된(또는 전송 대상이었던) 내용을 기록으로 만든다.

    여기서 새로 조립하는 것이 아니라, 실제 전송에 쓰이는 것과 **같은 조립기·
    같은 가드**를 같은 선택 범위로 한 번 더 통과시킨 결과다. 전시된 내용과
    실제로 나간 내용이 다를 수 없어야 한다.
    """
    guard = EgressGuard.from_config(config)
    facts = build_batch(picked.findings)
    checked = guard.check(facts)
    return {
        "scan_id": result.metadata.scan_id,
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
        "would_send": ai_used,
        "model": model,
        "note": (
            "이 내용이 AI에게 전달되는 전부입니다. 자산명·호스트명·IP·파일 경로·"
            "설치 버전·취약 여부 판정·대응 우선순위는 포함되지 않습니다."
        ),
    }


def export_scan(
    scan_id: str,
    out_dir: Path,
    *,
    config: Config,
    redact: bool = True,
    label: str = "",
) -> dict[str, Any]:
    """스캔 하나를 `out_dir/<scan_id>/` 로 내보내고 인덱스 항목을 돌려준다."""
    from .cli import _load_scan_result       # 순환 임포트 회피

    store = Store(config.db_path)
    if store.get_scan(scan_id) is None:
        raise FileNotFoundError(f"저장된 스캔이 아닙니다: {scan_id}")

    result = _load_scan_result(scan_id, config)
    keys = store.get_selection(scan_id)
    picked = selection_mod.apply(result.findings, keys)
    scoped = dataclasses.replace(result, findings=picked.findings)

    stored = store.get_narratives(scan_id)
    narratives = {cve: narrative_from_dict(payload) for cve, payload in stored.items()}
    narrative_meta = store.narrative_meta(scan_id)

    report = ReportBuilder(config, engine=RuleEngine.from_config(config)).build(
        scoped, narratives=narratives
    )

    scan_payload = to_jsonable(result)
    # 프론트엔드는 /api/scans/{id} 와 같은 모양을 기대한다.
    scan_payload = {
        "scan_id": result.metadata.scan_id,
        "created_at": result.metadata.created_at,
        "metadata": scan_payload["metadata"],
        "enrichment": scan_payload.get("enrichment") or {},
        "policy": scan_payload.get("policy") or {},
        "findings": scan_payload.get("findings") or [],
        "selection": {"keys": list(keys)},
        "narratives": narrative_meta,
    }
    if redact:
        scan_payload = _redact_scan(scan_payload)

    target = out_dir / scan_id
    target.mkdir(parents=True, exist_ok=True)

    report_payload = to_jsonable(report)
    report_payload["selection"] = picked.to_dict()
    if redact:
        for item in report_payload.get("findings") or []:
            local = item.get("local_analysis") or {}
            local["locations"] = []
            detection = local.get("detection") or {}
            detection["search_criteria"] = {}
            local["detection"] = detection
            item["local_analysis"] = local
        scan_meta = dict(report_payload.get("scan") or {})
        for field in ("sbom_filename", "sbom_sha256", "source"):
            if scan_meta.get(field):
                scan_meta[field] = REDACTED
        report_payload["scan"] = scan_meta

    _write_json(target / "scan.json", scan_payload)
    _write_json(target / "report.json", report_payload)
    (target / "report.md").write_text(to_markdown(report), encoding="utf-8")
    (target / "report.html").write_text(to_html(report), encoding="utf-8")
    _write_json(
        target / "egress.json",
        _egress_record(
            result, picked, config,
            ai_used=bool(narrative_meta["count"]),
            model=narrative_meta["model"],
        ),
    )

    return {
        "scan_id": scan_id,
        "created_at": result.metadata.created_at,
        "label": label or f"{result.metadata.grype_version or 'grype'} · {len(result.findings)}건",
        "finding_count": len(result.findings),
        "selected_count": len(picked.findings) if picked.requested else 0,
        "ai_used": report.ai_used,
        "metadata": scan_payload["metadata"],
    }


def export_all(
    out_dir: Path,
    *,
    config: Config | None = None,
    scan_ids: list[str] | None = None,
    limit: int = 5,
    redact: bool = True,
    clean: bool = True,
) -> dict[str, Any]:
    """스캔들을 정적 전시물로 내보내고 index.json 을 쓴다."""
    config = config or get_config()
    store = Store(config.db_path)

    if not scan_ids:
        scan_ids = [row["scan_id"] for row in store.list_scans(limit=limit)]
    if not scan_ids:
        raise FileNotFoundError(
            "내보낼 스캔이 없습니다. 먼저 스캔을 수행하세요: python -m core.cli scan sbom.json"
        )

    # 지난번에 내보낸 스캔이 남아 있으면 전시 목록과 파일이 어긋난다.
    if clean and out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    entries = [
        export_scan(scan_id, out_dir, config=config, redact=redact)
        for scan_id in scan_ids
    ]

    audit = AuditLog(config.audit_dir).tail(limit=200)
    index = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "redacted": redact,
        "tools": {
            "grype": entries[0]["metadata"].get("grype_version", "") if entries else "",
            "grype_db": entries[0]["metadata"].get("grype_db_built", "") if entries else "",
        },
        "egress_attempts": len([r for r in audit if r.get("action") == "send"]),
        "scans": entries,
    }
    _write_json(out_dir / "index.json", index)
    return index


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def warn_about_contents(index: dict[str, Any], out_dir: Path, stream=sys.stderr) -> None:
    """무엇을 내보냈는지 사람이 읽게 알린다.

    이 경고를 지우지 말 것. 여기서 만들어진 파일은 공개 리포에 커밋될 것을
    전제로 하며, 그 판단은 사람이 해야 한다.
    """
    scans = index.get("scans", [])
    print(f"\n내보내기 완료: {out_dir} · 스캔 {len(scans)}건", file=stream)
    for entry in scans:
        print(
            f"  - {entry['scan_id']} · 탐지 {entry['finding_count']}건"
            f" · 선택 {entry['selected_count']}건"
            f" · AI {'사용' if entry['ai_used'] else '미사용'}",
            file=stream,
        )
    print(
        "\n⚠ 내보낸 파일에는 내부 자산 정보가 들어 있습니다."
        "\n  담긴 것 : 설치 패키지명, 설치 버전, 취약 여부 판정, 대응 검토 우선순위",
        file=stream,
    )
    if index.get("redacted"):
        print(
            "  지운 것 : 파일 경로, SBOM 파일명·해시, 스캔 대상 문자열, Grype search_criteria",
            file=stream,
        )
    else:
        print(
            "  ⚠ --no-redact 로 내보냈습니다. 파일 경로와 스캔 대상 문자열이 그대로 들어 있습니다.",
            file=stream,
        )
    print(
        "\n  공개 리포에 커밋하기 전에 내용을 직접 확인하세요:"
        f"\n    grep -ri '내부도메인\\|사내\\|hostname' {out_dir}",
        file=stream,
    )
