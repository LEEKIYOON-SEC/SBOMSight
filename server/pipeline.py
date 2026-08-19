"""스캔 파이프라인 실행 — 단계별 진행 상태를 보고하며 돈다.

core/cli.py의 흐름과 동일하되, 각 단계가 끝날 때마다 JobRegistry에
결과를 알려 UI가 진행을 따라올 수 있게 한다.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from core import grype_runner, sbom as sbom_mod
from core.config import Config
from core.enrich import Enricher
from core.models import ScanResult, Ternary
from core.normalize import normalize_grype_report
from core.report import ReportBuilder
from core.ruleengine import RuleEngine, sort_key
from core.store import Store

from .jobs import Job, JobRegistry


def new_scan_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{uuid.uuid4().hex[:8]}"


def run_scan(
    *,
    job: Job,
    registry: JobRegistry,
    sbom_path: Path,
    original_name: str,
    config: Config,
    enrich: bool = True,
    nvd_budget: int = 40,
) -> None:
    """업로드된 SBOM 하나를 끝까지 처리한다. 실패는 해당 단계에 기록된다."""
    store = Store(config.db_path)

    # --- 1. SBOM 업로드 / 파싱 -------------------------------------------
    registry.start(job, "upload", f"{original_name} 파싱 중")
    try:
        _, fmt, packages, digest = sbom_mod.load(sbom_path)
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as exc:
        registry.fail(job, "upload", f"SBOM 파일을 읽을 수 없습니다: {exc}")
        return
    if fmt == "unknown":
        registry.finish(
            job, "upload",
            metric=f"{len(packages)}개",
            detail="SBOM 형식을 알아보지 못했습니다. Grype에 그대로 넘깁니다.",
        )
    else:
        registry.finish(job, "upload", metric=f"컴포넌트 {len(packages)}개", detail=fmt)

    # --- 2. 취약점 탐지 ---------------------------------------------------
    registry.start(job, "detect", "Grype 실행 중")
    try:
        raw = grype_runner.scan_sbom(sbom_path, config=config)
    except (grype_runner.ToolNotFoundError, grype_runner.ToolExecutionError, FileNotFoundError) as exc:
        registry.fail(job, "detect", str(exc))
        return

    result = normalize_grype_report(
        raw,
        scan_id=new_scan_id(),
        sbom_filename=original_name,
        sbom_format=fmt,
        sbom_sha256=digest,
        component_count=len(packages),
    )
    registry.finish(
        job, "detect",
        metric=f"{len(result.findings)}건 탐지",
        detail=f"grype {result.metadata.grype_version} · DB {result.metadata.grype_db_built or '미상'}",
    )

    # --- 3. 위협정보 보강 -------------------------------------------------
    findings = result.findings
    enrichment: dict = {}
    if enrich:
        registry.start(job, "enrich", "EPSS · CISA KEV · 공개 Exploit 조회 중")
        findings, report = Enricher(config, store).enrich(findings, nvd_budget=nvd_budget)
        enrichment = report.to_dict()
        usable = [name for name, s in report.sources.items() if s.usable]
        snapshots = sorted({s.snapshot_date for s in report.sources.values() if s.snapshot_date})
        registry.finish(
            job, "enrich",
            metric=f"{len(usable)}/{len(report.sources)}개 소스",
            detail=("스냅샷 " + ", ".join(snapshots)) if snapshots else "사용 가능한 스냅샷 없음",
        )
    else:
        registry.skip(job, "enrich", "보강을 건너뛰어 EPSS·KEV·Exploit이 미확인으로 남습니다")

    # --- 4. 대응 우선순위 판정 --------------------------------------------
    registry.start(job, "prioritize", "정책 룰 적용 중")
    engine = RuleEngine.from_config(config)
    findings = tuple(sorted(engine.apply(findings, stale_days=config.snapshot_stale_days), key=sort_key))
    counts = {p: 0 for p in ("P0", "P1", "P2", "P3")}
    for finding in findings:
        if finding.verdict:
            counts[finding.verdict.priority.value] += 1
    registry.finish(
        job, "prioritize",
        metric=" · ".join(f"{k} {v}" for k, v in counts.items() if v),
        detail=engine.policy.label,
    )

    result = ScanResult(
        metadata=result.metadata,
        findings=findings,
        enrichment=enrichment,
        policy={
            "version": engine.policy.version,
            "sha256": engine.policy.sha256,
            "sources": list(engine.policy.sources),
            "label": engine.policy.label,
        },
    )
    store.save_scan(result)

    # --- 5~7. 근거 · 권고 · 보고서 ------------------------------------------
    registry.start(job, "rationale", "판정 근거 정리 중")
    builder = ReportBuilder(config, engine=engine)
    report_model = builder.build(result)
    with_rules = sum(1 for i in report_model.findings if i.response_rationale["fired_rules"])
    registry.finish(
        job, "rationale",
        metric=f"{with_rules}건에 발화 룰",
        detail="나머지는 기본 등급으로 분류되었습니다",
    )

    registry.start(job, "recommend", "패치 절차 생성 중")
    fixable = sum(1 for i in report_model.findings if i.recommendation.has_fix)
    registry.finish(
        job, "recommend",
        metric=f"패치 가능 {fixable}건",
        detail=f"수정 버전 없음 {len(report_model.findings) - fixable}건은 완화 방안 제시",
    )

    registry.start(job, "report", "보고서 조립 중")
    registry.finish(
        job, "report",
        metric=f"{len(report_model.findings)}개 항목",
        detail="AI 미사용 (룰 기반)" if not report_model.ai_used else "AI 서술 포함",
    )

    summary = dict(report_model.summary)
    summary["component_count"] = len(packages)
    summary["policy"] = result.policy
    summary["enrichment"] = enrichment
    registry.complete(job, result.metadata.scan_id, summary)
