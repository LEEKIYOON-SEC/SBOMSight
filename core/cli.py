"""SBOMSight CLI.

웹 서버 없이도 전체 파이프라인이 돌아야 한다. 폐쇄망에서 반출한 SBOM을
받아 CLI만으로 스캔하고 리포트까지 뽑을 수 있는 것이 이 도구의 기본 형태다.

    python -m core.cli scan   sbom.cdx.json -o findings.json
    python -m core.cli sbom   rockylinux:9.3 -o sbom.cdx.json
    python -m core.cli report findings.json --no-ai -o report.md
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import artifacts, grype_runner, sbom as sbom_mod, syft_runner
from .enrich import Enricher
from .ruleengine import RuleEngine, sort_key
from .config import get_config
from .models import Finding, Priority, ScanResult, to_jsonable
from .normalize import normalize_grype_report
from .render import to_html, to_markdown
from .report import ReportBuilder
from .store import Store


def _new_scan_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{uuid.uuid4().hex[:8]}"


def _cmd_sbom(args: argparse.Namespace) -> int:
    config = get_config()
    out = Path(args.output) if args.output else None
    doc = syft_runner.generate_sbom(args.source, out, output_format=args.format, config=config)
    fmt, packages = sbom_mod.parse(doc)
    print(f"SBOM 생성 완료: {fmt}, 컴포넌트 {len(packages)}개", file=sys.stderr)
    if out:
        print(f"저장: {out}", file=sys.stderr)
    else:
        json.dump(doc, sys.stdout, indent=2)
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    config = get_config()
    config.ensure_dirs()

    sbom_path = Path(args.sbom)
    # 파일을 통째로 올리지 않는다. 형식·개수·해시만 훑는다 (core/sbom.py 참고).
    info = sbom_mod.inspect(sbom_path)
    if info.format == "unknown":
        print(
            f"경고: '{sbom_path.name}'의 SBOM 형식을 알아보지 못했습니다. "
            f"Grype에는 그대로 넘깁니다.",
            file=sys.stderr,
        )

    if args.offline:
        config.offline = True

    with artifacts.open_plain(sbom_path) as plain_path:
        raw = grype_runner.scan_sbom(plain_path, config=config)
    result = normalize_grype_report(
        raw,
        scan_id=args.scan_id or _new_scan_id(),
        sbom_filename=sbom_path.name,
        sbom_format=info.format,
        sbom_sha256=info.sha256,
        component_count=info.component_count or 0,
    )

    return _finish(result, args, config, component_count=info.component_count or 0)


def _finish(result: ScanResult, args, config, *, component_count: int) -> int:
    """정규화된 결과에 보강 → 판정 → 저장 → 출력을 적용한다.

    scan(SBOM에서 시작)과 analyze(Grype 출력에서 시작)가 공유한다.
    """
    store = Store(config.db_path)

    # --- 위협정보 보강 ------------------------------------------------------
    enrichment: dict = {}
    findings = result.findings
    if not args.no_enrich:
        findings, report = Enricher(config, store).enrich(findings, nvd_budget=args.nvd_budget)
        enrichment = report.to_dict()
        for name, status in report.sources.items():
            mark = "ok" if status.usable else "--"
            print(
                f"  [{mark}] {name:<11} {status.state:<8} "
                f"수록 {status.entries:>7}건 / 해당 {status.matched:>4}건 "
                f"{('스냅샷 ' + status.snapshot_date) if status.snapshot_date else ''}"
                f"{('  ' + status.detail) if status.detail else ''}",
                file=sys.stderr,
            )

    # --- 대응 검토 우선순위 판정 --------------------------------------------
    engine = RuleEngine.from_config(config)
    findings = engine.apply(findings, stale_days=config.snapshot_stale_days)

    result = ScanResult(
        metadata=result.metadata,
        findings=tuple(sorted(findings, key=sort_key)),
        unindexed_packages=result.unindexed_packages,
        enrichment=enrichment,
        policy={
            "version": engine.policy.version,
            "sha256": engine.policy.sha256,
            "sources": list(engine.policy.sources),
            "label": engine.policy.label,
        },
    )

    if not args.no_store:
        store.save_scan(result)

    payload = to_jsonable(result)
    if args.output:
        Path(args.output).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"저장: {args.output}", file=sys.stderr)
    else:
        json.dump(payload, sys.stdout, indent=2, ensure_ascii=False)

    _print_summary(result, engine, component_count)
    return 0


def _cmd_analyze(args: argparse.Namespace) -> int:
    """이미 확보한 Grype JSON 리포트를 분석한다.

    CI에서 grype를 돌리고 산출물만 넘겨받는 경우, 또는 grype를 설치할 수
    없는 환경에서 쓴다.
    """
    config = get_config()
    config.ensure_dirs()
    if args.offline:
        config.offline = True

    raw = json.loads(Path(args.grype_json).read_text(encoding="utf-8"))
    result = normalize_grype_report(
        raw,
        scan_id=args.scan_id or _new_scan_id(),
        sbom_filename=Path(args.grype_json).name,
        sbom_format="grype-json",
    )
    return _finish(result, args, config, component_count=result.metadata.component_count)


def _print_summary(result, engine, component_count: int) -> None:
    """사람이 읽는 요약. 판단 불가 건수를 반드시 함께 보여 준다 —
    '취약 0건'과 '판단 불가 30건'은 전혀 다른 상황이다."""
    from collections import Counter

    counts = Counter(f.verdict.priority.value for f in result.findings if f.verdict)
    vulnerable = sum(1 for f in result.findings if f.fix and f.fix.is_vulnerable.is_true())
    unknown = sum(1 for f in result.findings if f.fix and f.fix.is_vulnerable.value == "unknown")
    no_fix = sum(1 for f in result.findings if f.verdict and "no_fix_available" in f.verdict.flags)

    print(f"\n스캔 {result.metadata.scan_id}", file=sys.stderr)
    print(f"  컴포넌트 {component_count}개 → 탐지 {len(result.findings)}건", file=sys.stderr)
    levels = "  ".join(
        f"{p.value} {counts.get(p.value, 0)}건({engine.describe_level(p).get('label', '')})"
        for p in (Priority.P0, Priority.P1, Priority.P2, Priority.P3)
    )
    print(f"  대응 검토 우선순위: {levels}", file=sys.stderr)
    print(
        f"  취약 확인 {vulnerable}건 · 판단 불가 {unknown}건 · 수정 버전 없음 {no_fix}건",
        file=sys.stderr,
    )
    print(f"  적용 정책: {result.policy.get('label', '')}", file=sys.stderr)


def _load_scan_result(source: str, config=None) -> ScanResult:
    """findings.json(스캔 산출물) 또는 저장된 scan_id에서 ScanResult를 복원한다."""
    from .models import (
        AdvisoryPackage, Detection, ExploitMaturity, ExploitSource, FiredRule,
        FixAnalysis, FixState, InstalledPackage, Priority, RuleVerdict,
        ScanMetadata, Severity, Ternary, VersionGap, VulnIntel,
    )

    path = Path(source)
    if path.is_file():
        payload = json.loads(path.read_text(encoding="utf-8"))
    else:
        stored = Store((config or get_config()).db_path).get_scan(source)
        if stored is None:
            raise FileNotFoundError(f"파일도 스캔 ID도 아닙니다: {source}")
        payload = {
            "metadata": stored["metadata"],
            "findings": stored["findings"],
            "enrichment": stored.get("enrichment") or {},
            "policy": stored.get("policy") or {},
        }

    def revive(f: dict) -> Finding:
        inst, adv, intel = f["installed"], f["advisory"], f["intel"]
        det = f.get("detection") or {}
        fix = f.get("fix")
        verdict = f.get("verdict")
        return Finding(
            installed=InstalledPackage(
                name=inst["name"], version=inst["version"], type=inst.get("type", ""),
                purl=inst.get("purl", ""), cpes=tuple(inst.get("cpes", ())),
                locations=tuple(inst.get("locations", ())), language=inst.get("language", ""),
                sbom_ref=inst.get("sbom_ref", ""),
            ),
            advisory=AdvisoryPackage(
                advisory_package=adv["advisory_package"],
                advisory_ecosystem=adv.get("advisory_ecosystem", ""),
                affected_version_range=adv.get("affected_version_range", ""),
                fixed_version=adv.get("fixed_version", ""),
                fix_state=FixState(adv.get("fix_state", "unknown")),
                os_family=adv.get("os_family", ""),
            ),
            intel=VulnIntel(
                cve=intel["cve"], aliases=tuple(intel.get("aliases", ())),
                severity=Severity(intel.get("severity", "unknown")),
                cvss_score=intel.get("cvss_score"), cvss_vector=intel.get("cvss_vector", ""),
                cvss_version=intel.get("cvss_version", ""), cwe=tuple(intel.get("cwe", ())),
                description=intel.get("description", ""), published=intel.get("published", ""),
                references=tuple(intel.get("references", ())),
                epss=intel.get("epss"), epss_percentile=intel.get("epss_percentile"),
                epss_snapshot_date=intel.get("epss_snapshot_date", ""),
                kev=Ternary(intel.get("kev", "unknown")),
                kev_date_added=intel.get("kev_date_added", ""),
                kev_ransomware_use=intel.get("kev_ransomware_use", ""),
                kev_snapshot_date=intel.get("kev_snapshot_date", ""),
                exploit_available=Ternary(intel.get("exploit_available", "unknown")),
                exploit_maturity=ExploitMaturity(intel.get("exploit_maturity", "unknown")),
                exploit_sources=tuple(
                    ExploitSource(source=s["source"], ref=s.get("ref", ""), note=s.get("note", ""))
                    for s in intel.get("exploit_sources", ())
                ),
            ),
            detection=Detection(
                matcher=det.get("matcher", ""), match_type=det.get("match_type", ""),
                namespace=det.get("namespace", ""), search_criteria=det.get("search_criteria", {}),
            ),
            fix=FixAnalysis(
                installed_version=fix["installed_version"], fixed_version=fix.get("fixed_version", ""),
                comparator=fix.get("comparator", "generic"),
                is_vulnerable=Ternary(fix.get("is_vulnerable", "unknown")),
                update_available=Ternary(fix.get("update_available", "unknown")),
                fix_state=FixState(fix.get("fix_state", "unknown")),
                version_gap=VersionGap(fix.get("version_gap", "unknown")),
                reason=fix.get("reason", ""),
            ) if fix else None,
            verdict=RuleVerdict(
                priority=Priority(verdict["priority"]),
                fired_rules=tuple(
                    FiredRule(name=r["name"], explain=r.get("explain", ""))
                    for r in verdict.get("fired_rules", ())
                ),
                flags=tuple(verdict.get("flags", ())),
                policy_version=verdict.get("policy_version", ""),
                policy_sha256=verdict.get("policy_sha256", ""),
            ) if verdict else None,
        )

    meta = payload["metadata"]
    return ScanResult(
        metadata=ScanMetadata(**{k: v for k, v in meta.items() if k in ScanMetadata.__dataclass_fields__}),
        findings=tuple(revive(f) for f in payload.get("findings", ())),
        enrichment=payload.get("enrichment") or {},
        policy=payload.get("policy") or {},
    )


def _cmd_report(args: argparse.Namespace) -> int:
    """스캔 결과를 대응 검토 보고서로 옮긴다.

    --no-ai(기본값)로도 보고서는 완결된다. AI는 ②④의 서술을 더 읽기 좋게
    바꿀 뿐이며, 없으면 룰 기반 문장이 그 자리를 채운다.
    """
    config = get_config()
    result = _load_scan_result(args.source)

    narratives = None
    if args.ai:
        if not config.ai_ready():
            print(
                "경고: --ai를 지정했으나 SBOMSIGHT_AI_ENABLED/GEMINI_API_KEY가 없어 "
                "룰 기반 서술로 진행합니다.",
                file=sys.stderr,
            )
        else:
            from .ai_narrative import generate_narratives   # M5에서 추가된다
            narratives = generate_narratives(result.findings, config=config)

    report = ReportBuilder(config).build(result, narratives=narratives)
    text = to_html(report) if args.format == "html" else to_markdown(report)

    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"저장: {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)

    summary = report.summary
    print(
        f"\n보고서 생성 완료 — {summary['total']}건 "
        f"(P0 {summary['by_priority']['P0']} · P1 {summary['by_priority']['P1']} · "
        f"P2 {summary['by_priority']['P2']} · P3 {summary['by_priority']['P3']}), "
        f"서술: {'AI' if report.ai_used else '룰 기반'}",
        file=sys.stderr,
    )
    return 0


def _cmd_export(args: argparse.Namespace) -> int:
    from .export import export_all, warn_about_contents

    config = get_config()
    index = export_all(
        Path(args.out),
        config=config,
        scan_ids=args.scan or None,
        limit=args.limit,
        redact=not args.no_redact,
    )
    warn_about_contents(index, Path(args.out))
    return 0


def _cmd_scans(args: argparse.Namespace) -> int:
    store = Store(get_config().db_path)
    for row in store.list_scans(limit=args.limit):
        meta = row["metadata"]
        print(f"{row['scan_id']}  {row['created_at']}  탐지 {row['finding_count']:>4}건  {meta.get('sbom_filename','')}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sbomsight", description="SBOM 기반 취약점 대응 검토")
    sub = parser.add_subparsers(dest="command", required=True)

    p_sbom = sub.add_parser("sbom", help="Syft로 SBOM 생성")
    p_sbom.add_argument("source", help="이미지·디렉터리 등 (예: rockylinux:9.3, dir:/opt/app)")
    p_sbom.add_argument("-o", "--output")
    p_sbom.add_argument("--format", default="cyclonedx-json")
    p_sbom.set_defaults(func=_cmd_sbom)

    p_scan = sub.add_parser("scan", help="SBOM을 Grype로 스캔하고 정규화")
    p_scan.add_argument("sbom", help="SBOM JSON 파일 경로")
    p_scan.add_argument("-o", "--output")
    p_scan.add_argument("--scan-id")
    p_scan.add_argument("--no-store", action="store_true", help="SQLite에 저장하지 않음")
    p_scan.add_argument("--no-enrich", action="store_true", help="위협정보 보강 건너뜀 (EPSS/KEV/Exploit 미확인 상태로 남음)")
    p_scan.add_argument("--offline", action="store_true", help="네트워크를 쓰지 않고 캐시된 스냅샷만 사용")
    p_scan.add_argument("--nvd-budget", type=int, default=40, help="NVD에서 CWE를 조회할 최대 CVE 건수")
    p_scan.set_defaults(func=_cmd_scan)

    p_analyze = sub.add_parser("analyze", help="이미 확보한 Grype JSON 리포트를 분석")
    p_analyze.add_argument("grype_json", help="grype -o json 산출물")
    p_analyze.add_argument("-o", "--output")
    p_analyze.add_argument("--scan-id")
    p_analyze.add_argument("--no-store", action="store_true")
    p_analyze.add_argument("--no-enrich", action="store_true")
    p_analyze.add_argument("--offline", action="store_true")
    p_analyze.add_argument("--nvd-budget", type=int, default=40)
    p_analyze.set_defaults(func=_cmd_analyze)

    p_report = sub.add_parser("report", help="스캔 결과를 대응 검토 보고서로 생성")
    p_report.add_argument("source", help="findings.json 경로 또는 저장된 스캔 ID")
    p_report.add_argument("-o", "--output")
    p_report.add_argument("--format", choices=("markdown", "html"), default="markdown")
    p_report.add_argument(
        "--ai", action="store_true",
        help="AI 서술 사용 (기본은 미사용). 공개 취약점 데이터만 전달되며 "
             "자산 정보·설치 버전·판정 결과는 전달되지 않는다",
    )
    p_report.add_argument("--no-ai", dest="ai", action="store_false", help="AI 미사용 (기본값)")
    p_report.set_defaults(func=_cmd_report, ai=False)

    p_export = sub.add_parser(
        "export",
        help="스캔 결과를 GitHub Pages 전시용 정적 파일로 내보냄 (내부 정보 포함 — 확인 후 커밋)",
    )
    p_export.add_argument("--out", default="results", help="내보낼 디렉터리 (기본: results)")
    p_export.add_argument("--scan", action="append", help="내보낼 스캔 ID (여러 번 지정 가능)")
    p_export.add_argument("--limit", type=int, default=5, help="--scan 미지정 시 최근 N건")
    p_export.add_argument(
        "--no-redact", action="store_true",
        help="파일 경로·SBOM 파일명·스캔 대상 문자열까지 그대로 내보냄 (권장하지 않음)",
    )
    p_export.set_defaults(func=_cmd_export)

    p_scans = sub.add_parser("scans", help="저장된 스캔 목록")
    p_scans.add_argument("--limit", type=int, default=20)
    p_scans.set_defaults(func=_cmd_scans)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (syft_runner.ToolNotFoundError, syft_runner.ToolExecutionError, FileNotFoundError) as exc:
        print(f"오류: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
