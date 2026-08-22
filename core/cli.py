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

    raw_out = Path(args.raw_out) if getattr(args, "raw_out", None) else None
    with artifacts.open_plain(sbom_path) as plain_path:
        raw = grype_runner.scan_sbom(plain_path, config=config, raw_out=raw_out)
    if raw_out is not None:
        print(f"Grype 원본 보관: {raw_out} ({raw_out.stat().st_size:,} bytes)", file=sys.stderr)
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
                epss=intel.get("epss"),
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


def _cmd_verify(args: argparse.Namespace) -> int:
    """Grype 원본과 우리 결과를 대조한다.

    이 도구는 Grype 를 신뢰하기로 선택했다. Grype 가 틀리면 그것은 Grype 의
    오류이고 감수한다. 우리 코드 때문에 결과가 달라지는 것은 감수 대상이 아니므로,
    그 경계를 명령 하나로 확인할 수 있게 한다.
    """
    from .verify import load_grype_json, verify

    config = get_config()
    raw = load_grype_json(Path(args.grype_json))
    result = _load_scan_result(args.source, config)

    report = verify(raw, result)
    print(report.summary(), file=sys.stderr)
    if report.mismatches:
        print("", file=sys.stderr)
        for mismatch in report.mismatches[: args.limit]:
            print(f"  {mismatch}", file=sys.stderr)
        if len(report.mismatches) > args.limit:
            print(f"  … 외 {len(report.mismatches) - args.limit}건", file=sys.stderr)
    return 0 if report.ok else 1


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


def _cmd_asset(args: argparse.Namespace) -> int:
    """자산(서버) 관리와 이력 비교.

    이 도구의 관리 단위는 스캔이 아니라 서버 한 대다. CLI 로도 다룰 수 있어야
    폐쇄망에서 배치 스크립트로 매달 돌릴 수 있다.
    """
    from .assets import AssetError, Assets, diff_findings

    config = get_config()
    assets = Assets(config.db_path)
    store = Store(config.db_path)

    if args.action == "list":
        summary = store.asset_summary()
        rows = assets.list(include_archived=args.all)
        if not rows:
            print("자산이 없습니다. `python -m core.cli asset add <이름>` 으로 등록하세요.")
            return 0
        for asset in rows:
            info = summary.get(asset.asset_id, {})
            last = info.get("last_scan_at") or "스캔 없음"
            mark = " [보관]" if asset.archived else ""
            print(
                f"{asset.name:<24} {asset.group_name or '-':<14} {asset.os or '-':<16} "
                f"스캔 {info.get('scan_count', 0):>3}건  최근 {last}{mark}"
            )
        unassigned = summary.get("", {}).get("scan_count", 0)
        if unassigned:
            print(f"\n미분류 스캔 {unassigned}건 — `asset assign <스캔ID> <자산이름>` 으로 배정하세요.")
        return 0

    try:
        if args.action == "add":
            asset = assets.create(
                args.name, group_name=args.group or "", os=args.os or "", note=args.note or ""
            )
            print(f"등록: {asset.name} ({asset.asset_id})")
            return 0

        if args.action == "remove":
            asset = assets.by_name(args.name)
            if asset is None:
                print(f"오류: '{args.name}' 자산이 없습니다.", file=sys.stderr)
                return 1
            assets.delete(asset.asset_id)
            print(f"삭제: {asset.name} (스캔은 미분류로 남았습니다)")
            return 0

        if args.action == "assign":
            asset = assets.by_name(args.name)
            if asset is None:
                print(f"오류: '{args.name}' 자산이 없습니다.", file=sys.stderr)
                return 1
            if not store.assign_scan(args.scan_id, asset.asset_id):
                print(f"오류: 스캔 '{args.scan_id}' 을 찾을 수 없습니다.", file=sys.stderr)
                return 1
            print(f"배정: {args.scan_id} → {asset.name}")
            return 0

    except AssetError as exc:
        print(f"오류: {exc}", file=sys.stderr)
        return 1

    # history — 같은 자산의 최근 두 스캔을 대조한다.
    asset = assets.by_name(args.name)
    if asset is None:
        print(f"오류: '{args.name}' 자산이 없습니다.", file=sys.stderr)
        return 1

    scans = store.list_scans(limit=500, asset_id=asset.asset_id)
    if len(scans) < 2:
        print(f"'{asset.name}' 에 스캔이 {len(scans)}건뿐입니다. 비교하려면 2건 이상 필요합니다.")
        return 0

    head_id, base_id = scans[0]["scan_id"], scans[1]["scan_id"]
    base, head = store.get_scan(base_id), store.get_scan(head_id)
    assert base is not None and head is not None

    diff = diff_findings(
        base["findings"], head["findings"],
        base_scan_id=base_id, head_scan_id=head_id,
        base_created_at=base["created_at"], head_created_at=head["created_at"],
    )
    print(f"{asset.name}  {base['created_at']} → {head['created_at']}")
    print(f"  신규 {len(diff.added)}건 · 해소 {len(diff.resolved)}건 · 유지 {len(diff.remaining)}건\n")
    for label, changes in (("신규", diff.added), ("해소", diff.resolved)):
        for change in changes[: args.limit]:
            print(f"  [{label}] {change.cve:<18} {change.package_name} {change.installed_version}")
        if len(changes) > args.limit:
            print(f"  … {label} 외 {len(changes) - args.limit}건")
    return 0


def _cmd_user(args: argparse.Namespace) -> int:
    """계정 관리 — 최초 관리자를 만드는 부트스트랩용.

    평상시 계정 관리는 웹의 `설정 → 계정` 에서 한다. 여기 있는 이유는 두 가지다.
    관리자가 하나도 없는 상태에서 첫 계정을 만들 때, 그리고 비밀번호를 잊어
    웹으로 들어갈 수 없게 됐을 때.
    """
    import getpass

    from .accounts import ADMIN, AccountError, Accounts, VIEWER

    accounts = Accounts(get_config().db_path)

    if args.action == "list":
        users = accounts.list_users()
        if not users:
            print("계정이 없습니다. `python -m core.cli user add <이름> --role admin` 으로 만드세요.")
            return 0
        for user in users:
            last = user.last_login_at or "로그인 기록 없음"
            print(f"{user.username:<20} {user.role:<7} 생성 {user.created_at}  최근 {last}")
        return 0

    if args.action == "remove":
        try:
            accounts.delete(args.username)
        except AccountError as exc:
            print(f"오류: {exc}", file=sys.stderr)
            return 1
        print(f"삭제: {args.username}")
        return 0

    # add · passwd — 비밀번호는 인자로 받지 않는다. 셸 히스토리와 프로세스
    # 목록에 그대로 남기 때문이다.
    password = getpass.getpass("비밀번호: ")
    if password != getpass.getpass("비밀번호 확인: "):
        print("오류: 두 번 입력한 비밀번호가 다릅니다.", file=sys.stderr)
        return 1

    try:
        if args.action == "add":
            user = accounts.create(args.username, password, ADMIN if args.role == ADMIN else VIEWER)
            print(f"생성: {user.username} ({user.role})")
        else:
            accounts.set_password(args.username, password)
            print(f"비밀번호 변경: {args.username} (기존 세션은 모두 끊겼습니다)")
    except AccountError as exc:
        print(f"오류: {exc}", file=sys.stderr)
        return 1
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
    p_scan.add_argument(
        "--raw-out",
        help="Grype 원본 JSON을 남길 경로. 나중에 `verify`로 우리 결과와 대조할 수 있다",
    )
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

    p_verify = sub.add_parser(
        "verify",
        help="Grype 원본과 우리 결과를 대조 — 우리 코드가 결과를 바꾸지 않았는지 확인",
    )
    p_verify.add_argument("grype_json", help="grype -o json 산출물 (.gz 도 가능)")
    p_verify.add_argument("source", help="findings.json 경로 또는 저장된 스캔 ID")
    p_verify.add_argument("--limit", type=int, default=20, help="출력할 불일치 최대 건수")
    p_verify.set_defaults(func=_cmd_verify)

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

    p_asset = sub.add_parser("asset", help="자산(서버) 등록·배정·이력 비교")
    asset_sub = p_asset.add_subparsers(dest="action", required=True)

    a_add = asset_sub.add_parser("add", help="자산 등록")
    a_add.add_argument("name", help="서버 이름 (예: web-01)")
    a_add.add_argument("--group", help="그룹 (예: DMZ, 내부업무)")
    a_add.add_argument("--os", help="운영체제 (예: Rocky 9.3)")
    a_add.add_argument("--note")

    a_list = asset_sub.add_parser("list", help="자산 목록과 마지막 스캔")
    a_list.add_argument("--all", action="store_true", help="보관 처리한 자산도 표시")

    a_assign = asset_sub.add_parser("assign", help="스캔을 자산에 배정")
    a_assign.add_argument("scan_id")
    a_assign.add_argument("name", help="자산 이름")

    a_remove = asset_sub.add_parser("remove", help="자산 삭제 (스캔은 미분류로 남는다)")
    a_remove.add_argument("name")

    a_history = asset_sub.add_parser("history", help="최근 두 스캔 대조 — 신규·해소·유지")
    a_history.add_argument("name")
    a_history.add_argument("--limit", type=int, default=20, help="갈래별 출력 최대 건수")

    p_asset.set_defaults(func=_cmd_asset)

    p_user = sub.add_parser(
        "user",
        help="계정 관리 (최초 관리자 생성·비밀번호 복구용. 평소에는 웹 설정 → 계정에서)",
    )
    user_sub = p_user.add_subparsers(dest="action", required=True)

    u_add = user_sub.add_parser("add", help="계정 생성")
    u_add.add_argument("username")
    u_add.add_argument("--role", choices=("admin", "viewer"), default="viewer")

    u_passwd = user_sub.add_parser("passwd", help="비밀번호 변경 (기존 세션은 모두 끊긴다)")
    u_passwd.add_argument("username")

    u_remove = user_sub.add_parser("remove", help="계정 삭제")
    u_remove.add_argument("username")

    user_sub.add_parser("list", help="계정 목록")
    p_user.set_defaults(func=_cmd_user)

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
