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

from . import grype_runner, sbom as sbom_mod, syft_runner
from .config import get_config
from .models import to_jsonable
from .normalize import normalize_grype_report
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
    _, fmt, packages, digest = sbom_mod.load(sbom_path)
    if fmt == "unknown":
        print(
            f"경고: '{sbom_path.name}'의 SBOM 형식을 알아보지 못했습니다. "
            f"Grype에는 그대로 넘깁니다.",
            file=sys.stderr,
        )

    raw = grype_runner.scan_sbom(sbom_path, config=config)
    result = normalize_grype_report(
        raw,
        scan_id=args.scan_id or _new_scan_id(),
        sbom_filename=sbom_path.name,
        sbom_format=fmt,
        sbom_sha256=digest,
        component_count=len(packages),
    )

    if not args.no_store:
        Store(config.db_path).save_scan(result)

    payload = to_jsonable(result)
    if args.output:
        Path(args.output).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"저장: {args.output}", file=sys.stderr)
    else:
        json.dump(payload, sys.stdout, indent=2, ensure_ascii=False)

    vulnerable = sum(1 for f in result.findings if f.fix and f.fix.is_vulnerable.is_true())
    unknown = sum(1 for f in result.findings if f.fix and f.fix.is_vulnerable.value == "unknown")
    print(
        f"\n스캔 {result.metadata.scan_id}: 컴포넌트 {len(packages)}개 → "
        f"탐지 {len(result.findings)}건 (취약 확인 {vulnerable}, 판단 불가 {unknown})",
        file=sys.stderr,
    )
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
    p_scan.set_defaults(func=_cmd_scan)

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
