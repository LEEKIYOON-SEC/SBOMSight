#!/usr/bin/env python3
"""GitHub Pages 데모용 취약점 인덱스 빌더.

**진짜 Syft + 진짜 Grype**로 만든다. 이 스크립트가 데모의 신뢰성을 떠받친다 —
브라우저 매칭 엔진이 쓰는 인덱스가 손으로 지어낸 것이 아니라 실제 도구의
산출물에서 파생되었다는 사실이 파리티 테스트와 함께 데모를 '시늉'이 아니게
만든다.

흐름:
    1. 지정한 이미지들에 syft 실행 → SBOM (CycloneDX JSON)
    2. 각 SBOM에 grype 실행 → 취약점 매치
    3. core/enrich.py 로 EPSS · KEV · Exploit-DB · Metasploit 결합
    4. 패키지명 기준 샤딩 JSON으로 출력

인덱스는 '아는 패키지(covered)'와 '취약점이 있는 패키지(vulns)'를 구분해
담는다. 그래야 브라우저가 "인덱스 미수록"을 정직하게 표기할 수 있다.

    python3 scripts/build_demo_index.py --out demo-data
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import grype_runner, sbom as sbom_mod, syft_runner  # noqa: E402
from core.config import get_config  # noqa: E402
from core.enrich import Enricher  # noqa: E402
from core.models import to_jsonable  # noqa: E402
from core.normalize import normalize_grype_report  # noqa: E402
from core.store import Store  # noqa: E402

# 취약점이 확실히 나오도록 구버전 태그를 고정한다. 최신 태그를 쓰면 어느 날
# 데모에 표시할 항목이 0건이 되어 버린다.
DEFAULT_SOURCES = [
    ("rockylinux-9.3", "rockylinux:9.3"),
    ("node-18-bullseye", "node:18-bullseye"),
    ("python-3.10-slim", "python:3.10-slim"),
]


def shard_key(ecosystem: str, name: str) -> str:
    """web/js/core/matcher.js 의 shardKey() 와 **같은 규칙**이어야 한다."""
    eco = (ecosystem or "unknown").lower()
    first = (name or "").strip().lower()[:1] or "_"
    bucket = first if first.isalnum() and first.isascii() else "_"
    return f"{eco}-{bucket}"


def entry_from_finding(finding) -> dict[str, Any]:
    """Finding에서 인덱스 항목을 만든다.

    설치 버전은 담지 않는다 — 인덱스는 '어떤 버전이 취약한가'를 아는 것이고,
    '무엇이 설치되어 있는가'는 방문자가 올린 SBOM이 정한다.
    """
    intel = finding.intel
    advisory = finding.advisory
    return {
        "cve": intel.cve,
        "aliases": list(intel.aliases),
        "severity": intel.severity.value,
        "cvss_score": intel.cvss_score,
        "cvss_vector": intel.cvss_vector,
        "cvss_version": intel.cvss_version,
        "cwe": list(intel.cwe),
        "description": intel.description,
        "published": intel.published,
        "references": list(intel.references)[:8],
        "epss": intel.epss,
        "epss_percentile": intel.epss_percentile,
        "epss_snapshot_date": intel.epss_snapshot_date,
        "kev": intel.kev.value,
        "kev_date_added": intel.kev_date_added,
        "kev_ransomware_use": intel.kev_ransomware_use,
        "kev_snapshot_date": intel.kev_snapshot_date,
        "exploit_available": intel.exploit_available.value,
        "exploit_maturity": intel.exploit_maturity.value,
        "exploit_sources": [to_jsonable(s) for s in intel.exploit_sources],
        "advisory_package": advisory.advisory_package,
        "advisory_ecosystem": advisory.advisory_ecosystem,
        "constraint": advisory.affected_version_range,
        "fixed_version": advisory.fixed_version,
        "fix_state": advisory.fix_state.value,
        "os_family": advisory.os_family,
        "namespace": finding.detection.namespace,
        "matcher": finding.detection.matcher,
    }


def build(sources: list[tuple[str, str]], out_dir: Path, *, nvd_budget: int) -> dict[str, Any]:
    config = get_config()
    config.ensure_dirs()
    store = Store(config.db_path)
    enricher = Enricher(config, store)

    sbom_dir = out_dir / "sboms"
    index_dir = out_dir / "vuln-index"
    sbom_dir.mkdir(parents=True, exist_ok=True)
    index_dir.mkdir(parents=True, exist_ok=True)

    shards: dict[str, dict[str, Any]] = {}
    source_meta: list[dict[str, Any]] = []
    enrichment_meta: dict[str, Any] = {}
    grype_version = grype_runner.version(config)
    grype_db = grype_runner.db_status(config)

    for name, image in sources:
        print(f"[syft ] {image}", file=sys.stderr)
        sbom_path = sbom_dir / f"{name}.cdx.json"
        syft_runner.generate_sbom(image, sbom_path, config=config)
        _, fmt, packages, _ = sbom_mod.load(sbom_path)
        print(f"        컴포넌트 {len(packages)}개", file=sys.stderr)

        print(f"[grype] {image}", file=sys.stderr)
        raw = grype_runner.scan_sbom(sbom_path, config=config)
        result = normalize_grype_report(raw, scan_id=f"demo-{name}", sbom_filename=sbom_path.name,
                                        sbom_format=fmt, component_count=len(packages))
        print(f"        탐지 {len(result.findings)}건", file=sys.stderr)

        findings, report = enricher.enrich(result.findings, nvd_budget=nvd_budget)
        enrichment_meta = report.to_dict()

        # 이 SBOM에 있던 모든 패키지를 '아는 패키지'로 기록한다.
        for pkg in packages:
            key = shard_key(pkg.type, pkg.name)
            shard = shards.setdefault(key, {"covered": set(), "vulns": {}})
            shard["covered"].add(pkg.name)

        for finding in findings:
            key = shard_key(finding.installed.type, finding.installed.name)
            shard = shards.setdefault(key, {"covered": set(), "vulns": {}})
            shard["covered"].add(finding.installed.name)
            entries = shard["vulns"].setdefault(finding.installed.name, [])
            # 같은 CVE·제약 조합은 한 번만 담는다.
            signature = (finding.intel.cve, finding.advisory.affected_version_range)
            if any((e["cve"], e["constraint"]) == signature for e in entries):
                continue
            entries.append(entry_from_finding(finding))

        source_meta.append({
            "name": name, "image": image, "sbom": f"sboms/{name}.cdx.json",
            "components": len(packages), "findings": len(findings),
        })

    # --- 샤드 기록 -----------------------------------------------------------
    for key, shard in shards.items():
        payload = {"covered": sorted(shard["covered"]), "vulns": shard["vulns"]}
        (index_dir / f"{key}.json").write_text(
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")), encoding="utf-8"
        )

    intel_snapshot = {
        name: status.get("snapshot_date", "")
        for name, status in enrichment_meta.items()
        if status.get("snapshot_date")
    }
    manifest = {
        "version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "syft_version": syft_runner.version(config),
        "grype_version": grype_version,
        "grype_db_built": str((grype_db or {}).get("built") or ""),
        "shards": sorted(shards),
        "package_count": sum(len(s["covered"]) for s in shards.values()),
        "vuln_count": sum(len(v) for s in shards.values() for v in s["vulns"].values()),
        "vulnerable_package_count": sum(len(s["vulns"]) for s in shards.values()),
        "sources": source_meta,
        "intel_snapshot": intel_snapshot,
        "enrichment": enrichment_meta,
        "notice": (
            "이 인덱스는 진짜 Syft와 Grype로 생성되었습니다. 브라우저 매칭 엔진은 "
            "여기 담긴 영향 버전범위를 생태계 규칙으로 평가합니다."
        ),
    }
    (index_dir / "index.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    total_bytes = sum(p.stat().st_size for p in index_dir.glob("*.json"))
    print(
        f"\n인덱스 생성 완료: 샤드 {len(shards)}개 · 패키지 {manifest['package_count']}개 · "
        f"취약점 {manifest['vuln_count']}건 · {total_bytes / 1024:.0f}KB",
        file=sys.stderr,
    )
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="데모용 취약점 인덱스 생성")
    parser.add_argument("--out", default="demo-data", help="출력 디렉터리")
    parser.add_argument("--source", action="append", metavar="NAME=IMAGE",
                        help="대상 (반복 가능). 예: rocky=rockylinux:9.3")
    parser.add_argument("--nvd-budget", type=int, default=60, help="NVD에서 CWE를 조회할 최대 CVE 수")
    args = parser.parse_args(argv)

    sources = DEFAULT_SOURCES
    if args.source:
        sources = []
        for item in args.source:
            name, _, image = item.partition("=")
            if not image:
                parser.error(f"--source 형식은 NAME=IMAGE 입니다: {item}")
            sources.append((name, image))

    for binary in ("syft", "grype"):
        if not shutil.which(binary):
            print(f"오류: {binary}를 찾을 수 없습니다. scripts/install-tools.sh 로 설치하세요.",
                  file=sys.stderr)
            return 2

    build(sources, Path(args.out), nvd_budget=args.nvd_budget)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
