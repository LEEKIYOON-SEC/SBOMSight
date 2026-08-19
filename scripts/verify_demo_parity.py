#!/usr/bin/env python3
"""브라우저 매칭 엔진이 진짜 Grype와 같은 판정을 내는지 검증한다.

파리티 테스트(tests/js/parity.test.mjs)는 JS 구현과 Python 구현을 대조한다.
이 스크립트는 그보다 한 단계 위를 본다 — **브라우저 엔진의 결과가 진짜
Grype의 결과와 같은가.**

    진짜 Grype (SBOM 스캔)        ─┐
                                   ├─→ 같은 finding 집합인가?
    브라우저 엔진 (인덱스 매칭)   ─┘

여기서 어긋나면 데모는 실제 동작을 보여 주는 것이 아니라 흉내에 불과하다.
그래서 CI는 불일치가 있으면 배포하지 않는다.

    python3 scripts/verify_demo_parity.py --demo-data demo-data
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import grype_runner, sbom as sbom_mod  # noqa: E402
from core.config import get_config  # noqa: E402
from core.normalize import normalize_grype_report  # noqa: E402

# 브라우저 엔진을 Node에서 그대로 돌린다. 데모에서 실행되는 것과 같은 코드다.
RUNNER = r"""
import { readFileSync } from 'node:fs';
import { parseSbom } from './web/js/core/sbom.js';
import { VulnIndex, matchPackages, shardKey } from './web/js/core/matcher.js';

const [sbomPath, indexDir] = process.argv.slice(2);
const manifest = JSON.parse(readFileSync(`${indexDir}/index.json`, 'utf8'));

// 브라우저는 fetch로 샤드를 받는다. Node에서는 파일에서 읽어 같은 자료구조를 만든다.
const index = new VulnIndex(manifest, { base: indexDir });
index.loadShards = async (keys) => {
  for (const key of new Set(keys)) {
    if (!index.availableShards.has(key) || index._shards.has(key)) continue;
    const data = JSON.parse(readFileSync(`${indexDir}/${key}.json`, 'utf8'));
    index._shards.set(key, { covered: new Set(data.covered || []), vulns: data.vulns || {} });
  }
};

const [, packages] = parseSbom(JSON.parse(readFileSync(sbomPath, 'utf8')));
const { findings, unindexed } = await matchPackages(packages, index);
process.stdout.write(JSON.stringify({
  matches: findings.map((f) => [f.intel.cve, f.installed.name, f.installed.version]),
  unindexed: unindexed.length,
  packages: packages.length,
}));
"""


def run_browser_engine(sbom_path: Path, index_dir: Path) -> dict:
    with tempfile.NamedTemporaryFile("w", suffix=".mjs", delete=False, dir=".") as handle:
        handle.write(RUNNER)
        runner_path = Path(handle.name)
    try:
        proc = subprocess.run(
            ["node", str(runner_path), str(sbom_path), str(index_dir)],
            capture_output=True, text=True, check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"브라우저 엔진 실행 실패:\n{proc.stderr}")
        return json.loads(proc.stdout)
    finally:
        runner_path.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="브라우저 엔진 ↔ 진짜 Grype 파리티 검증")
    parser.add_argument("--demo-data", default="demo-data")
    parser.add_argument("--allow-missing", type=int, default=0,
                        help="허용할 누락 건수 (기본 0). 인덱스 축약 등 알려진 사유가 있을 때만 사용")
    args = parser.parse_args(argv)

    demo = Path(args.demo_data)
    index_dir = demo / "vuln-index"
    manifest = json.loads((index_dir / "index.json").read_text(encoding="utf-8"))
    config = get_config()

    total_failures = 0
    for source in manifest.get("sources", []):
        sbom_path = demo / source["sbom"]
        print(f"\n=== {source['name']} ===", file=sys.stderr)

        # 1) 진짜 Grype
        raw = grype_runner.scan_sbom(sbom_path, config=config)
        _, _, packages, _ = sbom_mod.load(sbom_path)
        result = normalize_grype_report(raw, scan_id="parity")
        grype_set = {
            (f.intel.cve, f.installed.name, f.installed.version) for f in result.findings
        }

        # 2) 브라우저 엔진
        engine = run_browser_engine(sbom_path, index_dir)
        engine_set = {tuple(m) for m in engine["matches"]}

        missing = grype_set - engine_set      # Grype는 찾았는데 엔진이 놓친 것
        extra = engine_set - grype_set        # 엔진만 찾은 것

        print(f"  컴포넌트 {len(packages)}개 · Grype {len(grype_set)}건 · "
              f"엔진 {len(engine_set)}건 · 인덱스 미수록 {engine['unindexed']}개", file=sys.stderr)

        if missing:
            print(f"  ❌ 엔진이 놓침 {len(missing)}건:", file=sys.stderr)
            for item in sorted(missing)[:10]:
                print(f"       {item[0]}  {item[1]}@{item[2]}", file=sys.stderr)
        if extra:
            print(f"  ❌ 엔진만 탐지 {len(extra)}건:", file=sys.stderr)
            for item in sorted(extra)[:10]:
                print(f"       {item[0]}  {item[1]}@{item[2]}", file=sys.stderr)

        failures = len(missing) + len(extra)
        if failures == 0:
            print("  ✅ 완전 일치", file=sys.stderr)
        total_failures += failures

    if total_failures > args.allow_missing:
        print(f"\n파리티 검증 실패: 불일치 {total_failures}건", file=sys.stderr)
        print("데모가 실제 Grype와 다른 판정을 내고 있습니다. 배포하지 마십시오.", file=sys.stderr)
        return 1

    print("\n✅ 브라우저 엔진이 진짜 Grype와 같은 판정을 냅니다.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
