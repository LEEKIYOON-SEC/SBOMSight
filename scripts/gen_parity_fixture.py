#!/usr/bin/env python3
"""파리티 테스트용 기대값 생성.

**실제 Python 구현을 돌려** 결과를 기록한다. 손으로 적은 기대값이라면
두 구현이 함께 틀린 것을 잡지 못한다.

    python3 scripts/gen_parity_fixture.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config import get_config  # noqa: E402
from core.fixanalysis import analyze  # noqa: E402
from core.models import (  # noqa: E402
    AdvisoryPackage, ExploitMaturity, ExploitSource, FixState, InstalledPackage,
    Severity, Ternary, VulnIntel, to_jsonable,
)
from core.normalize import normalize_grype_report  # noqa: E402
from core.policy import load as load_policy  # noqa: E402
from core.prompt import build_prompt  # noqa: E402
from core.report import ReportBuilder  # noqa: E402
from core.ruleengine import RuleEngine  # noqa: E402
from core.vulnfact import build_batch  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

# 파리티 픽스처는 결정론적이어야 한다 — 시각이 매번 바뀌면 CI가 "기대값이
# 낡았다"고 오판한다. 대조 대상은 시각이 아니라 두 구현의 판정 결과다.
FIXED_TIMESTAMP = "2026-01-01T00:00:00+00:00"


def ScanResultShim(result, timestamp):
    """metadata.created_at 만 고정한 사본을 만든다."""
    import dataclasses

    from core.models import ScanResult

    return ScanResult(
        metadata=dataclasses.replace(result.metadata, created_at=timestamp),
        findings=result.findings,
        unindexed_packages=result.unindexed_packages,
        enrichment=result.enrichment,
        policy=result.policy,
    )


def fix_analysis_cases():
    cases = [
        ("rpm, 영향 범위 안",
         InstalledPackage("xz", "5.6.0-2.el9", "rpm"),
         AdvisoryPackage("xz", "rpm", "< 5.6.2", "5.6.2", FixState.FIXED_AVAILABLE), True),
        ("rpm, 이미 패치됨",
         InstalledPackage("xz", "5.6.2-1.el9", "rpm"),
         AdvisoryPackage("xz", "rpm", "< 5.6.2", "5.6.2", FixState.FIXED_AVAILABLE), True),
        ("rpm, epoch 포함",
         InstalledPackage("openssl", "1:3.0.7-24.el9", "rpm"),
         AdvisoryPackage("openssl", "rpm", "< 1:3.0.7-27.el9_4", "1:3.0.7-27.el9_4"), True),
        ("수정 버전 없음 (wont-fix)",
         InstalledPackage("zlib", "1.2.11-40.el9", "rpm"),
         AdvisoryPackage("zlib", "rpm", "*", "", FixState.WONT_FIX), True),
        ("비교 불가한 버전 문자열",
         InstalledPackage("weird", "git-abc123", "npm"),
         AdvisoryPackage("weird", "npm", "< 2.0.0", "2.0.0"), True),
        ("semver 전이 의존성",
         InstalledPackage("cross-spawn", "7.0.3", "npm"),
         AdvisoryPackage("cross-spawn", "npm", ">=7.0.0,<7.0.5", "7.0.5"), True),
        ("pep440",
         InstalledPackage("requests", "2.31.0", "python"),
         AdvisoryPackage("requests", "python", "<2.32.0", "2.32.0"), True),
        ("범위도 수정본도 없음",
         InstalledPackage("mystery", "1.0.0", "npm"),
         AdvisoryPackage("mystery", "npm"), True),
        ("스캐너 판정과 불일치",
         InstalledPackage("pkg", "9.9.9", "rpm"),
         AdvisoryPackage("pkg", "rpm", "< 5.6.2", "5.6.2"), True),
    ]
    out = []
    for name, installed, advisory, detected in cases:
        out.append({
            "name": name,
            "installed": to_jsonable(installed),
            "advisory": to_jsonable(advisory),
            "detected_by_scanner": detected,
            "expected": to_jsonable(analyze(installed, advisory, detected_by_scanner=detected)),
        })
    return out


def rule_engine_cases(engine: RuleEngine):
    from core.models import Finding

    def finding(**kwargs):
        installed = InstalledPackage("pkg", kwargs.pop("installed_version", "1.0.0"),
                                     kwargs.pop("ecosystem", "npm"))
        advisory = AdvisoryPackage(
            "pkg", installed.type,
            kwargs.pop("affected", f"<{kwargs.get('fixed', '2.0.0')}"),
            kwargs.pop("fixed", "2.0.0"),
            kwargs.pop("fix_state", FixState.UNKNOWN),
        )
        intel = VulnIntel(cve="CVE-2024-0001", severity=Severity.UNKNOWN, **kwargs)
        return Finding(installed=installed, advisory=advisory, intel=intel,
                       fix=analyze(installed, advisory))

    cases = [
        ("KEV 단독 → P0", finding(cvss_score=4.0, kev=Ternary.TRUE,
                                  epss_snapshot_date="2099-01-01", kev_snapshot_date="2099-01-01")),
        ("EPSS 높음 + CVSS 높음 → P0", finding(cvss_score=7.5, epss=0.6, kev=Ternary.FALSE,
                                              epss_snapshot_date="2099-01-01")),
        ("무기화 exploit → P0", finding(cvss_score=8.0, kev=Ternary.FALSE,
                                       exploit_available=Ternary.TRUE,
                                       exploit_maturity=ExploitMaturity.WEAPONIZED,
                                       epss_snapshot_date="2099-01-01")),
        ("CVSS Critical 단독 → P1", finding(cvss_score=9.8, kev=Ternary.FALSE,
                                           epss_snapshot_date="2099-01-01")),
        ("공개 PoC + High → P1", finding(cvss_score=7.5, kev=Ternary.FALSE,
                                        exploit_available=Ternary.TRUE,
                                        exploit_maturity=ExploitMaturity.PUBLIC_POC,
                                        epss_snapshot_date="2099-01-01")),
        ("CVSS High 단독 → P2", finding(cvss_score=7.5, kev=Ternary.FALSE,
                                       exploit_maturity=ExploitMaturity.NONE,
                                       exploit_available=Ternary.FALSE,
                                       epss=0.01, epss_snapshot_date="2099-01-01")),
        ("아무 신호 없음 → P3", finding(cvss_score=4.0, kev=Ternary.FALSE, epss=0.001,
                                      exploit_available=Ternary.FALSE,
                                      exploit_maturity=ExploitMaturity.NONE,
                                      epss_snapshot_date="2099-01-01")),
        ("데이터 전부 미확인", finding(cvss_score=None)),
        ("수정 버전 없음", finding(cvss_score=9.8, fixed="", affected="*",
                                 fix_state=FixState.WONT_FIX, kev=Ternary.FALSE,
                                 epss_snapshot_date="2099-01-01")),
        ("버전 비교 불가", finding(cvss_score=5.0, installed_version="git-abcdef",
                                kev=Ternary.FALSE, epss_snapshot_date="2099-01-01")),
        ("오래된 스냅샷", finding(cvss_score=5.0, kev=Ternary.FALSE, epss=0.01,
                               exploit_available=Ternary.FALSE,
                               exploit_maturity=ExploitMaturity.NONE,
                               epss_snapshot_date="2020-01-01", kev_snapshot_date="2020-01-01")),
    ]
    out = []
    for name, f in cases:
        out.append({
            "name": name,
            "finding": to_jsonable(f),
            "stale_days": 7,
            "expected": to_jsonable(engine.evaluate(f, stale_days=7)),
        })
    return out


def main() -> int:
    config = get_config()
    policy = load_policy(config.rules_dir / "priority.json")
    engine = RuleEngine(policy)

    # 실제 Grype 픽스처에서 만든 findings — 보고서 대조에 쓴다.
    raw = json.loads((ROOT / "tests/fixtures/grype-sample.json").read_text(encoding="utf-8"))
    result = normalize_grype_report(raw, scan_id="parity-scan", sbom_filename="parity.cdx.json",
                                    sbom_format="cyclonedx-json", component_count=42)
    # 생성 시각을 고정한다. 그러지 않으면 이 파일이 매번 달라져 CI의
    # "기대값이 낡았는가" 검사가 언제나 실패한다. 대조하려는 것은 시각이
    # 아니라 두 구현의 판정 결과다.
    result = ScanResultShim(result, FIXED_TIMESTAMP)

    # 위협정보를 결정론적으로 주입한다 (네트워크에 의존하지 않기 위해).
    import dataclasses
    patches = {
        "CVE-2024-3094": dict(epss=0.9134, epss_percentile=0.9991, epss_snapshot_date="2099-01-01",
                              kev=Ternary.TRUE, kev_date_added="2024-03-29",
                              kev_ransomware_use="Unknown", kev_snapshot_date="2099-01-01",
                              exploit_available=Ternary.TRUE,
                              exploit_maturity=ExploitMaturity.WEAPONIZED,
                              exploit_sources=(ExploitSource("exploit_db", "EDB-52128", "검증됨"),
                                               ExploitSource("metasploit", "exploit/linux/local/xz", "XZ RCE")),
                              cwe=("CWE-506",)),
        "CVE-2024-2511": dict(epss=0.0043, epss_percentile=0.512, epss_snapshot_date="2099-01-01",
                              kev=Ternary.FALSE, kev_snapshot_date="2099-01-01",
                              exploit_available=Ternary.FALSE,
                              exploit_maturity=ExploitMaturity.NONE, cwe=("CWE-400",)),
        "CVE-2024-21538": dict(epss=0.15, epss_percentile=0.93, epss_snapshot_date="2099-01-01",
                               kev=Ternary.FALSE, kev_snapshot_date="2099-01-01",
                               exploit_available=Ternary.TRUE,
                               exploit_maturity=ExploitMaturity.PUBLIC_POC,
                               exploit_sources=(ExploitSource("exploit_db", "EDB-52129"),),
                               cwe=("CWE-1333",)),
        "CVE-2023-45853": dict(epss=0.006, epss_percentile=0.41, epss_snapshot_date="2099-01-01",
                               kev=Ternary.FALSE, kev_snapshot_date="2099-01-01",
                               exploit_available=Ternary.FALSE,
                               exploit_maturity=ExploitMaturity.NONE, cwe=("CWE-190",)),
        "CVE-2024-35195": dict(epss=0.0009, epss_percentile=0.213, epss_snapshot_date="2099-01-01",
                               kev=Ternary.FALSE, kev_snapshot_date="2099-01-01",
                               exploit_available=Ternary.FALSE,
                               exploit_maturity=ExploitMaturity.NONE, cwe=("CWE-295",)),
    }
    from core.models import Finding
    enriched = tuple(
        Finding(installed=f.installed, advisory=f.advisory,
                intel=dataclasses.replace(f.intel, **patches.get(f.intel.cve, {})),
                detection=f.detection, fix=f.fix)
        for f in result.findings
    )
    judged = engine.apply(enriched, stale_days=7)

    from core.models import ScanResult
    scan_result = ScanResult(metadata=result.metadata, findings=judged,
                             policy={"version": policy.version, "sha256": policy.sha256,
                                     "sources": list(policy.sources), "label": policy.label})
    report = ReportBuilder(config, engine=engine).build(scan_result)
    report.generated_at = FIXED_TIMESTAMP

    facts = build_batch(judged)
    playbooks = {
        name: json.loads((config.rules_dir / "playbooks" / f"{name}.json").read_text(encoding="utf-8"))
        for name in ("rpm", "deb", "npm", "pip", "maven", "generic")
    }

    payload = {
        "notice": [
            "scripts/gen_parity_fixture.py 가 실제 Python 구현을 돌려 생성한 기대값이다.",
            "손으로 고치지 말 것 — 구현을 바꿨으면 스크립트를 다시 돌린다.",
        ],
        "policy_version": policy.version,
        "policy_sha256": policy.sha256,
        "policy_sources": list(policy.sources),
        "priority_policy": policy.data,
        "playbooks": playbooks,
        "fix_analysis": fix_analysis_cases(),
        "rule_engine": rule_engine_cases(engine),
        "scan": to_jsonable(result.metadata),
        "findings": [to_jsonable(f) for f in judged],
        "vuln_facts": facts,
        "prompt": build_prompt(facts),
        "report": to_jsonable(report),
    }

    out = ROOT / "tests/fixtures/parity-expected.json"
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"생성: {out} ({out.stat().st_size / 1024:.0f}KB)")
    print(f"  FixAnalysis {len(payload['fix_analysis'])}건 · "
          f"RuleEngine {len(payload['rule_engine'])}건 · "
          f"보고서 {len(report.findings)}건")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
