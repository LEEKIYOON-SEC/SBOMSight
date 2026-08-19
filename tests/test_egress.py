"""이그레스 가드 테스트.

이 파일이 지키는 계약이 SBOMSight의 보안 주장 전부다:
  1. VulnFact 조립기는 로컬 계층을 **시그니처에서** 받지 않는다.
  2. 공용 벡터(policy/egress-test-vectors.json)의 모든 차단 항목이 차단된다.
  3. 실제 Finding에서 조립한 payload에 내부 문자열이 하나도 없다.

같은 벡터를 JS 구현도 통과해야 한다 (tests/js/sanitizer.test.mjs).
"""

import inspect
import json
from pathlib import Path

import pytest

from core import vulnfact
from core.models import (
    AdvisoryPackage,
    Detection,
    ExploitMaturity,
    ExploitSource,
    FiredRule,
    FixAnalysis,
    FixState,
    Finding,
    InstalledPackage,
    Priority,
    RuleVerdict,
    Severity,
    Ternary,
    VersionGap,
    VulnIntel,
)
from core.sanitizer import EgressBlocked, EgressGuard

VECTORS = json.loads(Path("policy/egress-test-vectors.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def guard():
    return EgressGuard.from_config()


def make_fact(vector):
    fact = dict(VECTORS["base_fact"])
    fact.update(vector.get("patch") or {})
    for key in vector.get("remove") or ():
        fact.pop(key, None)
    return fact


# ---------------------------------------------------------------------------
# 1. 조립기 — 구조적 방어
# ---------------------------------------------------------------------------


class TestAssemblyIsStructurallySafe:
    def test_builder_signature_cannot_see_local_layers(self):
        """이 테스트가 이 프로젝트에서 가장 중요한 한 줄이다.

        조립 함수가 InstalledPackage·FixAnalysis·RuleVerdict·Detection을
        인자로 받지 않는다는 것을 시그니처 수준에서 고정한다. 누군가 편의를
        위해 Finding을 통째로 넘기도록 바꾸면 여기서 깨진다.
        """
        params = inspect.signature(vulnfact.build_vuln_fact).parameters
        # `from __future__ import annotations` 때문에 애너테이션은 문자열이다.
        # 문자열 비교가 오히려 소스에 보이는 것과 일치한다.
        annotations = {str(p.annotation) for p in params.values()}
        assert annotations == {"AdvisoryPackage", "VulnIntel"}
        assert len(params) == 2

        # 로컬 계층은 어떤 형태로도 들어올 수 없다.
        forbidden = {"Finding", "InstalledPackage", "FixAnalysis", "RuleVerdict", "Detection"}
        assert not (annotations & forbidden)

    def test_assembled_fact_has_only_allowed_keys(self, guard):
        fact = vulnfact.build_vuln_fact(
            AdvisoryPackage("xz", "rpm", "< 5.6.2", "5.6.2", FixState.FIXED_AVAILABLE, "rhel"),
            VulnIntel(cve="CVE-2024-3094", severity=Severity.CRITICAL),
        )
        assert set(fact) <= set(guard.allowed)

    def test_exploit_source_free_text_is_dropped(self):
        """저장소가 채운 자유 텍스트는 무엇이 들어 있을지 보장할 수 없다."""
        fact = vulnfact.build_vuln_fact(
            AdvisoryPackage("xz", "rpm"),
            VulnIntel(
                cve="CVE-2024-3094",
                exploit_sources=(ExploitSource("exploit_db", "EDB-1", "내부 확인 완료 — 3층 WEB"),),
            ),
        )
        assert fact["exploit_sources"] == [{"source": "exploit_db", "ref": "EDB-1"}]
        assert "내부" not in json.dumps(fact, ensure_ascii=False)

    def test_unknown_exploit_source_kind_is_dropped(self):
        fact = vulnfact.build_vuln_fact(
            AdvisoryPackage("xz", "rpm"),
            VulnIntel(cve="CVE-2024-3094",
                      exploit_sources=(ExploitSource("internal_redteam", "OP-1"),)),
        )
        assert fact["exploit_sources"] == []

    def test_batch_deduplicates_by_cve_and_package(self):
        """같은 CVE가 여러 자산에서 나와도 한 번만 나간다 —
        중복 건수는 곧 '우리 환경에 몇 대나 있는가'라는 내부 정보다."""
        def finding(host_version):
            return Finding(
                installed=InstalledPackage("xz", host_version, "rpm"),
                advisory=AdvisoryPackage("xz", "rpm", "< 5.6.2", "5.6.2"),
                intel=VulnIntel(cve="CVE-2024-3094"),
            )

        facts = vulnfact.build_batch([finding("5.6.0-1.el9"), finding("5.6.0-2.el9")])
        assert len(facts) == 1


# ---------------------------------------------------------------------------
# 2. 공용 벡터 — Python/JS 동치성의 기준
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("vector", VECTORS["vectors"], ids=lambda v: v["name"])
def test_shared_vectors(guard, vector):
    result = guard.check([make_fact(vector)])
    if vector["expect"] == "pass":
        assert result.ok, f"통과해야 하는데 차단됨: {[v.to_dict() for v in result.violations]}"
        return

    assert not result.ok, "차단되어야 하는데 통과함"
    if "rule" in vector:
        rules = {v.rule for v in result.violations}
        assert vector["rule"] in rules, f"기대 규칙 {vector['rule']}, 실제 {rules}"


@pytest.mark.parametrize("vector", VECTORS["batch_vectors"], ids=lambda v: v["name"])
def test_shared_batch_vectors(guard, vector):
    facts = [dict(VECTORS["base_fact"]) for _ in range(vector["repeat_base"])]
    result = guard.check(facts)
    assert result.ok == (vector["expect"] == "pass")
    if vector["expect"] == "block" and "rule" in vector:
        assert vector["rule"] in {v.rule for v in result.violations}


# ---------------------------------------------------------------------------
# 3. 실제 Finding에서 조립한 payload
# ---------------------------------------------------------------------------


@pytest.fixture
def hostile_finding():
    """내부 정보가 잔뜩 박힌 Finding. 이 중 무엇도 나가서는 안 된다."""
    return Finding(
        installed=InstalledPackage(
            name="xz",
            version="5.6.0-2.el9",
            type="rpm",
            purl="pkg:rpm/rocky/xz@5.6.0-2.el9?arch=x86_64",
            cpes=("cpe:2.3:a:xz:xz:5.6.0:*:*:*:*:*:*:*",),
            locations=("/var/lib/rpm/rpmdb.sqlite", "/opt/인사시스템/lib"),
            sbom_ref="550e8400-e29b-41d4-a716-446655440000",
        ),
        advisory=AdvisoryPackage("xz", "rpm", "< 5.6.2", "5.6.2", FixState.FIXED_AVAILABLE, "rhel"),
        intel=VulnIntel(
            cve="CVE-2024-3094",
            severity=Severity.CRITICAL,
            cvss_score=10.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            kev=Ternary.TRUE,
            exploit_available=Ternary.TRUE,
            exploit_maturity=ExploitMaturity.WEAPONIZED,
            exploit_sources=(ExploitSource("exploit_db", "EDB-52128", "3층 WEB 서버에서 확인"),),
            description="Malicious code was discovered in the upstream tarballs of xz.",
            references=("https://nvd.nist.gov/vuln/detail/CVE-2024-3094",),
        ),
        detection=Detection(
            matcher="rpm-matcher",
            match_type="exact-direct-match",
            namespace="rocky:distro:rocky:9",
            search_criteria={"package": {"name": "xz", "version": "5.6.0-2.el9"},
                             "host": "was01.corp", "ip": "10.20.30.40"},
        ),
        fix=FixAnalysis(
            installed_version="5.6.0-2.el9", fixed_version="5.6.2", comparator="rpm",
            is_vulnerable=Ternary.TRUE, update_available=Ternary.TRUE,
            fix_state=FixState.FIXED_AVAILABLE, version_gap=VersionGap.PATCH,
        ),
        verdict=RuleVerdict(
            priority=Priority.P0,
            fired_rules=(FiredRule("kev_listed", "CISA KEV 등재"),),
            flags=("update_available",),
            policy_version="1", policy_sha256="a" * 64,
        ),
    )


INTERNAL_STRINGS = [
    "5.6.0-2.el9",                              # 설치 버전
    "/var/lib/rpm",                             # 파일 경로
    "인사시스템",                                # 내부 한글 표기
    "550e8400-e29b-41d4-a716-446655440000",     # 자산 UUID
    "was01.corp",                               # 내부 호스트명
    "10.20.30.40",                              # 내부 IP
    "rocky:distro:rocky:9",                     # 탐지 namespace
    "P0",                                       # 대응 우선순위 판정
    "kev_listed",                               # 발화 룰
    "3층 WEB",                                  # exploit note의 내부 메모
]


class TestRealFindingPayload:
    def test_no_internal_string_survives_assembly(self, hostile_finding):
        payload = json.dumps(vulnfact.build_from_finding(hostile_finding), ensure_ascii=False)
        leaked = [s for s in INTERNAL_STRINGS if s in payload]
        assert leaked == [], f"내부 문자열이 payload에 남아 있음: {leaked}"

    def test_payload_passes_the_guard(self, guard, hostile_finding):
        result = guard.check([vulnfact.build_from_finding(hostile_finding)])
        assert result.ok, [v.to_dict() for v in result.violations]

    def test_enforce_raises_on_violation(self, guard):
        fact = dict(VECTORS["base_fact"])
        fact["installed_version"] = "5.6.0-2.el9"
        with pytest.raises(EgressBlocked) as excinfo:
            guard.enforce([fact])
        assert "installed_version" in str(excinfo.value)

    def test_enforce_is_all_or_nothing(self, guard):
        """문제 있는 항목만 빼고 나머지를 보내지 않는다 — 무엇이 어떻게
        새려 했는지 모르는 상태에서 나머지가 안전하다고 볼 근거가 없다."""
        clean = dict(VECTORS["base_fact"])
        dirty = dict(VECTORS["base_fact"], priority="P0")
        with pytest.raises(EgressBlocked):
            guard.enforce([clean, dirty])


class TestPolicyProvenance:
    def test_result_records_policy_identity(self, guard):
        result = guard.check([dict(VECTORS["base_fact"])])
        assert result.policy_version == "1"
        assert len(result.policy_sha256) == 64

    def test_every_allowed_field_is_produced_by_the_builder(self, guard):
        """정책에 있는데 조립기가 만들지 않는 필드가 있으면 정책이 과대하다."""
        fact = vulnfact.build_vuln_fact(
            AdvisoryPackage("p", "rpm"), VulnIntel(cve="CVE-2024-0001")
        )
        assert set(guard.allowed) == set(fact)
