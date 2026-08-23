"""연계 상승 — 저위험 조합이 고위험으로 올라서는 경로.

AI 가 실제로 값을 더하는 자리다. 여기서 고정하는 것은 두 가지다.

- **후보 선정이 결정론적인가.** 무엇을 왜 보낼지는 우리 코드가 CVSS 벡터로
  정한다. AI 는 고른 것들 사이의 연쇄 논리만 서술한다.
- **나가는 것이 여전히 공개 데이터뿐인가.** 설치 버전·판정·자산 정보가 섞이면
  이 기능은 쓸 수 없다.
"""

from __future__ import annotations

import pytest

from core import escalation
from core.ai_narrative import build_vuln_fact_from_payload
from core.config import get_config
from core.sanitizer import EgressGuard

# CVSS 벡터 → 역할. 실제로 이 모양이 등급을 뛰게 한다.
FOOTHOLD_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"      # 인증 없는 정보 노출
SCOPE_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N"          # 범위 변경
ESCALATION_VECTOR = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"     # 로컬 권한 상승
ADMIN_VECTOR = "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"          # 관리자 필요
NOISE_VECTOR = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L"          # 가벼운 DoS


def _payload(cve: str, vector: str, *, kev: str = "unknown", epss: float | None = 0.1,
             score: float = 7.5, package: str = "pkg") -> dict:
    return {
        "key": f"{cve}|{package}|1.0.0|pkg:rpm/{package}@1.0.0",
        "intel": {
            "cve": cve, "cvss_score": score, "cvss_vector": vector, "cvss_version": "3.1",
            "severity": "high", "cwe": ["CWE-200"], "epss": epss, "kev": kev,
            "exploit_available": "unknown", "exploit_maturity": "unknown",
            "exploit_sources": [], "published": "2026-01-01", "aliases": [],
            "description": "", "epss_snapshot_date": "", "kev_date_added": "",
            "kev_ransomware_use": "", "references": [],
        },
        "advisory": {
            "advisory_package": package, "advisory_ecosystem": "rpm",
            "affected_version_range": "< 2.0.0", "fixed_version": "2.0.0",
            "fix_state": "fixed_available", "os_family": "rhel",
        },
        # 아래는 **로컬 계층**이다. 전송 데이터에 하나도 나타나면 안 된다.
        "installed": {"name": package, "version": "1.0.0-secret", "type": "rpm",
                      "purl": f"pkg:rpm/{package}@1.0.0", "locations": ["/opt/secret/path"]},
        "fix": {"installed_version": "1.0.0-secret", "fixed_version": "2.0.0",
                "update_available": "true", "fix_state": "fixed_available",
                "version_gap": "major", "comparator": "rpm", "reason": ""},
        "verdict": {"priority": "P0", "flags": [], "fired_rules": []},
        "detection": {"matcher": "rpm-matcher", "match_type": "exact", "namespace": "rhel:9"},
    }


class TestCandidateSelection:
    """무엇을 보낼지는 **우리가** 정한다. 그 판단이 벡터에서 읽혀야 한다."""

    @pytest.mark.parametrize("vector,expected", [
        (FOOTHOLD_VECTOR, escalation.FOOTHOLD),
        (SCOPE_VECTOR, escalation.FOOTHOLD),
        (ESCALATION_VECTOR, escalation.ESCALATION),
        (ADMIN_VECTOR, escalation.ESCALATION),
    ])
    def test_vectors_map_to_roles(self, vector, expected):
        verdict = escalation.classify(vector)
        assert verdict is not None
        assert verdict[0] == expected
        assert verdict[1], "왜 뽑혔는지를 함께 들고 다녀야 화면에 적을 수 있다"

    def test_noise_is_not_a_candidate(self):
        """자격이 필요 없어도 얻는 것이 없으면 발판이 아니다."""
        assert escalation.classify(NOISE_VECTOR) is None

    def test_a_missing_vector_is_never_a_candidate(self):
        """근거 없이 연쇄 논리에 넣으면 모델이 지어내는 자리가 된다."""
        assert escalation.classify("") is None
        assert escalation.classify("근거없음") is None

    def test_kev_is_picked_before_unconfirmed(self):
        picked = escalation.pick([
            _payload("CVE-2026-000001", FOOTHOLD_VECTOR, kev="unknown", epss=0.9),
            _payload("CVE-2026-000002", FOOTHOLD_VECTOR, kev="true", epss=0.01),
        ], limit=5)
        assert [c.cve for c in picked[escalation.FOOTHOLD]] == [
            "CVE-2026-000002", "CVE-2026-000001",
        ]

    def test_the_same_cve_is_sent_once(self):
        """같은 CVE 가 여러 패키지에서 나와도 모델에게는 같은 공개 취약점이다."""
        picked = escalation.pick([
            _payload("CVE-2026-000001", FOOTHOLD_VECTOR, package="a"),
            _payload("CVE-2026-000001", FOOTHOLD_VECTOR, package="b"),
        ], limit=5)
        assert [c.cve for c in picked[escalation.FOOTHOLD]] == ["CVE-2026-000001"]

    def test_limit_is_per_role(self):
        payloads = [
            _payload(f"CVE-2026-00{i:04d}", FOOTHOLD_VECTOR, epss=i / 100) for i in range(10)
        ] + [
            _payload(f"CVE-2026-01{i:04d}", ESCALATION_VECTOR, epss=i / 100) for i in range(10)
        ]
        picked = escalation.pick(payloads, limit=3)
        assert len(picked[escalation.FOOTHOLD]) == 3
        assert len(picked[escalation.ESCALATION]) == 3


class TestNothingPrivateLeaves:
    """나가는 것은 공개 데이터뿐이다. 이 기능이 그 원칙의 예외가 되면 안 된다."""

    def test_the_fact_carries_no_local_layer(self):
        fact = build_vuln_fact_from_payload(_payload("CVE-2026-000001", FOOTHOLD_VECTOR))
        blob = repr(fact)
        for secret in ("1.0.0-secret", "/opt/secret/path", "P0", "version_gap", "fix_state"):
            assert secret not in blob, f"{secret} 이(가) 전송 데이터에 있다"

    def test_the_guard_accepts_what_we_assemble(self):
        """조립기가 어긋나면 가드가 막는다 — 실제로 처음 짤 때 막혔다."""
        facts = [
            build_vuln_fact_from_payload(_payload("CVE-2026-000001", FOOTHOLD_VECTOR)),
            build_vuln_fact_from_payload(_payload("CVE-2026-000002", ESCALATION_VECTOR)),
        ]
        result = EgressGuard.from_config(get_config()).check(facts)
        assert result.ok, [v.to_dict() for v in result.violations]

    def test_the_prompt_shows_everything_it_sends(self):
        """이 문자열 전체를 화면에 그대로 보여 줄 수 있어야 한다."""
        from core.prompt import build_escalation_full_text

        facts = [build_vuln_fact_from_payload(_payload("CVE-2026-000001", FOOTHOLD_VECTOR))]
        text = build_escalation_full_text(facts, [])
        assert "CVE-2026-000001" in text
        assert "1.0.0-secret" not in text
        assert "/opt/secret/path" not in text


class TestEscalationApi:
    def test_candidates_are_counted_without_calling_ai(self, client, seeded_scan):
        """생성 전에 "무엇을 보낼 것인가"를 먼저 보여 준다."""
        body = client.get(f"/api/scans/{seeded_scan}/escalation").json()
        assert body["generated"] is False
        assert set(body["candidates"]["counts"]) == {"foothold", "escalation"}
        assert body["ai_ready"] is False          # 테스트 환경에는 키가 없다

    def test_preview_sends_nothing(self, client, seeded_scan):
        body = client.get(f"/api/scans/{seeded_scan}/escalation/preview").json()
        assert "prompt" in body and "facts" in body
        assert body["ok"] is True, body.get("violations")

    def test_generation_is_refused_without_a_key(self, client, seeded_scan):
        response = client.post(f"/api/scans/{seeded_scan}/escalation")
        assert response.status_code == 409
        assert "SBOMSIGHT_AI_ENABLED" in response.json()["detail"]


@pytest.fixture
def multi_cve_scan(client):
    """CVE 가 여럿 달린 패키지 하나를 담은 스캔.

    "한 건만" 과 "묶음 전체" 를 구분하려면 한 묶음에 CVE 가 둘 이상 있어야
    한다. 기본 픽스처에는 그런 묶음이 없다.
    """
    from core.config import get_config
    from core.models import (
        AdvisoryPackage, Finding, FixState, InstalledPackage, Priority,
        RuleVerdict, ScanMetadata, ScanResult, Severity, VulnIntel,
    )
    from core.store import Store

    findings = tuple(
        Finding(
            installed=InstalledPackage(name="openssl", version="1.0.0", type="rpm",
                                       purl="pkg:rpm/openssl@1.0.0"),
            advisory=AdvisoryPackage(advisory_package="openssl", advisory_ecosystem="rpm",
                                     affected_version_range="< 2.0.0", fixed_version="2.0.0",
                                     fix_state=FixState.FIXED_AVAILABLE),
            intel=VulnIntel(cve=f"CVE-2026-2000{i}", severity=Severity.HIGH, cvss_score=7.5,
                            cvss_vector=FOOTHOLD_VECTOR, cvss_version="3.1"),
            verdict=RuleVerdict(priority=Priority.P1),
        )
        for i in range(3)
    )
    Store(get_config().db_path).save_scan(ScanResult(
        metadata=ScanMetadata(scan_id="multi-1", created_at="2026-08-23T00:00:00+00:00",
                              sbom_filename="a.json"),
        findings=findings,
    ))
    return "multi-1"


class TestNarrativeScope:
    """생성 범위가 요청한 만큼이어야 한다.

    분당 토큰(TPM)을 사람 손에 맞추려고 단위를 잘게 나눴는데, 한 건을
    눌렀더니 묶음 전체가 나가면 그 조절이 무의미해진다.
    """

    @staticmethod
    def _stub(monkeypatch, seen):
        import server.app
        from core.ai_narrative import NarrativeRun
        from core.report import Narrative

        def fake_run(findings, *, config, scan_id):
            seen["cves"] = [f.intel.cve for f in findings]
            return NarrativeRun(
                narratives={f.intel.cve: Narrative(technical_risk="설명", source="ai")
                            for f in findings},
                model="stub", requested=len(findings),
            )

        monkeypatch.setattr(server.app.config, "ai_enabled", True)
        monkeypatch.setattr(server.app.config, "gemini_api_key", "test-key")
        monkeypatch.setattr(server.app, "run_narratives", fake_run)

    def test_one_cve_sends_only_that_cve(self, client, multi_cve_scan, monkeypatch):
        group = client.get(f"/api/scans/{multi_cve_scan}/packages").json()["packages"][0]
        assert group["cve_count"] == 3

        seen: dict = {}
        self._stub(monkeypatch, seen)
        body = client.post(f"/api/scans/{multi_cve_scan}/narratives", json={
            "package": group["package"], "version": group["installed_version"],
            "cve": "CVE-2026-20001",
        }).json()

        assert seen["cves"] == ["CVE-2026-20001"], "요청한 한 건만 나가야 한다"
        assert body["requested"] == 1
        assert body["cve"] == "CVE-2026-20001"

    def test_without_a_cve_the_whole_package_goes(self, client, multi_cve_scan, monkeypatch):
        group = client.get(f"/api/scans/{multi_cve_scan}/packages").json()["packages"][0]
        seen: dict = {}
        self._stub(monkeypatch, seen)
        body = client.post(f"/api/scans/{multi_cve_scan}/narratives", json={
            "package": group["package"], "version": group["installed_version"],
        }).json()
        assert body["requested"] == 3
        assert len(seen["cves"]) == 3

    def test_an_unknown_cve_is_refused(self, client, seeded_scan, monkeypatch):
        group = client.get(f"/api/scans/{seeded_scan}/packages").json()["packages"][0]
        self._stub(monkeypatch, {})
        response = client.post(f"/api/scans/{seeded_scan}/narratives", json={
            "package": group["package"], "version": group["installed_version"],
            "cve": "CVE-1999-99999",
        })
        assert response.status_code == 404
