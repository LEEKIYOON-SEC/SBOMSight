"""AI 산문 계층 테스트 (Mode A).

지키는 계약:
  1. AI가 없어도 보고서는 완결된다 — 실패는 룰 문장으로 물러선다.
  2. AI 응답이 대응 우선순위를 바꿀 수 없다.
  3. 표현 정책 위반은 리포트에 실리지 않는다.
  4. 이그레스 가드가 막으면 **네트워크 호출이 일어나지 않는다**.
"""

import json
from pathlib import Path

import pytest

from core.audit import AuditLog, payload_hash
from core.config import Config
from core.gemini import GeminiClient, GeminiError, GeminiUnavailable, extract_json
from core.models import (
    AdvisoryPackage,
    FixState,
    Finding,
    InstalledPackage,
    Priority,
    RuleVerdict,
    Severity,
    Ternary,
    VulnIntel,
)
from core.report import Narrative, ReportBuilder
from core.sanitizer import EgressBlocked, EgressGuard
from core.tone import ToneGuard
from core import ai_narrative


@pytest.fixture(scope="module")
def tone():
    return ToneGuard.from_config()


@pytest.fixture
def config(tmp_path):
    cfg = Config()
    cfg.data_dir = tmp_path / "data"
    cfg.ensure_dirs()
    return cfg


def make_finding(cve="CVE-2024-3094"):
    installed = InstalledPackage("xz", "5.6.0-2.el9", "rpm", locations=("/var/lib/rpm",))
    advisory = AdvisoryPackage("xz", "rpm", "< 5.6.2", "5.6.2", FixState.FIXED_AVAILABLE, "rhel")
    return Finding(
        installed=installed,
        advisory=advisory,
        intel=VulnIntel(cve=cve, severity=Severity.CRITICAL, cvss_score=10.0,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        kev=Ternary.TRUE),
        verdict=RuleVerdict(priority=Priority.P0, policy_version="1", policy_sha256="a" * 64),
    )


# ---------------------------------------------------------------------------
# 표현 가드
# ---------------------------------------------------------------------------


class TestToneGuard:

    @pytest.mark.parametrize(
        "text,rule",
        [
            ("귀사의 WEB 서버는 매우 위험합니다.", "first_person_org"),
            ("우리 조직에 Critical 위험입니다.", "first_person_org"),
            ("해당 서버는 반드시 패치해야 합니다.", "asset_reference"),
            ("사내 운영 서버에 적용하십시오.", "asset_reference"),
            ("반드시 패치를 적용해야 합니다.", "imperative_must"),
            ("이 취약점은 매우 위험합니다.", "risk_assertion"),
            ("이 항목은 P0 등급에 해당합니다.", "priority_claim"),
            ("우선순위는 P1 입니다.", "priority_claim"),
            ("방치하면 반드시 악용될 것입니다.", "breach_prediction"),
            ("조치 방법:\ndnf upgrade openssl", "fabricated_command"),
            ("Token: abc\napt-get install foo", "fabricated_command"),
        ],
    )
    def test_forbidden_phrasings_are_caught(self, tone, text, rule):
        violations = tone.inspect({"response_rationale": text})
        assert rule in {v.rule for v in violations}, f"{rule} 미검출: {text}"

    @pytest.mark.parametrize(
        "text",
        [
            "공개된 위협정보를 기준으로 볼 때 우선적인 대응을 검토할 필요가 있습니다.",
            "CISA KEV 등재 및 공개 Exploit 존재를 고려할 때 신속한 대응이 권고됩니다.",
            "CVSS 벡터상 네트워크를 통해 인증 없이 접근 가능한 형태로 분류됩니다.",
            "높은 우선순위로 조치하는 것을 권고합니다.",
            "공개된 정보만으로는 확인되지 않습니다.",
        ],
    )
    def test_preferred_phrasings_pass(self, tone, text):
        assert tone.inspect({"technical_risk": text}) == []

    def test_empty_text_is_not_flagged(self, tone):
        assert tone.inspect({"a": "", "b": None}) == []

    def test_policy_identity_is_recorded(self, tone):
        assert tone.policy.version == "1"
        assert len(tone.policy.sha256) == 64


# ---------------------------------------------------------------------------
# AI 응답 병합
# ---------------------------------------------------------------------------


class TestResponseMerging:
    def test_priority_fields_in_ai_response_are_dropped(self):
        """모델이 등급을 우겨넣어도 Narrative에는 자리가 없다."""
        narrative = ai_narrative._to_narrative({
            "cve": "CVE-2024-3094",
            "technical_risk": "서술",
            "priority": "P0",
            "risk_level": "critical",
            "verdict": {"priority": "P0"},
            "is_vulnerable": True,
        })
        assert narrative.technical_risk == "서술"
        assert not hasattr(narrative, "priority")
        assert "priority" not in Narrative.__dataclass_fields__

    def test_ai_narrative_does_not_change_verdict(self):
        """리포트의 우선순위는 룰 판정 그대로다."""
        from core.models import ScanMetadata, ScanResult

        finding = make_finding()
        result = ScanResult(
            metadata=ScanMetadata(scan_id="s", created_at="2026-08-19T00:00:00+00:00"),
            findings=(finding,),
        )
        report = ReportBuilder().build(
            result,
            narratives={"CVE-2024-3094": Narrative(technical_risk="AI 서술", source="ai")},
        )
        item = report.findings[0]
        assert item.narrative_source == "ai"
        assert item.priority is Priority.P0        # 룰 판정이 그대로 유지된다
        assert item.technical_risk["narrative"] == "AI 서술"

    def test_missing_narrative_falls_back_to_rule_text(self):
        from core.models import ScanMetadata, ScanResult

        result = ScanResult(
            metadata=ScanMetadata(scan_id="s", created_at="2026-08-19T00:00:00+00:00"),
            findings=(make_finding(),),
        )
        report = ReportBuilder().build(result, narratives={})
        item = report.findings[0]
        assert item.narrative_source == "rule"
        assert item.technical_risk["narrative"]      # 비어 있지 않다


# ---------------------------------------------------------------------------
# 오케스트레이션
# ---------------------------------------------------------------------------


class TestGenerateNarratives:
    def test_returns_empty_when_ai_disabled(self, config):
        """AI 없이도 보고서가 완결된다는 전제가 여기서 지켜진다."""
        assert config.ai_ready() is False
        assert ai_narrative.generate_narratives([make_finding()], config=config) == {}

    def test_tone_violation_drops_narrative(self, config, monkeypatch):
        config.ai_enabled = True
        config.gemini_api_key = "test-key"

        class FakeResult:
            analyses = [
                {"cve": "CVE-2024-3094", "technical_risk": "귀사의 서버는 매우 위험합니다.",
                 "exploitability_note": "n", "response_rationale": "r"},
                {"cve": "CVE-2024-0002", "technical_risk": "공개 데이터 기준의 정상적인 서술입니다.",
                 "exploitability_note": "n", "response_rationale": "r"},
            ]
            model = "test"
            attempts = 1
            raw_length = 0

        monkeypatch.setattr(GeminiClient, "available", lambda self: True)
        monkeypatch.setattr(GeminiClient, "analyze", lambda self, facts, scan_id="": FakeResult())

        result = ai_narrative.generate_narratives(
            [make_finding("CVE-2024-3094"), make_finding("CVE-2024-0002")], config=config
        )
        assert "CVE-2024-3094" not in result       # 표현 위반 → 버려짐
        assert "CVE-2024-0002" in result

    def test_gemini_failure_falls_back_quietly(self, config, monkeypatch):
        config.ai_enabled = True
        config.gemini_api_key = "test-key"

        monkeypatch.setattr(GeminiClient, "available", lambda self: True)

        def boom(self, facts, scan_id=""):
            raise GeminiError("쿼터 소진")

        monkeypatch.setattr(GeminiClient, "analyze", boom)
        assert ai_narrative.generate_narratives([make_finding()], config=config) == {}

    def test_egress_block_is_raised_not_swallowed(self, config, monkeypatch):
        """가드가 막았다면 버그이거나 공격이다. 조용히 넘기지 않는다."""
        config.ai_enabled = True
        config.gemini_api_key = "test-key"

        monkeypatch.setattr(GeminiClient, "available", lambda self: True)

        def blocked(self, facts, scan_id=""):
            from core.sanitizer import Violation
            raise EgressBlocked([Violation("forbidden_field", "facts[0].priority", "금칙 필드명")])

        monkeypatch.setattr(GeminiClient, "analyze", blocked)
        with pytest.raises(EgressBlocked):
            ai_narrative.generate_narratives([make_finding()], config=config)


# ---------------------------------------------------------------------------
# Gemini 클라이언트
# ---------------------------------------------------------------------------


class TestGeminiClient:
    def test_no_api_key_means_unavailable(self, config):
        client = GeminiClient(config)
        assert client.available() is False
        with pytest.raises(GeminiUnavailable):
            client._client()

    def test_guard_blocks_before_any_network_call(self, config, monkeypatch):
        """가드를 통과하지 못하면 _client()에 도달조차 하지 않아야 한다."""
        config.ai_enabled = True
        config.gemini_api_key = "test-key"
        client = GeminiClient(config)

        called = []
        monkeypatch.setattr(GeminiClient, "_client", lambda self: called.append(1))

        with pytest.raises(EgressBlocked):
            client.analyze([{"cve": "CVE-2024-3094", "advisory_package": "xz",
                             "installed_version": "5.6.0-2.el9"}])
        assert called == [], "가드 위반인데 클라이언트가 만들어졌다"

    def test_blocked_attempt_is_audited(self, config):
        config.ai_enabled = True
        config.gemini_api_key = "test-key"
        client = GeminiClient(config)

        with pytest.raises(EgressBlocked):
            client.analyze([{"cve": "CVE-2024-3094", "advisory_package": "xz", "priority": "P0"}])

        records = AuditLog(config.audit_dir).tail()
        assert records
        assert records[0]["outcome"] == "blocked"
        assert records[0]["action"] == "send"
        assert any("priority" in v["path"] for v in records[0]["violations"])

    @pytest.mark.parametrize(
        "text",
        [
            '{"analyses": []}',
            '```json\n{"analyses": []}\n```',
            '```\n{"analyses": []}\n```',
            '설명이 앞에 붙은 경우 {"analyses": []} 뒤에도 텍스트',
        ],
    )
    def test_json_extraction_survives_fences_and_prose(self, text):
        assert extract_json(text) == {"analyses": []}

    def test_unparseable_response_raises(self):
        with pytest.raises(GeminiError):
            extract_json("JSON이 전혀 없는 응답")


# ---------------------------------------------------------------------------
# 감사 로그
# ---------------------------------------------------------------------------


class TestAuditLog:
    def test_records_payload_and_hash(self, tmp_path):
        log = AuditLog(tmp_path)
        facts = [{"cve": "CVE-2024-3094"}]
        record = log.record(action="send", outcome="allowed", facts=facts,
                            policy_version="1", policy_sha256="b" * 64, scan_id="s1")

        assert record.payload_sha256 == payload_hash(facts)
        assert record.fact_count == 1

        tail = log.tail()
        assert tail[0]["payload"] == facts       # 무엇을 보냈는지 사후 확인이 가능해야 한다
        assert tail[0]["scan_id"] == "s1"

    def test_hash_is_stable_regardless_of_key_order(self):
        assert payload_hash([{"a": 1, "b": 2}]) == payload_hash([{"b": 2, "a": 1}])

    def test_tail_returns_newest_first(self, tmp_path):
        log = AuditLog(tmp_path)
        for i in range(3):
            log.record(action="preview", outcome="allowed", facts=[{"cve": f"CVE-2024-000{i}"}])
        tail = log.tail()
        assert [r["payload"][0]["cve"] for r in tail] == [
            "CVE-2024-0002", "CVE-2024-0001", "CVE-2024-0000"
        ]
