"""선택 범위 테스트.

담당자가 체크한 항목만 AI로 나가고, 그 항목만 보고서가 된다. 이 두 범위가
갈라지면 "미리보기에서 본 것"과 "실제로 나간 것"이 달라진다 — 이 제품이
지키겠다고 한 유일한 약속이 깨지는 지점이므로 벡터를 명시적으로 둔다.
"""

import json
from pathlib import Path

import pytest

from core import selection
from core.models import ScanResult
from core.normalize import normalize_grype_report
from core.ruleengine import RuleEngine
from core.vulnfact import build_batch

FIXTURE = Path(__file__).parent / "fixtures" / "grype-sample.json"


@pytest.fixture
def findings():
    result = normalize_grype_report(json.loads(FIXTURE.read_text()), scan_id="sel-1")
    return RuleEngine.from_config().apply(result.findings)


class TestApply:
    def test_empty_selection_means_everything(self, findings):
        """빈 선택을 '아무것도 아님'으로 읽으면 보고서가 빈 문서가 된다."""
        picked = selection.apply(findings, [])
        assert picked.findings == tuple(findings)
        assert picked.is_all is True
        assert picked.to_dict()["scope"] == "all"

    def test_none_is_also_everything(self, findings):
        assert selection.apply(findings, None).findings == tuple(findings)

    def test_picks_only_requested(self, findings):
        keys = [findings[0].key, findings[2].key]
        picked = selection.apply(findings, keys)
        assert [f.key for f in picked.findings] == keys
        assert picked.is_all is False
        assert picked.to_dict()["scope"] == "selection"

    def test_preserves_original_order(self, findings):
        """선택 순서가 아니라 원본 순서를 지킨다 — 미리보기와 보고서가
        같은 순서로 보여야 한다."""
        keys = [findings[2].key, findings[0].key]
        picked = selection.apply(findings, keys)
        assert [f.key for f in picked.findings] == [findings[0].key, findings[2].key]

    def test_duplicate_keys_yield_one_finding(self, findings):
        picked = selection.apply(findings, [findings[0].key, findings[0].key])
        assert len(picked.findings) == 1
        assert picked.to_dict()["requested"] == 1

    def test_unknown_keys_are_reported_not_swallowed(self, findings):
        picked = selection.apply(findings, [findings[0].key, "CVE-9999-1|nope|1.0|"])
        assert len(picked.findings) == 1
        assert picked.unknown == ("CVE-9999-1|nope|1.0|",)

    def test_all_unknown_yields_nothing(self, findings):
        picked = selection.apply(findings, ["not-a-key"])
        assert picked.findings == ()
        assert picked.is_all is False


class TestEgressScope:
    def test_facts_are_built_only_from_the_selection(self, findings):
        """고르지 않은 CVE는 조립 결과에 등장하지 않아야 한다."""
        picked = selection.apply(findings, [findings[0].key])
        facts = build_batch(picked.findings)
        assert {f["cve"] for f in facts} == {findings[0].intel.cve}

    def test_selection_does_not_leak_into_facts(self, findings):
        """선택 키에는 설치 패키지명·설치 버전이 들어 있다. VulnFact에는
        그 문자열이 어떤 형태로도 나타나면 안 된다."""
        picked = selection.apply(findings, [findings[0].key])
        blob = json.dumps(build_batch(picked.findings), ensure_ascii=False)
        assert findings[0].key not in blob
        assert findings[0].installed.version not in blob or (
            # advisory가 같은 문자열을 고정 버전으로 공표할 수는 있다.
            findings[0].installed.version == findings[0].advisory.fixed_version
        )
