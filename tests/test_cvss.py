"""CVSS 벡터·CWE 번역 테스트."""

import pytest

from core.cvss import classify_impact, cwe_label, describe, parse_vector


def test_parse_vector_drops_prefix():
    metrics = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert "CVSS" not in metrics
    assert metrics["AV"] == "N"
    assert metrics["C"] == "H"


def test_remote_unauthenticated_detected():
    facts = describe("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert facts.remote_unauthenticated is True
    assert facts.attack_vector == "네트워크"
    assert facts.privileges_required == "불필요"


def test_local_with_privileges_is_not_remote_unauthenticated():
    facts = describe("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:N/A:N")
    assert facts.remote_unauthenticated is False
    assert facts.attack_vector == "로컬"
    assert "관리자 권한 필요" in facts.privileges_required


def test_cvss_v4_impact_metrics_are_read():
    facts = describe("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H")
    assert facts.version == "4.0"
    assert facts.confidentiality == "높음"
    assert facts.remote_unauthenticated is True


def test_empty_vector_yields_unparsed_facts():
    facts = describe("")
    assert facts.parsed is False
    assert facts.preconditions == ()


@pytest.mark.parametrize(
    "vector,cwes,expected",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", (), "원격 코드 실행 (RCE) 가능성"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", ("CWE-400",), "서비스 거부 (DoS) 가능성"),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", ("CWE-200",), "정보 노출 가능성"),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", ("CWE-269",), "권한 상승 · 인가 우회 가능성"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", ("CWE-502",), "원격 코드 실행 (RCE) 가능성"),
    ],
)
def test_impact_classification(vector, cwes, expected):
    assert expected in classify_impact(vector, cwes)


def test_impact_labels_are_deduplicated():
    labels = classify_impact("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", ("CWE-787", "CWE-125"))
    assert len(labels) == len(set(labels))


def test_cwe_label_falls_back_to_number():
    assert cwe_label("CWE-787").startswith("CWE-787 범위 밖 쓰기")
    assert cwe_label("CWE-99999") == "CWE-99999"
