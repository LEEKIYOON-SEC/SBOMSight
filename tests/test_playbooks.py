"""패치 플레이북 테스트.

패치 명령은 AI가 아니라 여기서 나온다. 그래서 이 파일이 지키는 계약은
"어떤 생태계든, AI가 없어도, 실행 가능한 절차가 나온다"이다.
"""

import json
from pathlib import Path

import pytest

from core.playbooks import PlaybookLibrary

PLAYBOOK_DIR = Path("rules/playbooks")


@pytest.fixture(scope="module")
def library():
    return PlaybookLibrary(PLAYBOOK_DIR)


@pytest.mark.parametrize("name", [p.stem for p in PLAYBOOK_DIR.glob("*.json")])
def test_every_playbook_has_required_shape(name):
    book = json.loads((PLAYBOOK_DIR / f"{name}.json").read_text(encoding="utf-8"))
    for key in ("ecosystem", "label", "recommended_action", "recommended_action_no_fix",
                "precheck", "online", "airgapped", "verification", "mitigation_when_no_fix"):
        assert key in book, f"{name}.json 에 {key} 없음"
    assert book["airgapped"]["steps"], f"{name}: 폐쇄망 절차가 비어 있다"
    assert book["online"]["steps"]


@pytest.mark.parametrize(
    "ecosystem,expected",
    [
        ("rpm", "rpm"), ("rocky", "rpm"), ("rhel", "rpm"), ("almalinux", "rpm"),
        ("deb", "deb"), ("ubuntu", "deb"), ("debian", "deb"),
        ("npm", "npm"), ("javascript", "npm"),
        ("python", "pip"), ("pypi", "pip"),
        ("java-archive", "maven"), ("maven", "maven"),
        ("", "generic"), ("전혀-모르는-생태계", "generic"),
    ],
)
def test_ecosystem_maps_to_playbook(library, ecosystem, expected):
    assert library.for_ecosystem(ecosystem)["ecosystem"] == expected


class TestRpmAirgapped:
    """사용자가 지정한 실제 폐쇄망 절차가 담겨 있는가."""

    @pytest.fixture
    def rec(self, library):
        return library.build(
            ecosystem="rpm", package="xz", installed_version="5.6.0-2.el9",
            fixed_version="5.6.2", cve="CVE-2024-3094", os_family="rhel",
        )

    def test_download_with_dependencies(self, rec):
        steps = "\n".join(rec.airgapped_steps)
        assert "dnf download --resolve --alldeps" in steps

    def test_integrity_and_signature_check(self, rec):
        steps = "\n".join(rec.airgapped_steps)
        assert "rpm -K" in steps
        assert "sha256sum" in steps

    def test_localinstall_and_local_repo(self, rec):
        steps = "\n".join(rec.airgapped_steps)
        assert "dnf localinstall" in steps
        assert "createrepo_c" in steps

    def test_verification_includes_rescan(self, rec):
        checks = "\n".join(rec.verification)
        assert "rpm -q xz" in checks
        assert "grype sbom:" in checks


def test_templates_are_filled(library):
    rec = library.build(
        ecosystem="rpm", package="openssl", installed_version="1:3.0.7-24.el9",
        fixed_version="1:3.0.7-27.el9_4", cve="CVE-2024-2511",
    )
    joined = " ".join([rec.action, *rec.precheck, *rec.online_steps, *rec.verification])
    assert "{package}" not in joined
    assert "{fixed_version}" not in joined
    assert "openssl" in joined
    assert "1:3.0.7-27.el9_4" in joined


def test_no_fix_yields_mitigations_only(library):
    rec = library.build(
        ecosystem="rpm", package="zlib", installed_version="1.2.11-40.el9",
        fixed_version="", cve="CVE-2023-45853",
    )
    assert rec.has_fix is False
    assert rec.online_steps == ()
    assert rec.airgapped_steps == ()
    assert rec.verification == ()
    assert len(rec.mitigations) >= 3


def test_unknown_ecosystem_still_produces_actionable_steps(library):
    rec = library.build(
        ecosystem="cocoapods", package="Alamofire", installed_version="5.0.0",
        fixed_version="5.9.0", cve="CVE-2024-0000",
    )
    assert rec.ecosystem == "generic"
    assert rec.airgapped_steps          # 일반 절차라도 비어 있으면 안 된다
    assert "Alamofire" in rec.action
