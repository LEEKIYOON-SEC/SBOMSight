"""데모 인덱스 빌더 테스트.

가장 중요한 계약은 **샤드 키 규칙이 Python과 JavaScript에서 같아야 한다**는
것이다. 어긋나면 브라우저가 존재하는 샤드를 찾지 못해, 취약점이 있는데도
"인덱스 미수록"으로 조용히 넘어간다.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from build_demo_index import entry_from_finding, shard_key  # noqa: E402

from core.models import (  # noqa: E402
    AdvisoryPackage, Detection, ExploitMaturity, ExploitSource, FixState,
    Finding, InstalledPackage, Severity, Ternary, VulnIntel,
)

SHARD_CASES = [
    ("rpm", "xz"), ("rpm", "openssl"), ("rpm", "389-ds-base"),
    ("npm", "cross-spawn"), ("npm", "@babel/core"), ("npm", "_internal"),
    ("python", "Requests"), ("python", "urllib3"),
    ("go-module", "github.com/gin-gonic/gin"),
    ("java-archive", "commons-io"),
    ("", "orphan"), ("rpm", ""), ("RPM", "XZ"),
    ("deb", "libc6"), ("deb", "7zip"),
]


@pytest.mark.parametrize("ecosystem,name", SHARD_CASES, ids=lambda v: str(v))
def test_shard_key_matches_javascript(ecosystem, name):
    """어긋나면 브라우저가 샤드를 못 찾아 취약점이 조용히 사라진다."""
    script = (
        "import { shardKey } from './web/js/core/matcher.js';"
        f"process.stdout.write(shardKey({json.dumps(ecosystem)}, {json.dumps(name)}));"
    )
    proc = subprocess.run(
        ["node", "--input-type=module", "-e", script],
        capture_output=True, text=True, check=True,
        cwd=Path(__file__).resolve().parent.parent,
    )
    assert shard_key(ecosystem, name) == proc.stdout, (
        f"샤드 키 불일치: py={shard_key(ecosystem, name)!r} js={proc.stdout!r}"
    )


def test_shard_key_buckets_non_alphanumeric_together():
    assert shard_key("npm", "@babel/core") == "npm-_"
    assert shard_key("npm", "_internal") == "npm-_"
    assert shard_key("rpm", "") == "rpm-_"


def test_shard_key_is_case_insensitive():
    assert shard_key("RPM", "XZ") == shard_key("rpm", "xz")


def make_finding():
    return Finding(
        installed=InstalledPackage("xz", "5.6.0-2.el9", "rpm", locations=("/var/lib/rpm",),
                                   purl="pkg:rpm/rocky/xz@5.6.0-2.el9"),
        advisory=AdvisoryPackage("xz", "rpm", "< 5.6.2", "5.6.2", FixState.FIXED_AVAILABLE, "rhel"),
        intel=VulnIntel(
            cve="CVE-2024-3094", severity=Severity.CRITICAL, cvss_score=10.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cwe=("CWE-506",), epss=0.9134, kev=Ternary.TRUE,
            exploit_available=Ternary.TRUE, exploit_maturity=ExploitMaturity.WEAPONIZED,
            exploit_sources=(ExploitSource("exploit_db", "EDB-52128", "검증됨"),),
            references=tuple(f"https://example.test/{i}" for i in range(20)),
        ),
        detection=Detection(matcher="rpm-matcher", match_type="exact-direct-match",
                            namespace="rocky:distro:rocky:9"),
    )


class TestIndexEntry:
    def test_entry_carries_constraint_not_installed_version(self):
        """인덱스는 '어떤 버전이 취약한가'를 안다. '무엇이 설치되어 있는가'는
        방문자가 올린 SBOM이 정한다."""
        entry = entry_from_finding(make_finding())
        assert entry["constraint"] == "< 5.6.2"
        assert entry["fixed_version"] == "5.6.2"
        assert "installed_version" not in entry
        assert "5.6.0-2.el9" not in json.dumps(entry, ensure_ascii=False)

    def test_entry_has_no_local_paths(self):
        entry = entry_from_finding(make_finding())
        assert "/var/lib/rpm" not in json.dumps(entry, ensure_ascii=False)
        assert "purl" not in entry

    def test_entry_carries_threat_intel_and_sources(self):
        entry = entry_from_finding(make_finding())
        assert entry["kev"] == "true"
        assert entry["epss"] == 0.9134
        assert entry["exploit_maturity"] == "weaponized"
        assert entry["exploit_sources"][0]["ref"] == "EDB-52128"

    def test_references_are_capped(self):
        """인덱스 크기를 무한정 키우지 않는다."""
        entry = entry_from_finding(make_finding())
        assert len(entry["references"]) <= 8

    def test_entry_is_json_serializable(self):
        json.dumps(entry_from_finding(make_finding()), ensure_ascii=False)
