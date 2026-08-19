"""SBOM 파서 테스트 (CycloneDX / SPDX / Syft 네이티브)."""

import pytest

from core import sbom


CYCLONEDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": [
        {
            "type": "library", "name": "xz", "version": "5.6.0-2.el9", "bom-ref": "ref-1",
            "purl": "pkg:rpm/rocky/xz@5.6.0-2.el9?arch=x86_64",
            "properties": [
                {"name": "syft:package:type", "value": "rpm"},
                {"name": "syft:location:0:path", "value": "/var/lib/rpm/rpmdb.sqlite"},
            ],
        },
        {"type": "library", "name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"},
        {"type": "library", "name": "cross-spawn", "version": "7.0.3", "purl": "pkg:npm/cross-spawn@7.0.3"},
    ],
}

SPDX = {
    "spdxVersion": "SPDX-2.3",
    "packages": [
        {
            "name": "openssl", "versionInfo": "3.0.7-24.el9", "SPDXID": "SPDXRef-Package-1",
            "externalRefs": [
                {"referenceType": "purl", "referenceLocator": "pkg:rpm/rocky/openssl@3.0.7-24.el9"},
                {"referenceType": "cpe23Type", "referenceLocator": "cpe:2.3:a:openssl:openssl:3.0.7:*:*:*:*:*:*:*"},
            ],
        },
        {"name": "NOASSERTION", "versionInfo": "NOASSERTION"},
    ],
}

SYFT_NATIVE = {
    "descriptor": {"name": "syft", "version": "1.18.0"},
    "artifacts": [
        {
            "id": "abc", "name": "zlib", "version": "1.2.11-40.el9", "type": "rpm",
            "purl": "pkg:rpm/rocky/zlib@1.2.11-40.el9",
            "locations": [{"path": "/var/lib/rpm/rpmdb.sqlite"}],
        }
    ],
}


def test_detect_and_parse_cyclonedx():
    fmt, packages = sbom.parse(CYCLONEDX)
    assert fmt == "cyclonedx-json"
    assert len(packages) == 3
    xz = packages[0]
    assert (xz.name, xz.version, xz.type) == ("xz", "5.6.0-2.el9", "rpm")
    assert xz.locations == ("/var/lib/rpm/rpmdb.sqlite",)
    assert xz.sbom_ref == "ref-1"


def test_type_derived_from_purl_when_no_syft_property():
    _, packages = sbom.parse(CYCLONEDX)
    # pkg:pypi/... → python, pkg:npm/... → npm 으로 정규화되어야
    # comparator_for()가 pep440/semver를 고를 수 있다.
    assert packages[1].type == "python"
    assert packages[2].type == "npm"


def test_detect_and_parse_spdx():
    fmt, packages = sbom.parse(SPDX)
    assert fmt == "spdx-json"
    # NOASSERTION 항목은 버린다 — 이름 없는 패키지는 매칭할 수 없다.
    assert len(packages) == 1
    assert packages[0].name == "openssl"
    assert packages[0].type == "rpm"
    assert packages[0].cpes[0].startswith("cpe:2.3:a:openssl")


def test_detect_and_parse_syft_native():
    fmt, packages = sbom.parse(SYFT_NATIVE)
    assert fmt == "syft-json"
    assert packages[0].name == "zlib"
    assert packages[0].locations == ("/var/lib/rpm/rpmdb.sqlite",)


def test_unknown_format_yields_no_packages():
    fmt, packages = sbom.parse({"hello": "world"})
    assert fmt == "unknown"
    assert packages == []


@pytest.mark.parametrize(
    "purl,expected",
    [
        ("pkg:rpm/rocky/xz@5.6.0-2.el9?arch=x86_64", ("rpm", "xz", "5.6.0-2.el9")),
        ("pkg:pypi/requests@2.31.0", ("python", "requests", "2.31.0")),
        ("pkg:golang/github.com/gin-gonic/gin@v1.9.0", ("go-module", "gin", "v1.9.0")),
        ("pkg:maven/org.apache/commons@1.0", ("java-archive", "commons", "1.0")),
        ("not-a-purl", ("", "", "")),
    ],
)
def test_purl_parsing(purl, expected):
    assert sbom._from_purl(purl) == expected


def test_load_reads_file_and_hashes(tmp_path):
    import json

    path = tmp_path / "sbom.json"
    path.write_text(json.dumps(CYCLONEDX))
    payload, fmt, packages, digest = sbom.load(path)
    assert fmt == "cyclonedx-json"
    assert len(packages) == 3
    assert len(digest) == 64
    assert payload["bomFormat"] == "CycloneDX"
