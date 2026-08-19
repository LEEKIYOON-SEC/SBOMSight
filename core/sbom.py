"""SBOM 파싱 — CycloneDX JSON / SPDX JSON / Syft 네이티브 JSON.

여기서 나오는 것은 전부 `InstalledPackage`, 즉 **로컬 전용 계층**이다.
SBOM은 우리 자산의 구성 명세이며 통째로 내부 정보다.

같은 파싱을 브라우저(web/js/core/sbom.js)에서도 하므로 두 구현이 같은
패키지 집합을 뽑아내는지 파리티 테스트로 대조한다.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .models import InstalledPackage

# pkg:rpm/rocky/xz@5.6.0-2.el9?arch=x86_64  →  type=rpm, name=xz, version=5.6.0-2.el9
_PURL_RE = re.compile(
    r"^pkg:(?P<type>[^/]+)/(?P<rest>[^?#]+?)(?:@(?P<version>[^?#]+))?(?:[?#].*)?$"
)

# Syft가 CycloneDX/SPDX에 심어 두는 속성 키
_SYFT_TYPE_PROP = "syft:package:type"
_SYFT_LOCATION_PROP_RE = re.compile(r"^syft:location:\d+:path$")

_PURL_TYPE_ALIAS = {
    "pypi": "python",
    "golang": "go-module",
    "cargo": "rust-crate",
    "maven": "java-archive",
    "composer": "php-composer",
    "rubygems": "gem",
}


def _from_purl(purl: str) -> tuple[str, str, str]:
    """purl에서 (type, name, version)을 뽑는다."""
    m = _PURL_RE.match((purl or "").strip())
    if not m:
        return "", "", ""
    ptype = _PURL_TYPE_ALIAS.get(m.group("type").lower(), m.group("type").lower())
    rest = m.group("rest")
    name = rest.split("/")[-1]
    return ptype, name, m.group("version") or ""


def detect_format(payload: dict[str, Any]) -> str:
    """SBOM 문서의 형식을 알아낸다."""
    if not isinstance(payload, dict):
        return "unknown"
    if payload.get("bomFormat") == "CycloneDX" or "components" in payload and "specVersion" in payload:
        return "cyclonedx-json"
    if payload.get("spdxVersion") or "SPDXID" in payload:
        return "spdx-json"
    if "artifacts" in payload and "descriptor" in payload:
        return "syft-json"
    return "unknown"


def _parse_cyclonedx(payload: dict[str, Any]) -> list[InstalledPackage]:
    packages: list[InstalledPackage] = []
    for comp in payload.get("components") or ():
        if not isinstance(comp, dict):
            continue
        purl = str(comp.get("purl") or "")
        ptype_purl, name_purl, version_purl = _from_purl(purl)

        props = {}
        locations: list[str] = []
        for prop in comp.get("properties") or ():
            if not isinstance(prop, dict):
                continue
            key, value = str(prop.get("name") or ""), str(prop.get("value") or "")
            props[key] = value
            if _SYFT_LOCATION_PROP_RE.match(key) and value:
                locations.append(value)

        name = str(comp.get("name") or "") or name_purl
        version = str(comp.get("version") or "") or version_purl
        if not name:
            continue

        packages.append(
            InstalledPackage(
                name=name,
                version=version,
                type=props.get(_SYFT_TYPE_PROP, "") or ptype_purl,
                purl=purl,
                cpes=tuple(
                    str(cpe) for cpe in ([comp["cpe"]] if comp.get("cpe") else [])
                ),
                locations=tuple(locations),
                sbom_ref=str(comp.get("bom-ref") or ""),
            )
        )
    return packages


def _parse_spdx(payload: dict[str, Any]) -> list[InstalledPackage]:
    packages: list[InstalledPackage] = []
    for pkg in payload.get("packages") or ():
        if not isinstance(pkg, dict):
            continue
        purl = ""
        cpes: list[str] = []
        for ref in pkg.get("externalRefs") or ():
            if not isinstance(ref, dict):
                continue
            ref_type = str(ref.get("referenceType") or "").lower()
            locator = str(ref.get("referenceLocator") or "")
            if ref_type == "purl" and not purl:
                purl = locator
            elif ref_type.startswith("cpe"):
                cpes.append(locator)

        ptype, name_purl, version_purl = _from_purl(purl)
        name = str(pkg.get("name") or "") or name_purl
        version = str(pkg.get("versionInfo") or "") or version_purl
        if not name or name == "NOASSERTION":
            continue

        packages.append(
            InstalledPackage(
                name=name,
                version="" if version == "NOASSERTION" else version,
                type=ptype,
                purl=purl,
                cpes=tuple(cpes),
                sbom_ref=str(pkg.get("SPDXID") or ""),
            )
        )
    return packages


def _parse_syft(payload: dict[str, Any]) -> list[InstalledPackage]:
    packages: list[InstalledPackage] = []
    for art in payload.get("artifacts") or ():
        if not isinstance(art, dict):
            continue
        name = str(art.get("name") or "")
        if not name:
            continue
        locations = tuple(
            str(loc.get("path"))
            for loc in art.get("locations") or ()
            if isinstance(loc, dict) and loc.get("path")
        )
        packages.append(
            InstalledPackage(
                name=name,
                version=str(art.get("version") or ""),
                type=str(art.get("type") or ""),
                purl=str(art.get("purl") or ""),
                cpes=tuple(str(c) for c in art.get("cpes") or ()),
                locations=locations,
                language=str(art.get("language") or ""),
                sbom_ref=str(art.get("id") or ""),
            )
        )
    return packages


def parse(payload: dict[str, Any]) -> tuple[str, list[InstalledPackage]]:
    """SBOM 문서에서 (형식, 설치 패키지 목록)을 뽑는다."""
    fmt = detect_format(payload)
    if fmt == "cyclonedx-json":
        return fmt, _parse_cyclonedx(payload)
    if fmt == "spdx-json":
        return fmt, _parse_spdx(payload)
    if fmt == "syft-json":
        return fmt, _parse_syft(payload)
    return fmt, []


def load(path: Path) -> tuple[dict[str, Any], str, list[InstalledPackage], str]:
    """SBOM 파일을 읽어 (원문, 형식, 패키지, sha256)을 돌려준다."""
    raw = Path(path).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    payload = json.loads(raw.decode("utf-8"))
    fmt, packages = parse(payload)
    return payload, fmt, packages, digest
