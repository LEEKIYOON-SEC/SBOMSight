"""SBOM 파싱 — CycloneDX JSON / SPDX JSON / Syft 네이티브 JSON.

여기서 나오는 것은 전부 `InstalledPackage`, 즉 **로컬 전용 계층**이다.
SBOM은 우리 자산의 구성 명세이며 통째로 내부 정보다.

**대용량 SBOM은 통째로 읽지 않는다.** 실제 서버 한 대의 SBOM은 100MB를 넘고,
`json.load()`는 입력의 6배 남짓한 메모리를 쓴다(실측). 1GB짜리면 6GB, 10GB면
62GB가 필요해 PC에서는 불가능하다.

그럴 이유도 없다. 우리가 SBOM에서 필요한 것은 **형식과 컴포넌트 수 두 개뿐**이고,
취약점 매칭은 Grype가 파일 경로를 직접 읽어 처리한다. 그래서 `inspect()`는 파일을
청크로 훑으며 형식·개수·해시만 뽑는다 — 파일 크기와 무관하게 메모리가 일정하다.

`parse()`는 이미 메모리에 있는 문서(예: syft를 방금 실행해 받은 dict)를 다룰 때만 쓴다.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

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
    """SBOM 파일 전체를 읽어 (원문, 형식, 패키지, sha256)을 돌려준다.

    ⚠ 파일 크기의 6배 남짓한 메모리를 쓴다. 실 서버 SBOM(100MB+)에는 쓰지 말고
    `inspect()`를 쓰라. 이 함수는 패키지 목록 자체가 필요한 곳(테스트, 소형 문서)
    에만 남겨 둔다.
    """
    raw = Path(path).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    payload = json.loads(raw.decode("utf-8"))
    fmt, packages = parse(payload)
    return payload, fmt, packages, digest


# ---------------------------------------------------------------------------
# 스트리밍 훑기 — 파일을 통째로 올리지 않고 형식·개수·해시만 뽑는다
# ---------------------------------------------------------------------------

# 형식 판별은 파일 앞부분만 보면 된다. 세 형식 모두 문서 첫머리에 표지가 있다:
#   CycloneDX  {"$schema":…,"bomFormat":"CycloneDX",…
#   SPDX       {"spdxVersion":"SPDX-2.3",…
#   Syft       {"artifacts":[…
_HEAD_PROBE = 64 * 1024

# 형식별로 컴포넌트가 담기는 배열의 키.
_ARRAY_KEY = {
    "cyclonedx-json": b'"components"',
    "spdx-json": b'"packages"',
    "syft-json": b'"artifacts"',
}

# 배열 원소를 **정확히** 센다. 표지 문자열을 세는 방법도 생각했지만
# (`"bom-ref"` 등) 그 필드가 없는 SBOM이 실제로 존재해서 0개로 세어 버린다.
#
# 한때는 큰 파일에서 세기를 포기하고 "미상"을 내는 예산 제한을 두었는데 걷어냈다.
# 이 도구는 운영용이고, 화면에 뜨는 숫자는 전부 정확해야 한다. 시간이 더 걸리는
# 것은 감수할 수 있지만 불확실한 숫자를 남기는 것은 감수 대상이 아니다.
# 구조 문자만 골라 훑으므로 실측 약 24MB/s — 100MB가 4초로 파일을 받는 시간보다 짧다.
_STRUCTURAL = re.compile(rb'["{}\[\]\\]')


class _ArrayCounter:
    """JSON 배열의 원소 개수를 청크 단위로 정확히 센다.

    문자열 안의 중괄호와 이스케이프를 제대로 건너뛴다 — 라이선스 본문이나
    설명에 `{` 가 들어 있어도 깊이 계산이 틀어지지 않는다.
    """

    def __init__(self, key: bytes):
        self._key = key
        self._seeking = True          # 아직 배열을 못 찾았다
        self._tail = b""              # 키가 청크 경계에 걸릴 때를 위한 꼬리
        self._depth = 0
        self._in_str = False
        # 이스케이프는 "다음 바이트 하나"에만 걸린다. 불리언으로 들고 있으면
        # `\n` 처럼 이스케이프 대상이 구조 문자가 아닐 때 플래그가 남아, 그 뒤에
        # 오는 진짜 구조 문자를 삼켜 버린다. 그래서 위치로 기억한다.
        self._esc_next = False
        self.count = 0
        self.done = False

    def feed(self, chunk: bytes) -> None:
        if self.done:
            return

        if self._seeking:
            window = self._tail + chunk
            at = window.find(self._key)
            if at < 0:
                keep = len(self._key) - 1
                self._tail = window[-keep:] if keep else b""
                return
            bracket = window.find(b"[", at + len(self._key))
            if bracket < 0:
                # 키는 찾았지만 대괄호가 다음 청크에 있다. 키 뒤부터 다시 본다.
                self._tail = window[at:]
                return
            self._seeking = False
            self._tail = b""
            chunk, self._depth = window[bracket:], 0

        # 이 청크에서 이스케이프된 바이트의 위치. -1은 없음.
        # 직전 청크가 역슬래시로 끝났으면 이 청크의 첫 바이트가 그 대상이다.
        escaped_at = 0 if self._esc_next else -1
        self._esc_next = False

        for match in _STRUCTURAL.finditer(chunk):
            index = match.start()
            if index == escaped_at:
                continue                      # 이스케이프된 문자다. 구조가 아니다.
            char = match.group()
            if self._in_str:
                if char == b"\\":
                    escaped_at = index + 1
                    if escaped_at == len(chunk):
                        self._esc_next = True
                elif char == b'"':
                    self._in_str = False
                continue
            if char == b'"':
                self._in_str = True
            elif char in b"[{":
                if self._depth == 1 and char == b"{":
                    self.count += 1
                self._depth += 1
            else:
                self._depth -= 1
                if self._depth == 0:
                    self.done = True
                    return

    @property
    def result(self) -> int | None:
        if self._seeking:
            return None
        return self.count


@dataclass(frozen=True)
class SbomInfo:
    """SBOM 파일을 훑어 얻은 것. 패키지 목록은 들어 있지 않다."""

    format: str
    component_count: int | None      # None = 형식을 몰라 셀 수 없었음
    sha256: str
    size: int

    @property
    def count_label(self) -> str:
        return "미상" if self.component_count is None else f"{self.component_count:,}개"


class StreamingInspector:
    """청크를 먹여 주면 형식·컴포넌트 수·sha256을 한 번에 계산한다.

    업로드 핸들러가 받은 바이트를 그대로 흘려보내면 디스크 기록·해시·집계가
    한 번의 통과로 끝난다. 어느 순간에도 메모리에 있는 것은 청크 하나뿐이다.
    """

    def __init__(self) -> None:
        self._digest = hashlib.sha256()
        self._size = 0
        self._head = bytearray()
        # None = 아직 판별 전. "unknown" 도 판별 결과이므로 빈 문자열과 구분해야
        # 한다 — 구분하지 않으면 첫 청크에서 "unknown" 으로 잠겨 버린다.
        self._format: str | None = None
        self._counter: _ArrayCounter | None = None
        self._pending: list[bytes] = []   # 형식 판별 전에 들어온 청크

    def feed(self, chunk: bytes) -> None:
        if not chunk:
            return
        self._digest.update(chunk)
        self._size += len(chunk)

        # 앞부분이 다 찰 때까지는 계속 다시 판별한다. 표지가 첫 청크 뒤에
        # 오더라도 잡히게 하기 위함이다.
        if self._format is None:
            self._head.extend(chunk[: _HEAD_PROBE - len(self._head)])
            probed = _detect_format_bytes(bytes(self._head))
            if probed != "unknown" or len(self._head) >= _HEAD_PROBE:
                self._format = probed
                key = _ARRAY_KEY.get(probed)
                if key:
                    self._counter = _ArrayCounter(key)
                    # 판별 전에 흘려보낸 청크를 계수기에 다시 먹인다.
                    for held in self._pending:
                        self._counter.feed(held)
                self._pending.clear()
            else:
                self._pending.append(chunk)
                return

        if self._counter:
            self._counter.feed(chunk)

    def finish(self) -> SbomInfo:
        fmt = self._format if self._format is not None else _detect_format_bytes(bytes(self._head))
        return SbomInfo(
            format=fmt,
            component_count=self._counter.result if self._counter else None,
            sha256=self._digest.hexdigest(),
            size=self._size,
        )


def _detect_format_bytes(head: bytes) -> str:
    """파일 앞부분 바이트만으로 형식을 판별한다."""
    if b'"bomFormat"' in head or b'"CycloneDX"' in head:
        return "cyclonedx-json"
    if b'"spdxVersion"' in head or b'"SPDXID"' in head:
        return "spdx-json"
    if b'"artifacts"' in head:
        return "syft-json"
    return "unknown"


def _open_maybe_gzip(path: Path) -> BinaryIO:
    """`.gz` 로 저장된 것과 원본을 같은 방식으로 연다."""
    if Path(path).suffix == ".gz":
        return gzip.open(path, "rb")
    return open(path, "rb")


def inspect(path: Path, *, chunk_size: int = 1 << 20) -> SbomInfo:
    """SBOM 파일을 훑어 형식·컴포넌트 수·sha256을 얻는다.

    파일 크기와 무관하게 메모리는 청크 하나(기본 1MB)에 머문다.
    `.gz` 파일도 그대로 받는다 — 해시는 **압축 해제본** 기준이다.
    """
    inspector = StreamingInspector()
    with _open_maybe_gzip(Path(path)) as handle:
        while chunk := handle.read(chunk_size):
            inspector.feed(chunk)
    return inspector.finish()
