"""업로드된 SBOM과 Grype 산출물의 파일 보관.

두 가지를 지킨다.

**메모리에 통째로 올리지 않는다.** 업로드는 청크로 흘러 들어와 청크로 디스크에
쓰인다. 100MB든 10GB든 어느 순간 메모리에 있는 것은 청크 하나뿐이다.

**gzip으로 보관한다.** SBOM JSON은 구조가 반복적이라 압축이 아주 잘 먹는다
(실측 25배 이상). 서버 100대를 24개월 보관해도 원본 234GB가 압축하면 9GB다.
100GB 디스크에서도 수년을 버틴다.

Grype는 압축 파일을 읽지 못하므로, 스캔할 때만 임시 파일로 풀어 경로를 넘긴다
(`open_plain`). 그 임시 파일은 스캔이 끝나면 지운다.
"""

from __future__ import annotations

import gzip
import shutil
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Iterator

from .sbom import SbomInfo, StreamingInspector

CHUNK = 1 << 20  # 1MB


class UploadTooLarge(Exception):
    """허용 크기를 넘었다. 부분 기록은 호출부가 지운다."""

    def __init__(self, limit_mb: int):
        self.limit_mb = limit_mb
        super().__init__(f"업로드 크기가 {limit_mb}MB를 넘습니다.")


@dataclass(frozen=True)
class StoredFile:
    path: Path
    stored_bytes: int      # 디스크에 실제로 쓴 크기 (압축본)
    original_bytes: int    # 압축 해제 기준 크기

    @property
    def compressed(self) -> bool:
        return self.path.suffix == ".gz"

    @property
    def ratio(self) -> float:
        return self.original_bytes / self.stored_bytes if self.stored_bytes else 1.0


def _target(base: Path, name: str, *, compress: bool) -> Path:
    return base / (f"{name}.gz" if compress else name)


@contextmanager
def _writer(path: Path, *, compress: bool) -> Iterator[IO[bytes]]:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = gzip.open(path, "wb", compresslevel=6) if compress else open(path, "wb")
    try:
        yield handle
    finally:
        handle.close()


async def store_stream(
    chunks,
    base: Path,
    name: str,
    *,
    compress: bool = True,
    limit_mb: int = 0,
) -> tuple[StoredFile, SbomInfo]:
    """비동기 청크 스트림을 받아 저장하면서 동시에 훑는다.

    한 번의 통과로 기록·해시·형식 판별·컴포넌트 계수가 모두 끝난다. 파일을 두 번
    읽지 않는 것이 요점이다 — 10GB를 두 번 읽으면 그것만으로도 오래 걸린다.

    한도를 넘으면 쓰다 만 파일을 지우고 `UploadTooLarge` 를 던진다.
    """
    path = _target(base, name, compress=compress)
    inspector = StreamingInspector()
    limit = limit_mb * 1024 * 1024
    total = 0

    try:
        with _writer(path, compress=compress) as out:
            async for chunk in chunks:
                if not chunk:
                    continue
                total += len(chunk)
                if limit and total > limit:
                    raise UploadTooLarge(limit_mb)
                out.write(chunk)
                inspector.feed(chunk)
    except BaseException:
        path.unlink(missing_ok=True)
        raise

    return (
        StoredFile(path=path, stored_bytes=path.stat().st_size, original_bytes=total),
        inspector.finish(),
    )


def store_bytes(payload: bytes, base: Path, name: str, *, compress: bool = True) -> StoredFile:
    """이미 메모리에 있는 것을 저장한다 (Grype 산출물 등)."""
    path = _target(base, name, compress=compress)
    with _writer(path, compress=compress) as out:
        out.write(payload)
    return StoredFile(path=path, stored_bytes=path.stat().st_size, original_bytes=len(payload))


def store_file(src: Path, base: Path, name: str, *, compress: bool = True) -> StoredFile:
    """디스크에 이미 있는 파일을 보관처로 옮긴다. **원본 바이트를 그대로 옮긴다.**

    Grype 원본을 보관할 때 쓴다. `dict` 를 다시 `json.dumps` 해서 저장하면 키 순서·
    공백·유니코드 이스케이프가 달라져 "Grype 가 실제로 낸 것"과 미묘하게 어긋난다.
    나중에 원본과 대조(`core.cli verify`)하는 것이 이 도구가 Grype 를 신뢰하는
    근거이므로, 바이트가 변하면 안 된다.

    청크로 흘려 쓰므로 파일이 몇 GB 여도 메모리는 일정하다. 옮긴 뒤 원본은 지운다.
    """
    src = Path(src)
    path = _target(base, name, compress=compress)
    with _writer(path, compress=compress) as out, open(src, "rb") as handle:
        shutil.copyfileobj(handle, out, CHUNK)
    original = src.stat().st_size
    src.unlink(missing_ok=True)
    return StoredFile(path=path, stored_bytes=path.stat().st_size, original_bytes=original)


def read_bytes(path: Path) -> bytes:
    """저장본을 읽는다. 압축 여부는 확장자로 판단한다."""
    path = Path(path)
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rb") as handle:
        return handle.read()


@contextmanager
def open_plain(path: Path) -> Iterator[Path]:
    """압축본을 임시 파일로 풀어 그 경로를 넘긴다.

    Grype는 `.gz` 를 읽지 못한다. 압축되지 않은 파일이면 그대로 넘기고 아무것도
    복사하지 않는다 — 10GB를 괜히 한 번 더 쓰지 않기 위함이다.
    """
    path = Path(path)
    if path.suffix != ".gz":
        yield path
        return

    tmp = Path(tempfile.mkdtemp(prefix="sbomsight-")) / path.name[: -len(".gz")]
    try:
        with gzip.open(path, "rb") as src, open(tmp, "wb") as dst:
            shutil.copyfileobj(src, dst, CHUNK)
        yield tmp
    finally:
        shutil.rmtree(tmp.parent, ignore_errors=True)


def dir_size(path: Path) -> int:
    """디렉터리가 실제로 쓰는 디스크 크기. 설정 화면의 사용량 표시에 쓴다."""
    path = Path(path)
    if not path.exists():
        return 0
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file())
