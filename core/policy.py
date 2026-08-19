"""정책 파일 로딩 · 병합 · 해시.

정책은 전부 JSON이다. YAML이 아닌 이유는 브라우저가 의존성 없이 같은
파일을 읽어야 하기 때문이다 (web/js/core/*.js 가 fetch로 그대로 읽는다).

로드 결과에는 항상 **버전과 sha256이 따라붙는다.** 리포트에 이 값을 적어
두어야 "어떤 기준으로 판정했는지"를 나중에 추적할 수 있다. 임계값을 조용히
바꾸고 예전 리포트를 다시 해석하는 사고를 막기 위한 것이다.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class LoadedPolicy:
    data: dict[str, Any]
    version: str
    sha256: str
    sources: tuple[str, ...]

    @property
    def label(self) -> str:
        """리포트에 그대로 실을 수 있는 한 줄 표기."""
        names = " + ".join(self.sources)
        return f"{names} v{self.version} (sha256:{self.sha256[:12]})"


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """오버라이드를 기본 위에 얹는다.

    dict는 키 단위로 재귀 병합하고, list는 통째로 교체한다. `levels` 같은
    순서 있는 목록을 부분 병합하면 의미가 뒤틀리기 때문이다 — 바꾸려면
    전체를 다시 쓰게 한다.
    """
    result = dict(base)
    for key, value in override.items():
        if key.startswith("_"):          # _comment 등 주석 키는 무시
            continue
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = value
    return result


def _strip_comments(data: Any) -> Any:
    if isinstance(data, dict):
        return {k: _strip_comments(v) for k, v in data.items() if not k.startswith("_")}
    if isinstance(data, list):
        return [_strip_comments(v) for v in data]
    return data


def canonical_hash(data: dict[str, Any]) -> str:
    """정책 내용의 안정적인 해시. 키 순서와 공백에 흔들리지 않는다."""
    blob = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def load(default_path: Path, override_path: Path | None = None) -> LoadedPolicy:
    """기본 정책을 읽고, 오버라이드가 있으면 병합한다."""
    default_path = Path(default_path)
    data = _strip_comments(json.loads(default_path.read_text(encoding="utf-8")))
    sources = [default_path.name]

    if override_path is not None:
        override_path = Path(override_path)
        if override_path.is_file():
            override = _strip_comments(json.loads(override_path.read_text(encoding="utf-8")))
            data = _merge(data, override)
            sources.append(override_path.name)

    return LoadedPolicy(
        data=data,
        version=str(data.get("version") or "0"),
        sha256=canonical_hash(data),
        sources=tuple(sources),
    )
