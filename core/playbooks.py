"""패치 플레이북 — 결정론적 권고 절차 생성.

패치 명령은 **AI가 아니라 여기서** 나온다. 이유는 두 가지다:

  1. AI가 없거나 꺼져 있어도 실행 가능한 권고가 항상 나와야 한다.
  2. 운영 서버에 입력될 명령어를 생성 모델에 맡기면 환각의 대가가 너무 크다.

AI는 이 절차를 만들지 않는다. 왜 이 조치가 필요한지를 설명할 뿐이다.

렌더링에는 설치 버전 같은 로컬 값이 들어가지만, 이 렌더링은 전부 로컬에서
일어나며 결과가 외부로 나가지 않는다.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import Config, get_config

# 생태계 → 플레이북 파일 이름
_PLAYBOOK_FOR = {
    "rpm": "rpm",
    "rhel": "rpm", "redhat": "rpm", "centos": "rpm", "rocky": "rpm",
    "almalinux": "rpm", "amazonlinux": "rpm", "sles": "rpm", "opensuse": "rpm",
    "deb": "deb", "dpkg": "deb", "debian": "deb", "ubuntu": "deb",
    "npm": "npm", "javascript": "npm", "node": "npm",
    "python": "pip", "pypi": "pip", "python-pkg": "pip", "wheel": "pip", "egg": "pip",
    "java-archive": "maven", "maven": "maven", "java": "maven", "jar": "maven",
}


@dataclass(frozen=True)
class Recommendation:
    """리포트 ⑤권고사항 절에 그대로 들어가는 구조."""

    ecosystem: str
    label: str
    action: str
    has_fix: bool
    precheck: tuple[str, ...] = ()
    online_title: str = ""
    online_steps: tuple[str, ...] = ()
    airgapped_title: str = ""
    airgapped_note: str = ""
    airgapped_steps: tuple[str, ...] = ()
    verification: tuple[str, ...] = ()
    mitigations: tuple[str, ...] = ()


class PlaybookLibrary:
    def __init__(self, directory: Path):
        self.directory = Path(directory)
        self._cache: dict[str, dict[str, Any]] = {}

    @classmethod
    def from_config(cls, config: Config | None = None) -> "PlaybookLibrary":
        config = config or get_config()
        return cls(config.rules_dir / "playbooks")

    def _load(self, name: str) -> dict[str, Any]:
        if name not in self._cache:
            path = self.directory / f"{name}.json"
            if not path.is_file():
                path = self.directory / "generic.json"
            self._cache[name] = json.loads(path.read_text(encoding="utf-8"))
        return self._cache[name]

    def for_ecosystem(self, ecosystem: str) -> dict[str, Any]:
        key = _PLAYBOOK_FOR.get((ecosystem or "").strip().lower(), "generic")
        return self._load(key)

    def build(
        self,
        *,
        ecosystem: str,
        package: str,
        installed_version: str,
        fixed_version: str,
        cve: str,
        os_family: str = "",
    ) -> Recommendation:
        """플레이북 템플릿에 실제 값을 채워 권고사항을 만든다."""
        book = self.for_ecosystem(ecosystem)
        has_fix = bool(fixed_version)

        values = {
            "package": package or "해당 패키지",
            "installed_version": installed_version or "(확인 필요)",
            "fixed_version": fixed_version or "(공개된 수정 버전 없음)",
            "cve": cve,
            "os_family": os_family,
        }

        def fill(template: str) -> str:
            out = template
            for key, value in values.items():
                out = out.replace("{" + key + "}", str(value))
            return out

        def fill_all(items: Any) -> tuple[str, ...]:
            return tuple(fill(str(i)) for i in (items or ()))

        action_key = "recommended_action" if has_fix else "recommended_action_no_fix"
        online = book.get("online") or {}
        airgapped = book.get("airgapped") or {}

        return Recommendation(
            ecosystem=book.get("ecosystem", "generic"),
            label=book.get("label", "일반"),
            action=fill(book.get(action_key, "")),
            has_fix=has_fix,
            precheck=fill_all(book.get("precheck")),
            online_title=online.get("title", ""),
            online_steps=fill_all(online.get("steps")) if has_fix else (),
            airgapped_title=airgapped.get("title", ""),
            airgapped_note=fill(airgapped.get("note", "")),
            airgapped_steps=fill_all(airgapped.get("steps")) if has_fix else (),
            verification=fill_all(book.get("verification")) if has_fix else (),
            # 수정 버전이 없을 때만 완화 방안을 전면에 낸다. 패치가 가능한데
            # 완화책을 나란히 놓으면 "패치 안 해도 된다"로 읽힐 수 있다.
            mitigations=fill_all(book.get("mitigation_when_no_fix")) if not has_fix else (),
        )
