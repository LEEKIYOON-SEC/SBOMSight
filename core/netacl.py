"""접속 IP 허용 목록.

로그인과는 별개의 층이다. 로그인은 "당신이 누구인가"를 묻고, 이쪽은 "그 자리에서
말을 걸어도 되는가"를 묻는다. 비밀번호가 새어도 허용 대역 밖에서는 로그인 화면
자체를 못 보는 것이 목적이다.

**소켓 상대방 주소만 본다.** `X-Forwarded-For` 같은 헤더는 누구든 원하는 값으로
채워 보낼 수 있으므로, 그것으로 접근을 결정하면 허용 목록이 있으나 마나 하다.
리버스 프록시 뒤에 둘 계획이라면 이 기능 대신 프록시에서 막아야 한다.

목록이 비어 있으면 제한 없음이다 — 켜 본 적 없는 운영자가 잠기지 않게.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Iterable

MetaKey = "access.allowed_ips"


def parse_entry(text: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """`192.168.10.0/24`, `10.0.0.5`, `::1` 을 모두 네트워크로 받는다.

    prefix 없는 단일 주소는 /32(또는 /128)로 본다. 운영자가 `10.0.0.5` 라고 쓰면
    그 한 대를 뜻한 것이지 대역을 뜻한 것이 아니다.
    """
    entry = (text or "").strip()
    if not entry:
        raise ValueError("빈 항목입니다.")
    try:
        return ipaddress.ip_network(entry, strict=False)
    except ValueError as exc:
        raise ValueError(f"IP 또는 CIDR 형식이 아닙니다: {entry}") from exc


def parse_list(raw: Iterable[str] | str) -> tuple[str, ...]:
    """쉼표·줄바꿈으로 구분된 목록을 정규화한다. 잘못된 항목은 그 자리에서 알린다."""
    if isinstance(raw, str):
        items = [part for chunk in raw.splitlines() for part in chunk.split(",")]
    else:
        items = list(raw)

    seen: list[str] = []
    for item in items:
        entry = (item or "").strip()
        if not entry:
            continue
        text = str(parse_entry(entry))
        if text not in seen:
            seen.append(text)
    return tuple(seen)


@dataclass(frozen=True)
class Allowlist:
    entries: tuple[str, ...] = ()

    @classmethod
    def parse(cls, raw: Iterable[str] | str) -> "Allowlist":
        return cls(parse_list(raw))

    @property
    def active(self) -> bool:
        return bool(self.entries)

    def permits(self, ip: str) -> bool:
        """목록이 비어 있으면 전부 허용. 주소를 못 읽으면 거부한다.

        주소를 못 읽는 경우(유닉스 소켓 등)를 허용으로 처리하면, 그 경로 하나로
        목록 전체가 무력화된다. 판단할 수 없으면 막는 쪽이 맞다.
        """
        if not self.entries:
            return True
        try:
            address = ipaddress.ip_address((ip or "").strip())
        except ValueError:
            return False
        return any(address in parse_entry(entry) for entry in self.entries)

    def to_text(self) -> str:
        return "\n".join(self.entries)
