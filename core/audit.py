"""이그레스 감사 로그.

외부로 나간 것이 무엇인지 나중에 확인할 수 있어야 한다. "공개 데이터만
보냈습니다"라는 주장은 검증할 수 없으면 주장일 뿐이다.

기록 대상:
  - 전송 시도 전체 (성공·차단 모두)
  - payload 원문과 SHA-256
  - 적용된 이그레스 정책의 버전·해시
  - 차단된 경우 어떤 규칙에 왜 걸렸는지

JSON Lines로 쌓으며, data/audit/ 아래에 남는다(.gitignore 대상).
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_lock = threading.Lock()


def payload_hash(payload: Any) -> str:
    """전송 payload의 안정적인 해시. 키 순서와 공백에 흔들리지 않는다."""
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass
class EgressRecord:
    timestamp: str
    action: str                       # preview / send / blocked
    outcome: str                      # allowed / blocked / error
    fact_count: int
    payload_sha256: str
    policy_version: str
    policy_sha256: str
    scan_id: str = ""
    model: str = ""
    violations: list[dict[str, str]] = field(default_factory=list)
    error: str = ""
    payload: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AuditLog:
    def __init__(self, directory: Path, *, keep_payload: bool = True):
        """keep_payload: payload 원문을 함께 남길지.

        기본값 True다. 해시만 남기면 "무엇을 보냈는가"를 사후에 확인할 수
        없어 감사 로그의 목적을 잃는다. 이 로그 자체가 내부 자산이 아니라
        '외부로 나간 공개 데이터'의 사본이므로 보관해도 위험이 늘지 않는다.
        """
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.keep_payload = keep_payload

    @property
    def path(self) -> Path:
        day = datetime.now(timezone.utc).strftime("%Y%m%d")
        return self.directory / f"egress-{day}.jsonl"

    def record(
        self,
        *,
        action: str,
        outcome: str,
        facts: list[dict[str, Any]],
        policy_version: str = "",
        policy_sha256: str = "",
        scan_id: str = "",
        model: str = "",
        violations: list[dict[str, str]] | None = None,
        error: str = "",
    ) -> EgressRecord:
        record = EgressRecord(
            timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            action=action,
            outcome=outcome,
            fact_count=len(facts),
            payload_sha256=payload_hash(facts),
            policy_version=policy_version,
            policy_sha256=policy_sha256,
            scan_id=scan_id,
            model=model,
            violations=violations or [],
            error=error,
            payload=facts if self.keep_payload else [],
        )
        line = json.dumps(record.to_dict(), ensure_ascii=False)
        with _lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        return record

    def tail(self, limit: int = 50) -> list[dict[str, Any]]:
        """최근 기록. UI에서 "무엇이 언제 나갔는가"를 보여 줄 때 쓴다."""
        records: list[dict[str, Any]] = []
        for path in sorted(self.directory.glob("egress-*.jsonl"), reverse=True):
            lines = path.read_text(encoding="utf-8").splitlines()
            for line in reversed(lines):
                if not line.strip():
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
                if len(records) >= limit:
                    return records
        return records
