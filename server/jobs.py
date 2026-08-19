"""스캔 작업 진행 상태 관리.

UI가 보여 줘야 하는 것은 "취약점 몇 개 발견"이 아니라 **근거가 쌓여가는
과정**이다. 그래서 파이프라인의 각 단계를 그대로 노출한다:

    SBOM 업로드 → 취약점 탐지 → 위협정보 보강 → 대응 우선순위
                → 대응 검토 근거 → 권고사항 → 보고서

메모리에만 둔다. 완료된 결과는 SQLite에 저장되므로 서버를 재시작해도
스캔 결과는 남고, 진행 중이던 작업만 사라진다. PC 한 대에서 도는 단독
도구라 이 정도로 충분하다.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# (키, 표시 이름) — 프론트엔드 스테퍼가 이 순서를 그대로 쓴다.
STEPS: tuple[tuple[str, str], ...] = (
    ("upload", "SBOM 업로드"),
    ("detect", "취약점 탐지"),
    ("enrich", "위협정보 보강"),
    ("prioritize", "대응 우선순위"),
    ("rationale", "대응 검토 근거"),
    ("recommend", "권고사항"),
    ("report", "보고서"),
)


@dataclass
class Step:
    key: str
    label: str
    state: str = "pending"      # pending / running / done / failed / skipped
    detail: str = ""
    metric: str = ""            # "1,204개", "87건 탐지" 처럼 UI에 바로 찍히는 값
    started_at: str = ""
    finished_at: str = ""


@dataclass
class Job:
    job_id: str
    scan_id: str = ""
    state: str = "running"      # running / done / failed
    error: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
    steps: list[Step] = field(default_factory=lambda: [Step(key=k, label=l) for k, l in STEPS])
    summary: dict[str, Any] = field(default_factory=dict)

    def step(self, key: str) -> Step:
        for step in self.steps:
            if step.key == key:
                return step
        raise KeyError(key)

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "scan_id": self.scan_id,
            "state": self.state,
            "error": self.error,
            "created_at": self.created_at,
            "summary": self.summary,
            "steps": [
                {
                    "key": s.key, "label": s.label, "state": s.state,
                    "detail": s.detail, "metric": s.metric,
                    "started_at": s.started_at, "finished_at": s.finished_at,
                }
                for s in self.steps
            ],
        }


class JobRegistry:
    def __init__(self, max_jobs: int = 50):
        self._jobs: dict[str, Job] = {}
        self._order: list[str] = []
        self._lock = threading.Lock()
        self._max = max_jobs

    def create(self) -> Job:
        job = Job(job_id=uuid.uuid4().hex[:12])
        with self._lock:
            self._jobs[job.job_id] = job
            self._order.append(job.job_id)
            while len(self._order) > self._max:
                self._jobs.pop(self._order.pop(0), None)
        return job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    # --- 단계 전이 -------------------------------------------------------

    def start(self, job: Job, key: str, detail: str = "") -> None:
        with self._lock:
            step = job.step(key)
            step.state = "running"
            step.detail = detail
            step.started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    def finish(self, job: Job, key: str, *, metric: str = "", detail: str = "") -> None:
        with self._lock:
            step = job.step(key)
            step.state = "done"
            step.metric = metric or step.metric
            step.detail = detail or step.detail
            step.finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    def skip(self, job: Job, key: str, detail: str) -> None:
        with self._lock:
            step = job.step(key)
            step.state = "skipped"
            step.detail = detail

    def fail(self, job: Job, key: str, error: str) -> None:
        with self._lock:
            step = job.step(key)
            step.state = "failed"
            step.detail = error
            job.state = "failed"
            job.error = error

    def complete(self, job: Job, scan_id: str, summary: dict[str, Any]) -> None:
        with self._lock:
            job.state = "done"
            job.scan_id = scan_id
            job.summary = summary
