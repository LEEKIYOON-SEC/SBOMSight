"""Grype 서브프로세스 래퍼.

`grype sbom:<파일> -o json` 을 돌려 원본 JSON을 받는다. 정규화는
core/normalize.py 가 맡는다.

폐쇄망/오프라인 운영을 염두에 두고 DB 자동 갱신 여부를 설정으로 끌 수 있게
환경변수를 그대로 전달한다 (GRYPE_DB_AUTO_UPDATE 등).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .config import Config, get_config
from .syft_runner import ToolExecutionError, ToolNotFoundError, _resolve, _run  # noqa: F401

__all__ = ["scan_sbom", "version", "db_status", "ToolNotFoundError", "ToolExecutionError"]


def version(config: Config | None = None) -> str:
    config = config or get_config()
    try:
        out = _run([_resolve(config.grype_bin), "version", "-o", "json"], 60)
        return str(json.loads(out).get("version") or "")
    except (ToolNotFoundError, ToolExecutionError, json.JSONDecodeError):
        return ""


def db_status(config: Config | None = None) -> dict[str, Any]:
    """취약점 DB 상태. 오프라인 운영에서 DB가 얼마나 낡았는지 알아야 한다."""
    config = config or get_config()
    try:
        out = _run([_resolve(config.grype_bin), "db", "status", "-o", "json"], 60)
        return json.loads(out)
    except (ToolNotFoundError, ToolExecutionError, json.JSONDecodeError):
        return {}


def scan_sbom(sbom_path: Path, *, config: Config | None = None) -> dict[str, Any]:
    """SBOM 파일을 Grype로 스캔해 원본 JSON 리포트를 돌려준다."""
    config = config or get_config()
    sbom_path = Path(sbom_path)
    if not sbom_path.is_file():
        raise FileNotFoundError(f"SBOM 파일이 없습니다: {sbom_path}")

    env = os.environ.copy()
    if config.offline:
        # 오프라인 모드에서는 DB 자동 갱신 시도를 막아 스캔이 네트워크에서
        # 멈추지 않게 한다. DB는 미리 `grype db import`로 넣어 둔다.
        env.setdefault("GRYPE_DB_AUTO_UPDATE", "false")
        env.setdefault("GRYPE_CHECK_FOR_APP_UPDATE", "false")

    argv = [_resolve(config.grype_bin), f"sbom:{sbom_path}", "-o", "json", "-q"]
    import subprocess

    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True,
            timeout=config.tool_timeout_sec, check=False, env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise ToolExecutionError(f"grype 실행이 {config.tool_timeout_sec}초를 넘겨 중단되었습니다.") from exc

    # grype는 --fail-on 없이도 취약점 발견 시 0이 아닌 코드를 낼 수 있어
    # stdout이 유효한 JSON이면 성공으로 본다.
    stdout = proc.stdout or ""
    if stdout.strip():
        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            pass
    tail = (proc.stderr or stdout or "").strip().splitlines()[-10:]
    raise ToolExecutionError(f"grype 실행 실패 (exit={proc.returncode})\n" + "\n".join(tail))
