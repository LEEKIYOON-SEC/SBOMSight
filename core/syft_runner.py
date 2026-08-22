"""Syft 서브프로세스 래퍼.

폐쇄망 안에서는 담당자가 직접 syft를 돌려 SBOM JSON을 반출하는 것이 실제
운영 절차다. 이 래퍼는 인터넷 되는 PC에서 샘플·데모용 SBOM을 만들거나,
디렉터리를 즉석에서 스캔할 때 쓴다.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .config import Config, get_config


class ToolNotFoundError(RuntimeError):
    pass


class ToolExecutionError(RuntimeError):
    pass


def _resolve(binary: str) -> str:
    found = shutil.which(binary)
    if not found:
        raise ToolNotFoundError(
            f"'{binary}' 실행 파일을 찾을 수 없습니다. "
            f"scripts/install-tools.sh (Linux) 또는 scripts/install-tools.ps1 (Windows)로 설치하거나 "
            f"SYFT_BIN/GRYPE_BIN 환경변수로 경로를 지정하세요."
        )
    return found


def decode(raw: bytes) -> str:
    """도구 출력은 **항상 UTF-8로 읽는다.**

    `text=True` 만 주면 파이썬이 시스템 로케일 인코딩으로 디코딩한다. 한국어
    Windows 에서는 그것이 CP949 이고, Syft·Grype 가 내는 UTF-8 바이트(예: `—`
    = 0xE2 0x80 0x94)를 만나는 순간 리더 스레드가 UnicodeDecodeError 로 죽는다.
    그러면 출력이 통째로 사라지고 "실행 실패 (exit=0)" 같은 엉뚱한 오류만 남는다.

    진단용 문자열이 몇 글자 깨지는 것보다 도구를 못 쓰게 되는 쪽이 훨씬 나쁘므로
    errors="replace" 로 읽는다.
    """
    return raw.decode("utf-8", errors="replace")


def _run(argv: list[str], timeout: int) -> str:
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise ToolExecutionError(f"{argv[0]} 실행이 {timeout}초를 넘겨 중단되었습니다.") from exc

    stdout, stderr = decode(proc.stdout or b""), decode(proc.stderr or b"")
    if proc.returncode != 0:
        tail = (stderr or stdout).strip().splitlines()[-10:]
        raise ToolExecutionError(
            f"{argv[0]} 실행 실패 (exit={proc.returncode})\n" + "\n".join(tail)
        )
    return stdout


def version(config: Config | None = None) -> str:
    config = config or get_config()
    try:
        out = _run([_resolve(config.syft_bin), "version", "-o", "json"], 60)
        return str(json.loads(out).get("version") or "")
    except (ToolNotFoundError, ToolExecutionError, json.JSONDecodeError):
        return ""


def generate_sbom(
    source: str,
    output_path: Path | None = None,
    *,
    output_format: str = "cyclonedx-json",
    config: Config | None = None,
) -> dict[str, Any]:
    """source(이미지·디렉터리·파일)에 대한 SBOM을 만들어 dict로 돌려준다.

    source 예: 'rockylinux:9.3', 'dir:/opt/app', '/path/to/file'
    """
    config = config or get_config()
    argv = [_resolve(config.syft_bin), "scan", source, "-o", output_format, "-q"]
    raw = _run(argv, config.tool_timeout_sec)
    sbom = json.loads(raw)
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(sbom, indent=2), encoding="utf-8")
    return sbom
