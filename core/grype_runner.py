"""Grype 서브프로세스 래퍼.

`grype sbom:<파일> -o json` 을 돌려 원본 JSON을 받는다. 정규화는
core/normalize.py 가 맡는다.

폐쇄망/오프라인 운영을 염두에 두고 DB 자동 갱신 여부를 설정으로 끌 수 있게
환경변수를 그대로 전달한다 (GRYPE_DB_AUTO_UPDATE 등).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .config import Config, get_config
from .syft_runner import (  # noqa: F401
    ToolExecutionError,
    ToolNotFoundError,
    _resolve,
    _run,
    decode,
)

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


def scan_sbom(
    sbom_path: Path,
    *,
    config: Config | None = None,
    raw_out: Path | None = None,
) -> dict[str, Any]:
    """SBOM 파일을 Grype로 스캔해 원본 JSON 리포트를 돌려준다.

    **stdout 을 파이프가 아니라 파일로 받는다.** 이유가 둘 있다.

    1. 파이프로 받으면 파이썬이 리더 스레드에서 즉시 디코딩하는데, 그 인코딩이
       시스템 로케일(한국어 Windows 에서는 CP949)이다. Grype 가 내는 UTF-8
       바이트를 만나면 스레드가 UnicodeDecodeError 로 죽고, 출력이 통째로
       사라진 채 "실행 실패 (exit=0)" 같은 엉뚱한 오류만 남는다. 파일로 받으면
       바이트가 그대로 디스크에 앉고 우리가 UTF-8 로 읽는다.
    2. 서버 한 대의 결과가 수십 MB 다. 파이프 버퍼와 파이썬 문자열을 거치지
       않고 바로 앉히는 편이 메모리에도 낫고, 그 파일이 곧 보관본이 된다.

    raw_out: Grype 원본을 남길 경로. 주지 않으면 임시 파일에 받고 지운다.
    """
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

    with _output_file(raw_out) as out_path:
        try:
            with open(out_path, "wb") as sink:
                proc = subprocess.run(
                    argv, stdout=sink, stderr=subprocess.PIPE,
                    timeout=config.tool_timeout_sec, check=False, env=env,
                )
        except subprocess.TimeoutExpired as exc:
            raise ToolExecutionError(
                f"grype 실행이 {config.tool_timeout_sec}초를 넘겨 중단되었습니다."
            ) from exc

        stderr = decode(proc.stderr or b"")
        size = out_path.stat().st_size if out_path.exists() else 0

        # grype는 취약점을 찾으면 0이 아닌 코드를 낼 수 있으므로, 종료 코드가
        # 아니라 **출력이 유효한 JSON인가**로 성공을 판단한다.
        if size:
            raw = out_path.read_bytes()
            try:
                return json.loads(decode(raw))
            except json.JSONDecodeError as exc:
                head = decode(raw[:400]).strip()
                raise ToolExecutionError(
                    f"grype 출력을 JSON으로 읽지 못했습니다 (exit={proc.returncode}, "
                    f"{size:,} bytes).\n출력 앞부분: {head}"
                    + (f"\ngrype 오류: {stderr.strip()}" if stderr.strip() else "")
                ) from exc

        detail = stderr.strip() or "grype가 아무 출력도 내지 않았습니다."
        raise ToolExecutionError(
            f"grype 실행 실패 (exit={proc.returncode})\n"
            + "\n".join(detail.splitlines()[-10:])
        )


@contextmanager
def _output_file(raw_out: Path | None):
    """Grype 출력을 받을 경로. 지정이 없으면 임시 파일을 쓰고 지운다."""
    if raw_out is not None:
        raw_out = Path(raw_out)
        raw_out.parent.mkdir(parents=True, exist_ok=True)
        yield raw_out
        return

    tmp_dir = Path(tempfile.mkdtemp(prefix="sbomsight-grype-"))
    try:
        yield tmp_dir / "grype.json"
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
