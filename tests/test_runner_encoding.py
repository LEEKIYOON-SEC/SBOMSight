"""도구 출력 인코딩 회귀 테스트.

한국어 Windows 에서 실제로 터진 것을 고정한다.

    UnicodeDecodeError: 'cp949' codec can't decode byte 0xe2 in position 144239

원인은 `subprocess.run(..., text=True)` 였다. `text=True` 만 주면 파이썬이
자식 프로세스 출력을 **시스템 로케일 인코딩**으로 디코딩한다. 한국어 Windows 에서
그것은 CP949 이고, Grype·Syft 가 내는 UTF-8 바이트(`—` = E2 80 94 등)를 만나는
순간 표준출력 리더 스레드가 예외로 죽는다. 출력은 통째로 사라지고 종료 코드만
남아 "grype 실행 실패 (exit=0)" 이라는 앞뒤 안 맞는 오류가 화면에 뜬다.

여기서는 그 상황을 로케일에 의존하지 않고 재현한다 — 비ASCII UTF-8 을 내는
가짜 도구를 만들어 실행하고, 우리 래퍼가 그것을 온전히 읽는지 본다. 개발기는
UTF-8 로케일이라 회귀가 나도 통과해 버릴 수 있으므로, CP949 로 디코딩하면
실제로 깨지는 바이트열인지도 함께 확인한다.
"""

from __future__ import annotations

import ast
import json
import os
import sys
import tempfile
import textwrap
from pathlib import Path

import pytest

from core import grype_runner
from core.config import Config
from core.syft_runner import ToolExecutionError, decode

# Grype 가 실제로 내는 종류의 비ASCII. CP949 에 없는 문자를 일부러 고른다.
TRICKY = "libxml2 — 취약점 설명 · CVE‑2024‑25062 “인용부호” ✓"


def test_tricky_text_is_undecodable_as_cp949():
    """이 테스트가 무엇을 막고 있는지에 대한 전제 확인.

    이 바이트열이 CP949 로 그냥 읽히는 것이었다면 아래 테스트들은 아무것도
    증명하지 못한다.
    """
    raw = TRICKY.encode("utf-8")
    with pytest.raises(UnicodeDecodeError):
        raw.decode("cp949")


def test_decode_reads_utf8_regardless_of_locale():
    assert decode(TRICKY.encode("utf-8")) == TRICKY


def test_decode_never_raises_on_broken_bytes():
    """진단 문자열 몇 글자가 깨지는 것보다 도구를 못 쓰게 되는 쪽이 나쁘다."""
    assert decode(b"\xff\xfe not utf-8") .endswith("not utf-8")


def _fake_grype(
    tmp_path: Path, monkeypatch, *, stdout: str, stderr: str = "", code: int = 0
) -> Config:
    """비ASCII UTF-8 을 바이트로 내뱉는 **진짜 실행 파일**을 만들어 붙인다.

    subprocess 를 가짜로 바꾸지 않는다. 버그가 있던 자리가 정확히 subprocess 의
    디코딩 동작이었으므로, 그 경로를 그대로 통과시켜야 의미가 있다.

    스크립트가 print() 를 쓰지 않는 것도 같은 이유다 — 파이썬의 stdout 인코딩이
    끼어들면 재현하려는 조건이 흐려진다. 버퍼에 바이트를 직접 쓴다.
    """
    script = tmp_path / "fake_grype.py"
    script.write_text(
        textwrap.dedent(
            f"""
            import sys
            sys.stdout.buffer.write({stdout.encode("utf-8")!r})
            sys.stderr.buffer.write({stderr.encode("utf-8")!r})
            sys.exit({code})
            """
        ).strip(),
        encoding="utf-8",
    )

    if os.name == "nt":
        shim = tmp_path / "grype.cmd"
        shim.write_text(f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n', encoding="ascii")
    else:
        shim = tmp_path / "grype"
        shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n', encoding="ascii")
        shim.chmod(0o755)

    # `_resolve` 는 PATH 를 뒤진다. 우리 shim 을 PATH 앞에 놓아 실제로 찾히게 한다.
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ.get("PATH", ""))

    config = Config(data_dir=tmp_path / "data")
    config.grype_bin = "grype"
    config.tool_timeout_sec = 60
    return config


def _sbom(tmp_path: Path) -> Path:
    path = tmp_path / "sbom.json"
    path.write_text("{}", encoding="utf-8")
    return path


def test_scan_sbom_reads_non_ascii_output(tmp_path, monkeypatch):
    """CP949 로는 못 읽는 출력을 grype 가 내도 스캔이 끝까지 간다."""
    payload = {
        "matches": [],
        "descriptor": {"name": "grype", "version": "0.100.0"},
        "note": TRICKY,
    }
    config = _fake_grype(tmp_path, monkeypatch, stdout=json.dumps(payload, ensure_ascii=False))

    raw = grype_runner.scan_sbom(_sbom(tmp_path), config=config)
    assert raw["note"] == TRICKY
    assert raw["descriptor"]["version"] == "0.100.0"


def test_scan_sbom_keeps_raw_bytes_when_asked(tmp_path, monkeypatch):
    """`raw_out` 을 주면 Grype 가 낸 바이트가 그대로 그 자리에 앉는다.

    나중에 `core.cli verify` 로 원본과 대조하는 것이 우리가 Grype 를 신뢰하는
    근거이므로, 바이트가 파이썬을 거치며 달라지면 안 된다.
    """
    body = json.dumps({"matches": [], "note": TRICKY}, ensure_ascii=False)
    config = _fake_grype(tmp_path, monkeypatch, stdout=body)
    raw_out = tmp_path / "keep" / "grype.json"

    grype_runner.scan_sbom(_sbom(tmp_path), config=config, raw_out=raw_out)
    assert raw_out.read_bytes() == body.encode("utf-8")


def test_scan_sbom_cleans_up_temp_output(tmp_path, monkeypatch):
    """`raw_out` 없이 돌리면 임시 파일이 남지 않는다."""
    config = _fake_grype(tmp_path, monkeypatch, stdout=json.dumps({"matches": []}))

    before = set(Path(tempfile.gettempdir()).glob("sbomsight-grype-*"))
    grype_runner.scan_sbom(_sbom(tmp_path), config=config)
    assert set(Path(tempfile.gettempdir()).glob("sbomsight-grype-*")) == before


def test_scan_sbom_reports_stderr_when_nothing_came_out(tmp_path, monkeypatch):
    """출력이 없으면 grype 가 왜 실패했는지를 그대로 보여 준다.

    예전에는 stdout 디코딩이 죽으면서 출력이 사라져 exit=0 인데 실패라는 말만
    남았다. 이제 실패 사유는 grype 의 stderr 다.
    """
    config = _fake_grype(
        tmp_path, monkeypatch, stdout="", stderr="데이터베이스를 열 수 없습니다 —", code=1
    )

    with pytest.raises(ToolExecutionError) as caught:
        grype_runner.scan_sbom(_sbom(tmp_path), config=config)
    assert "데이터베이스를 열 수 없습니다" in str(caught.value)


def test_scan_sbom_shows_head_of_unparsable_output(tmp_path, monkeypatch):
    """JSON이 아닌 출력이면 앞부분을 보여 준다 — 침묵보다 낫다."""
    config = _fake_grype(tmp_path, monkeypatch, stdout="이것은 JSON이 아닙니다 —")

    with pytest.raises(ToolExecutionError) as caught:
        grype_runner.scan_sbom(_sbom(tmp_path), config=config)
    assert "이것은 JSON이 아닙니다" in str(caught.value)


def test_no_subprocess_call_relies_on_locale_encoding():
    """`text=True` / `universal_newlines=True` 가 코드베이스에 다시 들어오는 것을 막는다.

    바로 그 인자가 파이썬을 시스템 로케일로 디코딩하게 만들고, 한국어 Windows 에서
    도구를 통째로 못 쓰게 만들었다. 바이트로 받아 `decode()` 로 읽어야 한다.
    """
    root = Path(__file__).resolve().parent.parent
    banned = {"text", "universal_newlines"}
    offenders = []

    # 문자열 검색이 아니라 AST 로 본다. 이 파일과 core/syft_runner.py 의 주석이
    # 바로 그 인자를 설명하고 있어서, 평문 검색은 설명을 위반으로 잡는다.
    for path in list((root / "core").rglob("*.py")) + list((root / "server").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            target = node.func
            name = target.attr if isinstance(target, ast.Attribute) else getattr(target, "id", "")
            if name not in {"run", "Popen", "check_output", "call", "check_call"}:
                continue
            for kw in node.keywords:
                if kw.arg in banned and getattr(kw.value, "value", None) is True:
                    offenders.append(
                        f"{path.relative_to(root).as_posix()}:{node.lineno} ({kw.arg}=True)"
                    )

    assert not offenders, (
        "subprocess 출력을 로케일 인코딩으로 디코딩하는 자리가 있습니다: "
        + ", ".join(offenders)
    )
