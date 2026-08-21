"""기동·설치 스크립트의 인코딩 검사.

이 파일이 존재하는 이유는 실제로 겪은 고장 때문이다.

`.ps1` 파일을 UTF-8 **BOM 없이** 저장했더니 한국어 Windows에서
`run-server.ps1` 이 아예 파싱되지 않았다:

    식에 닫는 ')'가 없습니다.
    + CategoryInfo : ParserError: (:) [], ParseException

Windows PowerShell 5.1은 BOM이 없는 `.ps1` 을 시스템 ANSI 코드페이지
(한국어 Windows에서는 CP949)로 읽는다. 한글의 UTF-8 바이트가 CP949의
lead 바이트(0x81–0xFE)로 해석되는데, 뒤따르는 ASCII 문자는 CP949의 trail
바이트 범위(0x41–0x5A, 0x61–0x7A, 0x81–0xFE)에 들지 않으므로 **두 바이트가
통째로 '?' 하나로 치환된다.** 그 결과 한글 뒤의 공백·마침표·줄바꿈, 그리고
치명적으로 **닫는 따옴표가 사라진다.**

검사가 문법이 아니라 바이트를 보는 이유가 여기 있다. 이 고장은 코드가
틀려서가 아니라 파일이 어떤 바이트로 저장됐는지 때문에 났고, 문법 검사로는
잡히지 않는다.
"""

from pathlib import Path

import pytest

SCRIPTS = Path(__file__).parent.parent / "scripts"
BOM = b"\xef\xbb\xbf"

PS1 = sorted(SCRIPTS.glob("*.ps1"))
SH = sorted(SCRIPTS.glob("*.sh"))


def _cp949_lead(b: int) -> bool:
    return 0x81 <= b <= 0xFE


def _cp949_trail(b: int) -> bool:
    return (0x41 <= b <= 0x5A) or (0x61 <= b <= 0x7A) or (0x81 <= b <= 0xFE)


def _swallowed_by_cp949(data: bytes) -> list[tuple[int, int]]:
    """CP949로 잘못 읽었을 때 먹히는 ASCII 문자 목록 → [(행, 바이트)]."""
    out: list[tuple[int, int]] = []
    i, line = 0, 1
    while i < len(data):
        if data[i] == 0x0A:
            line += 1
        if _cp949_lead(data[i]) and i + 1 < len(data) and not _cp949_trail(data[i + 1]):
            out.append((line, data[i + 1]))
            i += 2
            continue
        i += 1
    return out


class TestPowerShell:
    def test_scripts_exist(self):
        assert PS1, "검사할 .ps1 이 없다 — 경로가 바뀌었는지 확인하라"

    @pytest.mark.parametrize("path", PS1, ids=lambda p: p.name)
    def test_has_utf8_bom(self, path):
        """BOM이 없으면 한국어 Windows에서 파싱조차 되지 않는다."""
        head = path.read_bytes()[:3]
        assert head == BOM, (
            f"{path.name} 에 UTF-8 BOM이 없습니다. Windows PowerShell 5.1이 "
            f"CP949로 읽어 파서가 죽습니다. BOM을 붙여 다시 저장하세요."
        )

    @pytest.mark.parametrize("path", PS1, ids=lambda p: p.name)
    def test_is_valid_utf8(self, path):
        path.read_bytes().decode("utf-8")

    @pytest.mark.parametrize("path", PS1, ids=lambda p: p.name)
    def test_bom_actually_prevents_the_failure(self, path):
        """BOM을 뗐다면 실제로 깨졌을 자리가 있음을 확인한다.

        BOM이 형식적인 요구가 아니라 이 파일에 정말 필요하다는 것을 남긴다.
        한글이 전혀 없는 스크립트라면 먹히는 문자도 없으니 그대로 통과한다.
        """
        body = path.read_bytes()[3:]
        quotes_eaten = [ln for ln, b in _swallowed_by_cp949(body) if b == 0x22]
        if quotes_eaten:
            assert path.read_bytes().startswith(BOM), (
                f"{path.name} 은 {quotes_eaten} 행에서 닫는 따옴표가 먹힌다"
            )


class TestShell:
    def test_scripts_exist(self):
        assert SH

    @pytest.mark.parametrize("path", SH, ids=lambda p: p.name)
    def test_has_no_bom(self, path):
        """셸 스크립트에 BOM이 붙으면 셔뱅 앞에 바이트가 끼어 실행되지 않는다."""
        assert not path.read_bytes().startswith(BOM), (
            f"{path.name} 에 BOM이 붙었습니다. `#!` 앞에 바이트가 끼면 "
            f"커널이 셔뱅을 인식하지 못합니다."
        )

    @pytest.mark.parametrize("path", SH, ids=lambda p: p.name)
    def test_uses_lf_endings(self, path):
        """CRLF가 섞이면 셔뱅 줄 끝의 \\r 때문에 인터프리터를 찾지 못한다."""
        assert b"\r\n" not in path.read_bytes(), (
            f"{path.name} 에 CRLF가 있습니다. .gitattributes 가 LF를 강제하지만 "
            f"작업 트리에서 직접 편집하면 섞일 수 있습니다."
        )

    @pytest.mark.parametrize("path", SH, ids=lambda p: p.name)
    def test_starts_with_shebang(self, path):
        assert path.read_bytes().startswith(b"#!"), f"{path.name} 에 셔뱅이 없습니다"
