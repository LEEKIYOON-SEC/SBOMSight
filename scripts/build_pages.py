#!/usr/bin/env python3
"""GitHub Pages 배포물 조립.

Pages는 **전시장**이다. 스캔하지 않고, AI를 호출하지 않으며, 키를 담지
않는다. 실제 판정은 담당자 PC에서 진짜 Syft/Grype로 이루어지고, 그 결과를
`python -m core.cli export` 로 내보낸 것이 `results/` 에 들어 있다.

복사하는 것은 다음뿐이다:

    web/         프론트엔드 (실 운영과 같은 코드)
    policy/      이그레스 정책 (Python 가드가 읽는 것과 같은 파일)
    rules/       우선순위 정책 · 표현 정책 · 패치 플레이북 (같은 파일)
    results/     실 PC에서 내보낸 스캔·보고서·전송 기록

정책·룰 파일을 사본이 아니라 원본에서 가져오는 것이 중요하다. 사본을 따로
두면 두 벌이 갈라지고, 그러면 전시된 정책이 실제로 적용된 정책과 달라진다.

각 HTML에 `window.SBOMSIGHT_MODE = 'static'` 을 심어 프론트엔드가 로컬 서버를
찾는 요청(api/health)을 아예 보내지 않게 한다. 정적 호스팅에서 그 요청은
언제나 404이고, 콘솔에 오류로 남는다.

    python3 scripts/build_pages.py --out dist
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

MODE_MARKER = (
    "<script>\n"
    "  // 정적 배포이므로 로컬 서버를 찾지 않는다. scripts/build_pages.py 가 심는다.\n"
    "  window.SBOMSIGHT_MODE = 'static';\n"
    "</script>\n"
)


def build(out: Path, *, require_results: bool = True) -> int:
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    shutil.copytree(ROOT / "web", out, dirs_exist_ok=True)
    for name in ("policy", "rules"):
        shutil.copytree(ROOT / name, out / name, dirs_exist_ok=True)

    results = ROOT / "results"
    index = results / "index.json"
    if index.is_file():
        shutil.copytree(results, out / "results", dirs_exist_ok=True)
        manifest = json.loads(index.read_text(encoding="utf-8"))
        scans = manifest.get("scans", [])
        print(
            f"전시 결과: 스캔 {len(scans)}건 · 내보낸 시각 {manifest.get('generated_at', '?')}",
            file=sys.stderr,
        )
        for scan in scans:
            print(
                f"  - {scan.get('scan_id', '?')} · 탐지 {scan.get('finding_count', 0)}건"
                f" · 선택 {scan.get('selected_count', 0)}건"
                f" · AI {'사용' if scan.get('ai_used') else '미사용'}",
                file=sys.stderr,
            )
    elif require_results:
        print(
            "오류: results/index.json 이 없습니다.\n"
            "      실제 PC에서 스캔한 뒤 다음으로 결과를 내보내세요:\n"
            "        python -m core.cli export --out results",
            file=sys.stderr,
        )
        return 2
    else:
        print("경고: 전시할 결과 없이 조립합니다 (빈 화면이 나옵니다).", file=sys.stderr)

    for html in out.glob("*.html"):
        text = html.read_text(encoding="utf-8")
        if "SBOMSIGHT_MODE" in text:
            continue
        text = text.replace("</head>", f"{MODE_MARKER}</head>", 1)
        html.write_text(text, encoding="utf-8")

    # Jekyll 이 _ 로 시작하는 파일을 걸러내지 않도록.
    (out / ".nojekyll").write_text("", encoding="utf-8")

    total = sum(p.stat().st_size for p in out.rglob("*") if p.is_file())
    files = sum(1 for p in out.rglob("*") if p.is_file())
    print(f"배포물 조립 완료: {out} · 파일 {files}개 · {total / 1024:.0f}KB", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="GitHub Pages 배포물 조립")
    parser.add_argument("--out", default="dist")
    parser.add_argument("--allow-missing-results", action="store_true",
                        help="전시할 결과 없이도 조립 (레이아웃 확인용)")
    args = parser.parse_args(argv)
    return build(Path(args.out), require_results=not args.allow_missing_results)


if __name__ == "__main__":
    raise SystemExit(main())
