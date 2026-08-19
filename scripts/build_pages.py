#!/usr/bin/env python3
"""GitHub Pages 배포물 조립.

실 운영과 **같은 프론트엔드 코드**를 그대로 쓴다. 복사하는 것은 다음뿐이다:

    web/         프론트엔드 (실 운영과 동일)
    policy/      이그레스 정책 (Python 가드가 읽는 것과 같은 파일)
    rules/       우선순위 정책 · 표현 정책 · 패치 플레이북 (같은 파일)
    demo-data/   진짜 Syft/Grype로 만든 인덱스와 샘플 SBOM

정책·룰 파일을 복사가 아니라 원본에서 가져오는 것이 중요하다. 사본을 따로
두면 두 벌이 갈라지고, 그러면 데모가 보여 주는 판정이 실 운영과 달라진다.

각 HTML에 `window.SBOMSIGHT_MODE = 'demo'` 를 심어 프론트엔드가 로컬 서버를
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
    "  window.SBOMSIGHT_MODE = 'demo';\n"
    "</script>\n"
)


def build(out: Path, *, require_index: bool = True) -> int:
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    shutil.copytree(ROOT / "web", out, dirs_exist_ok=True)
    for name in ("policy", "rules"):
        shutil.copytree(ROOT / name, out / name, dirs_exist_ok=True)

    demo = ROOT / "demo-data"
    index = demo / "vuln-index" / "index.json"
    if index.is_file():
        shutil.copytree(demo, out / "demo-data", dirs_exist_ok=True)
        manifest = json.loads(index.read_text(encoding="utf-8"))
        print(
            f"인덱스: 패키지 {manifest.get('package_count', 0)}개 · "
            f"취약점 {manifest.get('vuln_count', 0)}건 · "
            f"grype {manifest.get('grype_version', '?')} "
            f"DB {manifest.get('grype_db_built', '?')}",
            file=sys.stderr,
        )
    elif require_index:
        print(
            "오류: demo-data/vuln-index/index.json 이 없습니다.\n"
            "      먼저 scripts/build_demo_index.py 를 실행하세요.",
            file=sys.stderr,
        )
        return 2
    else:
        print("경고: 데모 인덱스 없이 조립합니다 (스캔이 동작하지 않습니다).", file=sys.stderr)

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
    parser.add_argument("--allow-missing-index", action="store_true",
                        help="데모 인덱스 없이도 조립 (레이아웃 확인용)")
    args = parser.parse_args(argv)
    return build(Path(args.out), require_index=not args.allow_missing_index)


if __name__ == "__main__":
    raise SystemExit(main())
