#!/usr/bin/env bash
# `NOTICE.md` 를 다시 만든다 — 이 도구로 이 도구의 SBOM 을 뽑아서.
#
#   scripts/make-notice.sh
#
# syft 가 PATH 에 있어야 한다 (`SBOMSIGHT_SYFT` 로도 준다). 배포물을 훑으므로
# 먼저 빌드한다 — 저장소를 훑으면 시험에만 쓰는 것까지 목록에 들어간다.
set -euo pipefail
cd "$(dirname "$0")/.."

SYFT="${SBOMSIGHT_SYFT:-syft}"
JAR="target/sbomsight-1.0.0.jar"
SBOM="target/sbomsight.cdx.json"

command -v "$SYFT" >/dev/null 2>&1 || {
  echo "syft 가 없습니다. PATH 에 두거나 SBOMSIGHT_SYFT 로 주세요." >&2
  exit 1
}

[ -f "$JAR" ] || { echo "$JAR 가 없습니다. ./mvnw -B package 먼저." >&2; exit 1; }

echo "SBOM 을 뽑습니다 — $JAR"
"$SYFT" "$JAR" -o cyclonedx-json="$SBOM" -q

echo "NOTICE.md 를 씁니다"
python3 scripts/make-notice.py "$SBOM" > NOTICE.md

printf '\n완료 — NOTICE.md · %s\n' "$SBOM"
