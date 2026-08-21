#!/usr/bin/env bash
# 전체 테스트.
#
# 판정 로직은 전부 Python 한 벌이다. 브라우저에는 매칭 엔진도, 룰 엔진도,
# 이그레스 가드도 두지 않는다 — 두 벌을 두면 반드시 갈라지고, 갈라진 쪽이
# 틀린 판정을 내놓는다. 프론트엔드는 서버가 내려준 결과를 그리기만 한다.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 -m pytest "$@"
