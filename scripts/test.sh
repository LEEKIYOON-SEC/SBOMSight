#!/usr/bin/env bash
# 전체 시험.
#
#   ./scripts/test.sh                  # H2(MODE=MySQL) 로 빠르게
#   DB_PORT=13306 ./scripts/check-mariadb.sh   # 진짜 MySQL/MariaDB + Flyway 스키마로
#
# 판정 로직은 한 벌이다. 브라우저에는 매칭도 룰도 두지 않는다 — 두 벌을 두면
# 반드시 갈라지고, 갈라진 쪽이 틀린 판정을 내놓는다. 화면은 서버가 내려준
# 결과를 그리기만 한다.
set -euo pipefail
cd "$(dirname "$0")/.."

./mvnw -B test "$@"
