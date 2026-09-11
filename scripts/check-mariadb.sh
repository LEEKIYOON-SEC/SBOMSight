#!/usr/bin/env bash
#
# 전체 시험을 진짜 MySQL/MariaDB 에 태워 본다.
#
# 왜 필요한가. 시험은 H2(MODE=MySQL) 로 돌고 스키마도 JPA 가 만든다. 즉
# 시험이 통과해도 다음 둘은 확인된 적이 없다.
#
#   1) 우리가 쓴 JPQL 이 MySQL 방언으로 번역됐을 때 실제로 도는가.
#      H2 의 MODE=MySQL 은 흉내이지 MySQL 이 아니다. COUNT(DISTINCT ...)
#      여러 개, 상관 서브쿼리, ONLY_FULL_GROUP_BY 는 갈리는 자리다.
#   2) Flyway 가 만든 스키마와 JPA 엔티티가 서로 맞는가. create-drop 으로
#      만든 스키마는 언제나 엔티티와 맞는다 — 엔티티가 만들었으니까.
#      운영에서 쓰는 것은 db/migration/*.sql 이 만든 쪽이다.
#
# scripts/check-migrations.sh 는 마이그레이션이 도는지만 본다. 이 스크립트는
# 그 위에서 응용을 통째로 돌린다.
#
#   ./scripts/check-mariadb.sh
#   DB_HOST=127.0.0.1 DB_PORT=13306 ./scripts/check-mariadb.sh
#   DB_PORT=13306 ./scripts/check-mariadb.sh -Dtest=ZoneReportTest
set -euo pipefail

HOST="${DB_HOST:-127.0.0.1}"
PORT="${DB_PORT:-3306}"
USER="${DB_USER:-root}"
PASS="${DB_PASSWORD:-}"
DB="${DB_NAME:-sbomsight_apptest}"

CLIENT=$(command -v mariadb || command -v mysql) || {
    echo "mysql/mariadb 클라이언트가 없습니다." >&2
    exit 1
}

run_sql() {
    if [ -n "$PASS" ]; then
        "$CLIENT" -h "$HOST" -P "$PORT" -u "$USER" -p"$PASS" "$@"
    else
        "$CLIENT" -h "$HOST" -P "$PORT" -u "$USER" "$@"
    fi
}

cd "$(dirname "$0")/.."

echo "대상 ${HOST}:${PORT} · 데이터베이스 ${DB}"
# 매번 새로 만든다. 남은 데이터가 있으면 자산 수를 세는 시험이 흔들린다.
run_sql -e "DROP DATABASE IF EXISTS \`$DB\`;
            CREATE DATABASE \`$DB\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"

# 환경변수로 넘긴다. surefire 가 시험을 별도 JVM 으로 띄우므로 -D 는
# 그쪽에 닿지 않지만 환경변수는 그대로 물려받는다.
export SPRING_DATASOURCE_URL="jdbc:mysql://${HOST}:${PORT}/${DB}?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC"
export SPRING_DATASOURCE_USERNAME="$USER"
export SPRING_DATASOURCE_PASSWORD="$PASS"
export SPRING_DATASOURCE_DRIVER_CLASS_NAME="com.mysql.cj.jdbc.Driver"
# 스키마는 Flyway 가 만든다 — 운영에서 쓰는 그 파일들이다.
export SPRING_FLYWAY_ENABLED=true
export SPRING_JPA_HIBERNATE_DDL_AUTO=none

./mvnw -B test "$@"
