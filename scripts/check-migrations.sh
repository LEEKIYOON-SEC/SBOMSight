#!/usr/bin/env bash
#
# 마이그레이션을 진짜 MySQL/MariaDB 에 태워 본다.
#
# 왜 필요한가. 시험은 H2 로 돌고(application.yml, ddl-auto=create-drop,
# flyway.enabled=false) 스키마를 JPA 가 만든다. 즉 db/migration/*.sql 은
# 시험에서 **한 번도 실행되지 않는다.** 그대로 두면 마이그레이션이 처음
# 돌아가는 곳이 운영 PC 이고, 거기서 실패하면 손쓸 데가 없다.
#
# 여기서는 빈 DB 에 V1 부터 순서대로 태우고, 한 번 더 — 이번에는 기존
# 데이터를 넣은 상태에서 — 태워 본다. 자리를 옮기는 마이그레이션은 빈 DB
# 에서는 통과하고 데이터가 있을 때 깨지는 일이 흔하다.
#
#   ./scripts/check-migrations.sh                      # 127.0.0.1:3306 root
#   DB_HOST=127.0.0.1 DB_PORT=13306 ./scripts/check-migrations.sh
set -euo pipefail

HOST="${DB_HOST:-127.0.0.1}"
PORT="${DB_PORT:-3306}"
USER="${DB_USER:-root}"
PASS="${DB_PASSWORD:-}"
DB="${DB_NAME:-sbomsight_migcheck}"

CLIENT=$(command -v mariadb || command -v mysql) || {
    echo "mysql/mariadb 클라이언트가 없습니다." >&2
    exit 1
}

run() {
    if [ -n "$PASS" ]; then
        "$CLIENT" -h "$HOST" -P "$PORT" -u "$USER" -p"$PASS" "$@"
    else
        "$CLIENT" -h "$HOST" -P "$PORT" -u "$USER" "$@"
    fi
}

cd "$(dirname "$0")/.."
MIGRATIONS=$(ls src/main/resources/db/migration/V*.sql | sort -V)

apply_all() {
    for f in $MIGRATIONS; do
        printf '  %-28s ' "$(basename "$f")"
        if run "$DB" < "$f"; then echo "적용"; else echo "실패"; return 1; fi
    done
}

echo "1) 빈 DB 에 처음부터"
run -e "DROP DATABASE IF EXISTS \`$DB\`;
        CREATE DATABASE \`$DB\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
apply_all

echo
echo "2) 기존 데이터가 있는 DB 에"
run -e "DROP DATABASE IF EXISTS \`$DB\`;
        CREATE DATABASE \`$DB\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
# V5 직전까지 태우고 데이터를 넣는다.
for f in $MIGRATIONS; do
    case "$(basename "$f")" in V5__*) break ;; esac
    run "$DB" < "$f"
done
# 경계 사례를 일부러 섞는다: 뒤 공백, 빈 값, 공백만.
run "$DB" -e "
INSERT INTO assets (name, group_name, os_name, note, created_at) VALUES
 ('web-01','DMZ','Rocky 9.3','',NOW(6)),
 ('api-02','DMZ ','Rocky 9.3','',NOW(6)),
 ('db-01','내부업무','Rocky 8.9','',NOW(6)),
 ('log-01','','Ubuntu 22.04','',NOW(6)),
 ('dev-01','   ','Rocky 9.3','',NOW(6));"
for f in $MIGRATIONS; do
    case "$(basename "$f")" in V1__*|V2__*|V3__*|V4__*) continue ;; esac
    printf '  %-28s ' "$(basename "$f")"
    if run "$DB" < "$f"; then echo "적용"; else echo "실패"; exit 1; fi
done

echo
echo "3) 옮긴 결과 확인"
ORPHANS=$(run "$DB" -N -e "SELECT COUNT(*) FROM assets WHERE zone_id IS NULL;")
[ "$ORPHANS" = "0" ] || { echo "  구역 없는 자산 $ORPHANS 대 — 실패"; exit 1; }
echo "  구역 없는 자산 0대"

# 'DMZ' 와 'DMZ ' 가 한 구역으로 합쳐져야 한다.
DMZ=$(run "$DB" -N -e "SELECT COUNT(*) FROM assets a JOIN zones z ON z.id=a.zone_id WHERE z.name='DMZ';")
[ "$DMZ" = "2" ] || { echo "  DMZ 자산이 $DMZ 대 (2 여야 함) — 뒤 공백이 갈라졌습니다"; exit 1; }
echo "  'DMZ' 와 'DMZ ' 가 한 구역으로 합쳐짐"

UNASSIGNED=$(run "$DB" -N -e "SELECT COUNT(*) FROM assets a JOIN zones z ON z.id=a.zone_id WHERE z.name='미분류';")
[ "$UNASSIGNED" = "2" ] || { echo "  미분류 자산이 $UNASSIGNED 대 (2 여야 함)"; exit 1; }
echo "  빈 값·공백만인 것은 미분류로"

run "$DB" -e "SHOW COLUMNS FROM assets LIKE 'group_name';" | grep -q group_name \
    && { echo "  group_name 이 남아 있습니다 — 두 벌이 되면 갈라집니다"; exit 1; }
echo "  group_name 제거됨"

run -e "DROP DATABASE \`$DB\`;"
echo
echo "마이그레이션 확인 통과"
