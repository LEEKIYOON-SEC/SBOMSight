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
#   ./tests/check-migrations.sh                        # 127.0.0.1:3306 root
#   DB_HOST=127.0.0.1 DB_PORT=13306 ./tests/check-migrations.sh
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

    # V9 가 risk_acceptances 를 만든다. V11 이 그 행을 검토 결과로 옮기므로,
    # 옮길 것이 있는 상태에서 태워야 한다 — 빈 표를 옮기는 것은 아무것도
    # 확인하지 못한다. 경계 사례를 일부러 섞는다:
    #   살아 있는 것 / 철회된 것 / 같은 키에 철회분이 둘
    # V12 가 감사 로그의 로그인 기록으로 마지막·그 전 로그인을 채운다.
    # 채울 것이 있는 상태에서 태워야 한다. V6 이 audit_log 를, V7 이 users 의
    # 잠금 칸을 만든다 — 둘 다 있는 자리가 V7 직후다.
    case "$(basename "$f")" in V7__*)
        run "$DB" -e "
        INSERT INTO users (username, password_hash, role, enabled, must_change,
                           failed_attempts, password_changed_at, created_at)
        VALUES ('oldtimer','x','ADMIN',1,0,0,NOW(6),NOW(6)),
               ('newbie','x','VIEWER',1,1,0,NOW(6),NOW(6));
        INSERT INTO audit_log (at, actor, action, target, detail, client_ip) VALUES
         (NOW(6) - INTERVAL 10 DAY, 'oldtimer','LOGIN_SUCCESS','','',''),
         (NOW(6) - INTERVAL 3 DAY,  'oldtimer','LOGIN_SUCCESS','','',''),
         (NOW(6) - INTERVAL 1 DAY,  'oldtimer','LOGIN_SUCCESS','','',''),
         (NOW(6) - INTERVAL 2 DAY,  'oldtimer','LOGIN_FAILURE','','','');"
        echo "  └ 계정 2개와 로그인 기록을 넣었다 (성공 3 · 실패 1)" ;;
    esac

    # V14 가 ACCEPTED(하지 않고 닫음) 조치를 대기로 되돌린다. 되돌릴 것이
    # 있는 상태에서 태워야 한다 — 빈 표를 옮기는 것은 아무것도 확인하지
    # 못한다. 메모가 있는 것과 없는 것을 함께 넣는다(메모를 이어 붙인다).
    case "$(basename "$f")" in V13__*)
        run "$DB" -e "
        INSERT INTO remediations
          (asset_id, package_name, from_version, to_version, status, owner,
           due_date, opened_count, note, created_at, created_by, updated_at, updated_by)
        VALUES
         (1,'openssl','3.0.1','3.0.7','ACCEPTED','인프라운영팀',
          '2026-01-31', 3, '', NOW(6),'admin',NOW(6),'admin'),
         (2,'glibc','2.34','','ACCEPTED','',
          NULL, 1, '업무 영향 확인 중', NOW(6),'admin',NOW(6),'admin'),
         (3,'zlib','1.2.11','1.2.13','DONE','',
          NULL, 1, '', NOW(6),'admin',NOW(6),'admin');"
        echo "  └ 조치 3행을 넣었다 (하지 않고 닫음 2 · 완료 1)" ;;
    esac

    case "$(basename "$f")" in V9__*)
        run "$DB" -e "
        INSERT INTO risk_acceptances
          (asset_id, cve, package_name, reason, compensating, approved_by,
           accepted_at, accepted_by, review_by, revoked_at, revoked_by, revoke_note)
        VALUES
         -- 살아 있는 것 → 해당됨 · 조치 안 함
         (1,'CVE-2024-0001','openssl','업스트림에 수정 버전이 없습니다','WAF 로 차단',
          '보안-2026-0001', NOW(6),'admin','2099-12-31', NULL,'',''),
         -- 같은 키에 철회분이 둘. 살아 있는 것이 없으므로 미검토로 옮겨진다.
         (2,'CVE-2024-0002','glibc','옛 사유 1','','홍길동',
          NOW(6),'admin','2099-12-31', NOW(6),'admin','정책이 바뀜'),
         (2,'CVE-2024-0002','glibc','옛 사유 2','','홍길동',
          NOW(6),'admin','2099-12-31', NOW(6),'admin','다시 철회'),
         -- 철회된 것과 살아 있는 것이 같은 키에. 살아 있는 쪽이 이긴다.
         (3,'CVE-2024-0003','zlib','옛 사유','','',
          NOW(6),'admin','2099-12-31', NOW(6),'admin','거둠'),
         (3,'CVE-2024-0003','zlib','지금 사유입니다','접근 제한','보안-2026-0003',
          NOW(6),'admin','2099-12-31', NULL,'','');"
        echo "  └ 위험 수용 5행을 넣었다 (살아 있는 것 2 · 철회 3)" ;;
    esac
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

# --- V11: 위험 수용 → 검토 결과 -----------------------------------------
#
# 뜻이 그대로 보존되어야 한다. 살아 있던 수용은 "해당되는데 안 고치기로 했다"
# 이고, 그것이 상태 해당됨 + 대응 조치 안 함이다.

run "$DB" -e "SHOW TABLES LIKE 'risk_acceptances';" | grep -q risk_acceptances \
    && { echo "  risk_acceptances 가 남아 있습니다 — 두 벌이 되면 갈라집니다"; exit 1; }
echo "  risk_acceptances 제거됨"

TOTAL=$(run "$DB" -N -e "SELECT COUNT(*) FROM finding_analysis;")
[ "$TOTAL" = "3" ] || { echo "  검토 결과가 $TOTAL 행 (3 이어야 함) — 키마다 한 행이 아닙니다"; exit 1; }
echo "  검토 결과 3행 (키마다 하나)"

ALIVE=$(run "$DB" -N -e "
    SELECT CONCAT(state,'|',response,'|',approval_doc,'|',review_by)
    FROM finding_analysis WHERE cve='CVE-2024-0001';")
[ "$ALIVE" = "EXPLOITABLE|WILL_NOT_FIX|보안-2026-0001|2099-12-31" ] || {
    echo "  살아 있던 수용이 '$ALIVE' 로 옮겨졌습니다 — 뜻이 달라졌습니다"; exit 1; }
echo "  살아 있던 수용 → 해당됨 · 조치 안 함 (결재 번호·재검토일 보존)"

NOTE=$(run "$DB" -N -e "SELECT note FROM finding_analysis WHERE cve='CVE-2024-0001';")
[ "$NOTE" = "업스트림에 수정 버전이 없습니다" ] || { echo "  사유가 사라졌습니다: '$NOTE'"; exit 1; }
echo "  사유는 설명으로 그대로"

REVOKED=$(run "$DB" -N -e "SELECT state FROM finding_analysis WHERE cve='CVE-2024-0002';")
[ "$REVOKED" = "NOT_SET" ] || { echo "  철회된 것이 '$REVOKED' 입니다 (미검토여야 함)"; exit 1; }
echo "  철회만 남은 건 → 미검토 (지금 결정이 없다)"

# 살아 있는 것과 철회된 것이 같은 키에 있으면 살아 있는 쪽이 이겨야 한다.
WINNER=$(run "$DB" -N -e "
    SELECT CONCAT(state,'|',note) FROM finding_analysis WHERE cve='CVE-2024-0003';")
[ "$WINNER" = "EXPLOITABLE|지금 사유입니다" ] || {
    echo "  같은 키에 철회분이 섞였을 때 '$WINNER' 가 남았습니다"; exit 1; }
echo "  같은 키에 철회분이 있어도 살아 있는 쪽이 남음"

# 철회했다는 사실은 이력에 남아야 한다. 지우면 점검에서 답할 것이 없다.
EVENTS=$(run "$DB" -N -e "SELECT COUNT(*) FROM finding_analysis_event;")
[ "$EVENTS" -ge "5" ] || { echo "  변경 이력이 $EVENTS 줄뿐입니다"; exit 1; }
WITHDRAWN=$(run "$DB" -N -e "
    SELECT COUNT(*) FROM finding_analysis_event WHERE after_value='미검토';")
[ "$WITHDRAWN" = "3" ] || { echo "  철회 이력이 $WITHDRAWN 줄 (3 이어야 함)"; exit 1; }
echo "  수용·철회 이력 $EVENTS 줄이 그때 시각 그대로 남음"

# --- V12: 마지막 로그인 · 그 전 로그인 -----------------------------------
#
# last_login_at 은 V1 부터 있었는데 채우는 코드가 없어 늘 비어 있었다. 이미
# 쓰던 설치는 감사 로그의 로그인 기록으로 채운다 — 지어내는 것이 아니라
# 우리가 이미 가지고 있는 값이다.

LOGINS=$(run "$DB" -N -e "
    SELECT CONCAT(DATE(last_login_at),'|',DATE(previous_login_at))
    FROM users WHERE username='oldtimer';")
WANT="$(date -d '1 day ago' +%F)|$(date -d '3 days ago' +%F)"
[ "$LOGINS" = "$WANT" ] || {
    echo "  옛 계정의 로그인 시각이 '$LOGINS' 입니다 (기대 '$WANT')"; exit 1; }
echo "  감사 로그에서 마지막·그 전 로그인을 채움 (실패 기록은 안 셈)"

# 로그인한 적 없는 계정은 둘 다 비어 있어야 한다. 채워 넣으면 '최초 로그인'
# 인데 '임시 비밀번호' 라고 말하게 된다.
FRESH=$(run "$DB" -N -e "
    SELECT CONCAT(IFNULL(last_login_at,'-'),'|',IFNULL(previous_login_at,'-'))
    FROM users WHERE username='newbie';")
[ "$FRESH" = "-|-" ] || { echo "  로그인한 적 없는 계정에 시각이 찼습니다: '$FRESH'"; exit 1; }
echo "  로그인한 적 없는 계정은 둘 다 비어 있음"

# --- V13: 패키지 인벤토리 --------------------------------------------------
#
# 새 표라 옮길 데이터는 없다. 확인할 것은 **FK 가 제대로 걸렸는가** 다 —
# 자산이나 스캔을 지웠을 때 함께 사라지지 않으면 없는 자산의 패키지 목록이
# 화면에 남는다. H2 시험은 하이버네이트가 만든 스키마로 도므로 여기서
# 진짜 제약을 태워 본다.

CASCADES=$(run "$DB" -N -e "
    SELECT COUNT(*) FROM information_schema.REFERENTIAL_CONSTRAINTS
    WHERE CONSTRAINT_SCHEMA='$DB' AND TABLE_NAME='component'
      AND DELETE_RULE='CASCADE';")
[ "$CASCADES" = "2" ] || {
    echo "  component 의 CASCADE FK 가 $CASCADES 개입니다 (자산·스캔 둘이어야 함)"; exit 1; }
echo "  component FK 둘 다 ON DELETE CASCADE"

# 실제로 지워 본다. 제약 이름만 보고 넘어가면 방향이 뒤집혀 있어도 통과한다.
ASSET_ID=$(run "$DB" -N -e "SELECT id FROM assets LIMIT 1;")
run "$DB" -e "
INSERT INTO scans (asset_id, status, created_at, created_by, sbom_filename)
VALUES ($ASSET_ID, 'DONE', NOW(6), 'migcheck', 'sbom.json');"
SCAN_ID=$(run "$DB" -N -e "SELECT id FROM scans WHERE created_by='migcheck';")
run "$DB" -e "
INSERT INTO component (asset_id, scan_id, name, version, type, purl, location) VALUES
 ($ASSET_ID, $SCAN_ID, 'openssl-libs', '3.0.7-24', 'rpm',
  'pkg:rpm/rocky/openssl-libs@3.0.7-24', '/usr/lib64/libssl.so.3'),
 ($ASSET_ID, $SCAN_ID, 'glibc', '2.34-83', 'rpm', 'pkg:rpm/rocky/glibc@2.34-83', '');"
BEFORE=$(run "$DB" -N -e "SELECT COUNT(*) FROM component;")
[ "$BEFORE" = "2" ] || { echo "  인벤토리 2행이 안 들어갔습니다 ($BEFORE)"; exit 1; }

run "$DB" -e "DELETE FROM scans WHERE id=$SCAN_ID;"
AFTER=$(run "$DB" -N -e "SELECT COUNT(*) FROM component;")
[ "$AFTER" = "0" ] || {
    echo "  스캔을 지웠는데 인벤토리 $AFTER 행이 남았습니다"; exit 1; }
echo "  스캔을 지우면 그 스캔에서 온 인벤토리도 사라짐"

# --- V14: 조치의 `하지 않고 닫음` 을 없앴다 --------------------------------
#
# 같은 결정이 두 곳에 적힐 수 있었다 — 조치 상태의 ACCEPTED 와 검토 결과의
# will_not_fix. 남길 쪽은 검토 결과다(근거·재검토일·결재 번호가 거기 있다).
#
# 이미 닫아 둔 행은 **대기로 되돌리고 그 사실을 메모와 이력에 남긴다.**
# DONE 으로 바꾸면 하지 않은 일을 했다고 적는 셈이고, 조용히 지우면 누가
# 언제 닫았는지가 사라진다.

LEFT=$(run "$DB" -N -e "SELECT COUNT(*) FROM remediations WHERE status='ACCEPTED';")
[ "$LEFT" = "0" ] || { echo "  ACCEPTED 조치가 $LEFT 행 남았습니다"; exit 1; }
echo "  ACCEPTED 조치가 남지 않음"

REOPENED=$(run "$DB" -N -e "
    SELECT COUNT(*) FROM remediations
    WHERE status='OPEN' AND note LIKE '%[V14]%';")
[ "$REOPENED" = "2" ] || {
    echo "  되돌려진 조치가 $REOPENED 행입니다 (2행이어야 함)"; exit 1; }
echo "  닫혀 있던 2행이 대기로 돌아오고 메모에 남음"

# 메모가 있던 행은 **이어 붙여야** 한다. 덮어쓰면 사람이 적어 둔 것이 사라진다.
KEPT=$(run "$DB" -N -e "
    SELECT COUNT(*) FROM remediations
    WHERE note LIKE '%업무 영향 확인 중%' AND note LIKE '%[V14]%';")
[ "$KEPT" = "1" ] || { echo "  사람이 적은 메모가 덮여 없어졌습니다"; exit 1; }
echo "  사람이 적어 둔 메모는 지우지 않고 이어 붙임"

EVENTS=$(run "$DB" -N -e "
    SELECT COUNT(*) FROM remediation_events
    WHERE from_status='ACCEPTED' AND to_status='OPEN' AND actor='system';")
[ "$EVENTS" = "2" ] || {
    echo "  되돌린 이력이 $EVENTS 줄입니다 (2줄이어야 함)"; exit 1; }
echo "  되돌린 사실이 이력 2줄로 남음 (from ACCEPTED → to OPEN)"

# 완료였던 것은 건드리지 않는다.
DONE_KEPT=$(run "$DB" -N -e "SELECT COUNT(*) FROM remediations WHERE status='DONE';")
[ "$DONE_KEPT" = "1" ] || { echo "  완료 조치가 $DONE_KEPT 행입니다"; exit 1; }
echo "  완료였던 조치는 그대로"

run -e "DROP DATABASE \`$DB\`;"
echo
echo "마이그레이션 확인 통과"
