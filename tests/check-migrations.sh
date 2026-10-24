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
# 자바 마이그레이션(src/main/java/db/migration — V25~)도 제 차례에 태운다. 클라이언트로는 못 태우므로
# ./mvnw 로 실행기(tests/java/kr/sbomsight/MigrationRunner)를 부른다 — JDK 와 ~/.m2 가 있어야 한다.
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

# 연결 문자셋을 utf8mb4 로 못 박는다. 클라이언트는 지역 설정(LANG)을 따르는데, 비어 있으면 latin1 이라
# 마이그레이션 파일과 아래 데이터의 한글이 깨진 채 들어갔다(구역 `미분류` 까지). 넣을 때와 견줄 때가
# 같이 깨져 드러나지 않았고, JDBC 로 읽는 자바 마이그레이션(V25)이 처음 드러냈다 — 운영의 Flyway 는
# JDBC 라 처음부터 utf8mb4 다.
run() {
    if [ -n "$PASS" ]; then
        "$CLIENT" --default-character-set=utf8mb4 -h "$HOST" -P "$PORT" -u "$USER" -p"$PASS" "$@"
    else
        "$CLIENT" --default-character-set=utf8mb4 -h "$HOST" -P "$PORT" -u "$USER" "$@"
    fi
}

cd "$(dirname "$0")/.."
# SQL 과 자바를 한 줄로 — 버전 차례대로(파일 이름으로).
MIGRATIONS=$(for f in src/main/resources/db/migration/V*.sql src/main/java/db/migration/V*.java; do
                 [ -e "$f" ] || continue
                 printf '%s\t%s\n' "$(basename "$f")" "$f"
             done | sort -V | cut -f2)

# 자바 마이그레이션은 실행기가 같은 DB 에 붙어 그 클래스를 한 트랜잭션으로 부른다. 실행기의 출력
# (마이그레이션이 남긴 기록 포함)은 $JAVALOG 에 — 실패하면 끝부분을 보인다.
JAVALOG=$(mktemp)
trap 'rm -f "$JAVALOG"' EXIT
apply() {   # apply <마이그레이션 파일>
    case "$1" in
        *.sql) run "$DB" < "$1" ;;
        *.java)
            # stdout.encoding — 마이그레이션이 남긴 기록의 한글이 ? 로 찍히지 않게(Maven 의 출력).
            MIGCHECK_URL="jdbc:mariadb://${HOST}:${PORT}/${DB}?sslMode=disable" MIGCHECK_USER="$USER" \
            MIGCHECK_PASSWORD="$PASS" MIGCHECK_CLASS="db.migration.$(basename "$1" .java)" \
            MAVEN_OPTS="${MAVEN_OPTS:-} -Dstdout.encoding=UTF-8" \
                ./mvnw -B test -Dtest=MigrationRunner > "$JAVALOG" 2>&1 \
                && grep -q 'Tests run: 1, Failures: 0, Errors: 0, Skipped: 0' "$JAVALOG" \
                || { echo; tail -40 "$JAVALOG"; return 1; } ;;
    esac
}

# 자바 마이그레이션이 남긴 기록 — 고친 수 · 비운 기록. "  └ " 를 붙여 보인다.
java_said() {   # java_said <마이그레이션 파일>
    sed -n "s/.*$(basename "$1" .java) -*  *\(.*\)/  └ \1/p" "$JAVALOG"
}

apply_all() {
    for f in $MIGRATIONS; do
        printf '  %-28s ' "$(basename "$f")"
        if apply "$f"; then echo "적용"; else echo "실패"; return 1; fi
    done
}

# 패키지 식별자 벡터 — tests/resources/package-key-vectors.tsv. 칸: purl · 유형 · 이름 · V24 의 식별자 ·
# 지금의 식별자(앱의 PackageKey · V25). 줄마다 탐지 하나 · 패키지 하나를 넣는다(V23 고리).
vectors() { grep -v '^#' tests/resources/package-key-vectors.tsv | grep -v '^$' | tr '\t' '\037'; }

check_vectors() {   # check_vectors <4|5> — 넣은 탐지 · 패키지의 식별자가 그 칸과 같은가
    local n=0 purl type name v24 now want got
    while IFS=$'\037' read -r purl type name v24 now; do
        n=$((n + 1))
        if [ "$1" = 4 ]; then want=$v24; else want=$now; fi
        got=$(run "$DB" -N -r -e "
            SELECT CONCAT((SELECT package_key FROM findings WHERE finding_key = 'v24-vec-$n'), '|',
                          (SELECT package_key FROM component WHERE version = 'v24-vec-$n'));")
        [ "$got" = "$want|$want" ] || {
            echo "  벡터 $n ($purl · $type · $name) 의 식별자가 '$got' 입니다 (기대 '$want' 둘 — 탐지|패키지 · ${1}째 칸)"
            exit 1; }
    done < <(vectors)
}

review() {   # review <자산 이름> <번호> <이름> → 식별자 (비었으면 NULL)
    run "$DB" -N -r -e "
        SELECT IFNULL(fa.package_key, 'NULL') FROM finding_analysis fa JOIN assets a ON a.id = fa.asset_id
        WHERE a.name = '$1' AND fa.cve = '$2' AND fa.package_name = '$3';"
}

remediation() {   # remediation <자산 이름> <이름> → 식별자 (비었으면 NULL)
    run "$DB" -N -r -e "
        SELECT IFNULL(r.package_key, 'NULL') FROM remediations r JOIN assets a ON a.id = r.asset_id
        WHERE a.name = '$1' AND r.package_name = '$2';"
}

expect_reviews() {   # expect_reviews "<자산>|<번호>|<이름>|<식별자>" …
    local want asset cve name key got
    for want in "$@"; do
        IFS='|' read -r asset cve name key <<< "$want"
        got=$(review "$asset" "$cve" "$name")
        [ "$got" = "$key" ] || { echo "  검토 결과 $asset · $cve · $name 의 식별자가 '$got' 입니다 (기대 '$key')"; exit 1; }
    done
}

expect_remediations() {   # expect_remediations "<자산>|<이름>|<식별자>" …
    local want asset name key got
    for want in "$@"; do
        IFS='|' read -r asset name key <<< "$want"
        got=$(remediation "$asset" "$name")
        [ "$got" = "$key" ] || { echo "  조치 $asset · $name 의 식별자가 '$got' 입니다 (기대 '$key')"; exit 1; }
    done
}

# V24 가 검토 결과 · 조치에 단 식별자. V24 직후에 보고, 끝(3)에서 한 번 더 본다 — 이 기록들은 V25 가
# 다시 가를 까닭이 없다(한정자 · 이름 맞춤과 무관하다). 그대로여야 한다.
check_v24_records() {
    expect_reviews "v24-a|CVE-2099-2401|semver|NULL" \
                   "v24-b|CVE-2099-2401|semver|pkg:npm/semver" \
                   "v24-a|CVE-2099-2402|left-pad|pkg:npm/left-pad" \
                   "v24-a|CVE-2099-2403|jackson-databind|pkg:maven/com.fasterxml.jackson.core/jackson-databind" \
                   "v24-a|CVE-2099-2405|semver|pkg:npm/semver" \
                   "v24-a|CVE-2099-2499|semver|NULL" \
                   "v24-a|CVE-2099-2406|left-pad|pkg:npm/left-pad" \
                   "v24-a|CVE-2099-2407|PyYAML|NULL" \
                   "v24-a|CVE-2099-2407|pyyaml-dist|NULL"
    expect_remediations "v24-a|semver|NULL" "v24-b|semver|pkg:npm/semver" "v24-a|left-pad|pkg:npm/left-pad" \
                        "v24-a|jackson-databind|NULL" "v24-a|v24-gone|NULL" "v24-a|v24-legacy|NULL" \
                        "v24-a|PyYAML|NULL" "v24-a|pyyaml-dist|NULL"
    # 앞 판들이 넣은 기록도 같은 규칙으로 — purl 없는 옛 탐지의 패키지는 유형 없는 식별자(pkg:/이름).
    local got
    got=$(run "$DB" -N -r -e "
        SELECT CONCAT((SELECT IFNULL(package_key, 'NULL') FROM remediations WHERE package_name = 'tomcat-coyote'), '|',
                      (SELECT IFNULL(package_key, 'NULL') FROM finding_analysis WHERE cve = 'CVE-2025-5'), '|',
                      (SELECT IFNULL(package_key, 'NULL') FROM remediations WHERE package_name = 'libxml2'), '|',
                      (SELECT IFNULL(package_key, 'NULL') FROM finding_analysis WHERE cve = 'CVE-2024-0001'));")
    [ "$got" = "pkg:/tomcat-coyote|pkg:/tomcat-coyote|NULL|NULL" ] || {
        echo "  앞 판들의 기록이 '$got' 입니다 (기대 pkg:/tomcat-coyote|pkg:/tomcat-coyote|NULL|NULL)"; exit 1; }
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
    apply "$f"
done
# 경계 사례를 일부러 섞는다: 뒤 공백, 빈 값, 공백만.
run "$DB" -e "
INSERT INTO assets (name, group_name, os_name, note, created_at) VALUES
 ('web-01','DMZ','Rocky 9.3','',NOW(6)),
 ('api-02','DMZ ','Rocky 9.3','',NOW(6)),
 ('db-01','내부업무','Rocky 8.9','',NOW(6)),
 ('log-01','','Ubuntu 22.04','',NOW(6)),
 ('dev-01','   ','Rocky 9.3','',NOW(6));"
# V19 확인에 쓰는 긴 번호 — 탐지 칸(128자)에는 들고 옛 조치 대상 칸(64자)에는 안 드는 길이.
LONGID="LONG-$(printf 'x%.0s' $(seq 1 90))"
for f in $MIGRATIONS; do
    case "$(basename "$f")" in V1__*|V2__*|V3__*|V4__*) continue ;; esac
    printf '  %-28s ' "$(basename "$f")"
    if apply "$f"; then echo "적용"; else echo "실패"; exit 1; fi

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

    # V15 가 조치의 목표 버전을 등록한 검사에서 다시 모은다. 모을 것이 있는
    # 상태에서 태워야 한다 — 빈 표를 옮기는 것은 아무것도 확인하지 못한다.
    # 경계 사례를 일부러 섞는다: 글자 순과 버전 순이 다른 것(9.0.107 · 9.0.90),
    # 같은 버전이 둘, 해당 없음으로 적은 건, 수정 버전이 없는 건, 그리고
    # 등록한 검사가 지워진 조치.
    case "$(basename "$f")" in V14__*)
        run "$DB" -e "
        INSERT INTO scans (asset_id, status, created_at, created_by, sbom_filename)
        VALUES (1, 'DONE', NOW(6), 'v15check', 'sbom.json');
        SET @s = LAST_INSERT_ID();
        INSERT INTO findings (scan_id, finding_key, cve, package_name, fix_state, fixed_version) VALUES
         (@s, 'CVE-2025-1|tomcat-coyote', 'CVE-2025-1', 'tomcat-coyote', 'fixed', '9.0.68'),
         (@s, 'CVE-2025-2|tomcat-coyote', 'CVE-2025-2', 'tomcat-coyote', 'fixed', '9.0.90'),
         (@s, 'CVE-2025-3|tomcat-coyote', 'CVE-2025-3', 'tomcat-coyote', 'fixed', '9.0.107'),
         (@s, 'CVE-2025-4|tomcat-coyote', 'CVE-2025-4', 'tomcat-coyote', 'fixed', '9.0.68'),
         (@s, 'CVE-2025-5|tomcat-coyote', 'CVE-2025-5', 'tomcat-coyote', 'fixed', '9.0.200'),
         (@s, 'CVE-2025-6|tomcat-coyote', 'CVE-2025-6', 'tomcat-coyote', 'not-fixed', '');
        INSERT INTO finding_analysis (asset_id, cve, package_name, state, justification,
                                      created_at, updated_at)
        VALUES (1, 'CVE-2025-5', 'tomcat-coyote', 'NOT_AFFECTED', 'CODE_NOT_PRESENT', NOW(6), NOW(6));
        INSERT INTO remediations
          (asset_id, package_name, from_version, to_version, status, owner, opened_scan_id,
           opened_count, note, created_at, created_by, updated_at, updated_by)
        VALUES
         (1, 'tomcat-coyote', '9.0.50', '9.0.68', 'OPEN', '', @s,
          6, '', NOW(6), 'admin', NOW(6), 'admin'),
         (2, 'libxml2', '2.9.4', '2.9.4+dfsg1-7+deb10u4', 'OPEN', '', 999999,
          3, '', NOW(6), 'admin', NOW(6), 'admin');"
        echo "  └ 조치 2행과 등록한 검사(탐지 6건 · 해당 없음 1건)를 넣었다 — 하나는 등록한 검사가 지워진 것" ;;
    esac

    # V16 이 조치의 현재 버전을 등록한 검사에서 다시 모은다. 경계 사례:
    # 글자 순과 버전 순이 다른 것(2.14.1 · 2.9.1), 같은 버전이 둘, 대소문자만
    # 다른 것(RC1 · rc1), 버전이 빈 건, 그리고 모은 것이 칸(4,000자)을 넘는 조치.
    # V15 에서 넣은 조치들 — 탐지에 버전이 없는 검사 · 지워진 검사 · 검사를
    # 모르는 옛 조치 — 은 그대로여야 한다.
    case "$(basename "$f")" in V15__*)
        WIDE=$(for i in $(seq -w 1 400); do
                   printf "(@s,'CVE-2099-%s|widepkg','CVE-2099-%s','widepkg','1.0.0-build.%s.abcdef','fixed','2.0'),\n" "$i" "$i" "$i"
               done | sed '$ s/,$/;/')
        run "$DB" -e "
        INSERT INTO scans (asset_id, status, created_at, created_by, sbom_filename)
        VALUES (4, 'DONE', NOW(6), 'v16check', 'sbom.json');
        SET @s = LAST_INSERT_ID();
        INSERT INTO findings (scan_id, finding_key, cve, package_name, package_version, fix_state, fixed_version) VALUES
         (@s, 'CVE-2021-44228|log4j-core|a', 'CVE-2021-44228', 'log4j-core', '2.14.1', 'fixed', '2.15.0'),
         (@s, 'CVE-2021-45046|log4j-core|a', 'CVE-2021-45046', 'log4j-core', '2.14.1', 'fixed', '2.16.0'),
         (@s, 'CVE-2019-17571|log4j-core|b', 'CVE-2019-17571', 'log4j-core', '2.9.1', 'fixed', '2.17.1'),
         (@s, 'CVE-2022-0001|log4j-core|c', 'CVE-2022-0001', 'log4j-core', '2.17.0-RC1', 'fixed', '2.17.1'),
         (@s, 'CVE-2022-0002|log4j-core|d', 'CVE-2022-0002', 'log4j-core', '2.17.0-rc1', 'fixed', '2.17.1'),
         (@s, 'CVE-2022-0003|log4j-core|e', 'CVE-2022-0003', 'log4j-core', '', 'not-fixed', '');
        INSERT INTO findings (scan_id, finding_key, cve, package_name, package_version, fix_state, fixed_version) VALUES
        $WIDE
        INSERT INTO remediations
          (asset_id, package_name, from_version, to_version, status, owner, opened_scan_id,
           opened_count, note, created_at, created_by, updated_at, updated_by)
        VALUES
         (4, 'log4j-core', '2.14.1', '2.15.0', 'OPEN', '', @s,
          6, '', NOW(6), 'admin', NOW(6), 'admin'),
         (5, 'widepkg', '1.0.0-build.001.abcdef', '2.0', 'OPEN', '', @s,
          400, '', NOW(6), 'admin', NOW(6), 'admin');"
        echo "  └ 조치 2행과 등록한 검사(설치 버전 넷 · 빈 것 하나 / 버전 400가지)를 넣었다" ;;
    esac

    # V17 이 검사마다 SBOM 생성 시각을 채운다 — 원본은 만든 시각, 다시 검사는 사슬을
    # 거슬러 올라간 원본의 만든 시각, 원본이 지워진 다시 검사는 제 시각. 채울 것이
    # 있는 상태에서 태워야 한다. 경계 사례:
    #   사슬(원본 → 다시 → 다시의 다시 → 그 다시), 그 사이에 올린 새 원본,
    #   원본이 지워진 다시 검사, 실패한 검사, 그리고 41칸짜리 긴 사슬 — 한 번에 한
    #   칸씩 올라가는 갱신이었다면 스무 번에 끝까지 닿지 않는 길이다.
    # 옛 규칙(검사 시각)으로는 마지막 다시 검사가 최신이고, 새 규칙으로는 새 원본이다.
    case "$(basename "$f")" in V16__*)
        LONG="INSERT INTO scans (asset_id, status, created_at, created_by, sbom_filename)
              VALUES (4, 'DONE', '2026-06-01 09:00:00', 'v17check', 'long-00');
              SET @p = LAST_INSERT_ID();"
        for i in $(seq 1 40); do
            LONG="$LONG
              INSERT INTO scans (asset_id, status, created_at, created_by, sbom_filename, rescan_of)
              VALUES (4, 'DONE', '2026-06-01 09:00:00' + INTERVAL $i HOUR, 'v17check',
                      'long-$(printf %02d "$i")', @p);
              SET @p = LAST_INSERT_ID();"
        done
        run "$DB" -e "
        INSERT INTO scans (asset_id, status, created_at, created_by, sbom_filename)
        VALUES (3, 'DONE', '2026-08-01 10:00:00', 'v17check', 'chain-o1');
        SET @o1 = LAST_INSERT_ID();
        INSERT INTO scans (asset_id, status, created_at, created_by, sbom_filename, rescan_of)
        VALUES (3, 'DONE', '2026-08-10 10:00:00', 'v17check', 'chain-r1', @o1);
        SET @r1 = LAST_INSERT_ID();
        INSERT INTO scans (asset_id, status, created_at, created_by, sbom_filename, rescan_of)
        VALUES (3, 'DONE', '2026-08-20 10:00:00', 'v17check', 'chain-r2', @r1);
        SET @r2 = LAST_INSERT_ID();
        INSERT INTO scans (asset_id, status, created_at, created_by, sbom_filename, rescan_of)
        VALUES (3, 'DONE', '2026-08-25 10:00:00', 'v17check', 'chain-r3', @r2);
        INSERT INTO scans (asset_id, status, created_at, created_by, sbom_filename)
        VALUES (3, 'DONE', '2026-08-15 10:00:00', 'v17check', 'new-o2');
        INSERT INTO scans (asset_id, status, created_at, created_by, sbom_filename)
        VALUES (3, 'DONE', '2026-07-01 10:00:00', 'v17check', 'gone-o3');
        SET @o3 = LAST_INSERT_ID();
        INSERT INTO scans (asset_id, status, created_at, created_by, sbom_filename, rescan_of)
        VALUES (3, 'DONE', '2026-07-05 10:00:00', 'v17check', 'orphan-r4', @o3);
        DELETE FROM scans WHERE id = @o3;
        INSERT INTO scans (asset_id, status, created_at, created_by, sbom_filename)
        VALUES (3, 'FAILED', '2026-08-28 10:00:00', 'v17check', 'failed-o5');
        $LONG"
        echo "  └ 검사 48행을 넣었다 (사슬 넷 · 새 원본 · 원본을 지운 다시 검사 · 실패 · 41칸 사슬)" ;;
    esac

    # V18 이 둘로 갈린 검토 결과를 합친다(D4). 합칠 것이 있는 상태에서 태워야 한다.
    # 경계 사례:
    #   짝 — GHSA 쪽이 옛 결정(설명 · 추가 보안 통제 · 결재 문서 번호가 있다), CVE 쪽이
    #        나중 결정. 이력이 하나씩. 탐지 한 줄이 두 번호를 함께 갖고 있다
    #   근거 탐지가 없는 짝 — 합치지 않는다
    #   셋이 엮인 묶음(GHSA 둘이 한 CVE 를) — 합치지 않는다
    #   고친 시각이 같은 짝 — 나중에 만든 행이 남는다
    #   같은 번호의 다른 패키지 · 탐지가 다른 자산에만 있는 짝 — 그대로
    # 검사는 db-01(자산 3)에 넣지 않는다 — V17 확인이 그 자산의 최신 검사를 본다.
    case "$(basename "$f")" in V17__*)
        run "$DB" -e "
        INSERT INTO scans (asset_id, status, created_at, created_by, sbom_filename, sbom_created_at)
        VALUES (1, 'DONE', NOW(6), 'v18check', 'v18-a1', NOW(6));
        SET @s1 = LAST_INSERT_ID();
        INSERT INTO scans (asset_id, status, created_at, created_by, sbom_filename, sbom_created_at)
        VALUES (2, 'DONE', NOW(6), 'v18check', 'v18-a2', NOW(6));
        SET @s2 = LAST_INSERT_ID();
        INSERT INTO scans (asset_id, status, created_at, created_by, sbom_filename, sbom_created_at)
        VALUES (5, 'DONE', NOW(6), 'v18check', 'v18-a5', NOW(6));
        SET @s5 = LAST_INSERT_ID();
        INSERT INTO findings (scan_id, finding_key, cve, related_cve, package_name) VALUES
         (@s1, 'GHSA-p3|lodash',  'GHSA-p3aa-bbbb-cccc', 'CVE-2025-9999', 'lodash'),
         (@s2, 'GHSA-t1|netty',   'GHSA-t1t1-t1t1-t1t1', 'CVE-2025-7777', 'netty'),
         (@s2, 'GHSA-t2|netty',   'GHSA-t2t2-t2t2-t2t2', 'CVE-2025-7777', 'netty'),
         (@s5, 'GHSA-tie|zlib',   'GHSA-tiet-tiet-tiet', 'CVE-2025-5555', 'zlib');
        INSERT INTO finding_analysis
          (asset_id, cve, package_name, state, justification, response,
           note, other_control, approval_doc, review_by, created_at, updated_at, updated_by)
        VALUES
         (1, 'GHSA-p3aa-bbbb-cccc', 'lodash', 'NOT_AFFECTED', 'CODE_NOT_REACHABLE', NULL,
          '해당 함수를 쓰지 않음', '내부망만', '보안-2026-0001', NULL,
          '2026-08-01 09:00:00', '2026-08-01 09:00:00', 'kim'),
         (1, 'CVE-2025-9999', 'lodash', 'EXPLOITABLE', NULL, 'UPDATE', '', '', '', NULL,
          '2026-09-01 09:00:00', '2026-09-01 09:00:00', 'lee'),
         (1, 'GHSA-nolk-nolk-nolk', 'jackson', 'NOT_AFFECTED', 'CODE_NOT_PRESENT', NULL, '', '', '', NULL,
          '2026-08-01 09:00:00', '2026-08-01 09:00:00', 'kim'),
         (1, 'CVE-2025-8888', 'jackson', 'EXPLOITABLE', NULL, NULL, '', '', '', NULL,
          '2026-09-01 09:00:00', '2026-09-01 09:00:00', 'lee'),
         (2, 'GHSA-t1t1-t1t1-t1t1', 'netty', 'NOT_AFFECTED', 'CODE_NOT_PRESENT', NULL, '', '', '', NULL,
          '2026-08-01 09:00:00', '2026-08-01 09:00:00', 'kim'),
         (2, 'CVE-2025-7777', 'netty', 'IN_TRIAGE', NULL, NULL, '', '', '', NULL,
          '2026-08-15 09:00:00', '2026-08-15 09:00:00', 'lee'),
         (2, 'GHSA-t2t2-t2t2-t2t2', 'netty', 'EXPLOITABLE', NULL, 'WILL_NOT_FIX', '', '', '', '2026-12-31',
          '2026-09-01 09:00:00', '2026-09-01 09:00:00', 'park'),
         (5, 'GHSA-tiet-tiet-tiet', 'zlib', 'IN_TRIAGE', NULL, NULL, '', '', '', NULL,
          '2026-08-01 09:00:00', '2026-08-01 09:00:00', 'kim'),
         (5, 'CVE-2025-5555', 'zlib', 'NOT_AFFECTED', 'CODE_NOT_PRESENT', NULL, '', '', '', NULL,
          '2026-08-01 09:00:00', '2026-08-01 09:00:00', 'lee'),
         (1, 'CVE-2025-9999', 'other-pkg', 'NOT_AFFECTED', 'CODE_NOT_PRESENT', NULL, '', '', '', NULL,
          '2026-08-01 09:00:00', '2026-08-01 09:00:00', 'kim'),
         (4, 'GHSA-p3aa-bbbb-cccc', 'lodash', 'NOT_AFFECTED', 'CODE_NOT_PRESENT', NULL, '', '', '', NULL,
          '2026-08-01 09:00:00', '2026-08-01 09:00:00', 'kim'),
         (4, 'CVE-2025-9999', 'lodash', 'EXPLOITABLE', NULL, NULL, '', '', '', NULL,
          '2026-09-01 09:00:00', '2026-09-01 09:00:00', 'lee');
        INSERT INTO finding_analysis_event (analysis_id, at, actor, field_name, before_value, after_value)
        SELECT id, '2026-08-01 09:00:00', 'kim', '상태', '미검토', '해당 없음' FROM finding_analysis
        WHERE asset_id = 1 AND cve = 'GHSA-p3aa-bbbb-cccc' AND package_name = 'lodash';
        INSERT INTO finding_analysis_event (analysis_id, at, actor, field_name, before_value, after_value)
        SELECT id, '2026-09-01 09:00:00', 'lee', '상태', '미검토', '해당됨' FROM finding_analysis
        WHERE asset_id = 1 AND cve = 'CVE-2025-9999' AND package_name = 'lodash';"
        echo "  └ 검토 결과 12행을 넣었다 (짝 · 근거 없는 짝 · 셋 엮임 · 같은 시각 짝 · 다른 패키지 · 다른 자산)" ;;
    esac

    # V19 가 조치 대상을 등록한 검사에서 채우고(R9), (자산, 패키지)의 유일 키를 풀고(R7),
    # 이력 칸을 더하고 넓힌다(R8). 채울 것이 있는 상태에서 태워야 한다. 경계 사례:
    #   경로만 다른 같은 탐지(하나로) · 대소문자만 다른 설치 버전(둘로) · 함께 온 CVE ·
    #   64자를 넘는 번호(탐지와 같은 너비여야 한다 — 좁으면 이 판이 멈춘다)
    # 앞 판들이 넣은 조치 — 등록한 검사가 있는 것(tomcat-coyote · log4j-core · widepkg),
    # 지워진 것(libxml2), 모르는 것(openssl · glibc · zlib) — 도 함께 본다.
    # 대기로 넣는다 — V14 확인이 완료 조치 전부를 센다(V13 의 zlib 하나).
    case "$(basename "$f")" in V18__*)
        run "$DB" -e "
        INSERT INTO scans (asset_id, status, created_at, created_by, sbom_filename, sbom_created_at)
        VALUES (5, 'DONE', NOW(6), 'v19check', 'v19-a5', NOW(6));
        SET @s = LAST_INSERT_ID();
        INSERT INTO findings (scan_id, finding_key, cve, related_cve, package_name, package_version,
                              fix_state, fixed_version) VALUES
         (@s, 'GHSA-v19|pyyaml|/a',     'GHSA-v19v-v19v-v19v', 'CVE-2026-1919', 'pyyaml', '5.3', 'fixed', '5.4'),
         (@s, 'GHSA-v19|pyyaml|/b',     'GHSA-v19v-v19v-v19v', 'CVE-2026-1919', 'pyyaml', '5.3', 'fixed', '5.4'),
         (@s, 'CVE-2026-1920|pyyaml|c', 'CVE-2026-1920', '', 'pyyaml', '6.0-RC1', 'fixed', '6.0.1'),
         (@s, 'CVE-2026-1920|pyyaml|d', 'CVE-2026-1920', '', 'pyyaml', '6.0-rc1', 'fixed', '6.0.1'),
         (@s, '$LONGID|pyyaml', '$LONGID', '', 'pyyaml', '5.3', 'not-fixed', '');
        INSERT INTO remediations
          (asset_id, package_name, from_version, to_version, status, owner, opened_scan_id,
           opened_count, note, created_at, created_by, updated_at, updated_by)
        VALUES (5, 'pyyaml', '5.3 6.0-RC1 6.0-rc1', '5.4 6.0.1', 'OPEN', '', @s,
                5, '', NOW(6), 'admin', NOW(6), 'admin');
        INSERT INTO remediation_events (remediation_id, at, actor, from_status, to_status, comment)
        SELECT id, NOW(6), 'admin', 'OPEN', 'OPEN', '조치 등록' FROM remediations
        WHERE asset_id = 5 AND package_name = 'pyyaml';"
        echo "  └ 조치 1행과 등록한 검사(같은 탐지 둘 · 대소문자만 다른 버전 · 95자 번호)를 넣었다" ;;
    esac

    # V22 가 purl 없이 syft 의 이름으로 담긴 패키지 유형을 purl 의 이름으로 옮긴다. 옮길 것이
    # 있는 상태에서 태워야 한다. 경계 사례:
    #   purl 이 없는 java-archive · python · go-module · UnknownPackage (옮김)
    #   purl 이 있는 conda — purl 의 유형이다. syft 의 conda(→ generic)로 읽으면 안 된다
    #   purl 이 아닌 purl(`pkg://…` · 대문자 `PKG:`) — 앱이 purl 로 안 읽으니 옮김
    #   표에 없는 유형(binary) · 이름이 같은 유형(rpm) · 대소문자만 다른 것(Python) — 그대로
    # 검사는 db-01(자산 3)에 넣지 않는다 — V17 확인이 그 자산의 최신 검사를 본다.
    case "$(basename "$f")" in V21__*)
        run "$DB" -e "
        INSERT INTO scans (asset_id, status, created_at, created_by, sbom_filename, sbom_created_at)
        VALUES (1, 'DONE', NOW(6), 'v22check', 'v22-a1', NOW(6));
        SET @s = LAST_INSERT_ID();
        INSERT INTO component (asset_id, scan_id, name, version, type, purl) VALUES
         (1, @s, 'jackson-databind', '2.9.8', 'java-archive', ''),
         (1, @s, 'requests', '2.25.0', 'python', ''),
         (1, @s, 'mystery', '1.0', 'UnknownPackage', ''),
         (1, @s, 'weird', '0.1', 'go-module', 'pkg://weird@0.1'),
         (1, @s, 'upper', '1.0', 'python', 'PKG:pypi/upper@1.0'),
         (1, @s, 'numpy', '1.26.0', 'conda', 'pkg:conda/numpy@1.26.0'),
         (1, @s, 'log4j-core', '2.14.1', 'maven',
          'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1'),
         (1, @s, 'busybox', '1.36.1', 'binary', ''),
         (1, @s, 'openssl', '3.0.7', 'rpm', ''),
         (1, @s, 'pycase', '1.0', 'Python', '');"
        echo "  └ 패키지 10행을 넣었다 (purl 없는 syft 이름 넷 · purl 아닌 purl 둘 · purl 있는 것 둘 · 그대로 둘 것 셋)" ;;
    esac

    # V23 이 탐지의 수정 버전을 상세(fixVersions)의 후보 전부로 다시 모으고, 조치 대상과
    # 조치의 목표 버전에 나머지 후보를 더한다. 모을 것이 있는 상태에서 태워야 한다.
    # 탐지 (패키지 v23-ssl 1.1.1k — 칸에는 지금처럼 첫 번째만 적혀 있다):
    #   2068  후보 셋                              → 전부
    #   1292  GHSA · 함께 온 CVE, 뒤섞이고 겹치고 빈 것 · 앞뒤 빈칸 → 전부(글자 순)
    #         검토 결과는 GHSA 쪽 해당 없음(옛) · CVE 쪽 해당됨(나중) — 나중 것이 이긴다
    #   3711  후보 하나 · 2301 상세 없음 · 2302 읽을 수 없는 상세 · 2303 fixVersions 가 null
    #   2304  후보 백 개(1,000자를 넘는다)          → 그대로
    #   2305  첫 번째가 2068 과 같다 · 해당 없음으로 적힘 → 탐지는 전부, 목표에는 안 더함
    #   2307  RC1 · rc1                           → 둘 다
    # 조치: v23-ssl(목표 = 지금 규칙의 첫 번째들) · 목표에 따옴표가 든 것 · 역슬래시가 든 것 ·
    #       등록한 검사가 없는 것 — 뒤의 셋은 그대로여야 하고 마이그레이션은 멈추지 않아야 한다.
    # 검사는 api-02(자산 2)에 넣는다 — 자산 3 은 V17, 자산 5 는 V20 확인이 쓴다.
    case "$(basename "$f")" in V22__*)
        LONGFIX=$(for i in $(seq 1 100); do printf '"v%04d-long-version",' "$i"; done | sed 's/,$//')
        run "$DB" <<SQL
        INSERT INTO scans (asset_id, status, created_at, created_by, sbom_filename, sbom_created_at)
        VALUES (2, 'DONE', NOW(6), 'v23check', 'v23-a2', NOW(6));
        SET @s = LAST_INSERT_ID();
        INSERT INTO findings (scan_id, finding_key, cve, related_cve, package_name, package_version,
                              fix_state, fixed_version, detail_json) VALUES
         (@s, 'k2068', 'CVE-2022-2068', '', 'v23-ssl', '1.1.1k', 'fixed', '1.0.2zf',
          '{"urls":[],"fixVersions":["1.0.2zf","1.1.1p","3.0.4"],"cpes":["cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"]}'),
         (@s, 'k1292', 'GHSA-v23a-v23a-v23a', 'CVE-2022-1292', 'v23-ssl', '1.1.1k', 'fixed', '3.0.3',
          '{"fixVersions":["3.0.3","1.1.1o"," 1.0.2ze ","1.1.1o",""]}'),
         (@s, 'k3711', 'CVE-2021-3711', '', 'v23-ssl', '1.1.1k', 'fixed', '1.1.1l', '{"fixVersions":["1.1.1l"]}'),
         (@s, 'k2301', 'CVE-2099-2301', '', 'v23-ssl', '1.1.1k', 'fixed', '9.9', NULL),
         (@s, 'k2302', 'CVE-2099-2302', '', 'v23-ssl', '1.1.1k', 'fixed', '8.8', '{not json'),
         (@s, 'k2303', 'CVE-2099-2303', '', 'v23-ssl', '1.1.1k', 'not-fixed', '', '{"fixVersions":null}'),
         (@s, 'k2304', 'CVE-2099-2304', '', 'v23-ssl', '1.1.1k', 'fixed', 'v0001-long-version',
          '{"fixVersions":[$LONGFIX]}'),
         (@s, 'k2305', 'CVE-2099-2305', '', 'v23-ssl', '1.1.1k', 'fixed', '1.0.2zf', '{"fixVersions":["1.0.2zf","7.7.7"]}'),
         (@s, 'k2307', 'CVE-2099-2307', '', 'v23-ssl', '1.1.1k', 'fixed', '6.0-rc1', '{"fixVersions":["6.0-rc1","6.0-RC1"]}'),
         (@s, 'k2306', 'CVE-2099-2306', '', 'other-v23', '1.0', 'fixed', '1.0', '{"fixVersions":["1.0","2.0"]}'),
         (@s, 'k2308', 'CVE-2099-2308', '', 'v23-quote', '1.0', 'fixed', '1.0.2zf', '{"fixVersions":["1.0.2zf","5.5.5"]}'),
         (@s, 'k2309', 'CVE-2099-2309', '', 'v23-bslash', '1.0', 'fixed', '1.0.2zf', '{"fixVersions":["1.0.2zf","4.4.4"]}');
        INSERT INTO finding_analysis (asset_id, cve, package_name, state, created_at, updated_at) VALUES
         (2, 'CVE-2099-2305', 'v23-ssl', 'NOT_AFFECTED', '2026-08-01 09:00:00', '2026-08-01 09:00:00'),
         (2, 'GHSA-v23a-v23a-v23a', 'v23-ssl', 'NOT_AFFECTED', '2026-08-01 09:00:00', '2026-08-01 09:00:00'),
         (2, 'CVE-2022-1292', 'v23-ssl', 'EXPLOITABLE', '2026-09-01 09:00:00', '2026-09-01 09:00:00');
        INSERT INTO remediations
          (asset_id, package_name, from_version, to_version, status, owner, opened_scan_id,
           opened_count, note, created_at, created_by, updated_at, updated_by)
        VALUES
         (2, 'v23-ssl', '1.1.1k', '1.0.2zf 1.1.1l 3.0.3 6.0-rc1 8.8 9.9 v0001-long-version', 'OPEN', '', @s,
          9, '', NOW(6), 'admin', NOW(6), 'admin'),
         (2, 'v23-quote', '1.0', 'x"y 1.0.2zf', 'OPEN', '', @s, 1, '', NOW(6), 'admin', NOW(6), 'admin'),
         (2, 'v23-bslash', '1.0', CONCAT('a', CHAR(92 USING utf8mb4), 'b 1.0.2zf'), 'OPEN', '', @s,
          1, '', NOW(6), 'admin', NOW(6), 'admin'),
         (2, 'other-v23', '1.0', '1.0', 'OPEN', '', 999998, 1, '', NOW(6), 'admin', NOW(6), 'admin');
        INSERT INTO remediation_targets (remediation_id, cve, related_cve, package_version, fixed_version)
        SELECT r.id, f.cve, f.related_cve, f.package_version, f.fixed_version
        FROM remediations r JOIN findings f ON f.scan_id = r.opened_scan_id AND f.package_name = r.package_name
        WHERE r.package_name = 'v23-ssl';
SQL
        echo "  └ 탐지 12건 · 검토 결과 3행 · 조치 4행 · 조치 대상 9행을 넣었다 (후보 여럿 · 하나 · 없음 · 못 읽음 · 너무 긺 · 해당 없음 · 대소문자)" ;;
    esac

    # V24 가 탐지 · 인벤토리 · 검토 결과 · 조치에 패키지 식별자를 단다. 달 것이 있는 상태에서
    # 태워야 한다.
    #   벡터 — tests/resources/package-key-vectors.tsv 의 줄마다 탐지 하나 · 패키지 하나. 앱의
    #          PackageKey(PackageKeyTest)와 같은 기대값이 나와야 한다.
    #   v24-a — 검사 둘. 앞 검사: npm 과 PyPI 의 semver(같은 번호 2401) · npm left-pad(2402, 그리고
    #          GHSA 주 식별자에 함께 온 CVE 2406) · groupId 만 다른 jackson-databind 둘(2403 · 2404) ·
    #          같은 purl 을 다른 이름으로 적은 PyYAML / pyyaml-dist(2407). 뒤 검사: npm semver 만(2405).
    #   v24-b — npm semver 만(2401).
    #   검토 결과 — 2401 semver(a: 둘에 붙음 → 비움 / b: 하나 → 붙임) · 2402 left-pad · 2403
    #          jackson-databind(번호로 하나) · 2405 semver(뒤 검사의 npm 만) · 2499 semver(붙던 탐지
    #          없음 → 비움) · 2406(함께 온 CVE) · 2407 이름 둘이 한 식별자(→ 둘 다 비움).
    #   조치 — semver(a: 등록한 검사에 둘 → 비움 / b: 하나) · left-pad · jackson-databind(둘 → 비움) ·
    #          등록한 검사가 지워진 것 · 모르는 것 · 이름 둘이 한 식별자(→ 둘 다 비움). 전부 대기
    #          1회차 — V14 · V19 확인이 조치 전부의 상태와 회차를 센다.
    #   v25-a — V24 가 식별자를 단 뒤 V25 가 다시 가를 것(V24 는 한정자를 버려 한 식별자였다).
    #          검사 둘(앞 · 뒤). 2501 classifier 만 다른 둘(netty 네이티브 · 순수 jar) · 2502 네이티브
    #          하나뿐(jffi) · 2503 type 만 다른 둘(앞 검사에 순수 jar, 뒤 검사에 test-jar 도) · 2504 V24
    #          의 식별자 둘이 이름 맞춤으로 하나(pkg:pypi/PyYAML · pkg:pypi/pyyaml) · 2505 자리 바꿈(한쪽의
    #          V24 식별자가 다른 쪽의 새 식별자 — %2E 로 적힌 purl, 먼저 적은 쪽이 그리로 간다) · 2506
    #          바뀌지 않는 것(repository_url 은 원래 버린다). 검토 결과 8행, 조치 5행(전부 앞 검사에서 등록,
    #          대기 1회차).
    # 자산은 새로 만든다(내부업무 — 자산 수를 세는 확인이 없는 구역). 검토 결과 · 조치의 수를
    # 적어 두었다가 V24 · V25 직후에 견준다 — 지우거나 늘리지 않는다.
    case "$(basename "$f")" in V23__*)
        esc() { local s=${1//\\/\\\\}; s=${s//\'/\\\'}; printf '%s' "$s"; }
        FROWS=""; CROWS=""; n=0
        while IFS=$'\037' read -r purl type name _ _; do
            n=$((n + 1))
            FROWS="$FROWS${FROWS:+,}
         (@v, 'v24-vec-$n', 'CVE-2099-$((24000 + n))', '$(esc "$name")', 'v24-vec-$n', '$(esc "$type")', '$(esc "$purl")')"
            CROWS="$CROWS${CROWS:+,}
         (@va, @v, '$(esc "$name")', 'v24-vec-$n', '$(esc "$type")', '$(esc "$purl")')"
        done < <(vectors)
        VECTORS=$n
        run "$DB" -e "
        INSERT INTO assets (name, zone_id, os_name, note, created_at)
        SELECT 'v24-v', id, '', '', NOW(6) FROM zones WHERE name = '내부업무';
        SET @va = LAST_INSERT_ID();
        INSERT INTO scans (asset_id, status, created_at, created_by, sbom_filename, sbom_created_at)
        VALUES (@va, 'DONE', NOW(6), 'v24check', 'v24-vec', NOW(6));
        SET @v = LAST_INSERT_ID();
        INSERT INTO findings (scan_id, finding_key, cve, package_name, package_version, package_type, package_purl)
        VALUES $FROWS;
        INSERT INTO component (asset_id, scan_id, name, version, type, purl)
        VALUES $CROWS;

        INSERT INTO assets (name, zone_id, os_name, note, created_at)
        SELECT 'v24-a', id, '', '', NOW(6) FROM zones WHERE name = '내부업무';
        SET @a = LAST_INSERT_ID();
        INSERT INTO assets (name, zone_id, os_name, note, created_at)
        SELECT 'v24-b', id, '', '', NOW(6) FROM zones WHERE name = '내부업무';
        SET @b = LAST_INSERT_ID();
        INSERT INTO scans (asset_id, status, created_at, created_by, sbom_filename, sbom_created_at)
        VALUES (@a, 'DONE', '2026-09-01 09:00:00', 'v24check', 'v24-a1', '2026-09-01 09:00:00');
        SET @s1 = LAST_INSERT_ID();
        INSERT INTO scans (asset_id, status, created_at, created_by, sbom_filename, sbom_created_at)
        VALUES (@a, 'DONE', '2026-09-10 09:00:00', 'v24check', 'v24-a2', '2026-09-10 09:00:00');
        SET @s2 = LAST_INSERT_ID();
        INSERT INTO scans (asset_id, status, created_at, created_by, sbom_filename, sbom_created_at)
        VALUES (@b, 'DONE', '2026-09-01 09:00:00', 'v24check', 'v24-b1', '2026-09-01 09:00:00');
        SET @s3 = LAST_INSERT_ID();
        INSERT INTO findings (scan_id, finding_key, cve, related_cve, package_name, package_version,
                              package_type, package_purl) VALUES
         (@s1, 'a1', 'CVE-2099-2401', '', 'semver', '7.5.1', 'npm', 'pkg:npm/semver@7.5.1'),
         (@s1, 'a2', 'CVE-2099-2401', '', 'semver', '2.13.0', 'python', 'pkg:pypi/semver@2.13.0'),
         (@s1, 'a3', 'CVE-2099-2402', '', 'left-pad', '1.1.0', 'npm', 'pkg:npm/left-pad@1.1.0'),
         (@s1, 'a4', 'GHSA-v24g-v24g-v24g', 'CVE-2099-2406', 'left-pad', '1.1.0', 'npm', 'pkg:npm/left-pad@1.1.0'),
         (@s1, 'a5', 'CVE-2099-2403', '', 'jackson-databind', '2.9.8', 'java-archive',
          'pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.8'),
         (@s1, 'a6', 'CVE-2099-2404', '', 'jackson-databind', '1.9.13', 'java-archive',
          'pkg:maven/org.codehaus.jackson/jackson-databind@1.9.13'),
         (@s1, 'a7', 'CVE-2099-2407', '', 'PyYAML', '5.3', 'python', 'pkg:pypi/pyyaml@5.3'),
         (@s1, 'a8', 'CVE-2099-2407', '', 'pyyaml-dist', '5.3', 'python', 'pkg:pypi/pyyaml@5.3'),
         (@s2, 'a9', 'CVE-2099-2405', '', 'semver', '7.5.2', 'npm', 'pkg:npm/semver@7.5.2'),
         (@s3, 'b1', 'CVE-2099-2401', '', 'semver', '7.5.1', 'npm', 'pkg:npm/semver@7.5.1');
        INSERT INTO finding_analysis (asset_id, cve, package_name, state, created_at, updated_at) VALUES
         (@a, 'CVE-2099-2401', 'semver', 'NOT_AFFECTED', NOW(6), NOW(6)),
         (@b, 'CVE-2099-2401', 'semver', 'NOT_AFFECTED', NOW(6), NOW(6)),
         (@a, 'CVE-2099-2402', 'left-pad', 'FALSE_POSITIVE', NOW(6), NOW(6)),
         (@a, 'CVE-2099-2403', 'jackson-databind', 'NOT_AFFECTED', NOW(6), NOW(6)),
         (@a, 'CVE-2099-2405', 'semver', 'IN_TRIAGE', NOW(6), NOW(6)),
         (@a, 'CVE-2099-2499', 'semver', 'NOT_AFFECTED', NOW(6), NOW(6)),
         (@a, 'CVE-2099-2406', 'left-pad', 'EXPLOITABLE', NOW(6), NOW(6)),
         (@a, 'CVE-2099-2407', 'PyYAML', 'NOT_AFFECTED', NOW(6), NOW(6)),
         (@a, 'CVE-2099-2407', 'pyyaml-dist', 'FALSE_POSITIVE', NOW(6), NOW(6));
        INSERT INTO remediations
          (asset_id, package_name, from_version, to_version, status, owner, opened_scan_id,
           opened_count, note, created_at, created_by, updated_at, updated_by)
        VALUES
         (@a, 'semver', '', '', 'OPEN', '', @s1, 2, '', NOW(6), 'admin', NOW(6), 'admin'),
         (@b, 'semver', '', '', 'OPEN', '', @s3, 1, '', NOW(6), 'admin', NOW(6), 'admin'),
         (@a, 'left-pad', '', '', 'IN_PROGRESS', '', @s1, 2, '', NOW(6), 'admin', NOW(6), 'admin'),
         (@a, 'jackson-databind', '', '', 'OPEN', '', @s1, 2, '', NOW(6), 'admin', NOW(6), 'admin'),
         (@a, 'v24-gone', '', '', 'OPEN', '', 999997, 1, '', NOW(6), 'admin', NOW(6), 'admin'),
         (@a, 'v24-legacy', '', '', 'OPEN', '', NULL, 1, '', NOW(6), 'admin', NOW(6), 'admin'),
         (@a, 'PyYAML', '', '', 'OPEN', '', @s1, 1, '', NOW(6), 'admin', NOW(6), 'admin'),
         (@a, 'pyyaml-dist', '', '', 'OPEN', '', @s1, 1, '', NOW(6), 'admin', NOW(6), 'admin');"
        run "$DB" <<'SQL'
        INSERT INTO assets (name, zone_id, os_name, note, created_at)
        SELECT 'v25-a', id, '', '', NOW(6) FROM zones WHERE name = '내부업무';
        SET @c = LAST_INSERT_ID();
        INSERT INTO scans (asset_id, status, created_at, created_by, sbom_filename, sbom_created_at)
        VALUES (@c, 'DONE', '2026-09-01 09:00:00', 'v25check', 'v25-a1', '2026-09-01 09:00:00');
        SET @c1 = LAST_INSERT_ID();
        INSERT INTO scans (asset_id, status, created_at, created_by, sbom_filename, sbom_created_at)
        VALUES (@c, 'DONE', '2026-09-10 09:00:00', 'v25check', 'v25-a2', '2026-09-10 09:00:00');
        SET @c2 = LAST_INSERT_ID();
        INSERT INTO findings (scan_id, finding_key, cve, related_cve, package_name, package_version,
                              package_type, package_purl) VALUES
         (@c1, 'c1', 'CVE-2099-2501', '', 'netty-transport-native-epoll', '4.1.100.Final', 'java-archive',
          'pkg:maven/io.netty/netty-transport-native-epoll@4.1.100.Final?classifier=linux-x86_64'),
         (@c1, 'c2', 'CVE-2099-2501', '', 'netty-transport-native-epoll', '4.1.100.Final', 'java-archive',
          'pkg:maven/io.netty/netty-transport-native-epoll@4.1.100.Final'),
         (@c1, 'c3', 'CVE-2099-2502', '', 'jffi', '1.3.11', 'java-archive',
          'pkg:maven/com.github.jnr/jffi@1.3.11?classifier=native'),
         (@c1, 'c4', 'CVE-2099-2503', '', 'lib', '1.0', 'java-archive', 'pkg:maven/org.example/lib@1.0'),
         (@c2, 'c5', 'CVE-2099-2503', '', 'lib', '1.0', 'java-archive', 'pkg:maven/org.example/lib@1.0'),
         (@c2, 'c6', 'CVE-2099-2503', '', 'lib', '1.0', 'java-archive', 'pkg:maven/org.example/lib@1.0?type=test-jar'),
         (@c1, 'c7', 'CVE-2099-2504', '', 'PyYAML', '5.3', 'python', 'pkg:pypi/PyYAML@5.3'),
         (@c1, 'c8', 'CVE-2099-2504', '', 'pyyaml-dist', '5.3', 'python', 'pkg:pypi/pyyaml@5.3'),
         (@c1, 'c9', 'CVE-2099-2505', '', 'netty-codec-enc', '4.1.100.Final', 'java-archive',
          'pkg:maven/io%2Enetty/netty-codec@4.1.100.Final'),
         (@c1, 'c10', 'CVE-2099-2505', '', 'netty-codec', '4.1.100.Final', 'java-archive',
          'pkg:maven/io.netty/netty-codec@4.1.100.Final?classifier=linux-x86_64'),
         (@c1, 'c11', 'CVE-2099-2506', '', 'commons-text', '1.9', 'java-archive',
          'pkg:maven/org.apache.commons/commons-text@1.9?repository_url=https%3A%2F%2Frepo.example'),
         (@c2, 'c12', 'CVE-2099-2506', '', 'commons-text', '1.9', 'java-archive',
          'pkg:maven/org.apache.commons/commons-text@1.9');
        INSERT INTO finding_analysis (asset_id, cve, package_name, state, created_at, updated_at) VALUES
         (@c, 'CVE-2099-2501', 'netty-transport-native-epoll', 'NOT_AFFECTED', NOW(6), NOW(6)),
         (@c, 'CVE-2099-2502', 'jffi', 'NOT_AFFECTED', NOW(6), NOW(6)),
         (@c, 'CVE-2099-2503', 'lib', 'FALSE_POSITIVE', NOW(6), NOW(6)),
         (@c, 'CVE-2099-2504', 'PyYAML', 'NOT_AFFECTED', NOW(6), NOW(6)),
         (@c, 'CVE-2099-2504', 'pyyaml-dist', 'IN_TRIAGE', NOW(6), NOW(6)),
         (@c, 'CVE-2099-2505', 'netty-codec-enc', 'NOT_AFFECTED', NOW(6), NOW(6)),
         (@c, 'CVE-2099-2505', 'netty-codec', 'EXPLOITABLE', NOW(6), NOW(6)),
         (@c, 'CVE-2099-2506', 'commons-text', 'NOT_AFFECTED', NOW(6), NOW(6));
        INSERT INTO remediations
          (asset_id, package_name, from_version, to_version, status, owner, opened_scan_id,
           opened_count, note, created_at, created_by, updated_at, updated_by)
        VALUES
         (@c, 'netty-transport-native-epoll', '', '', 'OPEN', '', @c1, 2, '', NOW(6), 'admin', NOW(6), 'admin'),
         (@c, 'jffi', '', '', 'OPEN', '', @c1, 1, '', NOW(6), 'admin', NOW(6), 'admin'),
         (@c, 'lib', '', '', 'OPEN', '', @c1, 1, '', NOW(6), 'admin', NOW(6), 'admin'),
         (@c, 'PyYAML', '', '', 'OPEN', '', @c1, 1, '', NOW(6), 'admin', NOW(6), 'admin'),
         (@c, 'pyyaml-dist', '', '', 'OPEN', '', @c1, 1, '', NOW(6), 'admin', NOW(6), 'admin');
SQL
        COUNTS24=$(run "$DB" -N -e "
            SELECT CONCAT((SELECT COUNT(*) FROM finding_analysis), '|', (SELECT COUNT(*) FROM remediations), '|',
                          (SELECT COUNT(*) FROM findings), '|', (SELECT COUNT(*) FROM component));")
        echo "  └ 벡터 ${VECTORS}줄(탐지 · 패키지) · 탐지 10건 · 검토 결과 9행 · 조치 8행을 넣었다 (같은 이름의 npm/PyPI · groupId 둘 · 붙던 탐지 없음 · 지워진 검사 · 이름 둘이 한 식별자)"
        echo "  └ V25 가 다시 가를 것 — 탐지 12건 · 검토 결과 8행 · 조치 5행 (classifier · type 만 다른 둘 · 하나뿐 · 이름 맞춤으로 모임 · 자리 바꿈 · 바뀌지 않는 것)" ;;
    esac

    case "$(basename "$f")" in V24__*)
        AFTER24=$(run "$DB" -N -e "
            SELECT CONCAT((SELECT COUNT(*) FROM finding_analysis), '|', (SELECT COUNT(*) FROM remediations), '|',
                          (SELECT COUNT(*) FROM findings), '|', (SELECT COUNT(*) FROM component));")
        [ "$AFTER24" = "$COUNTS24" ] || {
            echo "  V24 앞뒤로 행 수가 다릅니다 — 검토 결과|조치|탐지|패키지 '$COUNTS24' → '$AFTER24'"; exit 1; }
        echo "  └ 검토 결과 · 조치 · 탐지 · 패키지 행 수 그대로 ($AFTER24) — 지우거나 합치지 않음"
        # V24 가 낸 식별자는 여기서 본다 — 뒤의 V25 가 새 규칙으로 다시 만든다.
        check_vectors 4
        echo "  └ 벡터 ${VECTORS}줄 — 탐지 · 패키지 모두 V24 의 식별자(4째 칸 — V24 를 만들던 때의 PackageKey)"
        check_v24_records
        echo "  └ 검토 결과 — 앞서 붙던 탐지가 한 패키지면 그 식별자 (번호 · 함께 온 CVE · 다른 검사의 것까지)"
        echo "      같은 이름의 둘에 붙던 것 · 붙던 탐지가 없는 것 · 이름 둘이 한 식별자에 모인 것은 비움"
        echo "  └ 조치 — 등록한 검사의 그 이름 탐지가 한 패키지면 그 식별자"
        echo "      둘 이상 · 등록한 검사가 지워졌거나 모르는 것 · 이름 둘이 한 식별자에 모인 것은 비움"
        echo "  └ 앞 판들의 기록도 — 등록한 검사가 있는 조치 · 탐지가 있는 검토 결과는 식별자, 위험 수용에서 옮긴 것 · 지워진 검사는 비움"
        # V25 가 다시 가를 것 — V24 는 한정자를 버려 변형 둘을 한 식별자로 붙였다.
        expect_reviews "v25-a|CVE-2099-2501|netty-transport-native-epoll|pkg:maven/io.netty/netty-transport-native-epoll" \
                       "v25-a|CVE-2099-2502|jffi|pkg:maven/com.github.jnr/jffi" \
                       "v25-a|CVE-2099-2503|lib|pkg:maven/org.example/lib" \
                       "v25-a|CVE-2099-2504|PyYAML|pkg:pypi/PyYAML" \
                       "v25-a|CVE-2099-2504|pyyaml-dist|pkg:pypi/pyyaml" \
                       "v25-a|CVE-2099-2505|netty-codec-enc|pkg:maven/io%2Enetty/netty-codec" \
                       "v25-a|CVE-2099-2505|netty-codec|pkg:maven/io.netty/netty-codec" \
                       "v25-a|CVE-2099-2506|commons-text|pkg:maven/org.apache.commons/commons-text"
        expect_remediations "v25-a|netty-transport-native-epoll|pkg:maven/io.netty/netty-transport-native-epoll" \
                            "v25-a|jffi|pkg:maven/com.github.jnr/jffi" "v25-a|lib|pkg:maven/org.example/lib" \
                            "v25-a|PyYAML|pkg:pypi/PyYAML" "v25-a|pyyaml-dist|pkg:pypi/pyyaml"
        echo "  └ v25-a — V24 는 classifier · type 만 다른 둘을 한 식별자로 붙였다 · PyYAML 과 pyyaml 은 둘로" ;;
    esac

    # V25 는 탐지 · 패키지 · 검토 결과 · 조치의 식별자만 고친다 — 행은 지우지도 합치지도 않는다.
    case "$(basename "$f")" in V25__*)
        SAID=$(java_said "$f")
        printf '%s\n' "$SAID"
        # 고친 수 — 탐지 28 = 벡터 가운데 식별자가 바뀌는 22줄 + v25-a 6건(네이티브 둘 · test-jar ·
        # PyYAML · %2E · 코덱 네이티브), 패키지 23 = 벡터 22줄 + V22 의 유형 `Python` 줄(pkg:Python →
        # pkg:python). 검토 결과 · 조치는 v25-a 의 것뿐이다 — V24 의 기록은 바뀔 까닭이 없다.
        WANT25="탐지 28 · 패키지 23 · 검토 결과 옮김 3 / 비움 4 · 조치 옮김 1 / 비움 3"
        printf '%s' "$SAID" | grep -qF "$WANT25" || {
            echo "  V25 가 고친 수가 다릅니다 (기대 '$WANT25')"; exit 1; }
        AFTER25=$(run "$DB" -N -e "
            SELECT CONCAT((SELECT COUNT(*) FROM finding_analysis), '|', (SELECT COUNT(*) FROM remediations), '|',
                          (SELECT COUNT(*) FROM findings), '|', (SELECT COUNT(*) FROM component));")
        [ "$AFTER25" = "$COUNTS24" ] || {
            echo "  V25 앞뒤로 행 수가 다릅니다 — 검토 결과|조치|탐지|패키지 '$COUNTS24' → '$AFTER25'"; exit 1; }
        echo "  └ 검토 결과 · 조치 · 탐지 · 패키지 행 수 그대로 ($AFTER25) — 지우거나 합치지 않음" ;;
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

# V11 이 옮긴 세 키만 센다 — 뒤(V15 확인)에서 검토 결과를 더 넣는다.
TOTAL=$(run "$DB" -N -e "
    SELECT COUNT(*) FROM finding_analysis
    WHERE cve IN ('CVE-2024-0001', 'CVE-2024-0002', 'CVE-2024-0003');")
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

# 기대값도 DB 안에서 만든다 — 씨앗이 DB 의 NOW() 로 들어갔으니 그 행과 그대로 견준다.
# 앞서 셸의 `date` 로 날짜를 만들어, 셸과 DB 의 시간대가 다르면 그날의 몇 시간 동안 날짜가
# 하루 어긋나 거짓으로 실패했다(셸 America/Los_Angeles · DB UTC 로 재현).
#   마지막 = 성공 중 가장 최근(1일 전) · 그 전 = 두 번째(3일 전) — 2일 전의 실패는 세지 않는다.
LOGINS=$(run "$DB" -N -e "
    SELECT CONCAT(
      last_login_at     = (SELECT at FROM audit_log WHERE actor = 'oldtimer' AND action = 'LOGIN_SUCCESS'
                           AND at > NOW(6) - INTERVAL 2 DAY),
      '|',
      previous_login_at = (SELECT at FROM audit_log WHERE actor = 'oldtimer' AND action = 'LOGIN_SUCCESS'
                           AND at < NOW(6) - INTERVAL 2 DAY AND at > NOW(6) - INTERVAL 5 DAY))
    FROM users WHERE username='oldtimer';")
[ "$LOGINS" = "1|1" ] || {
    echo "  옛 계정의 로그인 시각이 감사 로그와 다릅니다 ('$LOGINS' — 기대 1|1: 마지막 = 1일 전 성공 · 그 전 = 3일 전 성공)"
    run "$DB" -N -e "SELECT last_login_at, previous_login_at FROM users WHERE username='oldtimer';"
    exit 1; }
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
INSERT INTO scans (asset_id, status, created_at, sbom_created_at, created_by, sbom_filename)
VALUES ($ASSET_ID, 'DONE', NOW(6), NOW(6), 'migcheck', 'sbom.json');"
SCAN_ID=$(run "$DB" -N -e "SELECT id FROM scans WHERE created_by='migcheck';")
run "$DB" -e "
INSERT INTO component (asset_id, scan_id, name, version, type, purl, location) VALUES
 ($ASSET_ID, $SCAN_ID, 'openssl-libs', '3.0.7-24', 'rpm',
  'pkg:rpm/rocky/openssl-libs@3.0.7-24', '/usr/lib64/libssl.so.3'),
 ($ASSET_ID, $SCAN_ID, 'glibc', '2.34-83', 'rpm', 'pkg:rpm/rocky/glibc@2.34-83', '');"
# 이 검사의 행만 센다 — V22 확인에 쓸 행이 다른 검사에 함께 담겨 있다.
BEFORE=$(run "$DB" -N -e "SELECT COUNT(*) FROM component WHERE scan_id=$SCAN_ID;")
[ "$BEFORE" = "2" ] || { echo "  인벤토리 2행이 안 들어갔습니다 ($BEFORE)"; exit 1; }

run "$DB" -e "DELETE FROM scans WHERE id=$SCAN_ID;"
AFTER=$(run "$DB" -N -e "SELECT COUNT(*) FROM component WHERE scan_id=$SCAN_ID;")
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

# --- V15: 조치의 목표 버전 — 하나로 고르지 않는다 --------------------------
#
# 앞서 조치는 CVSS 가 가장 높은 건의 수정 버전 하나였다(여기서는 9.0.68 —
# 그리로 올려도 둘이 남는다). 등록한 검사에서 전부를 다시 모아야 하고,
# 모을 데가 없는 조치는 적혀 있던 것을 지우지 않아야 한다.

TV=$(run "$DB" -N -e "SELECT to_version FROM remediations WHERE package_name='tomcat-coyote';")
[ "$TV" = "9.0.107 9.0.68 9.0.90" ] || {
    echo "  목표 버전이 '$TV' 입니다 (기대 '9.0.107 9.0.68 9.0.90')"; exit 1; }
echo "  등록한 검사에서 수정 버전 전부를 모음 (글자 순 · 해당 없음과 수정 버전 없는 건은 뺌)"

GONE=$(run "$DB" -N -e "SELECT to_version FROM remediations WHERE package_name='libxml2';")
[ "$GONE" = "2.9.4+dfsg1-7+deb10u4" ] || {
    echo "  등록한 검사가 지워진 조치의 목표가 '$GONE' 로 바뀌었습니다"; exit 1; }
echo "  등록한 검사가 지워진 조치는 그대로"

LEGACY=$(run "$DB" -N -e "SELECT to_version FROM remediations WHERE package_name='zlib';")
[ "$LEGACY" = "1.2.13" ] || {
    echo "  등록한 검사를 모르는 옛 조치의 목표가 '$LEGACY' 로 바뀌었습니다"; exit 1; }
echo "  등록한 검사를 모르는 옛 조치(opened_scan_id 없음)도 그대로"

WIDTH=$(run "$DB" -N -e "
    SELECT CHARACTER_MAXIMUM_LENGTH FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA='$DB' AND TABLE_NAME='remediations' AND COLUMN_NAME='to_version';")
[ "$WIDTH" = "4000" ] || { echo "  to_version 이 $WIDTH 자입니다 (4000 이어야 함)"; exit 1; }
echo "  to_version 4000자"

# --- V16: 조치의 현재 버전 — 하나로 고르지 않는다 --------------------------
#
# 앞서 조치는 CVSS 가 가장 높은 건의 설치 버전 하나였다(여기서는 2.14.1).
# 같은 검사에 깔린 다른 벌(2.9.1 …)을 다시 모아야 하고, 모을 데가 없거나
# 칸을 넘는 조치는 적혀 있던 것을 지우지 않아야 한다.

FV=$(run "$DB" -N -e "SELECT from_version FROM remediations WHERE package_name='log4j-core';")
[ "$FV" = "2.14.1 2.17.0-RC1 2.17.0-rc1 2.9.1" ] || {
    echo "  현재 버전이 '$FV' 입니다 (기대 '2.14.1 2.17.0-RC1 2.17.0-rc1 2.9.1')"; exit 1; }
echo "  등록한 검사에서 설치 버전 전부를 모음 (글자 순 · 대소문자는 가름 · 빈 버전은 뺌)"

WIDE_KEPT=$(run "$DB" -N -e "SELECT from_version FROM remediations WHERE package_name='widepkg';")
[ "$WIDE_KEPT" = "1.0.0-build.001.abcdef" ] || {
    echo "  칸을 넘는 조치의 현재 버전이 '$(echo "$WIDE_KEPT" | cut -c1-60)…' 로 바뀌었습니다"; exit 1; }
echo "  모은 것이 4,000자를 넘는 조치는 그대로 (마이그레이션은 실패하지 않음)"

for pkg in "tomcat-coyote|9.0.50" "libxml2|2.9.4" "zlib|1.2.11" "openssl|3.0.1"; do
    name=${pkg%%|*}; want=${pkg#*|}
    got=$(run "$DB" -N -e "SELECT from_version FROM remediations WHERE package_name='$name';")
    [ "$got" = "$want" ] || { echo "  $name 의 현재 버전이 '$got' 로 바뀌었습니다 (기대 '$want')"; exit 1; }
done
echo "  버전이 적힌 탐지가 없는 검사 · 지워진 검사 · 검사를 모르는 조치는 그대로"

WIDTH=$(run "$DB" -N -e "
    SELECT CHARACTER_MAXIMUM_LENGTH FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA='$DB' AND TABLE_NAME='remediations' AND COLUMN_NAME='from_version';")
[ "$WIDTH" = "4000" ] || { echo "  from_version 이 $WIDTH 자입니다 (4000 이어야 함)"; exit 1; }
echo "  from_version 4000자"

# --- V17: SBOM 생성 시각 · 해시 · 도구 · 대상 ------------------------------
#
# 옛 검사는 SBOM 을 다시 읽어 채우지 않는다 — 시각 자리에 그 SBOM 을 업로드한
# 시각을 넣고 출처를 UNCONFIRMED 로 둔다. 다시 검사는 사슬을 거슬러 원본의 것을,
# 원본이 지워진 다시 검사(rescan_of 가 비었다)는 제 것을.

for row in "chain-o1|2026-08-01 10:00" "chain-r1|2026-08-01 10:00" "chain-r2|2026-08-01 10:00" \
           "chain-r3|2026-08-01 10:00" "new-o2|2026-08-15 10:00" "orphan-r4|2026-07-05 10:00" \
           "failed-o5|2026-08-28 10:00"; do
    name=${row%%|*}; want=${row#*|}
    got=$(run "$DB" -N -e "
        SELECT DATE_FORMAT(sbom_created_at, '%Y-%m-%d %H:%i') FROM scans WHERE sbom_filename='$name';")
    [ "$got" = "$want" ] || { echo "  $name 의 SBOM 생성 시각이 '$got' 입니다 (기대 '$want')"; exit 1; }
done
echo "  원본은 만든 시각 · 다시 검사는 사슬 끝 원본의 만든 시각 · 원본이 지워진 다시 검사는 제 시각"

LONG_AT=$(run "$DB" -N -e "
    SELECT CONCAT(COUNT(*), '|', COUNT(DISTINCT sbom_created_at), '|',
                  DATE_FORMAT(MIN(sbom_created_at), '%Y-%m-%d %H:%i'))
    FROM scans WHERE sbom_filename LIKE 'long-%';")
[ "$LONG_AT" = "41|1|2026-06-01 09:00" ] || {
    echo "  41칸 사슬이 '$LONG_AT' 입니다 (기대 '41|1|2026-06-01 09:00') — 끝까지 거슬러 오르지 못했습니다"; exit 1; }
echo "  41칸 사슬도 전부 원본의 시각"

# 옛 규칙(검사 시각)으로는 사슬의 마지막 다시 검사(8/25)가 최신이었다 — 옛 SBOM 이다.
CURRENT=$(run "$DB" -N -e "
    SELECT sbom_filename FROM scans WHERE asset_id=3 AND status='DONE'
    ORDER BY sbom_created_at DESC, created_at DESC, id DESC LIMIT 1;")
[ "$CURRENT" = "new-o2" ] || { echo "  db-01 의 최신 검사가 '$CURRENT' 입니다 (기대 'new-o2')"; exit 1; }
echo "  옛 SBOM 을 다시 검사한 줄이 최신 검사가 되지 않음 (새 원본이 최신)"

LEGACY=$(run "$DB" -N -e "
    SELECT CONCAT(COUNT(*), '|', SUM(sbom_time_source='UNCONFIRMED'), '|',
                  SUM(sbom_sha256 IS NULL), '|', SUM(sbom_tool=''), '|', SUM(sbom_target=''))
    FROM scans WHERE created_by <> 'migcheck';")
N=${LEGACY%%|*}
[ "$LEGACY" = "$N|$N|$N|$N|$N" ] || {
    echo "  옛 검사의 출처 · 해시 · 도구 · 대상이 '$LEGACY' 입니다 — 전부 확인되지 않음이어야 합니다"; exit 1; }
echo "  옛 검사 ${N}행 — 출처 UNCONFIRMED · 해시 · 도구 · 대상은 비움 (지어내 채우지 않음)"

NULLABLE=$(run "$DB" -N -e "
    SELECT IS_NULLABLE FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA='$DB' AND TABLE_NAME='scans' AND COLUMN_NAME='sbom_created_at';")
[ "$NULLABLE" = "NO" ] || { echo "  sbom_created_at 이 비어도 되는 칸입니다"; exit 1; }
run "$DB" -e "SHOW COLUMNS FROM scans LIKE 'sbom_root';" | grep -q sbom_root \
    && { echo "  이관에 쓴 sbom_root 가 남아 있습니다"; exit 1; }
echo "  sbom_created_at 은 비지 않는 칸 · 이관에 쓴 칸은 지움"

# --- V18: 둘로 갈린 검토 결과 ------------------------------------------------
#
# 나중에 고친 쪽을 남기고, 다른 쪽의 이력은 그때의 시각 그대로 옮기고, 다른 쪽의
# 결정은 `검토 결과 합침` 한 줄과 감사 로그로 남긴다(D4).

rows() {   # rows <자산> <패키지> → 개수|번호들|상태들
    run "$DB" -N -e "
        SELECT CONCAT(COUNT(*), '|', GROUP_CONCAT(cve ORDER BY cve), '|',
                      GROUP_CONCAT(state ORDER BY cve))
        FROM finding_analysis WHERE asset_id = $1 AND package_name = '$2';"
}

GOT=$(rows 1 lodash)
[ "$GOT" = "1|CVE-2025-9999|EXPLOITABLE" ] || { echo "  짝이 '$GOT' 입니다 (기대 1|CVE-2025-9999|EXPLOITABLE)"; exit 1; }
KEPT=$(run "$DB" -N -e "
    SELECT CONCAT(response, '|', updated_by, '|', DATE_FORMAT(updated_at, '%Y-%m-%d %H:%i'), '|',
                  DATE_FORMAT(created_at, '%Y-%m-%d %H:%i'))
    FROM finding_analysis WHERE asset_id = 1 AND package_name = 'lodash';")
[ "$KEPT" = "UPDATE|lee|2026-09-01 09:00|2026-08-01 09:00" ] \
    || { echo "  남긴 행이 '$KEPT' 입니다 — 값 · 고친 시각은 그대로, 처음 기록은 둘 중 이른 것(2026-08-01)"; exit 1; }
echo "  짝은 하나로 — 나중에 고친 쪽(CVE · 해당됨)이 남고 그 값은 그대로 · 처음 기록은 둘 중 이른 것"

HIST=$(run "$DB" -N -e "
    SELECT GROUP_CONCAT(CONCAT(e.field_name, ':', e.before_value, '>', e.after_value, '@', e.actor)
                        ORDER BY e.at, e.id SEPARATOR ' / ')
    FROM finding_analysis_event e JOIN finding_analysis a ON a.id = e.analysis_id
    WHERE a.asset_id = 1 AND a.package_name = 'lodash';")
WANT="상태:미검토>해당 없음@kim / 상태:미검토>해당됨@lee / 검토 결과 합침:GHSA-p3aa-bbbb-cccc · 해당 없음 · 취약한 코드를 실행하지 않음>CVE-2025-9999@"
[ "$HIST" = "$WANT" ] || { echo "  이력이 '$HIST' 입니다"; echo "  기대 '$WANT'"; exit 1; }
MOVED=$(run "$DB" -N -e "
    SELECT DATE_FORMAT(e.at, '%Y-%m-%d %H:%i') FROM finding_analysis_event e
    JOIN finding_analysis a ON a.id = e.analysis_id
    WHERE a.asset_id = 1 AND a.package_name = 'lodash' AND e.actor = 'kim';")
[ "$MOVED" = "2026-08-01 09:00" ] || { echo "  옮긴 이력의 시각이 '$MOVED' 입니다 (그때의 시각이어야 함)"; exit 1; }
echo "  지운 쪽의 이력은 그때의 시각으로 옮기고, 그 결정은 \`검토 결과 합침\` 한 줄로"

AUDIT=$(run "$DB" -N -e "
    SELECT CONCAT(COUNT(*), '|', SUM(actor = ''), '|',
                  SUM(ABS(TIMESTAMPDIFF(MINUTE, at, UTC_TIMESTAMP())) < 30))
    FROM audit_log WHERE action = 'ANALYSIS_MERGED';")
[ "$AUDIT" = "2|2|2" ] || { echo "  감사 로그가 '$AUDIT' 입니다 (기대 2|2|2 — 둘 · 계정 비움 · UTC)"; exit 1; }
DETAIL=$(run "$DB" -N -e "
    SELECT CONCAT(target, ' :: ', detail) FROM audit_log
    WHERE action = 'ANALYSIS_MERGED' AND target LIKE '%CVE-2025-9999';")
WANT="web-01 · CVE-2025-9999 :: lodash · GHSA-p3aa-bbbb-cccc · 해당 없음 · 취약한 코드를 실행하지 않음 → CVE-2025-9999 · 설명: 해당 함수를 쓰지 않음 · 추가 보안 통제: 내부망만 · 결재 문서 번호: 보안-2026-0001"
[ "$DETAIL" = "$WANT" ] || { echo "  감사 로그 내용이 '$DETAIL' 입니다"; echo "  기대 '$WANT'"; exit 1; }
echo "  감사 로그 2줄 — 계정 비움 · UTC 시각 · 이력에 없는 칸(설명 · 추가 보안 통제 · 결재 문서 번호)까지"

GOT=$(rows 5 zlib)
[ "$GOT" = "1|CVE-2025-5555|NOT_AFFECTED" ] || { echo "  같은 시각의 짝이 '$GOT' 입니다 (나중에 만든 CVE 행)"; exit 1; }
echo "  고친 시각이 같으면 나중에 만든 행이 남음"

for want in "1|jackson|2|CVE-2025-8888,GHSA-nolk-nolk-nolk" \
            "2|netty|3|CVE-2025-7777,GHSA-t1t1-t1t1-t1t1,GHSA-t2t2-t2t2-t2t2" \
            "1|other-pkg|1|CVE-2025-9999" \
            "4|lodash|2|CVE-2025-9999,GHSA-p3aa-bbbb-cccc"; do
    IFS='|' read -r asset pkg n ids <<< "$want"
    GOT=$(rows "$asset" "$pkg")
    [ "${GOT%|*}" = "$n|$ids" ] || { echo "  자산 $asset · $pkg 가 '$GOT' 입니다 (그대로여야 함: $n|$ids)"; exit 1; }
done
echo "  근거 탐지 없는 짝 · 셋 엮임 · 다른 패키지 · 다른 자산은 그대로"

run "$DB" -N -e "SHOW TABLES LIKE 'analysis%v18';" | grep -q . \
    && { echo "  이관에 쓴 표가 남아 있습니다"; exit 1; }
echo "  이관에 쓴 표는 지움"

# --- V19: 조치 회차 · 조치 대상 · 이력 칸 -------------------------------------
#
# 조치 대상은 등록한 검사에서 채운다(V15 · V16 과 같은 방식) — 똑같은 줄은 하나로,
# 글자가 다르면 둘로. 등록한 검사가 지워졌거나 모르는 조치는 비워 둔다(지어내 채우지
# 않는다 — 화면이 `확인되지 않음` 이라 적는다). 있던 조치는 모두 1회차다.

targets() {   # targets <패키지> → 그 패키지 조치의 조치 대상 수
    run "$DB" -N -e "
        SELECT COUNT(t.id) FROM remediations r LEFT JOIN remediation_targets t ON t.remediation_id = r.id
        WHERE r.package_name = '$1';"
}

for want in "pyyaml|4" "tomcat-coyote|6" "log4j-core|6" "widepkg|400" \
            "libxml2|0" "openssl|0" "glibc|0" "zlib|0"; do
    pkg=${want%%|*}; n=${want#*|}
    got=$(targets "$pkg")
    [ "$got" = "$n" ] || { echo "  $pkg 의 조치 대상이 $got 줄입니다 (기대 $n)"; exit 1; }
done
echo "  등록한 검사에서 조치 대상을 채움 · 등록한 검사가 지워졌거나 모르는 조치는 비워 둠"

PY=$(run "$DB" -N -e "
    SELECT CONCAT(SUM(t.cve = 'GHSA-v19v-v19v-v19v' AND t.related_cve = 'CVE-2026-1919'
                      AND t.package_version = '5.3' AND t.fixed_version = '5.4'), '|',
                  COUNT(DISTINCT CASE WHEN t.cve = 'CVE-2026-1920' THEN t.package_version COLLATE utf8mb4_bin END), '|',
                  SUM(t.cve = '$LONGID' AND CHAR_LENGTH(t.cve) = 95))
    FROM remediation_targets t JOIN remediations r ON r.id = t.remediation_id
    WHERE r.package_name = 'pyyaml';")
[ "$PY" = "1|2|1" ] || {
    echo "  pyyaml 의 조치 대상이 '$PY' 입니다 (기대 1|2|1 — 같은 탐지 하나 · 대소문자 다른 버전 둘 · 긴 번호 그대로)"; exit 1; }
echo "  경로만 다른 같은 탐지는 하나로 · 대소문자만 다른 버전은 둘로 · 함께 온 CVE 와 95자 번호는 그대로"

ROUNDS=$(run "$DB" -N -e "
    SELECT CONCAT(COUNT(*), '|', SUM(round_no = 1), '|', SUM(previous_id IS NULL)) FROM remediations;")
N=${ROUNDS%%|*}
[ "$ROUNDS" = "$N|$N|$N" ] || { echo "  있던 조치의 회차가 '$ROUNDS' 입니다 (전부 1회차 · 이전 조치 없음이어야 함)"; exit 1; }
echo "  있던 조치 ${N}행 — 전부 1회차 · 이전 조치 없음"

EVENTS=$(run "$DB" -N -e "
    SELECT CONCAT(COUNT(*), '|', SUM(field_name = '' AND before_value = '' AND after_value = ''))
    FROM remediation_events;")
N=${EVENTS%%|*}
[ "$N" -gt 0 ] && [ "$EVENTS" = "$N|$N" ] || {
    echo "  있던 조치 이력이 '$EVENTS' 입니다 — 새 칸은 비어 있어야 합니다(상태 줄)"; exit 1; }
WIDTH=$(run "$DB" -N -e "
    SELECT GROUP_CONCAT(CONCAT(TABLE_NAME, '.', COLUMN_NAME, '=', CHARACTER_MAXIMUM_LENGTH)
                        ORDER BY TABLE_NAME, COLUMN_NAME SEPARATOR ' ')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = '$DB' AND COLUMN_NAME IN ('before_value', 'after_value', 'field_name')
      AND TABLE_NAME IN ('remediation_events', 'finding_analysis_event');")
WANT="finding_analysis_event.after_value=2000 finding_analysis_event.before_value=2000 finding_analysis_event.field_name=32 remediation_events.after_value=1000 remediation_events.before_value=1000 remediation_events.field_name=32"
[ "$WIDTH" = "$WANT" ] || { echo "  이력 칸이 '$WIDTH' 입니다"; echo "  기대 '$WANT'"; exit 1; }
echo "  있던 조치 이력 ${N}줄은 상태 줄 그대로 · 이력 칸 — 조치 1,000자 · 검토 결과 2,000자"

run "$DB" -N -e "SHOW INDEX FROM remediations WHERE Key_name = 'uk_remediation_open';" | grep -q . \
    && { echo "  (자산, 패키지) 유일 키가 남아 있습니다"; exit 1; }
run "$DB" -N -e "SHOW INDEX FROM remediations WHERE Key_name = 'ix_remediation_asset_pkg';" | grep -q . \
    || { echo "  (자산, 패키지) 색인이 없습니다 — 자산 FK 와 조치 찾기가 기대는 색인"; exit 1; }
# 실제로 넣어 본다 — 1회차를 완료로 닫고 같은 (자산, 패키지)의 2회차를 연다.
run "$DB" -e "
    UPDATE remediations SET status = 'DONE', closed_at = NOW(6)
    WHERE asset_id = 5 AND package_name = 'pyyaml';
    INSERT INTO remediations
      (asset_id, package_name, round_no, previous_id, from_version, to_version, status, owner,
       opened_count, note, created_at, created_by, updated_at, updated_by)
    SELECT asset_id, package_name, 2, id, '', '', 'OPEN', '', 0, '', NOW(6), 'admin', NOW(6), 'admin'
    FROM remediations WHERE asset_id = 5 AND package_name = 'pyyaml';"
SECOND=$(run "$DB" -N -e "
    SELECT CONCAT(COUNT(*), '|', MAX(round_no)) FROM remediations WHERE asset_id = 5 AND package_name = 'pyyaml';")
[ "$SECOND" = "2|2" ] || { echo "  2회차를 넣지 못했습니다 ('$SECOND')"; exit 1; }
echo "  (자산, 패키지) 유일 키를 풀고 보통 색인으로 — 같은 패키지에 2회차가 들어감"

# 조치를 지우면 그 조치 대상도 사라진다 — 제약 이름만 보고 넘어가면 방향이 뒤집혀
# 있어도 통과한다. 이전 조치에는 FK 가 없다 — 1회차를 지워도 2회차는 막히지 않고
# 남는다(앱이 다음 회차가 있는 조치를 지우지 않는다 — RemediationService.delete).
run "$DB" -e "DELETE FROM remediations WHERE asset_id = 5 AND package_name = 'pyyaml' AND round_no = 1;"
LEFT="$(targets pyyaml)|$(run "$DB" -N -e "
    SELECT COUNT(*) FROM remediations WHERE asset_id = 5 AND package_name = 'pyyaml';")"
[ "$LEFT" = "0|1" ] || { echo "  조치를 지운 뒤 '$LEFT' 입니다 (기대 0|1 — 대상은 함께 사라지고 2회차는 남음)"; exit 1; }
echo "  조치를 지우면 조치 대상도 사라짐 (ON DELETE CASCADE) · 이전 조치에는 FK 없음"

SINCE=$(run "$DB" -N -e "
    SELECT CONCAT(setting_value, '|', ABS(TIMESTAMPDIFF(MINUTE, updated_at, UTC_TIMESTAMP())) < 30)
    FROM app_settings WHERE name = 'history_fields_since';")
[ "$SINCE" = "V19|1" ] || { echo "  이력이 모든 칸을 남기기 시작한 시각이 '$SINCE' 입니다 (기대 V19|1 — UTC)"; exit 1; }
echo "  이력이 모든 칸을 남기기 시작한 시각을 UTC 로 적음 (그 전 기록에만 각주)"

# --- V20: 보고서 발행본 ---------------------------------------------------------
#
# 새 표 셋 — 옮길 데이터가 없다. 지키는 것은 넷: 칸 너비(결재 문서 번호는 검토 결과와
# 같은 128자) · 발행 번호는 겹쳐 들어가지 않는다 · 검사 목록과 이력은 없는 발행본을
# 가리키지 못한다 · 자산을 지워도 발행본과 그 검사 목록은 남는다(검사 쪽 FK 없음, D6).

PUBCOLS=$(run "$DB" -N -e "
    SELECT GROUP_CONCAT(CONCAT(COLUMN_NAME, '=', DATA_TYPE,
                               IFNULL(CONCAT('(', CHARACTER_MAXIMUM_LENGTH, ')'), ''))
                        ORDER BY COLUMN_NAME SEPARATOR ' ')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = '$DB' AND TABLE_NAME = 'report_publications'
      AND COLUMN_NAME IN ('approval_doc', 'document_html', 'document_json', 'document_sha256', 'target_name');")
WANT="approval_doc=varchar(128) document_html=longtext(4294967295) document_json=longtext(4294967295) document_sha256=varchar(64) target_name=varchar(255)"
[ "$PUBCOLS" = "$WANT" ] || { echo "  발행본 칸이 '$PUBCOLS' 입니다"; echo "  기대 '$WANT'"; exit 1; }
echo "  발행본 칸 — 문서 둘은 LONGTEXT · 해시 64자 · 결재 문서 번호 128자(검토 결과와 같음)"

PUBSCAN=$(run "$DB" -N -e "SELECT MIN(id) FROM scans WHERE asset_id = 5;")
publish() {   # publish <종류> <연도> <일련번호> — 가리키는 검사는 자산 5의 첫 검사
    run "$DB" -e "
        INSERT INTO report_publications
          (kind, pub_year, pub_seq, published_at, published_by, target_name, asset_id, scan_id,
           document_json, document_html, document_sha256)
        VALUES ('$1', $2, $3, NOW(6), 'admin', 'v20-check', 5, $PUBSCAN, '{}', '<p>v20</p>', REPEAT('a', 64));"
}
publish SCAN 2026 1
publish SCAN 2026 2
publish ZONE 2027 1
if publish ZONE 2026 2 2>/dev/null; then
    echo "  같은 발행 번호(2026-0002)가 두 번 들어갔습니다"; exit 1
fi
echo "  발행 번호(연도, 일련번호)는 겹쳐 들어가지 않음 · 해가 바뀌면 1 부터"

PUB=$(run "$DB" -N -e "SELECT id FROM report_publications WHERE pub_year = 2026 AND pub_seq = 1;")
run "$DB" -e "
    INSERT INTO report_publication_scans (publication_id, scan_id) VALUES ($PUB, $PUBSCAN);
    INSERT INTO report_publication_events (publication_id, at, actor, before_value, after_value)
    VALUES ($PUB, NOW(6), 'admin', '', '보안-2026-0143');"
for t in report_publication_scans report_publication_events; do
    case $t in
        report_publication_scans)  bad="INSERT INTO $t (publication_id, scan_id) VALUES (999999, $PUBSCAN);" ;;
        report_publication_events) bad="INSERT INTO $t (publication_id, at) VALUES (999999, NOW(6));" ;;
    esac
    if run "$DB" -e "$bad" 2>/dev/null; then
        echo "  $t 가 없는 발행본을 가리켰습니다 — 발행본 쪽 FK 가 없습니다"; exit 1
    fi
done
echo "  가리키는 검사 · 결재 문서 번호 이력은 없는 발행본을 가리키지 못함 (FK)"

# 자산을 지운다 — 앱과 같은 차례로(검사 먼저, 그다음 자산 — AssetService.delete).
run "$DB" -e "DELETE FROM scans WHERE asset_id = 5; DELETE FROM assets WHERE id = 5;"
KEPT=$(run "$DB" -N -e "
    SELECT CONCAT((SELECT COUNT(*) FROM assets WHERE id = 5), '|',
                  (SELECT COUNT(*) FROM report_publications WHERE asset_id = 5), '|',
                  (SELECT COUNT(*) FROM report_publication_scans WHERE scan_id = $PUBSCAN), '|',
                  (SELECT COUNT(*) FROM report_publication_events WHERE publication_id = $PUB));")
[ "$KEPT" = "0|3|1|1" ] || {
    echo "  자산을 지운 뒤 '$KEPT' 입니다 (기대 0|3|1|1 — 자산은 사라지고 발행본 · 검사 목록 · 이력은 남음)"; exit 1; }
echo "  자산을 지워도 발행본 · 가리키던 검사 번호 · 이력은 남음 (검사 · 자산 쪽 FK 없음)"

# --- V21: 검토 결과의 번호 칸 — 탐지와 같은 128자 -------------------------------
#
# 탐지의 번호를 그대로 받는 칸 셋이 같은 너비인가. 앞서 검토 결과만 64자라 그보다 긴
# 번호의 탐지에는 검토 결과를 적을 수 없었다. 95자 번호가 실제로 들어가는지 넣어 본다.

CVEW=$(run "$DB" -N -e "
    SELECT GROUP_CONCAT(CONCAT(TABLE_NAME, '=', CHARACTER_MAXIMUM_LENGTH)
                        ORDER BY FIELD(TABLE_NAME, 'findings', 'finding_analysis', 'remediation_targets')
                        SEPARATOR ' ')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = '$DB' AND COLUMN_NAME = 'cve'
      AND TABLE_NAME IN ('findings', 'finding_analysis', 'remediation_targets');")
WANT="findings=128 finding_analysis=128 remediation_targets=128"
[ "$CVEW" = "$WANT" ] || { echo "  번호 칸이 '$CVEW' 입니다 (기대 '$WANT')"; exit 1; }
ANY=$(run "$DB" -N -e "SELECT MIN(id) FROM assets;")
run "$DB" -e "
    INSERT INTO finding_analysis (asset_id, cve, package_name, state, created_at, updated_at)
    VALUES ($ANY, '$LONGID', 'v21check', 'IN_TRIAGE', NOW(6), NOW(6));"
GOT=$(run "$DB" -N -e "SELECT CHAR_LENGTH(cve) FROM finding_analysis WHERE package_name = 'v21check';")
[ "$GOT" = "95" ] || { echo "  95자 번호의 검토 결과가 '$GOT' 자로 들어갔습니다"; exit 1; }
echo "  번호 칸 — 탐지 · 검토 결과 · 조치 대상 모두 128자 · 95자 번호의 검토 결과가 그대로 들어감"

# --- V22: 패키지 유형을 purl 의 이름으로 -----------------------------------------
#
# purl 없이 syft 의 이름으로 담긴 행만 옮긴다(앱의 PackageTypes 와 같은 표). purl 이 있는
# 행의 유형은 purl 의 것이라 그대로다 — `pkg:conda/…` 의 conda 를 syft 의 conda 로 읽어
# generic 으로 바꾸면 남의 이름이 된다.

V22SCAN=$(run "$DB" -N -e "SELECT id FROM scans WHERE created_by = 'v22check';")
TYPES=$(run "$DB" -N -e "
    SELECT GROUP_CONCAT(CONCAT(name, '=', type) ORDER BY name SEPARATOR ' ')
    FROM component WHERE scan_id = $V22SCAN;")
WANT="busybox=binary jackson-databind=maven log4j-core=maven mystery= numpy=conda openssl=rpm pycase=Python requests=pypi upper=pypi weird=golang"
[ "$TYPES" = "$WANT" ] || { echo "  유형이 '$TYPES' 입니다"; echo "  기대 '$WANT'"; exit 1; }
echo "  purl 없는 syft 이름(java-archive · python · go-module · UnknownPackage)을 purl 의 이름으로"
echo "  purl 이 있는 행(conda · maven) · 표에 없는 유형(binary) · 이름이 같은 유형(rpm) · 대소문자 다른 것은 그대로"

# --- V23: 탐지의 수정 버전 — 후보 전부 -------------------------------------------
#
# 탐지는 상세(fixVersions)의 후보 전부를 글자 순으로. 조치 대상은 짝지은 탐지의 것으로.
# 조치의 목표는 적혀 있던 것을 지우지 않고 세던 탐지의 나머지 후보를 더한다 — 해당 없음으로
# 적힌 탐지(2305)의 7.7.7 은 더하지 않는다. 읽을 수 없는 것은 그대로, 멈추지 않는다.

FIXW=$(run "$DB" -N -e "
    SELECT GROUP_CONCAT(CONCAT(TABLE_NAME, '=', CHARACTER_MAXIMUM_LENGTH) ORDER BY TABLE_NAME SEPARATOR ' ')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = '$DB' AND COLUMN_NAME = 'fixed_version'
      AND TABLE_NAME IN ('findings', 'remediation_targets');")
[ "$FIXW" = "findings=1000 remediation_targets=1000" ] || { echo "  수정 버전 칸이 '$FIXW' 입니다"; exit 1; }

V23SCAN=$(run "$DB" -N -e "SELECT id FROM scans WHERE created_by = 'v23check';")
GOT=$(run "$DB" -N -e "
    SELECT GROUP_CONCAT(CONCAT(cve, '=', fixed_version) ORDER BY cve SEPARATOR ' / ')
    FROM findings WHERE scan_id = $V23SCAN;")
WANT="CVE-2021-3711=1.1.1l / CVE-2022-2068=1.0.2zf 1.1.1p 3.0.4 / CVE-2099-2301=9.9 / CVE-2099-2302=8.8 / CVE-2099-2303= / CVE-2099-2304=v0001-long-version / CVE-2099-2305=1.0.2zf 7.7.7 / CVE-2099-2306=1.0 2.0 / CVE-2099-2307=6.0-RC1 6.0-rc1 / CVE-2099-2308=1.0.2zf 5.5.5 / CVE-2099-2309=1.0.2zf 4.4.4 / GHSA-v23a-v23a-v23a=1.0.2ze 1.1.1o 3.0.3"
[ "$GOT" = "$WANT" ] || { echo "  탐지의 수정 버전이"; echo "    '$GOT'"; echo "  기대"; echo "    '$WANT'"; exit 1; }
echo "  탐지 — 후보 전부를 글자 순으로 (겹친 것 · 빈 것 · 앞뒤 빈칸은 빼고 · RC1 과 rc1 은 둘)"
echo "  상세 없음 · 못 읽음 · null · 후보 하나 · 1,000자를 넘는 것은 그대로"

GOT=$(run "$DB" -N -e "
    SELECT GROUP_CONCAT(CONCAT(t.cve, '=', t.fixed_version) ORDER BY t.cve SEPARATOR ' / ')
    FROM remediation_targets t JOIN remediations r ON r.id = t.remediation_id
    WHERE r.package_name = 'v23-ssl';")
WANT="CVE-2021-3711=1.1.1l / CVE-2022-2068=1.0.2zf 1.1.1p 3.0.4 / CVE-2099-2301=9.9 / CVE-2099-2302=8.8 / CVE-2099-2303= / CVE-2099-2304=v0001-long-version / CVE-2099-2305=1.0.2zf 7.7.7 / CVE-2099-2307=6.0-RC1 6.0-rc1 / GHSA-v23a-v23a-v23a=1.0.2ze 1.1.1o 3.0.3"
[ "$GOT" = "$WANT" ] || { echo "  조치 대상의 수정 버전이"; echo "    '$GOT'"; echo "  기대"; echo "    '$WANT'"; exit 1; }
echo "  조치 대상 — 짝지은 탐지와 같은 목록 (첫 번째가 같아도 번호가 다르면 제 것)"

GOT=$(run "$DB" -N -e "SELECT to_version FROM remediations WHERE package_name = 'v23-ssl';")
WANT="1.0.2ze 1.0.2zf 1.1.1l 1.1.1o 1.1.1p 3.0.3 3.0.4 6.0-RC1 6.0-rc1 8.8 9.9 v0001-long-version"
[ "$GOT" = "$WANT" ] || { echo "  목표 버전이 '$GOT' 입니다"; echo "  기대 '$WANT'"; exit 1; }
echo "  조치의 목표 — 적혀 있던 것은 그대로 두고 세던 탐지의 나머지 후보를 더함"
echo "    (해당 없음으로 적힌 탐지의 7.7.7 은 안 더함 · 나중에 해당됨으로 고친 GHSA/CVE 짝은 더함)"

for want in "v23-quote|x\"y 1.0.2zf" "v23-bslash|a\\b 1.0.2zf" "other-v23|1.0"; do
    pkg=${want%%|*}; tv=${want#*|}
    got=$(run "$DB" -N -r -e "SELECT to_version FROM remediations WHERE package_name = '$pkg';")
    [ "$got" = "$tv" ] || { echo "  $pkg 의 목표가 '$got' 로 바뀌었습니다 (기대 '$tv')"; exit 1; }
done
echo "  따옴표 · 역슬래시가 든 목표와 등록한 검사가 없는 조치는 그대로 (마이그레이션은 멈추지 않음)"

run "$DB" -N -e "SHOW TABLES LIKE '%v23';" | grep -q . \
    && { echo "  이관에 쓴 표가 남아 있습니다"; exit 1; }
echo "  이관에 쓴 표는 지움"

# --- V24: 패키지 식별자 ------------------------------------------------------------
#
# 탐지 · 인벤토리는 purl 에서 버전 · 한정자를 뗀 것(없으면 유형 · 이름) — 앱의 PackageKey 와 같은
# 벡터로 견준다. 검토 결과 · 조치의 옛 기록은 앞서 붙던 탐지가 한 패키지일 때만 식별자를 받고,
# 아니면 비운 채(NULL) 남는다 — 지우지도 아무 패키지에나 붙이지도 않는다.
#
# V24 가 낸 식별자(벡터 · 검토 결과 · 조치)는 V24 직후에 봤다(2 의 V24 고리) — V25 가 탐지 · 패키지의
# 것을 새 규칙으로 다시 만들어 여기에는 남아 있지 않다. 여기서는 칸 · 유일 키 · 색인과, V25 가 다시
# 가를 까닭이 없는 기록이 그대로인지를 본다.

KEYCOLS=$(run "$DB" -N -e "
    SELECT GROUP_CONCAT(CONCAT(TABLE_NAME, '=', COLUMN_TYPE, ':', IS_NULLABLE, ':', COLLATION_NAME)
                        ORDER BY FIELD(TABLE_NAME, 'component', 'finding_analysis', 'findings', 'remediations')
                        SEPARATOR ' ')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = '$DB' AND COLUMN_NAME = 'package_key';")
WANT="component=varchar(512):NO:utf8mb4_bin finding_analysis=varchar(512):YES:utf8mb4_bin findings=varchar(512):NO:utf8mb4_bin remediations=varchar(512):YES:utf8mb4_bin"
[ "$KEYCOLS" = "$WANT" ] || { echo "  식별자 칸이 '$KEYCOLS' 입니다"; echo "  기대 '$WANT'"; exit 1; }
echo "  식별자 칸 — 탐지 · 패키지는 비지 않음, 검토 결과 · 조치는 비울 수 있음 · 글자 그대로 견줌(utf8mb4_bin)"

EMPTY=$(run "$DB" -N -e "
    SELECT CONCAT((SELECT COUNT(*) FROM findings WHERE package_key = ''), '|',
                  (SELECT COUNT(*) FROM component WHERE package_key = '' AND version LIKE 'v24-vec-%'));")
[ "$EMPTY" = "0|0" ] || { echo "  식별자가 빈 탐지 · 패키지가 있습니다 ('$EMPTY')"; exit 1; }
echo "  있던 탐지 전부에 식별자 (purl 이 없던 옛 탐지도 유형 · 이름으로)"

check_v24_records
echo "  V24 가 검토 결과 · 조치에 단 식별자 — 한정자 · 이름 맞춤과 무관한 것은 V25 뒤에도 그대로"

UX=$(run "$DB" -N -e "
    SELECT GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX SEPARATOR ',')
    FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = '$DB' AND TABLE_NAME = 'finding_analysis' AND INDEX_NAME = 'ux_analysis_key'
      AND NON_UNIQUE = 0;")
[ "$UX" = "asset_id,cve,package_key" ] || { echo "  검토 결과의 유일 키가 '$UX' 입니다"; exit 1; }
A=$(run "$DB" -N -e "SELECT id FROM assets WHERE name = 'v24-a';")
run "$DB" -e "
    INSERT INTO finding_analysis (asset_id, cve, package_name, package_key, state, created_at, updated_at)
    VALUES ($A, 'CVE-2099-2401', 'semver', 'pkg:npm/semver', 'IN_TRIAGE', NOW(6), NOW(6)),
           ($A, 'CVE-2099-2401', 'semver', 'pkg:pypi/semver', 'IN_TRIAGE', NOW(6), NOW(6)),
           ($A, 'CVE-2099-2401', 'semver-old', NULL, 'IN_TRIAGE', NOW(6), NOW(6));"
if run "$DB" -e "
    INSERT INTO finding_analysis (asset_id, cve, package_name, package_key, state, created_at, updated_at)
    VALUES ($A, 'CVE-2099-2401', 'semver', 'pkg:npm/semver', 'IN_TRIAGE', NOW(6), NOW(6));" 2>/dev/null; then
    echo "  같은 (자산, 번호, 식별자)의 검토 결과가 두 번 들어갔습니다"; exit 1
fi
echo "  유일 키 (자산, 번호, 식별자) — 같은 이름의 npm · PyPI 에 따로 적힘 · 비운 옛 기록은 몇이든 남음"

for ix in "findings|ix_findings_scan_pkgkey|scan_id,package_key" \
          "component|ix_component_pkgkey|package_key" \
          "remediations|ix_remediation_asset_pkgkey|asset_id,package_key"; do
    IFS='|' read -r table name cols <<< "$ix"
    got=$(run "$DB" -N -e "
        SELECT GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX SEPARATOR ',')
        FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA = '$DB' AND TABLE_NAME = '$table' AND INDEX_NAME = '$name';")
    [ "$got" = "$cols" ] || { echo "  $table 의 색인 $name 이 '$got' 입니다 (기대 '$cols')"; exit 1; }
done
echo "  색인 — 탐지 (검사, 식별자) · 패키지 (식별자) · 조치 (자산, 식별자)"

run "$DB" -N -e "SHOW TABLES LIKE '%v24';" | grep -q . \
    && { echo "  이관에 쓴 표가 남아 있습니다"; exit 1; }
echo "  이관에 쓴 표는 지움"

# --- V25: 패키지 식별자 — 한정자 ---------------------------------------------------------
#
# 식별자는 표준 파서로 읽은 purl 에서 버전 · 하위 경로와 유형별로 정한 한정자를 뗀 것 — Maven 의
# classifier · type 처럼 패키지를 가르는 한정자는 남는다. V25 는 자바(Flyway 가 부르는 클래스)이고
# 앱의 PackageKey 를 그대로 부른다 — 같은 벡터의 5째 칸이 진짜 DB 를 지나서도(읽고 · 고쳐 쓰고) 같은지
# 본다. 검토 결과 · 조치는 붙던 탐지의 새 식별자가 하나일 때만 옮기고, 아니면 비운다.

check_vectors 5
echo "  벡터 ${VECTORS}줄 — 탐지 · 패키지 모두 앱(PackageKeyTest)과 같은 식별자 (5째 칸)"

expect_reviews "v25-a|CVE-2099-2501|netty-transport-native-epoll|NULL" \
               "v25-a|CVE-2099-2502|jffi|pkg:maven/com.github.jnr/jffi?classifier=native" \
               "v25-a|CVE-2099-2503|lib|NULL" \
               "v25-a|CVE-2099-2504|PyYAML|NULL" \
               "v25-a|CVE-2099-2504|pyyaml-dist|NULL" \
               "v25-a|CVE-2099-2505|netty-codec-enc|pkg:maven/io.netty/netty-codec" \
               "v25-a|CVE-2099-2505|netty-codec|pkg:maven/io.netty/netty-codec?classifier=linux-x86_64" \
               "v25-a|CVE-2099-2506|commons-text|pkg:maven/org.apache.commons/commons-text"
echo "  검토 결과 — 그 자산의 검사 전부에서 붙던 탐지의 새 식별자가 하나면 그것 (네이티브 하나뿐 · 바뀌지 않는 것)"
echo "    classifier 만 다른 둘 · 뒤 검사에서 test-jar 에도 붙은 것 · 이름 맞춤으로 둘이 한 식별자에 모인 것은 비움"
echo "    자리 바꿈 — 먼저 적은 쪽이 다른 쪽의 V24 식별자로 가도 유일 키 (자산, 번호, 식별자)에 걸리지 않음"

expect_remediations "v25-a|netty-transport-native-epoll|NULL" \
                    "v25-a|jffi|pkg:maven/com.github.jnr/jffi?classifier=native" \
                    "v25-a|lib|pkg:maven/org.example/lib" \
                    "v25-a|PyYAML|NULL" "v25-a|pyyaml-dist|NULL"
echo "  조치 — 등록한 검사의 탐지로 (앞 검사에 순수 jar 뿐이던 lib 은 그 식별자 · 검토 결과와 갈림)"
echo "    등록한 검사에 classifier 만 다른 둘 · 이름 맞춤으로 둘이 한 식별자에 모인 것은 비움"

run -e "DROP DATABASE \`$DB\`;"
echo
echo "마이그레이션 확인 통과"
