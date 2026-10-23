-- 조치의 현재 버전 — 목표 버전(V15)처럼 하나로 고르지 않는다.
--
-- 앞서 조치는 등록한 검사에서 CVSS 가 가장 높은 건의 설치 버전 하나를 적었다.
-- 한 자산에 같은 패키지가 두 벌 깔려 있으면(서로 다른 앱의 log4j-core 2.14.1 ·
-- 2.9.1, 커널 여러 벌) 나머지가 조치 화면 · CSV 어디에도 없었다 — 보고서 3장은
-- 두 줄로 따로 싣는데 조치는 한 벌만 말했다.
--
-- 저장하는 꼴은 to_version 과 같다: 글자 순으로 빈칸 하나씩 띄워 잇는다
-- (FixVersions). 버전 하나만 적힌 옛 행도 그대로 읽힌다. 글자 순이지 버전
-- 순이 아니다 — 버전끼리 견주지 않는다.

-- 1) 넓힌다. to_version 과 같은 폭.
ALTER TABLE remediations
    MODIFY COLUMN from_version VARCHAR(4000) NOT NULL DEFAULT '';

-- 2) 이미 등록된 조치는 **등록한 검사에서 다시 모은다** — 등록 당시 건수
--    (opened_count)와 같은 건, 즉 그 검사에서 그 패키지 이름으로 탐지된 건
--    전부의 설치 버전. 검토 결과로 거르지 않는다 — 깔려 있는 버전은 검토와
--    상관없는 사실이다.
--
--    그대로 두는 것: 등록한 검사가 지워졌거나 모를 때, 그 검사에 버전이 적힌
--    건이 없을 때(비우면 적혀 있던 것이 사라진다), 모은 것이 칸(4,000자)을
--    넘을 때(넘는 채로 넣으면 이 마이그레이션이 실패해 앱이 뜨지 않는다).
--
--    겹침도 글자 그대로 가른다(utf8mb4_bin) — 앱(FixVersions)이 그렇게 모은다.
--    열의 정렬 규칙(대소문자 무시)으로 가르면 `RC1` 과 `rc1` 이 하나가 된다.
SET SESSION group_concat_max_len = 1048576;

UPDATE remediations r
SET r.from_version = (
        SELECT GROUP_CONCAT(DISTINCT f.package_version COLLATE utf8mb4_bin
                            ORDER BY f.package_version COLLATE utf8mb4_bin SEPARATOR ' ')
        FROM findings f
        WHERE f.scan_id = r.opened_scan_id
          AND f.package_name = r.package_name
          AND f.package_version <> '')
WHERE r.opened_scan_id IS NOT NULL
  AND EXISTS (SELECT 1 FROM findings f
              WHERE f.scan_id = r.opened_scan_id
                AND f.package_name = r.package_name
                AND f.package_version <> '')
  AND (SELECT CHAR_LENGTH(GROUP_CONCAT(DISTINCT f.package_version COLLATE utf8mb4_bin
                                       SEPARATOR ' '))
       FROM findings f
       WHERE f.scan_id = r.opened_scan_id
         AND f.package_name = r.package_name
         AND f.package_version <> '') <= 4000;
