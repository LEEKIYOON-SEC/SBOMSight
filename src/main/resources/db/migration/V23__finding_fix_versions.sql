-- 탐지의 수정 버전 — grype 이 준 후보 전부를 적는다 (하나로 고르지 않는다).
--
-- 탐지의 수정 버전 칸에는 grype 이 준 후보(fix.versions) 중 첫 번째만 담았다. NVD(CPE)로
-- 맞춘 건 — binary 로 찾은 openssl · curl … — 은 갈래마다 하나씩 여럿을 준다: openssl 1.1.1k
-- 의 CVE-2022-2068 은 1.0.2zf · 1.1.1p · 3.0.4. 첫 번째(1.0.2zf)는 1.1.1k 와 다른 갈래인데
-- 취약점 화면 · 보고서 · 조치의 목표가 그 하나만 말했다. 어느 것이 맞는지 고르는 것은 검사
-- 결과를 다시 판정하는 일이라 — 여럿이면 여럿을 적는다(사용자 결정 · FixVersions).
--
-- 저장하는 꼴은 조치의 목표 버전(V15)과 같다 — 글자 순으로 빈칸 하나씩 띄워 잇는다. 후보
-- 하나만 적힌 행은 그대로 읽힌다. 후보 전부는 이미 탐지의 상세(detail_json 의 fixVersions)에
-- 있다 — 거기서 다시 모은다. 상세가 없거나 읽을 수 없는 행, 모은 것이 칸(1,000자)을 넘는
-- 행은 그대로 둔다(지어내지 않는다 · 마이그레이션은 실패하지 않는다).
--
-- 글자를 그대로 견준다(utf8mb4_bin) — RC1 과 rc1 은 다른 버전이다(V16 과 같은 까닭).

-- 1) 넓힌다. 탐지의 칸을 그대로 옮겨 적는 조치 대상(V19)도 같은 너비로.
ALTER TABLE findings
    MODIFY COLUMN fixed_version VARCHAR(1000) NOT NULL DEFAULT '';
ALTER TABLE remediation_targets
    MODIFY COLUMN fixed_version VARCHAR(1000) NOT NULL DEFAULT '';

SET SESSION group_concat_max_len = 1048576;

-- 2) 후보가 둘 이상 적힌 탐지만 상세에서 편다. 하나 이하면 지금 칸(첫 번째)과 같다.
--    읽을 수 없는 상세는 빈 문서로 읽는다 — 그 행은 건너뛴다.
CREATE TABLE fix_candidates_v23 (
    finding_id BIGINT       NOT NULL,
    version    VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    PRIMARY KEY (finding_id, version)
) ENGINE = InnoDB;

INSERT IGNORE INTO fix_candidates_v23 (finding_id, version)
SELECT f.id, TRIM(j.version)
FROM findings f
JOIN JSON_TABLE(CASE WHEN JSON_VALID(f.detail_json) THEN f.detail_json ELSE '{}' END,
                '$.fixVersions[*]' COLUMNS (version VARCHAR(255) PATH '$')) j
WHERE (CASE WHEN JSON_VALID(f.detail_json) THEN JSON_LENGTH(f.detail_json, '$.fixVersions')
            ELSE 0 END) > 1
  AND TRIM(j.version) <> '';

-- 탐지마다 모은 꼴. 칸(1,000자)을 넘는 것은 싣지 않는다 — 그 탐지는 어디서나 그대로다.
CREATE TABLE fix_lists_v23 (
    finding_id BIGINT NOT NULL,
    versions   TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    PRIMARY KEY (finding_id)
) ENGINE = InnoDB;

INSERT INTO fix_lists_v23 (finding_id, versions)
SELECT finding_id, GROUP_CONCAT(version ORDER BY version SEPARATOR ' ')
FROM fix_candidates_v23
GROUP BY finding_id
HAVING CHAR_LENGTH(GROUP_CONCAT(version ORDER BY version SEPARATOR ' ')) <= 1000;

-- 3) 조치 대상 — 등록한 검사의 같은 탐지(번호 · 함께 온 CVE · 설치 버전 · 적혀 있던 첫
--    번째)의 것으로. 탐지 칸을 바꾸기 전에 한다 — 첫 번째로 짝을 찾는다. 한 대상에 서로
--    다른 목록이 짝지어지면 고르지 않고 그대로 둔다.
UPDATE remediation_targets t
JOIN (
    SELECT r.id AS remediation_id,
           f.cve AS cve,
           f.related_cve AS related_cve,
           f.package_version COLLATE utf8mb4_bin AS package_version,
           f.fixed_version COLLATE utf8mb4_bin AS first_version,
           MIN(x.versions) AS versions,
           COUNT(DISTINCT x.versions) AS lists
    FROM remediations r
    JOIN findings f ON f.scan_id = r.opened_scan_id AND f.package_name = r.package_name
    JOIN fix_lists_v23 x ON x.finding_id = f.id
    GROUP BY r.id, f.cve, f.related_cve,
             f.package_version COLLATE utf8mb4_bin, f.fixed_version COLLATE utf8mb4_bin
) m ON m.remediation_id = t.remediation_id
   AND m.cve = t.cve AND m.related_cve = t.related_cve
   AND m.package_version = t.package_version COLLATE utf8mb4_bin
   AND m.first_version = t.fixed_version COLLATE utf8mb4_bin
SET t.fixed_version = m.versions
WHERE m.lists = 1;

-- 4) 조치의 목표 버전 — 적혀 있던 것은 지우지 않고, 등록 때 세던 탐지의 나머지
--    후보를 더한다. 세던 탐지 = 등록한 검사의 그 패키지에서 수정 상태가 fixed 이고, 적혀
--    있던 첫 번째가 목표에 들어 있고, 지금 해당 없음 · 오탐으로 적혀 있지 않은 것(보고서
--    3장 · 조치 등록과 같은 규칙 — 나중에 고친 검토 결과가 이긴다).
--
--    목표는 빈칸으로 이은 글자라 JSON 배열로 바꿔 편다. 그렇게 읽히지 않는 목표(따옴표 ·
--    제어 문자가 든 것)와 역슬래시가 든 목표(JSON 이 다른 글자로 읽는다)는 건드리지 않는다 —
--    펴지 못하거나 다르게 편 채 다시 쓰면 적혀 있던 것이 지워지거나 바뀐다.
CREATE TABLE remediations_v23 (
    remediation_id BIGINT NOT NULL,
    PRIMARY KEY (remediation_id)
) ENGINE = InnoDB;

INSERT INTO remediations_v23 (remediation_id)
SELECT r.id
FROM remediations r
WHERE r.to_version <> ''
  AND LOCATE(CHAR(92 USING utf8mb4), r.to_version) = 0
  AND JSON_VALID(CONCAT('["', REPLACE(r.to_version, ' ', '","'), '"]'))
  AND EXISTS (
        SELECT 1
        FROM findings f
        JOIN scans s ON s.id = f.scan_id
        JOIN fix_lists_v23 x ON x.finding_id = f.id
        WHERE f.scan_id = r.opened_scan_id AND f.package_name = r.package_name
          AND f.fix_state = 'fixed'
          AND LOCATE(CONCAT(' ', f.fixed_version, ' ') COLLATE utf8mb4_bin,
                     CONCAT(' ', r.to_version, ' ') COLLATE utf8mb4_bin) > 0
          AND NOT EXISTS (
                SELECT 1 FROM finding_analysis fa
                WHERE fa.asset_id = s.asset_id AND fa.package_name = f.package_name
                  AND fa.state IN ('NOT_AFFECTED', 'FALSE_POSITIVE')
                  AND (fa.cve = f.cve OR (f.related_cve <> '' AND fa.cve = f.related_cve))
                  AND NOT EXISTS (
                        SELECT 1 FROM finding_analysis fd
                        WHERE fd.asset_id = s.asset_id AND fd.package_name = f.package_name
                          AND (fd.cve = f.cve OR (f.related_cve <> '' AND fd.cve = f.related_cve))
                          AND (fd.updated_at > fa.updated_at
                               OR (fd.updated_at = fa.updated_at AND fd.id > fa.id)))));

CREATE TABLE to_versions_v23 (
    remediation_id BIGINT       NOT NULL,
    version        VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    PRIMARY KEY (remediation_id, version)
) ENGINE = InnoDB;

-- 적혀 있던 것
INSERT IGNORE INTO to_versions_v23 (remediation_id, version)
SELECT r.id, TRIM(j.version)
FROM remediations r
JOIN remediations_v23 e ON e.remediation_id = r.id
JOIN JSON_TABLE(CASE WHEN JSON_VALID(CONCAT('["', REPLACE(r.to_version, ' ', '","'), '"]'))
                     THEN CONCAT('["', REPLACE(r.to_version, ' ', '","'), '"]') ELSE '[]' END,
                '$[*]' COLUMNS (version VARCHAR(255) PATH '$')) j
WHERE TRIM(j.version) <> '';

-- 세던 탐지의 후보 전부
INSERT IGNORE INTO to_versions_v23 (remediation_id, version)
SELECT r.id, c.version
FROM remediations r
JOIN remediations_v23 e ON e.remediation_id = r.id
JOIN findings f ON f.scan_id = r.opened_scan_id AND f.package_name = r.package_name
JOIN scans s ON s.id = f.scan_id
JOIN fix_lists_v23 x ON x.finding_id = f.id
JOIN fix_candidates_v23 c ON c.finding_id = f.id
WHERE f.fix_state = 'fixed'
  AND LOCATE(CONCAT(' ', f.fixed_version, ' ') COLLATE utf8mb4_bin,
             CONCAT(' ', r.to_version, ' ') COLLATE utf8mb4_bin) > 0
  AND NOT EXISTS (
        SELECT 1 FROM finding_analysis fa
        WHERE fa.asset_id = s.asset_id AND fa.package_name = f.package_name
          AND fa.state IN ('NOT_AFFECTED', 'FALSE_POSITIVE')
          AND (fa.cve = f.cve OR (f.related_cve <> '' AND fa.cve = f.related_cve))
          AND NOT EXISTS (
                SELECT 1 FROM finding_analysis fd
                WHERE fd.asset_id = s.asset_id AND fd.package_name = f.package_name
                  AND (fd.cve = f.cve OR (f.related_cve <> '' AND fd.cve = f.related_cve))
                  AND (fd.updated_at > fa.updated_at
                       OR (fd.updated_at = fa.updated_at AND fd.id > fa.id))));

-- 모은 것이 칸(4,000자)을 넘으면 그대로 둔다(V16 과 같다).
UPDATE remediations r
JOIN (
    SELECT remediation_id, GROUP_CONCAT(version ORDER BY version SEPARATOR ' ') AS versions
    FROM to_versions_v23
    GROUP BY remediation_id
) m ON m.remediation_id = r.id
SET r.to_version = m.versions
WHERE CHAR_LENGTH(m.versions) <= 4000;

-- 5) 탐지 — 마지막에. 앞의 둘이 적혀 있던 첫 번째로 짝을 찾는다.
UPDATE findings f
JOIN fix_lists_v23 x ON x.finding_id = f.id
SET f.fixed_version = x.versions;

-- 6) 이관에 쓴 표는 지운다.
DROP TABLE to_versions_v23;
DROP TABLE remediations_v23;
DROP TABLE fix_lists_v23;
DROP TABLE fix_candidates_v23;
