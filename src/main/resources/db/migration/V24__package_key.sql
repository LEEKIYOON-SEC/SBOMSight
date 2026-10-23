-- 패키지 식별자 — 탐지 · 인벤토리 · 검토 결과 · 조치가 "같은 패키지인가" 를 한 기준으로 가른다.
--
-- 앞서 기준이 셋이었다. 패키지 화면은 (이름, 유형), 검토 결과와 조치는 이름 하나. 그래서 한
-- 자산에 npm 의 semver 와 PyPI 의 semver 가 함께 깔려 있으면, npm 쪽에 적은 `해당 없음` 이
-- PyPI 쪽의 같은 번호 탐지까지 목록 · 보고서에서 뺐고, 조치 하나가 두 패키지를 함께 가졌다.
-- Maven 은 유형까지 같다 — groupId 만 다른 두 jackson-databind 가 한 패키지로 섞였다.
--
-- 식별자는 purl 에서 버전 · 한정자(?…) · 하위 경로(#…)를 뗀 것이다 — pkg:<유형>/<네임스페이스>/<이름>.
-- 유형만 소문자로 맞추고 나머지는 purl 에 적힌 그대로. purl 이 없으면 pkg:<유형>/<이름>(유형은
-- purl 의 이름으로 옮긴 것 — V22 와 같은 표), 유형도 모르면 pkg:/<이름>. 규칙은 앱의 PackageKey
-- 와 같다 — 같은 입력과 기대값을 tests/resources/package-key-vectors.tsv 에 두고 자바 시험
-- (PackageKeyTest)과 이 SQL(tests/check-migrations.sh)이 함께 견준다.
--
-- 검토 결과 · 조치의 옛 기록은 이름밖에 없다. 그 기록이 어느 패키지의 것인지는 **그 기록이
-- 앞서 붙던 탐지**로만 가린다 — 그 탐지들이 한 패키지면 그 식별자를 적고, 둘 이상이거나 하나도
-- 남아 있지 않으면 비워 둔다(NULL). 비운 기록은 지우지도 아무 패키지에나 붙이지도 않는다 —
-- 어느 탐지에도 붙지 않고(목록 · 보고서에서 아무것도 빼지 않는다) 대응 화면에 `패키지 확인
-- 필요` 로 남는다. 사람이 그 패키지의 탐지 줄에서 다시 적는다(docs/operations.md · V24).
--
-- 글자를 그대로 견준다(utf8mb4_bin) — 식별자 칸은 대소문자를 가린다(시험의 H2 와 같다).

-- ── 1) 칸 ──────────────────────────────────────────────────────────────────────
--
-- 탐지와 인벤토리는 비지 않는다(언제나 이름이 있다). 검토 결과와 조치는 비어 있을 수 있다 —
-- 비었으면 가르지 못한 옛 기록이다.

ALTER TABLE findings
    ADD COLUMN package_key VARCHAR(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin
        NOT NULL DEFAULT '' AFTER package_purl;
ALTER TABLE component
    ADD COLUMN package_key VARCHAR(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin
        NOT NULL DEFAULT '' AFTER purl;
ALTER TABLE finding_analysis
    ADD COLUMN package_key VARCHAR(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin
        NULL AFTER package_name;
ALTER TABLE remediations
    ADD COLUMN package_key VARCHAR(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin
        NULL AFTER package_name;

-- ── 2) 탐지 · 인벤토리의 식별자 ─────────────────────────────────────────────────
--
-- purl 마다 한 번 푼다 — 앱과 같은 차례로: `pkg:` 다음에서 뒤에서부터 `#` · `?` 를 떼고, 첫
-- `/` 앞(한 글자 이상)이 유형, 그 뒤에서 뒤에서부터 `@`(버전)를 떼고 끝의 `/` 를 뗀다. 남은 것이
-- 없거나 `/` 앞이 비면 purl 이 아니다 — 이름으로 만든다(아래).

CREATE TABLE purl_keys_v24 (
    purl        VARCHAR(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    rest        VARCHAR(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL DEFAULT '',
    path        VARCHAR(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL DEFAULT '',
    package_key VARCHAR(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL,
    PRIMARY KEY (purl)
) ENGINE = InnoDB;

-- 글자 그대로 하나씩 — 칸의 정렬 규칙(대소문자 무시)으로 겹치는 것을 지우면 `Foo` 와 `foo` 중
-- 하나가 빠진다.
INSERT IGNORE INTO purl_keys_v24 (purl)
SELECT DISTINCT package_purl COLLATE utf8mb4_bin FROM findings
WHERE package_purl COLLATE utf8mb4_bin LIKE 'pkg:%';
INSERT IGNORE INTO purl_keys_v24 (purl)
SELECT DISTINCT purl COLLATE utf8mb4_bin FROM component
WHERE purl COLLATE utf8mb4_bin LIKE 'pkg:%';

UPDATE purl_keys_v24 SET rest = SUBSTRING(purl, 5);
UPDATE purl_keys_v24
SET rest = LEFT(rest, CHAR_LENGTH(rest) - CHAR_LENGTH(SUBSTRING_INDEX(rest, '#', -1)) - 1)
WHERE LOCATE('#', rest) > 0;
UPDATE purl_keys_v24
SET rest = LEFT(rest, CHAR_LENGTH(rest) - CHAR_LENGTH(SUBSTRING_INDEX(rest, '?', -1)) - 1)
WHERE LOCATE('?', rest) > 0;
UPDATE purl_keys_v24
SET path = SUBSTRING(rest, LOCATE('/', rest) + 1)
WHERE LOCATE('/', rest) > 1;
UPDATE purl_keys_v24
SET path = LEFT(path, CHAR_LENGTH(path) - CHAR_LENGTH(SUBSTRING_INDEX(path, '@', -1)) - 1)
WHERE LOCATE('@', path) > 0;
UPDATE purl_keys_v24 SET path = TRIM(TRAILING '/' FROM path);
UPDATE purl_keys_v24
SET package_key = CONCAT('pkg:', LOWER(LEFT(rest, LOCATE('/', rest) - 1)), '/', path)
WHERE LOCATE('/', rest) > 1 AND path <> '';

UPDATE findings f
JOIN purl_keys_v24 k ON k.purl = f.package_purl COLLATE utf8mb4_bin
SET f.package_key = k.package_key
WHERE k.package_key IS NOT NULL;

UPDATE component c
JOIN purl_keys_v24 k ON k.purl = c.purl COLLATE utf8mb4_bin
SET c.package_key = k.package_key
WHERE k.package_key IS NOT NULL;

-- purl 로 읽지 못한 것 — pkg:<유형>/<이름>. 유형은 purl 의 이름으로(V22 · PackageTypes 와 같은
-- 표 — 인벤토리는 V22 가 이미 옮겼고, 탐지는 grype 의 이름이 그대로 담겨 있다). 표에 없는 유형은
-- 그대로, UnknownPackage 는 빈 값.
UPDATE findings
SET package_key = CONCAT('pkg:',
        CASE package_type COLLATE utf8mb4_bin
            WHEN 'pod'                    THEN 'cocoapods'
            WHEN 'conda'                  THEN 'generic'
            WHEN 'dart-pub'               THEN 'pub'
            WHEN 'dotnet'                 THEN 'nuget'
            WHEN 'erlang-otp'             THEN 'otp'
            WHEN 'github-action'          THEN 'github'
            WHEN 'github-action-workflow' THEN 'github'
            WHEN 'go-module'              THEN 'golang'
            WHEN 'java-archive'           THEN 'maven'
            WHEN 'jenkins-plugin'         THEN 'maven'
            WHEN 'linux-kernel'           THEN 'generic'
            WHEN 'linux-kernel-module'    THEN 'generic'
            WHEN 'php-composer'           THEN 'composer'
            WHEN 'php-pear'               THEN 'pear'
            WHEN 'php-pecl'               THEN 'pear'
            WHEN 'python'                 THEN 'pypi'
            WHEN 'lua-rocks'              THEN 'luarocks'
            WHEN 'R-package'              THEN 'cran'
            WHEN 'rust-crate'             THEN 'cargo'
            WHEN 'UnknownPackage'         THEN ''
            ELSE package_type
        END, '/', TRIM(package_name))
WHERE package_key = '';

UPDATE component
SET package_key = CONCAT('pkg:',
        CASE type COLLATE utf8mb4_bin
            WHEN 'pod'                    THEN 'cocoapods'
            WHEN 'conda'                  THEN 'generic'
            WHEN 'dart-pub'               THEN 'pub'
            WHEN 'dotnet'                 THEN 'nuget'
            WHEN 'erlang-otp'             THEN 'otp'
            WHEN 'github-action'          THEN 'github'
            WHEN 'github-action-workflow' THEN 'github'
            WHEN 'go-module'              THEN 'golang'
            WHEN 'java-archive'           THEN 'maven'
            WHEN 'jenkins-plugin'         THEN 'maven'
            WHEN 'linux-kernel'           THEN 'generic'
            WHEN 'linux-kernel-module'    THEN 'generic'
            WHEN 'php-composer'           THEN 'composer'
            WHEN 'php-pear'               THEN 'pear'
            WHEN 'php-pecl'               THEN 'pear'
            WHEN 'python'                 THEN 'pypi'
            WHEN 'lua-rocks'              THEN 'luarocks'
            WHEN 'R-package'              THEN 'cran'
            WHEN 'rust-crate'             THEN 'cargo'
            WHEN 'UnknownPackage'         THEN ''
            ELSE type
        END, '/', TRIM(name))
WHERE package_key = '';

DROP TABLE purl_keys_v24;

-- ── 3) 검토 결과 — 앞서 붙던 탐지로 가른다 ─────────────────────────────────────
--
-- 앞서 검토 결과는 같은 자산의 탐지 가운데 이름이 같고 번호(주 식별자 또는 함께 온 CVE)가 같은
-- 것에 붙었다(FindingRepository 의 식 — 칸의 정렬 규칙으로 견줬다). 그 자산의 검사 전부에서 그런
-- 탐지를 찾는다 — 지금 검사에서 사라진 것(이미 올린 것)도 지난 검사에 남아 있다.
--
--   그 탐지들의 식별자가 하나    → 그 식별자
--   둘 이상(같은 이름의 다른 패키지) · 하나도 없음(검사를 지웠다 · 위험 수용에서 옮긴 것) → 비움

CREATE TABLE analysis_keys_v24 (
    analysis_id BIGINT NOT NULL,
    package_key VARCHAR(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL,
    packages    INT    NOT NULL,
    PRIMARY KEY (analysis_id)
) ENGINE = InnoDB;

INSERT INTO analysis_keys_v24 (analysis_id, package_key, packages)
SELECT fa.id, MIN(f.package_key), COUNT(DISTINCT f.package_key)
FROM finding_analysis fa
JOIN scans s ON s.asset_id = fa.asset_id
JOIN findings f ON f.scan_id = s.id AND f.package_name = fa.package_name
               AND (f.cve = fa.cve OR (f.related_cve <> '' AND f.related_cve = fa.cve))
GROUP BY fa.id;

UPDATE finding_analysis fa
JOIN analysis_keys_v24 k ON k.analysis_id = fa.id
SET fa.package_key = k.package_key
WHERE k.packages = 1;

-- 이름이 다른 둘이 한 식별자에 모이면(같은 purl 을 syft 가 다른 이름으로 적은 것) 둘 다 비운다 —
-- (자산, 번호, 패키지)에 검토 결과는 하나라 하나를 골라야 하는데, 고르는 것이 곧 합치는 것이다.
CREATE TABLE analysis_clash_v24 (
    analysis_id BIGINT NOT NULL,
    PRIMARY KEY (analysis_id)
) ENGINE = InnoDB;

INSERT INTO analysis_clash_v24 (analysis_id)
SELECT DISTINCT a.id
FROM finding_analysis a
JOIN finding_analysis b ON b.asset_id = a.asset_id AND b.cve = a.cve
                       AND b.package_key = a.package_key AND b.id <> a.id;

UPDATE finding_analysis fa
JOIN analysis_clash_v24 c ON c.analysis_id = fa.id
SET fa.package_key = NULL;

DROP TABLE analysis_clash_v24;
DROP TABLE analysis_keys_v24;

-- 한 건에 검토 결과는 하나다 — 이제 (자산, 번호, 식별자)로. 비운 옛 기록은 몇이든 들어간다
-- (NULL 은 겹치지 않는다). 새 키를 먼저 두고 옛 키를 지운다 — 자산 FK(fk_analysis_asset)가
-- asset_id 로 시작하는 색인을 하나 요구한다(V19 와 같은 까닭).
ALTER TABLE finding_analysis ADD UNIQUE KEY ux_analysis_key_v24 (asset_id, cve, package_key);
ALTER TABLE finding_analysis DROP INDEX ux_analysis_key;
ALTER TABLE finding_analysis RENAME INDEX ux_analysis_key_v24 TO ux_analysis_key;

-- ── 4) 조치 — 등록한 검사의 탐지로 가른다 ──────────────────────────────────────
--
-- 조치는 등록한 검사(opened_scan_id)의 그 이름 탐지 전부를 대상으로 열렸다(조치 대상도 거기서
-- 왔다 — V19). 그 탐지들의 식별자가 하나면 그것, 둘 이상이거나 등록한 검사가 지워졌거나 모르면
-- (V15 전의 조치) 비운다. 다른 검사 · 인벤토리에서 이름으로 찾지 않는다 — 그 검사에 있던 것이
-- 지금 남은 것과 같은 패키지라는 근거가 없다.

CREATE TABLE remediation_keys_v24 (
    remediation_id BIGINT NOT NULL,
    package_key    VARCHAR(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL,
    packages       INT    NOT NULL,
    PRIMARY KEY (remediation_id)
) ENGINE = InnoDB;

INSERT INTO remediation_keys_v24 (remediation_id, package_key, packages)
SELECT r.id, MIN(f.package_key), COUNT(DISTINCT f.package_key)
FROM remediations r
JOIN scans s ON s.id = r.opened_scan_id AND s.asset_id = r.asset_id
JOIN findings f ON f.scan_id = s.id AND f.package_name = r.package_name
GROUP BY r.id;

UPDATE remediations r
JOIN remediation_keys_v24 k ON k.remediation_id = r.id
SET r.package_key = k.package_key
WHERE k.packages = 1;

-- 이름이 다른 조치들이 한 식별자에 모이면 다 비운다 — 회차는 같은 이름으로만 이어졌으니(앱이
-- (자산, 이름)으로 최신 회차를 찾았다) 이름이 다르면 다른 기록이다. 한 식별자에 두면 합친 것이다.
CREATE TABLE remediation_clash_v24 (
    remediation_id BIGINT NOT NULL,
    PRIMARY KEY (remediation_id)
) ENGINE = InnoDB;

INSERT INTO remediation_clash_v24 (remediation_id)
SELECT DISTINCT a.id
FROM remediations a
JOIN remediations b ON b.asset_id = a.asset_id AND b.package_key = a.package_key
                   AND b.package_name <> a.package_name;

UPDATE remediations r
JOIN remediation_clash_v24 c ON c.remediation_id = r.id
SET r.package_key = NULL;

DROP TABLE remediation_clash_v24;
DROP TABLE remediation_keys_v24;

-- ── 5) 색인 ────────────────────────────────────────────────────────────────────
--
-- 조치 등록 · 조치 상세가 검사 하나의 그 패키지 탐지를 찾는다(scan_id, package_key). 패키지
-- 화면이 식별자로 줄을 묶고 펼친다. 조치는 (자산, 식별자)의 최신 회차를 찾는다.

ALTER TABLE findings ADD KEY ix_findings_scan_pkgkey (scan_id, package_key);
ALTER TABLE component ADD KEY ix_component_pkgkey (package_key);
ALTER TABLE remediations ADD KEY ix_remediation_asset_pkgkey (asset_id, package_key);
