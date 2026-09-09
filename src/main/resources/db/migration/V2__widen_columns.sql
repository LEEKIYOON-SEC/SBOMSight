-- 실제 grype 출력으로 재어 본 뒤 넓힌다.
--
-- 손으로 만든 픽스처에는 짧은 값만 있었다. 실제 grype 0.87 출력에서는
-- CVSS 벡터가 174자였고(CVSS 4.0 은 더 길다), VARCHAR(128) 에 걸려
-- **98건짜리 스캔이 통째로 실패했다.** 한 값이 길다고 결과 전체를 잃는 것은
-- 어떤 경우에도 맞지 않는다.
--
-- 아래 폭은 실측값에 여유를 크게 둔 것이다. 그래도 넘치는 값이 오면
-- Finding 의 setter 가 잘라서 담는다 — 잘린 사실은 로그에 남는다.

ALTER TABLE findings
    -- 실측 174. CVSS 4.0 은 선택 지표까지 붙으면 400자를 넘길 수 있다.
    MODIFY COLUMN cvss_vector        VARCHAR(512) NOT NULL DEFAULT '',
    -- npm·maven 범위 표기는 길어진다 (">=1.5,<1.10.0 (unknown)" 형태가 겹친다)
    MODIFY COLUMN version_constraint VARCHAR(512) NOT NULL DEFAULT '',
    MODIFY COLUMN fixed_version      VARCHAR(255) NOT NULL DEFAULT '',
    MODIFY COLUMN package_version    VARCHAR(255) NOT NULL DEFAULT '',
    MODIFY COLUMN namespace          VARCHAR(255) NOT NULL DEFAULT '',
    MODIFY COLUMN match_type         VARCHAR(64)  NOT NULL DEFAULT '',
    MODIFY COLUMN matcher            VARCHAR(64)  NOT NULL DEFAULT '',
    MODIFY COLUMN severity           VARCHAR(32)  NOT NULL DEFAULT '',
    MODIFY COLUMN cvss_version       VARCHAR(16)  NOT NULL DEFAULT '',
    MODIFY COLUMN package_type       VARCHAR(64)  NOT NULL DEFAULT '',
    MODIFY COLUMN package_language   VARCHAR(64)  NOT NULL DEFAULT '',
    MODIFY COLUMN fix_state          VARCHAR(32)  NOT NULL DEFAULT '',
    MODIFY COLUMN cve                VARCHAR(128) NOT NULL;

ALTER TABLE remediations
    MODIFY COLUMN from_version VARCHAR(255) NOT NULL DEFAULT '',
    MODIFY COLUMN to_version   VARCHAR(255) NOT NULL DEFAULT '';
