-- 위험 수용.
--
-- 수정본이 없어 고칠 수 없는 건에 "왜 그대로 두는가" 를 남긴다. 점검에서
-- "이건 왜 안 고쳤냐" 를 반드시 묻고, 그때 답이 없으면 방치로 읽힌다.
--
-- 조치(remediations)와 단위가 다르다. 조치는 패키지를 올리는 일이라
-- (자산, 패키지) 가 단위지만, 수용은 "이 취약점을 이런 이유로 받아들인다"
-- 이므로 취약점 하나하나가 단위다. 한 패키지 안에서 어떤 건은 수용하고
-- 어떤 건은 다른 통제로 막는 일이 실제로 있다.
--
-- (CVE, 패키지명) 으로 잡는다. 버전을 넣으면 부분 패치로 버전이 바뀌는
-- 순간 수용이 조용히 풀린다 — 이력 대조와 같은 이유다.

CREATE TABLE risk_acceptances (
    id           BIGINT       NOT NULL AUTO_INCREMENT,
    asset_id     BIGINT       NOT NULL,
    cve          VARCHAR(64)  NOT NULL,   -- grype 의 주 식별자 (CVE 또는 GHSA)
    package_name VARCHAR(255) NOT NULL,

    reason       VARCHAR(2000) NOT NULL,  -- 왜 받아들이는가. 비워 둘 수 없다
    compensating VARCHAR(1000) NOT NULL DEFAULT '',  -- 대신 무엇으로 막는가
    approved_by  VARCHAR(128) NOT NULL,   -- 승인한 사람. 계정이 아니라 사람 이름

    accepted_at  DATETIME(6)  NOT NULL,
    accepted_by  VARCHAR(64)  NOT NULL,   -- 화면에서 등록한 계정
    -- 기한 없는 수용은 방치와 구분되지 않는다. 이 날짜가 지나면 다시 본다.
    review_by    DATE         NOT NULL,

    revoked_at   DATETIME(6)  NULL,
    revoked_by   VARCHAR(64)  NOT NULL DEFAULT '',
    revoke_note  VARCHAR(1000) NOT NULL DEFAULT '',

    PRIMARY KEY (id),
    CONSTRAINT fk_acceptance_asset FOREIGN KEY (asset_id) REFERENCES assets (id)
        ON DELETE CASCADE,
    -- 같은 자산의 같은 취약점을 두 번 수용할 수는 없다. 철회한 것은
    -- revoked_at 이 차므로 이 제약에 걸리지 않아야 한다 — 그래서 키에
    -- 넣지 않고 애플리케이션이 '살아 있는 것' 을 확인한다.
    KEY ix_acceptance_key (asset_id, cve, package_name),
    KEY ix_acceptance_review (review_by, revoked_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;
