-- SBOMSight 최초 스키마
--
-- 설계 원칙 하나: **grype 이 낸 값은 그대로 담고 다시 계산하지 않는다.**
-- 우리가 만들어 내는 것은 조치(remediation) 뿐이고, 나머지 열은 전부
-- grype JSON 에서 그대로 옮겨 온 것이다. 어느 열이 grype 의 어느 필드에서
-- 왔는지 주석으로 남긴다 — 나중에 원본과 대조할 수 있어야 한다.

-- ---------------------------------------------------------------------------
-- 계정
-- ---------------------------------------------------------------------------
CREATE TABLE users (
    id            BIGINT       NOT NULL AUTO_INCREMENT,
    username      VARCHAR(64)  NOT NULL,
    password_hash VARCHAR(255) NOT NULL,   -- BCrypt
    role          VARCHAR(16)  NOT NULL,   -- ADMIN | VIEWER
    display_name  VARCHAR(64)  NOT NULL DEFAULT '',
    enabled       BOOLEAN      NOT NULL DEFAULT TRUE,
    -- 초기화된 계정. 바꾸기 전에는 다른 화면이 열리지 않는다.
    must_change   BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at    DATETIME(6)  NOT NULL,
    last_login_at DATETIME(6)  NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_users_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- 자산 — 관리 단위는 스캔이 아니라 서버 한 대다
-- ---------------------------------------------------------------------------
CREATE TABLE assets (
    id          BIGINT       NOT NULL AUTO_INCREMENT,
    name        VARCHAR(128) NOT NULL,   -- web-01
    group_name  VARCHAR(128) NOT NULL DEFAULT '',  -- DMZ / 내부업무
    os_name     VARCHAR(128) NOT NULL DEFAULT '',
    note        VARCHAR(500) NOT NULL DEFAULT '',
    created_at  DATETIME(6)  NOT NULL,
    archived_at DATETIME(6)  NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_assets_name (name),
    KEY ix_assets_group (group_name, name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- 스캔 — SBOM 한 장에 grype 을 한 번 돌린 결과
-- ---------------------------------------------------------------------------
CREATE TABLE scans (
    id             BIGINT       NOT NULL AUTO_INCREMENT,
    asset_id       BIGINT       NOT NULL,
    status         VARCHAR(16)  NOT NULL,   -- QUEUED | RUNNING | DONE | FAILED
    created_at     DATETIME(6)  NOT NULL,
    finished_at    DATETIME(6)  NULL,
    created_by     VARCHAR(64)  NOT NULL DEFAULT '',

    -- 올라온 SBOM
    sbom_filename  VARCHAR(255) NOT NULL DEFAULT '',
    sbom_format    VARCHAR(32)  NOT NULL DEFAULT '',  -- cyclonedx-json | spdx-json | syft-json
    sbom_bytes     BIGINT       NOT NULL DEFAULT 0,
    sbom_path      VARCHAR(500) NOT NULL DEFAULT '',  -- gzip 보관 경로
    grype_path     VARCHAR(500) NOT NULL DEFAULT '',  -- grype 원본 JSON(gzip)
    component_count INT         NOT NULL DEFAULT 0,   -- SBOM 안의 컴포넌트 수

    -- grype 이 스스로 밝힌 것. 보고서가 "무엇으로 판정했는지"를 증명하는 근거라
    -- 결과와 함께 남긴다. 없으면 그 보고서를 나중에 재현할 수 없다.
    grype_version  VARCHAR(64)  NOT NULL DEFAULT '',  -- descriptor.version
    grype_db_built DATETIME(6)  NULL,                 -- descriptor.db.built
    distro_name    VARCHAR(64)  NOT NULL DEFAULT '',  -- distro.name
    distro_version VARCHAR(64)  NOT NULL DEFAULT '',  -- distro.version

    -- 회계. 몇 건이 들어와 몇 건이 남았는지 남기지 않으면, 사라진 건수를
    -- 아무도 눈치채지 못한다.
    match_count    INT          NOT NULL DEFAULT 0,   -- grype matches 원소 수
    finding_count  INT          NOT NULL DEFAULT 0,   -- 저장된 건수
    merged_count   INT          NOT NULL DEFAULT 0,   -- 같은 키로 합쳐진 수
    dropped_count  INT          NOT NULL DEFAULT 0,   -- 이름이 없어 버린 수

    error_message  VARCHAR(1000) NOT NULL DEFAULT '',
    PRIMARY KEY (id),
    KEY ix_scans_asset (asset_id, created_at),
    CONSTRAINT fk_scans_asset FOREIGN KEY (asset_id) REFERENCES assets (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- 탐지 — grype match 하나
--
-- 정렬·필터에 쓰는 값은 열로 꺼내 둔다. 서버 한 대가 5만 건을 내는데
-- JSON 을 매번 풀어 정렬하면 한 페이지 넘기는 데도 초 단위로 걸린다.
-- ---------------------------------------------------------------------------
CREATE TABLE findings (
    id                BIGINT       NOT NULL AUTO_INCREMENT,
    scan_id           BIGINT       NOT NULL,

    -- 같은 CVE 라도 패키지가 다르면 다른 건이다. 이력 대조의 축이기도 하다.
    finding_key       VARCHAR(512) NOT NULL,

    cve               VARCHAR(64)  NOT NULL,          -- vulnerability.id
    severity          VARCHAR(16)  NOT NULL DEFAULT '',  -- vulnerability.severity
    -- vulnerability.cvss[] 중 고른 하나. 어느 것을 골랐는지도 남긴다.
    cvss_score        DECIMAL(4,2) NULL,
    cvss_vector       VARCHAR(128) NOT NULL DEFAULT '',
    cvss_version      VARCHAR(8)   NOT NULL DEFAULT '',
    -- grype 0.8x 이상이 주는 값. 없으면 NULL 로 두고 "미확인"으로 표시한다.
    epss              DECIMAL(9,8) NULL,              -- vulnerability.epss[].epss
    kev               BOOLEAN      NULL,              -- vulnerability.knownExploited 유무
    kev_ransomware    BOOLEAN      NULL,
    grype_risk        DECIMAL(9,4) NULL,              -- vulnerability.risk

    -- 설치된 것 (artifact)
    package_name      VARCHAR(255) NOT NULL,
    package_version   VARCHAR(128) NOT NULL DEFAULT '',
    package_type      VARCHAR(32)  NOT NULL DEFAULT '',
    package_purl      VARCHAR(512) NOT NULL DEFAULT '',
    package_language  VARCHAR(32)  NOT NULL DEFAULT '',

    -- 수정 (vulnerability.fix)
    fix_state         VARCHAR(24)  NOT NULL DEFAULT '',  -- fixed|not-fixed|wont-fix|unknown
    fixed_version     VARCHAR(128) NOT NULL DEFAULT '',  -- fix.versions[0]
    -- matchDetails[].found.versionConstraint
    version_constraint VARCHAR(255) NOT NULL DEFAULT '',

    -- 매칭 근거 (matchDetails). 왜 이 건이 잡혔는지 화면에서 보여 준다.
    match_type        VARCHAR(48)  NOT NULL DEFAULT '',  -- exact-direct-match 등
    matcher           VARCHAR(48)  NOT NULL DEFAULT '',  -- rpm-matcher 등
    namespace         VARCHAR(96)  NOT NULL DEFAULT '',  -- rocky:distro:rocky:9

    data_source       VARCHAR(500) NOT NULL DEFAULT '',
    description       TEXT         NULL,
    -- urls, cpes, locations, relatedVulnerabilities 등 표에 안 쓰는 것들
    detail_json       LONGTEXT     NULL,

    PRIMARY KEY (id),
    UNIQUE KEY uk_findings_scan_key (scan_id, finding_key),
    KEY ix_findings_scan_sort (scan_id, severity, cvss_score),
    KEY ix_findings_scan_pkg (scan_id, package_name),
    KEY ix_findings_cve (cve),
    CONSTRAINT fk_findings_scan FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- 조치 — **우리가 만드는 유일한 판단**
--
-- grype 결과는 스캔마다 새로 쌓이지만 조치는 그것을 가로지른다. 그래서
-- 스캔이 아니라 자산 + 패키지에 매단다. "openssl 을 3.0.7 로 올린다"가
-- 실무자가 실제로 실행하는 단위다.
-- ---------------------------------------------------------------------------
CREATE TABLE remediations (
    id             BIGINT       NOT NULL AUTO_INCREMENT,
    asset_id       BIGINT       NOT NULL,
    package_name   VARCHAR(255) NOT NULL,
    -- 조치를 만들 때의 현재 버전과 목표 버전. 나중에 무엇을 근거로 정했는지
    -- 되짚기 위한 것이고, 판정에는 쓰지 않는다.
    from_version   VARCHAR(128) NOT NULL DEFAULT '',
    to_version     VARCHAR(128) NOT NULL DEFAULT '',

    status         VARCHAR(16)  NOT NULL,   -- OPEN | IN_PROGRESS | DONE | ACCEPTED
    owner          VARCHAR(64)  NOT NULL DEFAULT '',
    due_date       DATE         NULL,
    note           VARCHAR(1000) NOT NULL DEFAULT '',

    -- 만들 당시 이 패키지가 안고 있던 건수. 이력에서 "그때 몇 건이었나"를
    -- 보여 주기 위한 스냅샷이다.
    opened_scan_id BIGINT       NULL,
    opened_count   INT          NOT NULL DEFAULT 0,

    created_at     DATETIME(6)  NOT NULL,
    created_by     VARCHAR(64)  NOT NULL DEFAULT '',
    updated_at     DATETIME(6)  NOT NULL,
    updated_by     VARCHAR(64)  NOT NULL DEFAULT '',
    closed_at      DATETIME(6)  NULL,

    PRIMARY KEY (id),
    UNIQUE KEY uk_remediation_open (asset_id, package_name),
    KEY ix_remediation_status (status, due_date),
    CONSTRAINT fk_remediation_asset FOREIGN KEY (asset_id) REFERENCES assets (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 조치의 발자취. 누가 언제 무엇을 바꿨는지 남는다 — 결재·감사에서 필요하다.
CREATE TABLE remediation_events (
    id             BIGINT       NOT NULL AUTO_INCREMENT,
    remediation_id BIGINT       NOT NULL,
    at             DATETIME(6)  NOT NULL,
    actor          VARCHAR(64)  NOT NULL DEFAULT '',
    from_status    VARCHAR(16)  NOT NULL DEFAULT '',
    to_status      VARCHAR(16)  NOT NULL DEFAULT '',
    comment        VARCHAR(1000) NOT NULL DEFAULT '',
    PRIMARY KEY (id),
    KEY ix_rem_event (remediation_id, at),
    CONSTRAINT fk_rem_event FOREIGN KEY (remediation_id) REFERENCES remediations (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
