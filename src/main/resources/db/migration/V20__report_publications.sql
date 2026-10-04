-- 보고서 발행 — 그때 그린 문서와 계산 결과를 굳혀 둔다 (R11, D6).
--
-- 보고서는 열 때마다 지금 데이터로 다시 계산됐다(재현 시험 P8). 결재에 올린 뒤 검토
-- 결과를 하나 적거나 자산을 운영 종료하면 같은 검사 · 같은 기간의 보고서가 다른 숫자를
-- 냈다 — 결재한 문서가 무엇이었는지 남지 않았다. 이제 `발행` 을 누르면 그 순간의 문서를
-- 저장한다.
--
-- ── 1) 발행본 ─────────────────────────────────────────────────────────────────
--
--   kind            SCAN(점검 결과 보고서 — 검사 하나) · ZONE(구역 현황 보고서 — 구역 · 기간)
--   pub_year · pub_seq   발행 번호(연도-일련번호). 그해 안에서 1 부터. 유일 키가 겹침을
--                   막는다 — 동시에 눌린 둘이 같은 번호를 매기면 뒤의 것이 막히고, 앱이
--                   새로 읽어 다음 번호를 받는다(PublicationService).
--   published_by    발행한 로그인 계정. 사람이 적는 칸이 아니다.
--   target_name     대상의 이름 — 발행 때의 자산 이름 · 구역 이름. 자산을 지워도 남는다.
--   asset_id · scan_id · zone_id · period_from · period_to
--                   무엇을 발행했는가. FK 를 두지 않는다 — 자산을 지워도 발행본은 남는다
--                   (D6). 가리키던 것이 사라지면 번호만 남는다.
--   document_html   그때 그린 문서 그대로. 화면의 단추 · 폼은 빼고 문서 정보에 발행 번호 ·
--                   발행 시각 · 발행자를 넣어 그린다.
--   document_json   그때의 계산 결과.
--   document_sha256 document_html 의 UTF-8 바이트 그대로의 SHA-256. 발행본을 볼 때마다
--                   다시 대조한다 — 맞지 않으면 문서를 보이지 않는다.
--   approval_doc    사내 결재 문서 번호. 발행한 뒤에 적는다 — 문서(해시) 밖이다. 검토
--                   결과의 같은 칸과 같은 너비(V11).
--
-- 발행본은 지우지 않는다 — 앱에 지우는 길이 없다.

CREATE TABLE report_publications (
    id              BIGINT       NOT NULL AUTO_INCREMENT,
    kind            VARCHAR(16)  NOT NULL,
    pub_year        INT          NOT NULL,
    pub_seq         INT          NOT NULL,
    published_at    DATETIME(6)  NOT NULL,
    published_by    VARCHAR(64)  NOT NULL,
    target_name     VARCHAR(255) NOT NULL,
    asset_id        BIGINT       NULL,
    scan_id         BIGINT       NULL,
    zone_id         BIGINT       NULL,
    period_from     DATE         NULL,
    period_to       DATE         NULL,
    document_json   LONGTEXT     NOT NULL,
    document_html   LONGTEXT     NOT NULL,
    document_sha256 VARCHAR(64)  NOT NULL,
    approval_doc    VARCHAR(128) NOT NULL DEFAULT '',
    PRIMARY KEY (id),
    UNIQUE KEY uk_report_publication_number (pub_year, pub_seq),
    KEY ix_report_publication_scan (scan_id),
    KEY ix_report_publication_zone (zone_id, period_from, period_to)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;

-- ── 2) 발행본이 가리키는 검사 ─────────────────────────────────────────────────
--
-- 발행본의 수가 나온 완료 검사 — 점검 결과 보고서는 그 검사와 6장(이전 검사 · 최근 검사
-- 추이)의 검사, 구역 현황 보고서는 3장의 자산마다 기준이 된 검사와 7장 대조에 쓴 기준선.
-- 이 검사들은 하나씩 지우지 못한다(D6, ScanService.delete). 검사 쪽 FK 는 두지 않는다 —
-- 자산을 지우면 그 검사는 함께 지워지고, 발행본은 남는다.

CREATE TABLE report_publication_scans (
    publication_id BIGINT NOT NULL,
    scan_id        BIGINT NOT NULL,
    PRIMARY KEY (publication_id, scan_id),
    KEY ix_report_publication_scans_scan (scan_id),
    CONSTRAINT fk_report_publication_scans FOREIGN KEY (publication_id)
        REFERENCES report_publications (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;

-- ── 3) 결재 문서 번호 이력 ────────────────────────────────────────────────────
--
-- 바꿀 때마다 앞뒤 값과 계정 · 시각. 같은 값을 다시 적은 것은 남기지 않는다.

CREATE TABLE report_publication_events (
    id             BIGINT       NOT NULL AUTO_INCREMENT,
    publication_id BIGINT       NOT NULL,
    at             DATETIME(6)  NOT NULL,
    actor          VARCHAR(64)  NOT NULL DEFAULT '',
    before_value   VARCHAR(128) NOT NULL DEFAULT '',
    after_value    VARCHAR(128) NOT NULL DEFAULT '',
    PRIMARY KEY (id),
    KEY ix_report_publication_event (publication_id, at),
    CONSTRAINT fk_report_publication_event FOREIGN KEY (publication_id)
        REFERENCES report_publications (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;
