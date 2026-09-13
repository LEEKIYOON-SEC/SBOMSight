-- 검토 결과 — 탐지 하나에 대한 우리의 결정.
--
-- grype 이 낸 것은 '탐지', 우리가 적는 것은 '검토 결과' 다. 여기에 무엇을
-- 적어도 grype 의 말은 그대로 남는다. 탐지 건수도 보고서의 원본 숫자도 줄지
-- 않는다.
--
-- 앞서 risk_acceptances 라는 표가 따로 있었다. 그런데 '위험 수용' 은 다섯
-- 상태 중 하나(해당됨)와 다섯 대응 중 하나(조치 안 함)의 조합일 뿐이었다.
-- 표를 따로 두니 같은 건에 '수용' 과 '조치' 가 각각 달릴 수 있었고 둘이 무슨
-- 관계인지는 아무 데도 없었다. 한 표로 합친다.
--
-- 저장값은 CycloneDX VEX 표준 그대로다. 화면에만 우리 말을 쓴다 — 내보낸
-- 파일을 다른 도구가 읽어야 하고, 점검에서도 표준 이름으로 답해야 한다.

CREATE TABLE finding_analysis (
    id            BIGINT       NOT NULL AUTO_INCREMENT,
    asset_id      BIGINT       NOT NULL,
    cve           VARCHAR(64)  NOT NULL,   -- grype 의 주 식별자 (CVE 또는 GHSA)
    package_name  VARCHAR(255) NOT NULL,

    -- NOT_SET · IN_TRIAGE · EXPLOITABLE · NOT_AFFECTED · FALSE_POSITIVE
    state         VARCHAR(32)  NOT NULL DEFAULT 'NOT_SET',
    -- 해당 없음(NOT_AFFECTED) 일 때만 찬다. 아홉 가지 표준값.
    justification VARCHAR(64)  NULL,
    -- UPDATE · ROLLBACK · WORKAROUND_AVAILABLE · CAN_NOT_FIX · WILL_NOT_FIX
    response      VARCHAR(32)  NULL,

    note          VARCHAR(2000) NOT NULL DEFAULT '',  -- 사람이 적는 설명
    other_control VARCHAR(1000) NOT NULL DEFAULT '',  -- 다른 통제
    -- 사내 결재 문서 번호. 이 도구에 승인 절차는 없다 — 그 결재를 가리키는
    -- 번호만 둔다. 앞서 열 이름이 approved_by 였고 화면에는 '승인한 사람'
    -- 이라고 떠 있었다. 아무나 아무 이름이나 적는 칸이었다.
    approval_doc  VARCHAR(128) NOT NULL DEFAULT '',

    -- 고치지 않고 두기로 한 대응(조치 불가·조치 안 함)에만 받는다.
    -- 기한 없이 남겨 둔 것은 방치와 구분되지 않는다.
    review_by     DATE         NULL,

    created_at    DATETIME(6)  NOT NULL,
    updated_at    DATETIME(6)  NOT NULL,
    updated_by    VARCHAR(64)  NOT NULL DEFAULT '',   -- 로그인 계정

    PRIMARY KEY (id),
    CONSTRAINT fk_analysis_asset FOREIGN KEY (asset_id) REFERENCES assets (id)
        ON DELETE CASCADE,
    -- 한 건에 검토 결과는 하나다. 앞서 수용은 철회하고 다시 수용할 수 있어
    -- 같은 키의 행이 여럿이었는데, 그래서 '지금 결정이 무엇인가' 를 세는 데
    -- 늘 revoked_at IS NULL 을 달아야 했다. 하나로 못 박고 바뀐 것은 이력에
    -- 쌓는다.
    UNIQUE KEY ux_analysis_key (asset_id, cve, package_name),
    KEY ix_analysis_state (state),
    KEY ix_analysis_review (review_by)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 변경 이력. 덮어쓰기만 하면 "언제부터 해당 없음이었나" 에 답할 수 없다.
CREATE TABLE finding_analysis_event (
    id           BIGINT      NOT NULL AUTO_INCREMENT,
    analysis_id  BIGINT      NOT NULL,
    at           DATETIME(6) NOT NULL,
    actor        VARCHAR(64) NOT NULL DEFAULT '',
    field_name   VARCHAR(32) NOT NULL DEFAULT '',   -- 상태 · 근거 · 대응 · 재검토일
    before_value VARCHAR(255) NOT NULL DEFAULT '',
    after_value  VARCHAR(255) NOT NULL DEFAULT '',

    PRIMARY KEY (id),
    CONSTRAINT fk_analysis_event FOREIGN KEY (analysis_id) REFERENCES finding_analysis (id)
        ON DELETE CASCADE,
    KEY ix_analysis_event (analysis_id, at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;


-- ── 옛 위험 수용을 옮긴다 ──────────────────────────────────────────────
--
-- 뜻이 그대로 보존되어야 한다:
--   살아 있는 수용 = "탐지는 우리한테 해당되는데, 고칠 수 있어도 안 하기로 했다"
--                  → 상태 해당됨(EXPLOITABLE) · 대응 조치 안 함(WILL_NOT_FIX)
--
-- 목록에서 감추지 않는다. §7 의 초안에는 '감춤=예' 라고 적어 두었으나 §4.5 에서
-- 감추기 칸 자체를 없앴고, 감추는 축을 상태로 옮겼다. 해당됨은 보이는 상태다 —
-- 안 고치기로 한 것은 눈앞에 남아 있어야 한다는 것이 §4.4 의 결론이다.

INSERT INTO finding_analysis
    (asset_id, cve, package_name, state, justification, response,
     note, other_control, approval_doc, review_by,
     created_at, updated_at, updated_by)
SELECT r.asset_id, r.cve, r.package_name,
       'EXPLOITABLE', NULL, 'WILL_NOT_FIX',
       r.reason, r.compensating, r.approved_by, r.review_by,
       r.accepted_at, r.accepted_at, r.accepted_by
FROM risk_acceptances r
WHERE r.revoked_at IS NULL;

-- 철회된 수용은 '지금의 결정' 이 아니다. 같은 건에 살아 있는 수용이 없다면
-- 그 건은 지금 아무 결정도 없는 상태 — 미검토다. 그렇다고 지우면 "한때
-- 수용했다가 거뒀다" 는 사실이 사라진다. 행은 미검토로 두고 그 사실은
-- 이력에 남긴다.
--
-- 같은 키에 철회분이 여럿일 수 있으므로 가장 나중 것 하나만 행으로 만든다.
INSERT INTO finding_analysis
    (asset_id, cve, package_name, state, justification, response,
     note, other_control, approval_doc, review_by,
     created_at, updated_at, updated_by)
SELECT r.asset_id, r.cve, r.package_name,
       'NOT_SET', NULL, NULL,
       '', '', '', NULL,
       r.accepted_at, r.revoked_at, r.revoked_by
FROM risk_acceptances r
WHERE r.revoked_at IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM risk_acceptances a
                  WHERE a.asset_id = r.asset_id AND a.cve = r.cve
                    AND a.package_name = r.package_name
                    AND a.revoked_at IS NULL)
  AND r.id = (SELECT MAX(x.id) FROM risk_acceptances x
              WHERE x.asset_id = r.asset_id AND x.cve = r.cve
                AND x.package_name = r.package_name);

-- 이력: 수용한 일. 살아 있는 것도 철회된 것도 전부 남긴다. 옮겨 온 이력은
-- 그때의 시각을 그대로 쓴다 — 마이그레이션을 돌린 날이 아니다.
INSERT INTO finding_analysis_event
    (analysis_id, at, actor, field_name, before_value, after_value)
SELECT f.id, r.accepted_at, r.accepted_by, '상태', '미검토', '해당됨 · 조치 안 함'
FROM risk_acceptances r
JOIN finding_analysis f
  ON f.asset_id = r.asset_id AND f.cve = r.cve AND f.package_name = r.package_name;

-- 이력: 철회한 일.
INSERT INTO finding_analysis_event
    (analysis_id, at, actor, field_name, before_value, after_value)
SELECT f.id, r.revoked_at, r.revoked_by, '상태', '해당됨 · 조치 안 함', '미검토'
FROM risk_acceptances r
JOIN finding_analysis f
  ON f.asset_id = r.asset_id AND f.cve = r.cve AND f.package_name = r.package_name
WHERE r.revoked_at IS NOT NULL;

DROP TABLE risk_acceptances;
