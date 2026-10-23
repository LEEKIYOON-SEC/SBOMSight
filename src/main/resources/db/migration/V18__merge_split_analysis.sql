-- 둘로 갈린 검토 결과를 하나로 합친다(D4).
--
-- 앞서 검토 결과를 찾는 순서가 두 벌이었다 — 표는 CVE 번호를 먼저, 목록 · 보고서는
-- 주 식별자(GHSA)를 먼저 찾았다. 저장은 보낸 번호로만 찾아 없으면 새 행을 만들어서,
-- GHSA 로만 오던 탐지에 나중에 CVE 가 붙고 표에서 고치면 같은 취약점의 행이 둘이
-- 됐다(재현 시험 P3). 위험 수용에서 옮겨 온 행(V11 — 그때의 주 식별자로 적힘)을 표에서
-- 고쳐도 그랬다. 그 건을 표는 고친 결정으로, 목록 · 보고서는 옛 결정으로 말했다.
-- 이제 읽기 · 쓰기가 한 규칙이다(FindingAnalysisService.analysisOf — 두 번호 중 어느
-- 쪽이든, 그런 행이 둘이면 나중에 고친 것). 이미 갈린 행을 여기서 합친다.
--
-- 갈린 짝 — 같은 자산 · 같은 패키지의 두 행인데, 그 자산의 어느 탐지 한 줄이 두 번호를
-- 주 식별자와 함께 온 CVE 로 함께 갖고 있다. 같은 취약점이라는 근거가 남아 있는 것만
-- 합친다. 근거가 없으면(탐지가 지워졌으면) 어느 탐지도 두 행을 함께 고르지 않는다.
--
-- 합치는 법(D4):
--   - 나중에 고친 쪽(updated_at, 같으면 나중에 만든 행)을 남긴다. 그 행의 지금 값은
--     그대로다.
--   - 다른 쪽의 이력은 남긴 쪽으로 옮긴다 — 그때의 시각 그대로. 그래서 남긴 쪽의 처음
--     기록(created_at)은 둘 중 이른 것으로 맞춘다 — 옮겨 온 이력이 처음 기록보다 앞서지
--     않게(검토 결과 상세의 `처음 기록`). 고친 시각(updated_at)은 그대로다.
--   - 다른 쪽의 값(번호 · 검토 상태 · 근거 · 대응 방안 · 재검토일)은 남긴 쪽 이력에
--     `검토 결과 합침` 한 줄로 남긴다. 설명 · 추가 보안 통제 · 결재 문서 번호는 이력에
--     담지 않는 칸이라(analysis-detail 의 각주) 감사 로그에 함께 남긴다.
--   - 감사 로그에 `검토 결과 합침`(ANALYSIS_MERGED)을 남긴다. 계정은 비워 둔다 — 사람이
--     한 일이 아니다.
--
-- **셋 이상이 엮인 묶음은 합치지 않는다.** 규칙은 탐지의 두 번호만 보므로, 어느 한
-- 행으로 합쳐도 어느 탐지에선가 결정이 떨어진다. 읽기 규칙이 나중 것을 고르므로 화면은
-- 서로 어긋나지 않는다.
--
-- 시각은 UTC 다 — 앱이 Instant 를 UTC 로 적는다(Hibernate). NOW() 는 DB 서버의
-- 시간대라 한국 시각 서버에서는 9시간 뒤로 찍힌다.
--
-- 돕는 표 둘은 끝에 지운다. 글자 맞춤(COLLATE)은 다른 표와 같게 적어 둔다 — DB 를
-- 맞춤 없이 만들면 표는 서버 기본(MySQL 8 은 utf8mb4_0900_ai_ci)을 따른다. 지금 쓰임
-- (요약 칸을 이어 붙여 다른 표에 옮겨 적는다)은 맞춤이 갈려도 돌지만, 다른 표의 칸과
-- 같은지(=) 맞대면 ERROR 1267 로 멈춘다(MySQL 8.4.10 에서 둘 다 확인).

CREATE TABLE analysis_link_v18 (
    a_id BIGINT NOT NULL,
    b_id BIGINT NOT NULL,
    PRIMARY KEY (a_id, b_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;

INSERT INTO analysis_link_v18 (a_id, b_id)
SELECT x.id, y.id
FROM finding_analysis x
JOIN finding_analysis y
  ON y.asset_id = x.asset_id AND y.package_name = x.package_name AND y.id <> x.id
WHERE EXISTS (SELECT 1 FROM findings f JOIN scans s ON s.id = f.scan_id
              WHERE s.asset_id = x.asset_id AND f.package_name = x.package_name
                AND ((f.cve = x.cve AND f.related_cve = y.cve)
                  OR (f.cve = y.cve AND f.related_cve = x.cve)));

CREATE TABLE analysis_merge_v18 (
    loser_id  BIGINT        NOT NULL,
    winner_id BIGINT        NOT NULL,
    summary   VARCHAR(1000) NOT NULL DEFAULT '',
    PRIMARY KEY (loser_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 짝이 하나뿐인 두 행만 — 나중에 고친 쪽이 남는다.
INSERT INTO analysis_merge_v18 (loser_id, winner_id)
SELECT l.a_id, l.b_id
FROM analysis_link_v18 l
JOIN finding_analysis lo ON lo.id = l.a_id
JOIN finding_analysis wi ON wi.id = l.b_id
WHERE (wi.updated_at > lo.updated_at OR (wi.updated_at = lo.updated_at AND wi.id > lo.id))
  AND (SELECT COUNT(*) FROM analysis_link_v18 c WHERE c.a_id = l.a_id) = 1
  AND (SELECT COUNT(*) FROM analysis_link_v18 c WHERE c.a_id = l.b_id) = 1;

-- 지우는 쪽의 결정 — 화면에 찍는 말로 적는다(이력은 사람이 읽는 것이다). 말은
-- AnalysisState · AnalysisJustification · AnalysisResponse 의 label 그대로다.
UPDATE analysis_merge_v18 m
JOIN finding_analysis lo ON lo.id = m.loser_id
SET m.summary = CONCAT_WS(' · ', lo.cve,
        CASE lo.state
            WHEN 'NOT_SET'        THEN '미검토'
            WHEN 'IN_TRIAGE'      THEN '검토 중'
            WHEN 'EXPLOITABLE'    THEN '해당됨'
            WHEN 'NOT_AFFECTED'   THEN '해당 없음'
            WHEN 'FALSE_POSITIVE' THEN '오탐'
            ELSE lo.state END,
        CASE lo.justification
            WHEN 'CODE_NOT_PRESENT'                THEN '취약한 코드가 들어 있지 않음'
            WHEN 'CODE_NOT_REACHABLE'              THEN '취약한 코드를 실행하지 않음'
            WHEN 'REQUIRES_CONFIGURATION'          THEN '특정 설정을 켜야 하는데 안 켜 둠'
            WHEN 'REQUIRES_DEPENDENCY'             THEN '함께 있어야 할 다른 패키지가 없음'
            WHEN 'REQUIRES_ENVIRONMENT'            THEN '특정 환경에서만 되는데 그 환경이 아님'
            WHEN 'PROTECTED_BY_COMPILER'           THEN '컴파일 옵션이 막고 있음'
            WHEN 'PROTECTED_AT_RUNTIME'            THEN '실행 환경이 막고 있음'
            WHEN 'PROTECTED_AT_PERIMETER'          THEN '방화벽·WAF가 막고 있음'
            WHEN 'PROTECTED_BY_MITIGATING_CONTROL' THEN '추가 보안 통제가 막고 있음'
            ELSE lo.justification END,
        CASE lo.response
            WHEN 'UPDATE'               THEN '업그레이드'
            WHEN 'ROLLBACK'             THEN '다운그레이드'
            WHEN 'WORKAROUND_AVAILABLE' THEN '우회 조치 (패치 미적용)'
            WHEN 'CAN_NOT_FIX'          THEN '조치 불가'
            WHEN 'WILL_NOT_FIX'         THEN '위험 수용'
            ELSE lo.response END,
        CASE WHEN lo.review_by IS NULL THEN NULL
             ELSE CONCAT('재검토일 ', DATE_FORMAT(lo.review_by, '%Y-%m-%d')) END);

-- 남기는 쪽의 이력에 한 줄 — 무엇을 합쳤는지(변경 내용: 지운 쪽의 결정 → 남긴 번호).
INSERT INTO finding_analysis_event (analysis_id, at, actor, field_name, before_value, after_value)
SELECT m.winner_id, UTC_TIMESTAMP(6), '', '검토 결과 합침', LEFT(m.summary, 255), wi.cve
FROM analysis_merge_v18 m
JOIN finding_analysis wi ON wi.id = m.winner_id;

-- 감사 로그 — 이력에 담지 않는 칸(설명 · 추가 보안 통제 · 결재 문서 번호)까지.
INSERT INTO audit_log (at, actor, action, target, detail, client_ip)
SELECT UTC_TIMESTAMP(6), '', 'ANALYSIS_MERGED',
       LEFT(CONCAT(a.name, ' · ', wi.cve), 256),
       LEFT(CONCAT(lo.package_name, ' · ', m.summary, ' → ', wi.cve,
                   CASE WHEN lo.note <> '' THEN CONCAT(' · 설명: ', lo.note) ELSE '' END,
                   CASE WHEN lo.other_control <> ''
                        THEN CONCAT(' · 추가 보안 통제: ', lo.other_control) ELSE '' END,
                   CASE WHEN lo.approval_doc <> ''
                        THEN CONCAT(' · 결재 문서 번호: ', lo.approval_doc) ELSE '' END),
            1000),
       ''
FROM analysis_merge_v18 m
JOIN finding_analysis lo ON lo.id = m.loser_id
JOIN finding_analysis wi ON wi.id = m.winner_id
JOIN assets a ON a.id = lo.asset_id;

-- 처음 기록은 둘 중 이른 것 — 아래에서 옮겨 오는 이력이 그보다 앞서지 않게.
UPDATE finding_analysis wi
JOIN analysis_merge_v18 m ON m.winner_id = wi.id
JOIN finding_analysis lo ON lo.id = m.loser_id
SET wi.created_at = LEAST(wi.created_at, lo.created_at);

-- 지우는 쪽의 이력을 남기는 쪽으로 — 그때의 시각 그대로.
UPDATE finding_analysis_event e
JOIN analysis_merge_v18 m ON m.loser_id = e.analysis_id
SET e.analysis_id = m.winner_id;

DELETE fa FROM finding_analysis fa
JOIN analysis_merge_v18 m ON m.loser_id = fa.id;

DROP TABLE analysis_merge_v18;
DROP TABLE analysis_link_v18;
