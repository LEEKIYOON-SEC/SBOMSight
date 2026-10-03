-- 조치 회차 · 조치 대상 · 적는 칸까지 남기는 이력 (R7 · R8 · R9, D5).
--
-- ── 1) 조치 회차 ──────────────────────────────────────────────────────────────
--
-- 앞서 조치는 (자산, 패키지)에 하나뿐이었다(uk_remediation_open). 완료한 뒤 같은
-- 패키지에 새 취약점이 나오면 `조치 등록` 은 그 완료된 조치로 보냈고 목표 버전도
-- 옛것이었다. 담당자는 완료를 다시 열 수밖에 없었고, 다시 열면 완료 시각이 지워져
-- 구역 보고서의 `기간 중 완료` 에서 그 완료가 사라졌다(재현 시험 P2).
--
-- 이제 닫힌 조치만 있는 패키지에 `조치 등록` 을 누르면 새 조치를 연다(D5) — 조치
-- 회차가 하나 늘고, 이전 조치를 가리킨다. `열린 조치는 (자산, 패키지)에 하나` 는
-- 앱이 자산 행을 잠가 지킨다(RemediationService.open).
--
-- 유일 키를 지우기 전에 같은 칸의 보통 색인을 먼저 둔다 — 자산 FK
-- (fk_remediation_asset)가 asset_id 로 시작하는 색인을 하나 요구하는데, 지금은 유일
-- 키가 그 몫을 하고 있다. 먼저 지우면 MySQL · MariaDB 가 FK 에 필요한 색인이라며 거절한다.
--
-- 이전 조치(previous_id)에는 FK 를 두지 않는다. 자산을 지우면 그 자산의 조치가 한
-- 번에 사라지는데(fk_remediation_asset ON DELETE CASCADE), 같은 표를 가리키는 FK 가
-- 그 사이에 끼면 지우는 순서에 따라 막힐 수 있다. 회차는 같은 (자산, 패키지) 안에서만
-- 이어지므로 자산이 지워질 때 함께 사라지고, 조치 하나를 지울 때는 앱이 다음 회차가
-- 있는 조치를 지우지 않는다.

ALTER TABLE remediations ADD KEY ix_remediation_asset_pkg (asset_id, package_name);
ALTER TABLE remediations DROP INDEX uk_remediation_open;
ALTER TABLE remediations
    ADD COLUMN round_no    INT    NOT NULL DEFAULT 1 AFTER package_name,
    ADD COLUMN previous_id BIGINT NULL AFTER round_no;

-- ── 2) 조치 대상 ──────────────────────────────────────────────────────────────
--
-- 조치는 패키지에 매달려 있어 무엇을 고치려던 것인지(CVE)를 몰랐다. 그래서 완료한 뒤
-- 같은 패키지에 새 취약점이 나오면 "조치가 덜 됐다(완료 · 탐지 남음)" 와 "새
-- 취약점이다(완료 · 신규 탐지)" 를 가를 수 없었다(R9 · R10).
--
-- 등록 당시의 탐지를 담는다 — 번호 · 함께 온 CVE · 설치 버전 · 수정 버전. 칸 너비는
-- 탐지(findings)와 같다(V2 · V3) — 좁으면 긴 번호의 탐지가 있는 패키지에서 등록이
-- 실패한다. 등록 당시 건수(opened_count)와 같은 건이다. 똑같은 줄(경로만 다른 같은
-- 탐지)은 하나로 — 글자 그대로 견준다(utf8mb4_bin). 열의 정렬 규칙(대소문자 무시)으로
-- 가르면 `RC1` 과 `rc1` 이 하나가 된다(V16 과 같은 까닭).
--
-- 이미 등록된 조치는 등록한 검사에서 채운다(V15 · V16 과 같은 방식). 그 검사가
-- 지워졌거나 모르면 채우지 않는다 — 화면은 `확인되지 않음` 이라 적고, 완료 뒤 남은
-- 탐지를 가를 근거가 없으므로 앞서처럼 `완료 · 탐지 남음` 으로 말한다.

CREATE TABLE remediation_targets (
    id              BIGINT       NOT NULL AUTO_INCREMENT,
    remediation_id  BIGINT       NOT NULL,
    cve             VARCHAR(128) NOT NULL,
    related_cve     VARCHAR(128) NOT NULL DEFAULT '',
    package_version VARCHAR(255) NOT NULL DEFAULT '',
    fixed_version   VARCHAR(255) NOT NULL DEFAULT '',
    PRIMARY KEY (id),
    KEY ix_rem_target (remediation_id),
    CONSTRAINT fk_rem_target FOREIGN KEY (remediation_id) REFERENCES remediations (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;

INSERT INTO remediation_targets (remediation_id, cve, related_cve, package_version, fixed_version)
SELECT DISTINCT r.id,
       f.cve COLLATE utf8mb4_bin, f.related_cve COLLATE utf8mb4_bin,
       f.package_version COLLATE utf8mb4_bin, f.fixed_version COLLATE utf8mb4_bin
FROM remediations r
JOIN findings f ON f.scan_id = r.opened_scan_id AND f.package_name = r.package_name;

-- ── 3) 이력 ───────────────────────────────────────────────────────────────────
--
-- 조치 이력은 상태가 바뀔 때만, 검토 결과 이력은 고르는 칸(검토 상태 · 근거 · 대응
-- 방안 · 재검토일)만 남겼다. "누가 기한을 밀었나" · "결재 문서 번호는 언제 바뀌었나"
-- 에 답할 것이 없었다(R8). 이제 바뀐 칸마다 앞뒤 값을 남긴다.
--
--   조치 — 상태 줄은 그대로(from_status · to_status), 담당 · 기한 · 설명은 칸 이름과
--          앞뒤 값. 설명은 1,000자까지라 그만큼 둔다.
--   검토 결과 — 앞뒤 값 칸이 255자라 설명(2,000자)이 들어가지 않았다. 넓힌다.

ALTER TABLE remediation_events
    ADD COLUMN field_name   VARCHAR(32)   NOT NULL DEFAULT '' AFTER to_status,
    ADD COLUMN before_value VARCHAR(1000) NOT NULL DEFAULT '' AFTER field_name,
    ADD COLUMN after_value  VARCHAR(1000) NOT NULL DEFAULT '' AFTER before_value;

ALTER TABLE finding_analysis_event
    MODIFY COLUMN before_value VARCHAR(2000) NOT NULL DEFAULT '',
    MODIFY COLUMN after_value  VARCHAR(2000) NOT NULL DEFAULT '';

-- ── 4) 언제부터인가 ───────────────────────────────────────────────────────────
--
-- 이 판 전에 바뀐 적는 칸은 이력에 없다 — 지어내 채우지 않는다. 그 대신 언제부터
-- 남겼는지 적어 두고, 그보다 먼저 만든 조치 · 검토 결과의 상세가 각주로 밝힌다(없는
-- 기록을 있는 것처럼 보이게 두지 않는다). 시각은 UTC — 앱이 Instant 를 UTC 로 적는다.

INSERT INTO app_settings (name, setting_value, updated_at, updated_by)
VALUES ('history_fields_since', 'V19', UTC_TIMESTAMP(6), '');
