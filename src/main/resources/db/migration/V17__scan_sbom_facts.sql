-- 검사에 SBOM 이 말하는 것을 남긴다 — 생성 시각 · 해시 · 생성 도구 · 대상.
--
-- 앞서 화면과 보고서의 시각은 전부 검사가 돈 시각(created_at)이었다. 그래서
--   ① 옛 줄에서 `다시 검사` 를 누르면 옛 SBOM 이 그 자산의 최신 검사가 됐고,
--   ② 40일 전에 뜬 SBOM 을 다시 검사하면 `30일 넘은 자산` 에서 빠지고 구역
--      보고서가 그 자산을 이번 기간에 검사한 것으로 셌고,
--   ③ 보고서의 `점검 일시` 가 오늘이 되어 서버를 오늘 점검한 것처럼 읽혔다.
-- 최신 검사는 이제 SBOM 생성 시각으로 고른다(ScanRepository.currentOf).
--
-- 새 검사는 코드가 채운다 — 업로드 때 해시를, 검사가 SBOM 을 읽을 때 시각 ·
-- 도구 · 대상을(CycloneDX metadata.timestamp · SPDX creationInfo.created).
-- 다시 검사는 원본 것을 물려받는다.

ALTER TABLE scans
    ADD COLUMN sbom_created_at  DATETIME(6)  NULL AFTER finished_at,
    -- PENDING · SBOM · NO_TIMESTAMP · CLOCK_AHEAD · UNCONFIRMED (SbomTime)
    ADD COLUMN sbom_time_source VARCHAR(16)  NOT NULL DEFAULT 'UNCONFIRMED' AFTER sbom_created_at,
    ADD COLUMN sbom_sha256      VARCHAR(64)  NULL AFTER sbom_path,
    ADD COLUMN sbom_tool        VARCHAR(255) NOT NULL DEFAULT '' AFTER sbom_sha256,
    ADD COLUMN sbom_target      VARCHAR(255) NOT NULL DEFAULT '' AFTER sbom_tool;

-- 이미 쌓인 검사.
--
-- **SBOM 을 다시 읽어 채우지 않는다.** 보관된 sbom.json.gz 를 전부 풀어 훑는 것은
-- 마이그레이션이 할 일이 아니고(V13 과 같은 까닭), 그때 읽지 않은 값을 지금 지어내
-- 채우면 어디까지가 기록이고 어디부터가 추정인지 가를 수 없다(V10). 출처를
-- UNCONFIRMED 로 두면 화면이 `업로드 시각으로 대체 (SBOM 생성 시각 확인되지 않음)`
-- 이라고 밝힌다. 해시 · 도구 · 대상은 비워 둔다 — `확인되지 않음`.
--
-- 시각 자리에는 그 SBOM 을 **업로드한 시각**을 넣는다 — 원본은 제 created_at,
-- 다시 검사는 사슬을 거슬러 올라간 원본의 created_at. 그래야 옛 SBOM 을 다시
-- 검사한 줄이 이관 뒤에도 최신 검사가 되지 않는다. 원본이 지워진 다시 검사는
-- rescan_of 가 비어(V8, ON DELETE SET NULL) 원본과 가를 수 없으므로 제 시각이다.
--
-- 사슬은 길 수 있다 — 앞서 `다시 검사` 가 모든 줄에 있었다. 재귀 질의는 MariaDB 와
-- MySQL 8 이 UPDATE 에서 받는 꼴이 달라 쓰지 않고, 줄마다 "뿌리" 를 적어 한 번에
-- 한 칸씩이 아니라 **두 배씩** 거슬러 올라간다(뿌리의 뿌리). 스무 번이면 길이
-- 100만까지 닿는다. 바뀔 것이 없으면 한 번에 끝나는 갱신이다.
ALTER TABLE scans ADD COLUMN sbom_root BIGINT NULL;

UPDATE scans SET sbom_root = COALESCE(rescan_of, id);

UPDATE scans s JOIN scans p ON p.id = s.sbom_root SET s.sbom_root = p.sbom_root WHERE p.sbom_root <> s.sbom_root;
UPDATE scans s JOIN scans p ON p.id = s.sbom_root SET s.sbom_root = p.sbom_root WHERE p.sbom_root <> s.sbom_root;
UPDATE scans s JOIN scans p ON p.id = s.sbom_root SET s.sbom_root = p.sbom_root WHERE p.sbom_root <> s.sbom_root;
UPDATE scans s JOIN scans p ON p.id = s.sbom_root SET s.sbom_root = p.sbom_root WHERE p.sbom_root <> s.sbom_root;
UPDATE scans s JOIN scans p ON p.id = s.sbom_root SET s.sbom_root = p.sbom_root WHERE p.sbom_root <> s.sbom_root;
UPDATE scans s JOIN scans p ON p.id = s.sbom_root SET s.sbom_root = p.sbom_root WHERE p.sbom_root <> s.sbom_root;
UPDATE scans s JOIN scans p ON p.id = s.sbom_root SET s.sbom_root = p.sbom_root WHERE p.sbom_root <> s.sbom_root;
UPDATE scans s JOIN scans p ON p.id = s.sbom_root SET s.sbom_root = p.sbom_root WHERE p.sbom_root <> s.sbom_root;
UPDATE scans s JOIN scans p ON p.id = s.sbom_root SET s.sbom_root = p.sbom_root WHERE p.sbom_root <> s.sbom_root;
UPDATE scans s JOIN scans p ON p.id = s.sbom_root SET s.sbom_root = p.sbom_root WHERE p.sbom_root <> s.sbom_root;
UPDATE scans s JOIN scans p ON p.id = s.sbom_root SET s.sbom_root = p.sbom_root WHERE p.sbom_root <> s.sbom_root;
UPDATE scans s JOIN scans p ON p.id = s.sbom_root SET s.sbom_root = p.sbom_root WHERE p.sbom_root <> s.sbom_root;
UPDATE scans s JOIN scans p ON p.id = s.sbom_root SET s.sbom_root = p.sbom_root WHERE p.sbom_root <> s.sbom_root;
UPDATE scans s JOIN scans p ON p.id = s.sbom_root SET s.sbom_root = p.sbom_root WHERE p.sbom_root <> s.sbom_root;
UPDATE scans s JOIN scans p ON p.id = s.sbom_root SET s.sbom_root = p.sbom_root WHERE p.sbom_root <> s.sbom_root;
UPDATE scans s JOIN scans p ON p.id = s.sbom_root SET s.sbom_root = p.sbom_root WHERE p.sbom_root <> s.sbom_root;
UPDATE scans s JOIN scans p ON p.id = s.sbom_root SET s.sbom_root = p.sbom_root WHERE p.sbom_root <> s.sbom_root;
UPDATE scans s JOIN scans p ON p.id = s.sbom_root SET s.sbom_root = p.sbom_root WHERE p.sbom_root <> s.sbom_root;
UPDATE scans s JOIN scans p ON p.id = s.sbom_root SET s.sbom_root = p.sbom_root WHERE p.sbom_root <> s.sbom_root;
UPDATE scans s JOIN scans p ON p.id = s.sbom_root SET s.sbom_root = p.sbom_root WHERE p.sbom_root <> s.sbom_root;

UPDATE scans s JOIN scans r ON r.id = s.sbom_root SET s.sbom_created_at = r.created_at;

ALTER TABLE scans DROP COLUMN sbom_root;

ALTER TABLE scans MODIFY sbom_created_at DATETIME(6) NOT NULL;

-- 최신 검사를 고르는 질의가 자산마다 SBOM 생성 시각으로 줄 세운다.
CREATE INDEX ix_scans_asset_sbom ON scans (asset_id, sbom_created_at);
