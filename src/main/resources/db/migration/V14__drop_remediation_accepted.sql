-- 조치 상태에서 `ACCEPTED`(하지 않고 닫음) 를 없앤다.
--
-- 같은 결정이 두 곳에 적힐 수 있었다.
--
--   ① 조치 상태            remediations.status = 'ACCEPTED'
--   ② 검토 결과의 대응     finding_analysis.response = 'will_not_fix'
--
-- 그러면 보고서는 한쪽만 읽고, 두 쪽이 다르게 적혀 있어도 아무도 모른다.
-- 한 가지를 가리키는 말은 하나만 쓴다 (rework-plan §4.0.2).
--
-- **남길 쪽은 검토 결과다.** 통제가 그쪽에만 있다.
--
--                     ACCEPTED (없앰)      will_not_fix
--   근거               없음                 아홉 가지 중 하나
--   재검토일           없음                 **반드시 받는다**
--   결재 문서 번호     없음                 적는 칸이 있다
--
-- 근거도 재검토일도 없이 아무나 눌러 닫을 수 있는 상태는 통제가 있는 것처럼
-- 보이는 만큼 없느니만 못하다. 앞서 이 상태의 화면 이름이 `예외 승인` 이어서
-- 이름을 고쳤는데, 이번에는 상태 자체를 없앤다.
--
-- ── 이미 닫아 둔 행을 어떻게 하나 ────────────────────────────────────────────
--
-- `DONE` 으로 바꾸지 않는다 — 하지 않은 일을 했다고 적는 셈이다.
-- 조용히 지우지 않는다 — 누가 언제 닫았는지가 사라진다.
--
-- **`OPEN` 으로 되돌리고 그 사실을 메모와 이력에 남긴다.** 그러면 사람이
-- 검토 결과에 근거와 재검토일을 붙여 다시 결정하게 된다. 그것이 원래 필요했던
-- 절차다.

-- 1) 무엇을 되돌렸는지 이력에 먼저 남긴다. 상태를 바꾼 뒤에 남기면 `from`
--    값을 이미 잃는다.
INSERT INTO remediation_events (remediation_id, at, actor, from_status, to_status, comment)
SELECT id, NOW(6), 'system', 'ACCEPTED', 'OPEN',
       CONCAT('V14 — `하지 않고 닫음` 상태를 없애고 대기로 되돌렸습니다. ',
              '안 고치기로 한 결정은 취약점의 검토 결과에 근거와 재검토일과 함께 적습니다.')
FROM remediations
WHERE status = 'ACCEPTED';

-- 2) 메모에도 남긴다. 이력은 상세 화면을 열어야 보이고, 목록에서는 메모가
--    먼저 보인다.
UPDATE remediations
SET note = TRIM(CONCAT(
        CASE WHEN note = '' THEN '' ELSE CONCAT(note, ' / ') END,
        '[V14] 앞서 `하지 않고 닫음` 으로 닫혀 있었습니다 — 검토 결과에 다시 적어 주세요.')),
    status = 'OPEN',
    updated_at = NOW(6),
    updated_by = 'system'
WHERE status = 'ACCEPTED';

-- 3) 주석을 실제와 맞춘다. 열은 VARCHAR 라 값 제약이 없고, 주석만 옛 목록을
--    들고 있었다 — 다음 사람이 그것을 보고 아직 있는 값으로 읽는다.
ALTER TABLE remediations
    MODIFY COLUMN status VARCHAR(16) NOT NULL COMMENT 'OPEN | IN_PROGRESS | DONE';
