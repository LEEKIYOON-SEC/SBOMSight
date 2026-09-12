-- 검사가 지금 어디까지 왔는가.
--
-- status 는 대기·검사 중·완료·실패 넷뿐이라, 몇 분씩 걸리는 grype 이 도는
-- 동안 화면에 "검사 중" 한 마디만 떠 있었다. 돌고 있는지 멈췄는지 알 수 없어
-- 사람이 새로고침만 반복하게 된다.
--
-- 기존 행은 빈 값으로 남는다. 이미 끝난 검사에 단계를 지어내 채우지 않는다 —
-- 그때 무엇을 지나갔는지는 기록이 없고, 없는 것을 만들어 넣으면 그 뒤로는
-- 어디까지가 기록이고 어디부터가 추정인지 구분할 수 없다.
ALTER TABLE scans
    ADD COLUMN stage VARCHAR(16) NOT NULL DEFAULT '' AFTER status;

-- 이미 끝난 검사는 DONE 으로 둔다. 이건 추정이 아니라 status 가 말해 주는
-- 사실이다.
UPDATE scans SET stage = 'DONE' WHERE status = 'DONE';
