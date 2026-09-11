-- 로그인 실패 잠금과 비밀번호 변경 주기.
--
-- 둘 다 users 에 칸을 더하는 일이라 한 번에 한다.
--
-- 실패 횟수를 감사 로그에서 세는 방법도 있지만 그러지 않는다. 감사 로그는
-- '무슨 일이 있었는가' 의 기록이고, 잠금 여부는 '지금 어떤 상태인가' 다.
-- 기록을 상태로 쓰면 성공 시 초기화가 어색해지고("마지막 성공 이후의 실패만
-- 센다" 같은 질의가 필요해진다), 기록을 손대는 순간 잠금이 풀린다.

ALTER TABLE users
    ADD COLUMN failed_attempts INT NOT NULL DEFAULT 0 AFTER must_change,
    ADD COLUMN locked_at DATETIME(6) NULL AFTER failed_attempts,
    -- 변경 주기 계산의 기준. 기존 계정은 지금을 기준으로 삼는다 —
    -- NULL 로 두면 "한 번도 바꾼 적 없음" 과 구분되지 않아 전원이
    -- 다음 로그인에서 변경 화면에 걸린다.
    ADD COLUMN password_changed_at DATETIME(6) NULL AFTER locked_at;

UPDATE users SET password_changed_at = NOW(6) WHERE password_changed_at IS NULL;

-- 잠긴 계정을 찾는 질의가 설정 화면에서 돈다.
CREATE INDEX ix_users_locked ON users (locked_at);
