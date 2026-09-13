-- 마지막 로그인과 그 전 로그인.
--
-- last_login_at 은 V1 부터 있었지만 **한 번도 채워지지 않았다.**
-- setLastLoginAt 을 부르는 곳이 코드 어디에도 없었다. 두 군데가 조용히
-- 망가져 있었다.
--
--   ① 설정의 '마지막 로그인' 이 모든 계정에서 언제나 '없음'
--   ② 비밀번호 변경 화면이 "최초 로그인입니다" 와 "임시 비밀번호로
--      로그인하셨습니다" 를 last_login_at IS NULL 로 갈랐는데, 늘 NULL 이라
--      **관리자가 초기화한 계정에도 '최초 로그인' 이라고 말했다**
--
-- 그런데 로그인할 때 last_login_at 을 채우기만 하면 ②가 반대로 뒤집힌다.
-- 첫 로그인에도 값이 생기므로 이번에는 전부 '임시 비밀번호' 가 된다.
-- 비밀번호 화면은 로그인 **다음 요청**에서 뜨기 때문에 순서로 풀 수 없다.
--
-- 그래서 사실 두 개를 두 칸에 나눠 적는다.
--
--   last_login_at      이번에 들어온 시각        → 설정의 '마지막 로그인'
--   previous_login_at  그 전에 들어온 시각        → NULL 이면 이번이 처음
--
-- 추측하지 않는다. "처음인가" 를 날짜 하나로 눈치껏 가르려 하면 언젠가
-- 틀리고, 틀린 줄도 모른다.

ALTER TABLE users ADD COLUMN previous_login_at DATETIME(6) NULL AFTER last_login_at;


-- 이미 쓰던 설치에는 두 칸이 다 비어 있다. 그대로 두면 오늘 이후 로그인부터만
-- 맞고, 그때까지는 멀쩡히 쓰던 계정이 '최초 로그인' 으로 보인다.
--
-- 감사 로그에 로그인 성공 기록이 이미 남아 있다 — 그것으로 채운다.
-- 지어내는 것이 아니라 우리가 이미 가지고 있는 값이다.

UPDATE users u
SET u.last_login_at = (
        SELECT MAX(a.at) FROM audit_log a
        WHERE a.actor = u.username AND a.action = 'LOGIN_SUCCESS')
WHERE u.last_login_at IS NULL;

-- 그 전 로그인 = 마지막 것을 뺀 나머지 중 가장 나중.
UPDATE users u
SET u.previous_login_at = (
        SELECT MAX(a.at) FROM audit_log a
        WHERE a.actor = u.username AND a.action = 'LOGIN_SUCCESS'
          AND a.at < u.last_login_at)
WHERE u.last_login_at IS NOT NULL;
