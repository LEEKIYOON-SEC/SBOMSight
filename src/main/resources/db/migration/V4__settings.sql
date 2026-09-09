-- 웹에서 바꾸는 설정.
--
-- 환경변수는 부트스트랩 값이다 — 처음 띄울 때 쓰고, 웹에서 한 번이라도
-- 저장하면 그때부터 이 표의 값이 쓰인다. 서버를 다시 띄우지 않고 바꿀 수
-- 있어야 하는 것만 여기 둔다.
-- 열 이름을 `value` 로 두지 않는다. 여러 DB 에서 예약어라, 그대로 쓰면
-- 방언에 따라 표가 조용히 안 만들어진다(H2 에서 실제로 그랬다).
CREATE TABLE app_settings (
    name          VARCHAR(64)   NOT NULL,
    setting_value VARCHAR(4000) NOT NULL,
    updated_at    DATETIME(6)   NOT NULL,
    updated_by    VARCHAR(64)   NOT NULL DEFAULT '',
    PRIMARY KEY (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
