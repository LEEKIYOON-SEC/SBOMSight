-- 감사 로그.
--
-- "누가 지웠냐" 에 답할 수 없는 도구는 점검을 통과하지 못한다. 지금까지
-- 남는 것은 users.last_login_at 하나뿐이었다 — 마지막 로그인 시각. 누가
-- 자산을 지웠고, 누가 접근 IP 를 바꿨고, 누가 남의 비밀번호를 초기화했는지
-- 아무 흔적도 없었다.
--
-- 지우지 않는다. 보관 기간을 코드로 정해 두면 그 기간이 지난 뒤 "그때 누가
-- 했냐" 를 물었을 때 답이 없다. 용량은 줄 하나가 수백 바이트라 문제가 되지
-- 않는다(연 10만 건이어도 수십 MB).

CREATE TABLE audit_log (
    id        BIGINT       NOT NULL AUTO_INCREMENT,
    at        DATETIME(6)  NOT NULL,
    actor     VARCHAR(64)  NOT NULL DEFAULT '',   -- 한 일을 한 계정. 로그인 실패는 시도한 이름
    action    VARCHAR(48)  NOT NULL,              -- AuditEvent 의 이름
    target    VARCHAR(256) NOT NULL DEFAULT '',   -- 무엇에 대해 (자산 이름 · 계정 이름 · 구역 이름)
    detail    VARCHAR(1000) NOT NULL DEFAULT '',  -- 사람이 읽을 한 줄. 비밀번호는 절대 담지 않는다
    client_ip VARCHAR(64)  NOT NULL DEFAULT '',   -- 소켓 주소만. X-Forwarded-For 는 믿지 않는다
    PRIMARY KEY (id),
    KEY ix_audit_at (at DESC),
    KEY ix_audit_actor (actor, at DESC),
    KEY ix_audit_action (action, at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;
