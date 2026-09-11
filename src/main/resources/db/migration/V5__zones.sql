-- 구역(ZONE)을 1급 개념으로.
--
-- 지금까지 구역은 assets.group_name 이라는 그냥 문자열이었다. 표에 찍히기만
-- 하고 관리 단위로 쓰이지 않았다 — 순서도 없고, 오타로 'DMZ' 와 'dmz' 가
-- 따로 생겨도 막을 길이 없었다. 망분리가 전제인 환경에서 구역은 자산의
-- 꼬리표가 아니라 관리의 축이다.
--
-- group_name 을 남겨 두고 zone_id 를 더하는 방법도 있지만 그러지 않는다.
-- 같은 뜻을 담은 칸이 둘이면 언젠가 갈라지고, 그때 어느 쪽이 맞는지 아무도
-- 모른다.

CREATE TABLE zones (
    id         BIGINT       NOT NULL AUTO_INCREMENT,
    name       VARCHAR(64)  NOT NULL,
    sort_order INT          NOT NULL DEFAULT 0,   -- 화면에 세우는 순서
    color      VARCHAR(16)  NOT NULL DEFAULT '',  -- 좌측 레일 색
    note       VARCHAR(500) NOT NULL DEFAULT '',
    created_at DATETIME(6)  NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_zones_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 어디에도 속하지 않는 자산이 생기지 않도록 받을 자리를 먼저 만든다.
-- 자산이 한 대도 없는 새 설치에서도 구역 하나는 있어야 자산 등록이 된다.
INSERT INTO zones (name, sort_order, color, created_at)
VALUES ('미분류', 9999, '#6f7e8d', NOW(6));

-- 쓰고 있던 그룹 이름을 그대로 구역으로 옮긴다. 앞뒤 공백은 버린다 —
-- 'DMZ ' 와 'DMZ' 가 다른 구역이 되면 안 된다.
INSERT INTO zones (name, sort_order, color, created_at)
SELECT TRIM(group_name), 0, '', NOW(6)
FROM assets
WHERE TRIM(group_name) <> ''
GROUP BY TRIM(group_name);

ALTER TABLE assets ADD COLUMN zone_id BIGINT NULL AFTER name;

UPDATE assets a
  JOIN zones z
    ON z.name = CASE WHEN TRIM(a.group_name) = '' THEN '미분류' ELSE TRIM(a.group_name) END
   SET a.zone_id = z.id;

-- 채운 뒤에 조인다. 처음부터 NOT NULL 로 만들면 기존 행이 있는 설치에서
-- 이 마이그레이션 자체가 실패한다.
ALTER TABLE assets MODIFY zone_id BIGINT NOT NULL;

ALTER TABLE assets DROP KEY ix_assets_group;
ALTER TABLE assets DROP COLUMN group_name;

ALTER TABLE assets
    ADD CONSTRAINT fk_assets_zone FOREIGN KEY (zone_id) REFERENCES zones (id);
CREATE INDEX ix_assets_zone ON assets (zone_id, name);
