-- 패키지 인벤토리 — 무엇이 어디에 몇 버전으로 깔려 있나.
--
-- 지금까지 남는 것은 scans.component_count 라는 숫자 하나뿐이었다. 그래서
-- **취약점이 붙은 패키지만** 알 수 있었다. log4j 가 어디 깔려 있는지는 CVE 가
-- 터진 다음에야, 그것도 grype 이 매치를 낸 자산에서만 찾을 수 있었다.
--
-- SBOM 에는 이미 전부 들어 있다. SbomStorage 가 컴포넌트를 세느라 앞에서부터
-- 흘려 읽고 있으니 **세는 김에 담는다.**
--
-- 보관 범위: **자산마다 최신 검사 것만.** 컴포넌트 12만 개짜리 SBOM 을 검사마다
-- 쌓으면 감당이 안 된다 (100대 × 월1회 × 12개월 = 1억 4천만 행). 새 검사가
-- 읽히면 그 자산의 이전 행을 지운다.
--
-- scan_id 를 함께 두는 이유는 두 가지다.
--   ① 화면에 "기준이 된 검사" 를 찍는다 — 언제 본 것인지 모르는 목록은
--      "지금 깔려 있는 것" 이라고 말할 수 없다.
--   ② 스캔을 지우면 그 스캔에서 온 인벤토리도 함께 사라진다 (CASCADE).

CREATE TABLE component (
    id         BIGINT       NOT NULL AUTO_INCREMENT,
    asset_id   BIGINT       NOT NULL,
    scan_id    BIGINT       NOT NULL,

    name       VARCHAR(255) NOT NULL,
    version    VARCHAR(255) NOT NULL DEFAULT '',
    -- rpm · deb · java-archive · python · npm … purl 에서 딴다. purl 이
    -- 없으면 형식이 준 값을 쓴다. 우리가 지어내지 않는다.
    type       VARCHAR(64)  NOT NULL DEFAULT '',
    purl       VARCHAR(512) NOT NULL DEFAULT '',
    -- 설치 경로. SBOM 이 담아 줄 때만 있다. 비어 있는 것은 "경로가 없는
    -- 패키지" 가 아니라 **SBOM 이 안 담은 것**이다.
    location   VARCHAR(1000) NOT NULL DEFAULT '',

    PRIMARY KEY (id),

    -- 자산 화면의 `패키지` 탭
    KEY ix_component_asset (asset_id, name),
    -- 스캔 교체 · 스캔 삭제
    KEY ix_component_scan (scan_id),
    -- /packages 의 이름 묶기와 버전 분포
    KEY ix_component_name (name, version),

    CONSTRAINT fk_component_asset FOREIGN KEY (asset_id)
        REFERENCES assets (id) ON DELETE CASCADE,
    CONSTRAINT fk_component_scan FOREIGN KEY (scan_id)
        REFERENCES scans (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- 이미 쌓인 SBOM 을 여기서 되읽지는 않는다.
--
-- 채우려면 보관된 sbom.json.gz 를 전부 풀어 다시 훑어야 하는데, 그것은
-- 마이그레이션이 할 일이 아니다 (검사 하나에 몇 분씩 걸리고, 실패하면
-- 스키마 변경이 절반만 된 채로 멈춘다). 다음 검사부터 찬다.
--
-- 그래서 화면은 **비어 있는 것과 안 본 것을 구분해서 말해야 한다** —
-- "이 자산은 패키지가 없다" 가 아니라 "이 자산은 아직 다시 검사하지
-- 않았다" 다. PackageController 가 그렇게 가른다.
