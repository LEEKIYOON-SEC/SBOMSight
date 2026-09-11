-- 재검사와 설치 경로.
--
-- 1) 재검사 — 보관된 SBOM 을 갱신된 grype DB 로 다시 돌린다. 대상 서버에
--    다시 갈 필요가 없다. syft 와 grype 을 나눠 둔 구조의 가장 큰 이점인데
--    지금까지 쓰지 않고 있었다. 어느 스캔에서 나온 재검사인지 남겨야
--    이력에서 "같은 SBOM 인데 결과가 달라진" 것을 읽을 수 있다.
--
-- 2) 설치 경로 — grype 이 주는 artifact.locations 를 detail_json 안에만
--    넣어 두고 있었다. 조회도 정렬도 CSV 도 되지 않는다. "어느 파일이냐" 는
--    조치할 때 반드시 묻는 것이라 열로 뺀다.

ALTER TABLE scans
    ADD COLUMN rescan_of BIGINT NULL AFTER created_by;

-- 원본 스캔이 지워져도 재검사는 남는다(SET NULL). 원본이 사라졌다고 그
-- 결과까지 지우면 그때 무엇을 봤는지 설명할 수 없다.
ALTER TABLE scans
    ADD CONSTRAINT fk_scans_rescan_of FOREIGN KEY (rescan_of) REFERENCES scans (id)
        ON DELETE SET NULL;

-- 경로는 길다. /opt/app/WEB-INF/lib/... 가 흔하고 컨테이너 안이면 더 길다.
-- 넘치면 Finding.clip 이 잘라 담는다 — 한 값 때문에 스캔 전체를 잃지 않는다.
ALTER TABLE findings
    ADD COLUMN install_path VARCHAR(1024) NOT NULL DEFAULT '' AFTER package_language;
