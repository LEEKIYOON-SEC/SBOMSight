-- 검토 결과의 번호 칸을 탐지와 같은 너비로 (64 → 128자).
--
-- 탐지의 번호 칸(findings.cve)은 V2 에서 128자로 넓혔는데, 검토 결과의 번호 칸
-- (finding_analysis.cve)은 V11 에서 64자로 만들었다. 65자가 넘는 번호의 탐지에 검토 결과를
-- 적으면 DB 가 거절했고, 화면은 그것을 "동시에 두 번 눌렸다" 로 읽어 한 번 더 적다가 오류
-- 화면이 됐다(FindingAnalysisTest). 조치 대상(remediation_targets.cve, V19)은 처음부터
-- 탐지와 같은 128자다.
--
-- 넓히기만 한다 — 있던 값은 그대로다. 유일 키(ux_analysis_key)는 MySQL · MariaDB 가 다시
-- 만든다.

ALTER TABLE finding_analysis
    MODIFY COLUMN cve VARCHAR(128) NOT NULL;
