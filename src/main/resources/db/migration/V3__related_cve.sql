-- grype 의 주 식별자와 CVE 번호를 함께 담는다.
--
-- 언어 생태계(maven·npm·pypi)에서 grype 의 vulnerability.id 는 GHSA 번호다.
-- 실제 grype 0.87 출력 98건이 전부 GHSA 였고, CVE 번호는 relatedVulnerabilities
-- 안에 들어 있었다(98건 모두 있었다).
--
-- 결재·보고는 CVE 번호로 돈다. GHSA-jfh8-c2jp-5v3q 만 적힌 표는 읽는 사람이
-- 매번 찾아봐야 한다. 그래서 **grype 이 이미 준 CVE 를 꺼내 함께 담는다** —
-- 주 식별자를 바꾸는 것이 아니라, 같은 응답 안에 있던 값을 옆에 놓는 것이다.

ALTER TABLE findings
    ADD COLUMN related_cve VARCHAR(128) NOT NULL DEFAULT '' AFTER cve;

CREATE INDEX ix_findings_related_cve ON findings (related_cve);
