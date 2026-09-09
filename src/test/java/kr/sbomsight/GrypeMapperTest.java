package kr.sbomsight;

import com.fasterxml.jackson.databind.ObjectMapper;
import kr.sbomsight.domain.Asset;
import kr.sbomsight.domain.Finding;
import kr.sbomsight.domain.Scan;
import kr.sbomsight.grype.GrypeMapper;
import kr.sbomsight.grype.GrypeReport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * grype 결과를 옮기는 규칙을 못 박는다.
 *
 * <p>여기서 지키는 것은 하나다 — <b>우리 코드 때문에 grype 의 판정이 달라지지
 * 않는다.</b> grype 이 틀렸다면 그것은 grype 의 오류로 감수하지만, 옮기는
 * 과정에서 값이 바뀌거나 사라지는 것은 감수 대상이 아니다.
 */
class GrypeMapperTest {

    private final ObjectMapper json = new ObjectMapper();
    private final GrypeMapper mapper = new GrypeMapper(json);

    private GrypeMapper.Result map(String body) throws Exception {
        GrypeReport report = json.readValue(body, GrypeReport.class);
        return mapper.map(scan(), report);
    }

    private Scan scan() {
        Asset asset = new Asset();
        asset.setName("web-01");
        return new Scan(asset, "tester");
    }

    // -----------------------------------------------------------------------
    // 값을 그대로 옮기는가
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("grype 이 준 심각도·CVSS·수정 버전을 그대로 담는다")
    void copiesValuesVerbatim() throws Exception {
        GrypeMapper.Result result = map("""
            {"matches":[{
              "vulnerability":{"id":"CVE-2024-3094","severity":"Critical",
                "dataSource":"https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
                "cvss":[{"type":"Primary","version":"3.1",
                         "vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                         "metrics":{"baseScore":10.0}}],
                "fix":{"versions":["5.6.2"],"state":"fixed"}},
              "matchDetails":[{"type":"exact-direct-match","matcher":"rpm-matcher",
                "searchedBy":{"namespace":"rocky:distro:rocky:9"},
                "found":{"versionConstraint":"< 5.6.2 (rpm)"}}],
              "artifact":{"name":"xz","version":"5.6.0-2.el9","type":"rpm",
                          "purl":"pkg:rpm/rocky/xz@5.6.0-2.el9"}}]}
            """);

        assertThat(result.findings()).hasSize(1);
        Finding finding = result.findings().get(0);

        assertThat(finding.getCve()).isEqualTo("CVE-2024-3094");
        assertThat(finding.getSeverity()).isEqualTo("Critical");
        assertThat(finding.getCvssScore()).isEqualByComparingTo("10.00");
        assertThat(finding.getCvssVector()).isEqualTo("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        assertThat(finding.getPackageName()).isEqualTo("xz");
        assertThat(finding.getPackageVersion()).isEqualTo("5.6.0-2.el9");
        assertThat(finding.getFixState()).isEqualTo("fixed");
        assertThat(finding.getFixedVersion()).isEqualTo("5.6.2");
        assertThat(finding.getVersionConstraint()).isEqualTo("< 5.6.2 (rpm)");
        assertThat(finding.getMatchType()).isEqualTo("exact-direct-match");
        assertThat(finding.getNamespace()).isEqualTo("rocky:distro:rocky:9");
    }

    @Test
    @DisplayName("조치 가능 여부는 fix.state 만 본다 — 버전을 다시 비교하지 않는다")
    void fixAvailabilityComesOnlyFromGrype() throws Exception {
        // 설치 버전이 수정 버전보다 높아 보여도 grype 이 fixed 라고 하면 fixed 다.
        // 우리 비교자에 흠이 하나만 있어도 grype 이 잡은 건이 화면에서 사라진다.
        GrypeMapper.Result result = map("""
            {"matches":[{
              "vulnerability":{"id":"CVE-1","severity":"High",
                "fix":{"versions":["1.0.0"],"state":"fixed"}},
              "artifact":{"name":"weird","version":"99.0.0","type":"rpm"}}]}
            """);

        assertThat(result.findings().get(0).isFixAvailable()).isTrue();
        assertThat(result.findings().get(0).getFixedVersion()).isEqualTo("1.0.0");
    }

    @Test
    @DisplayName("wont-fix 는 조치가 아니라 수정본 없음으로 남는다")
    void wontFixIsNoFix() throws Exception {
        GrypeMapper.Result result = map("""
            {"matches":[{
              "vulnerability":{"id":"CVE-2","severity":"Medium","fix":{"state":"wont-fix"}},
              "artifact":{"name":"glibc","version":"2.34","type":"rpm"}}]}
            """);

        Finding finding = result.findings().get(0);
        assertThat(finding.isFixAvailable()).isFalse();
        assertThat(finding.isNoFix()).isTrue();
        assertThat(finding.getFixedVersion()).isEmpty();
    }

    // -----------------------------------------------------------------------
    // 없는 값을 지어내지 않는가 — 가장 중요한 것
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("EPSS·KEV 를 grype 이 주지 않으면 null 로 남긴다")
    void missingExploitDataStaysUnknown() throws Exception {
        // 옛 grype 은 이 값을 주지 않는다. 0/false 로 채우면 "악용 확률 0%",
        // "악용된 적 없음" 이라는, 아무도 확인하지 않은 판정이 화면에 뜬다.
        GrypeMapper.Result result = map("""
            {"matches":[{
              "vulnerability":{"id":"CVE-3","severity":"High"},
              "artifact":{"name":"curl","version":"8.4.0","type":"rpm"}}]}
            """);

        Finding finding = result.findings().get(0);
        assertThat(finding.getEpss()).isNull();
        assertThat(finding.getKev()).isNull();
        assertThat(finding.getGrypeRisk()).isNull();
    }

    @Test
    @DisplayName("CVSS 가 없으면 점수를 비워 둔다 — 0 점으로 채우지 않는다")
    void missingCvssStaysNull() throws Exception {
        GrypeMapper.Result result = map("""
            {"matches":[{
              "vulnerability":{"id":"CVE-4","severity":"Unknown"},
              "artifact":{"name":"foo","version":"1.0","type":"rpm"}}]}
            """);

        assertThat(result.findings().get(0).getCvssScore()).isNull();
    }

    @Test
    @DisplayName("EPSS·KEV 가 오면 그대로 담는다")
    void exploitDataIsCarried() throws Exception {
        GrypeMapper.Result result = map("""
            {"matches":[{
              "vulnerability":{"id":"CVE-2024-3094","severity":"Critical",
                "epss":[{"cve":"CVE-2024-3094","epss":0.1234,"percentile":0.95}],
                "knownExploited":[{"cve":"CVE-2024-3094",
                                   "knownRansomwareCampaignUse":"Known"}],
                "risk":8.75},
              "artifact":{"name":"xz","version":"5.6.0","type":"rpm"}}]}
            """);

        Finding finding = result.findings().get(0);
        assertThat(finding.getEpss()).isEqualByComparingTo("0.1234");
        assertThat(finding.getKev()).isTrue();
        assertThat(finding.getKevRansomware()).isTrue();
        assertThat(finding.getGrypeRisk()).isEqualByComparingTo("8.7500");
    }

    @Test
    @DisplayName("KEV 목록이 왔지만 이 CVE 가 없으면 false 다 — null 이 아니다")
    void kevCheckedButNotListed() throws Exception {
        // 목록 자체가 왔다는 것은 grype 이 KEV 를 확인했다는 뜻이다. 그때는
        // "확인했고 없었다"(false)이지 "모른다"(null)가 아니다.
        GrypeMapper.Result result = map("""
            {"matches":[{
              "vulnerability":{"id":"CVE-5","severity":"Low","knownExploited":[]},
              "artifact":{"name":"bar","version":"1.0","type":"rpm"}}]}
            """);

        assertThat(result.findings().get(0).getKev()).isFalse();
    }

    // -----------------------------------------------------------------------
    // CVSS 고르기
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("판이 높고 Primary 인 CVSS 를 고른다")
    void picksHighestVersionPrimaryCvss() throws Exception {
        GrypeMapper.Result result = map("""
            {"matches":[{
              "vulnerability":{"id":"CVE-6","severity":"High","cvss":[
                {"type":"Secondary","version":"2.0","vector":"AV:N/AC:L","metrics":{"baseScore":5.0}},
                {"type":"Primary","version":"3.1","vector":"CVSS:3.1/AV:N","metrics":{"baseScore":7.5}},
                {"type":"Secondary","version":"3.1","vector":"CVSS:3.1/AV:L","metrics":{"baseScore":4.0}}]},
              "artifact":{"name":"baz","version":"1.0","type":"rpm"}}]}
            """);

        Finding finding = result.findings().get(0);
        assertThat(finding.getCvssScore()).isEqualByComparingTo("7.50");
        assertThat(finding.getCvssVersion()).isEqualTo("3.1");
    }

    @Test
    @DisplayName("주 항목에 CVSS 가 없으면 관련 CVE 것을 쓴다")
    void fallsBackToRelatedCvss() throws Exception {
        // 배포판 권고는 CVSS 가 비는 일이 흔하고, grype 이 그 건과 NVD 항목을
        // 스스로 한 건으로 묶어 준다. 출처를 넘나드는 것이 아니다.
        GrypeMapper.Result result = map("""
            {"matches":[{
              "vulnerability":{"id":"RHSA-2024:1234","severity":"Important"},
              "relatedVulnerabilities":[{"id":"CVE-2024-3094",
                "description":"Malicious code in xz.",
                "cvss":[{"type":"Primary","version":"3.1","vector":"CVSS:3.1/AV:N",
                         "metrics":{"baseScore":10.0}}]}],
              "artifact":{"name":"xz","version":"5.6.0","type":"rpm"}}]}
            """);

        Finding finding = result.findings().get(0);
        assertThat(finding.getCvssScore()).isEqualByComparingTo("10.00");
        assertThat(finding.getDescription()).isEqualTo("Malicious code in xz.");
    }

    // -----------------------------------------------------------------------
    // CVE 번호 — 결재·보고가 이 번호로 돈다
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("주 식별자가 GHSA 면 함께 온 CVE 를 꺼내 옆에 담는다")
    void extractsRelatedCve() throws Exception {
        GrypeMapper.Result result = map("""
            {"matches":[{
              "vulnerability":{"id":"GHSA-jfh8-c2jp-5v3q","severity":"Critical"},
              "relatedVulnerabilities":[{"id":"CVE-2021-44228"}],
              "artifact":{"name":"log4j-core","version":"2.14.1","type":"java-archive"}}]}
            """);

        Finding finding = result.findings().get(0);
        // grype 의 주 식별자는 그대로 남는다 — 바꾸지 않는다.
        assertThat(finding.getCve()).isEqualTo("GHSA-jfh8-c2jp-5v3q");
        assertThat(finding.getRelatedCve()).isEqualTo("CVE-2021-44228");
        // 화면에는 CVE 를 크게, GHSA 를 옆에.
        assertThat(finding.getDisplayId()).isEqualTo("CVE-2021-44228");
        assertThat(finding.getSecondaryId()).isEqualTo("GHSA-jfh8-c2jp-5v3q");
    }

    @Test
    @DisplayName("주 식별자가 이미 CVE 면 그대로 쓰고 두 번 보여 주지 않는다")
    void primaryCveNeedsNoAlias() throws Exception {
        GrypeMapper.Result result = map("""
            {"matches":[{
              "vulnerability":{"id":"CVE-2024-3094","severity":"Critical"},
              "artifact":{"name":"xz","version":"5.6.0","type":"rpm"}}]}
            """);

        Finding finding = result.findings().get(0);
        assertThat(finding.getDisplayId()).isEqualTo("CVE-2024-3094");
        assertThat(finding.getSecondaryId()).isEmpty();
    }

    @Test
    @DisplayName("CVE 가 없으면 지어내지 않고 grype 이 준 번호를 그대로 쓴다")
    void neverInventsACve() throws Exception {
        GrypeMapper.Result result = map("""
            {"matches":[{
              "vulnerability":{"id":"GHSA-xxxx-yyyy-zzzz","severity":"High"},
              "relatedVulnerabilities":[{"id":"GMS-2021-123"}],
              "artifact":{"name":"thing","version":"1.0","type":"npm"}}]}
            """);

        Finding finding = result.findings().get(0);
        assertThat(finding.getRelatedCve()).isEmpty();
        assertThat(finding.getDisplayId()).isEqualTo("GHSA-xxxx-yyyy-zzzz");
        assertThat(finding.getSecondaryId()).isEmpty();
    }

    // -----------------------------------------------------------------------
    // 회계 — 몇 건이 들어와 몇 건이 남았는가
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("같은 키가 두 번 오면 합치고 그 수를 남긴다")
    void mergesDuplicatesAndCounts() throws Exception {
        GrypeMapper.Result result = map("""
            {"matches":[
              {"vulnerability":{"id":"CVE-7","severity":"High"},
               "artifact":{"name":"openssl","version":"3.0.0","type":"rpm",
                           "purl":"pkg:rpm/openssl@3.0.0"}},
              {"vulnerability":{"id":"CVE-7","severity":"High"},
               "artifact":{"name":"openssl","version":"3.0.0","type":"rpm",
                           "purl":"pkg:rpm/openssl@3.0.0"}}]}
            """);

        assertThat(result.findings()).hasSize(1);
        assertThat(result.matches()).isEqualTo(2);
        assertThat(result.merged()).isEqualTo(1);
        assertThat(result.dropped()).isZero();
    }

    @Test
    @DisplayName("같은 CVE 라도 패키지가 다르면 다른 건이다")
    void samecveDifferentPackagesAreSeparate() throws Exception {
        GrypeMapper.Result result = map("""
            {"matches":[
              {"vulnerability":{"id":"CVE-8","severity":"High"},
               "artifact":{"name":"openssl","version":"3.0.0","type":"rpm"}},
              {"vulnerability":{"id":"CVE-8","severity":"High"},
               "artifact":{"name":"openssl-libs","version":"3.0.0","type":"rpm"}}]}
            """);

        assertThat(result.findings()).hasSize(2);
        assertThat(result.merged()).isZero();
    }

    @Test
    @DisplayName("이름이나 CVE 가 없는 건은 세어서 버린다 — 조용히 사라지지 않는다")
    void countsDropped() throws Exception {
        GrypeMapper.Result result = map("""
            {"matches":[
              {"vulnerability":{"id":"CVE-9","severity":"High"},
               "artifact":{"name":"good","version":"1.0","type":"rpm"}},
              {"vulnerability":{"id":"CVE-10","severity":"High"},
               "artifact":{"name":"","version":"1.0","type":"rpm"}},
              {"vulnerability":{"id":"","severity":"High"},
               "artifact":{"name":"nameless","version":"1.0","type":"rpm"}}]}
            """);

        assertThat(result.findings()).hasSize(1);
        assertThat(result.matches()).isEqualTo(3);
        assertThat(result.dropped()).isEqualTo(2);
        // 회계가 맞는가: match = finding + merged + dropped
        assertThat(result.matches())
                .isEqualTo(result.findings().size() + result.merged() + result.dropped());
    }

    // -----------------------------------------------------------------------
    // grype 이 판을 올려도 깨지지 않는가
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("모르는 필드가 있어도 읽는다")
    void toleratesUnknownFields() throws Exception {
        // grype 이 판을 올릴 때마다 필드가 붙는다. 그때마다 파싱이 깨지면
        // 취약점 DB 를 최신으로 못 쓴다.
        GrypeMapper.Result result = map("""
            {"matches":[{
              "vulnerability":{"id":"CVE-11","severity":"High","brandNewField":{"a":1},
                               "anotherOne":[1,2,3]},
              "artifact":{"name":"foo","version":"1.0","type":"rpm","futureThing":true}}],
             "somethingEntirelyNew":{"x":1}}
            """);

        assertThat(result.findings()).hasSize(1);
        assertThat(result.findings().get(0).getCve()).isEqualTo("CVE-11");
    }

    @Test
    @DisplayName("스캔 메타 — grype 판·DB 기준일·배포판을 남긴다")
    void capturesScanMetadata() throws Exception {
        GrypeReport report = json.readValue("""
            {"matches":[],
             "distro":{"name":"rocky","version":"9.3","idLike":["rhel"]},
             "descriptor":{"name":"grype","version":"0.87.0",
                           "db":{"built":"2026-08-18T01:23:45Z","schemaVersion":5}}}
            """, GrypeReport.class);

        Scan scan = scan();
        mapper.applyMetadata(scan, report);

        assertThat(scan.getGrypeVersion()).isEqualTo("0.87.0");
        assertThat(scan.getGrypeDbBuilt()).isNotNull();
        assertThat(scan.getDistroName()).isEqualTo("rocky");
        assertThat(scan.getDistroVersion()).isEqualTo("9.3");
    }

    @Test
    @DisplayName("빈 결과도 오류가 아니다 — 취약점이 없는 서버가 있다")
    void emptyIsFine() throws Exception {
        GrypeMapper.Result result = map("{\"matches\":[]}");
        assertThat(result.findings()).isEmpty();
        assertThat(result.matches()).isZero();
    }

    /**
     * <b>실제 grype 이 낸 출력 전체를 태운다.</b>
     *
     * <p>손으로 만든 픽스처는 우리가 상상한 모양일 뿐이다. 실제로 grype 0.87 의
     * {@code descriptor.db.location} 은 캐시 경로 문자열인데 그것을 숫자로
     * 짐작해 두었다가, 98건짜리 스캔이 파싱 단계에서 통째로 실패했다. 손으로
     * 만든 픽스처로는 절대 안 잡혔을 오류다.
     */
    @Test
    @DisplayName("실제 grype 0.87 출력 98건을 한 건도 잃지 않고 옮긴다")
    void mapsRealGrypeOutput() throws Exception {
        String body = new String(
                getClass().getResourceAsStream("/grype-0.87-real.json").readAllBytes());
        GrypeReport report = json.readValue(body, GrypeReport.class);

        Scan scan = scan();
        mapper.applyMetadata(scan, report);
        GrypeMapper.Result result = mapper.map(scan, report);

        assertThat(report.matches()).hasSize(98);
        assertThat(result.dropped()).isZero();
        assertThat(result.matches())
                .isEqualTo(result.findings().size() + result.merged() + result.dropped());

        // 스캔 메타가 실제 값으로 채워졌는가
        assertThat(scan.getGrypeVersion()).isEqualTo("0.87.0");
        assertThat(scan.getGrypeDbBuilt()).isNotNull();

        // grype 이 준 심각도 분포가 그대로 남았는가 (Critical 21 · High 59 · Medium 18)
        Map<String, Long> bySeverity = result.findings().stream()
                .collect(Collectors.groupingBy(Finding::getSeverity, Collectors.counting()));
        assertThat(bySeverity).containsEntry("Critical", 21L)
                              .containsEntry("High", 59L)
                              .containsEntry("Medium", 18L);

        // fix.state 분포도 그대로 (fixed 97 · not-fixed 1)
        Map<String, Long> byFix = result.findings().stream()
                .collect(Collectors.groupingBy(Finding::getFixState, Collectors.counting()));
        assertThat(byFix).containsEntry("fixed", 97L).containsEntry("not-fixed", 1L);

        // 0.87 은 EPSS·KEV 를 주지 않는다. 전부 미확인이어야 하고, 0/false 로
        // 채워져 있으면 안 된다.
        assertThat(result.findings()).allSatisfy(f -> {
            assertThat(f.getEpss()).isNull();
            assertThat(f.getKev()).isNull();
        });

        // 모든 건에 CVE 와 패키지 이름이 있다
        assertThat(result.findings()).allSatisfy(f -> {
            assertThat(f.getCve()).isNotBlank();
            assertThat(f.getPackageName()).isNotBlank();
        });

        // 98건 전부 GHSA 가 주 식별자이고, grype 이 CVE 를 함께 줬다.
        // 표에 GHSA 만 적히면 읽는 사람이 매번 찾아봐야 한다.
        assertThat(result.findings()).allSatisfy(f -> {
            assertThat(f.getCve()).startsWith("GHSA-");
            assertThat(f.getRelatedCve()).startsWith("CVE-");
            assertThat(f.getDisplayId()).startsWith("CVE-");
        });

        // log4shell 이 제대로 잡혔는가
        Finding log4shell = result.findings().stream()
                .filter(f -> "CVE-2021-44228".equals(f.getRelatedCve()))
                .findFirst().orElseThrow();
        assertThat(log4shell.getPackageName()).isEqualTo("log4j-core");
        assertThat(log4shell.getPackageVersion()).isEqualTo("2.14.1");
        assertThat(log4shell.getFixedVersion()).isEqualTo("2.15.0");
        assertThat(log4shell.getCvssScore()).isEqualByComparingTo("10.00");
    }

    @Test
    @DisplayName("실제 grype 픽스처를 온전히 옮긴다")
    void mapsRealFixture() throws Exception {
        String body = new String(getClass().getResourceAsStream("/grype-sample.json").readAllBytes());
        GrypeReport report = json.readValue(body, GrypeReport.class);
        GrypeMapper.Result result = mapper.map(scan(), report);

        // 원본의 match 수와 저장 건수가 맞아야 한다.
        assertThat(result.matches()).isEqualTo(report.matches().size());
        assertThat(result.matches())
                .isEqualTo(result.findings().size() + result.merged() + result.dropped());

        Map<String, Finding> byCve = result.findings().stream()
                .collect(Collectors.toMap(Finding::getCve, f -> f, (a, b) -> a));

        Finding xz = byCve.get("CVE-2024-3094");
        assertThat(xz).isNotNull();
        assertThat(xz.getPackageName()).isEqualTo("xz");
        assertThat(xz.getSeverity()).isEqualTo("Critical");
        assertThat(xz.getCvssScore()).isEqualByComparingTo(new BigDecimal("10.00"));
        assertThat(xz.isFixAvailable()).isTrue();

        // 픽스처는 옛 grype(0.79) 이라 EPSS·KEV 가 없다. 전부 미확인이어야 한다.
        List<Finding> withExploitData = result.findings().stream()
                .filter(f -> f.getEpss() != null || f.getKev() != null).toList();
        assertThat(withExploitData).isEmpty();
    }
}
