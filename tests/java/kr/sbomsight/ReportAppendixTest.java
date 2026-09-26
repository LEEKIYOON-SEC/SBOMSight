package kr.sbomsight;

import kr.sbomsight.domain.AnalysisJustification;
import kr.sbomsight.domain.AnalysisState;
import kr.sbomsight.domain.Asset;
import kr.sbomsight.domain.Finding;
import kr.sbomsight.domain.Scan;
import kr.sbomsight.domain.ScanStatus;
import kr.sbomsight.domain.Zone;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.FindingRepository;
import kr.sbomsight.repo.ScanRepository;
import kr.sbomsight.service.FindingAnalysisService;
import kr.sbomsight.service.ZoneService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * <b>무엇이 위험한가 — 보고서 부록과 CVE 상세의 취약점 설명.</b>
 *
 * <p>앞서 보고서 어디에도 취약점의 설명이 없었다 — 번호와 건수뿐이라, 받는
 * 사람이 번호를 하나씩 밖에서 찾아봐야 했다. CVE 상세도 번호와 점수뿐이었다.
 * 설명은 검사 결과에 이미 있다(grype 이 준 원문).
 *
 * <p>부록은 실제 악용 · 심각만, 원문의 첫 문장만 싣는다. 목록이므로 해당
 * 없음 · 오탐은 3 · 4장처럼 뺀다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class ReportAppendixTest {

    @Autowired MockMvc mvc;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired FindingAnalysisService analyses;
    @Autowired ZoneService zoneService;

    private Zone zone;
    private Asset web;
    private Scan webScan;

    @BeforeEach
    void seed() {
        zone = zoneService.create("부록-" + System.nanoTime(), "#6f7e8d", "");
        web = asset("web-");
        Asset db = asset("db-");
        webScan = scanOf(web);
        Scan dbScan = scanOf(db);

        finding(webScan, "CVE-2099-1001", "openssl", "Critical", null, 9.8,
                "OpenSSL has a flaw in X (e.g. Y). Attackers can Z.");
        finding(webScan, "CVE-2099-1002", "xz", "High", true, 7.5,
                "XZ backdoor allows remote access.\nMore text.");
        finding(webScan, "CVE-2099-1003", "zlib", "Medium", null, 5.0, "Zlib medium thing.");
        finding(webScan, "CVE-2099-1004", "glibc", "Critical", null, 9.0, "Glibc critical but reviewed.");
        finding(webScan, "CVE-2099-1005", "curl", "Critical", null, null, "A".repeat(300));
        finding(webScan, "CVE-2099-1006", "bash", "Critical", null, null, null);
        // 같은 취약점이 다른 자산에도 — 구역 보고서는 한 줄로 모으고 자산을 센다.
        finding(dbScan, "CVE-2099-1001", "openssl", "Critical", null, 9.1,
                "OpenSSL has a flaw in X (e.g. Y). Attackers can Z.");

        analyses.record(web, "CVE-2099-1004", "glibc", AnalysisState.NOT_AFFECTED,
                        AnalysisJustification.CODE_NOT_PRESENT, null, "", "", "", null, "tester");
    }

    @Test
    @DisplayName("자산 보고서 부록 — 실제 악용 · 심각만, 원문 첫 문장, 실제 악용 먼저")
    void theAssetReportHasTheAppendix() throws Exception {
        String appendix = appendix(page("/reports/scan/" + webScan.getId()));
        assertThat(appendix)
                .contains("CVE-2099-1001").contains("CVE-2099-1002")
                .contains("CVE-2099-1005").contains("CVE-2099-1006")
                .as("심각도 보통은 싣지 않는다").doesNotContain("CVE-2099-1003")
                .as("해당 없음으로 검토한 것은 목록에서 뺀다").doesNotContain("CVE-2099-1004");
        assertThat(appendix)
                .as("줄임말(e.g.)에서 끊지 않고, 둘째 문장은 싣지 않는다")
                .contains("OpenSSL has a flaw in X (e.g. Y).")
                .doesNotContain("Attackers can Z")
                .contains("XZ backdoor allows remote access.")
                .doesNotContain("More text");
        assertThat(appendix.indexOf("CVE-2099-1002"))
                .as("실제 악용이 먼저").isLessThan(appendix.indexOf("CVE-2099-1001"));
        assertThat(appendix.indexOf("CVE-2099-1001"))
                .as("CVSS 가 있는 것이 없는 것보다 먼저").isLessThan(appendix.indexOf("CVE-2099-1005"));
        // 마침표 없는 긴 설명은 잘리고 잘린 것이 보인다. 설명이 없으면 —.
        assertThat(appendix).contains("A".repeat(239) + "…").doesNotContain("A".repeat(240));
        assertThat(flat(appendix)).contains("CVE-2099-1006</td>")
                .containsPattern("CVE-2099-1006</td>.*?<td lang=\"en\">—</td>");
    }

    @Test
    @DisplayName("구역 보고서 부록 — 여러 자산에 걸린 취약점은 한 줄, 자산 수를 적는다")
    void theZoneReportCountsAssets() throws Exception {
        String appendix = flat(appendix(page("/reports/zone?zone=" + zone.getId())));
        assertThat(appendix)
                .containsPattern("CVE-2099-1001</td>.*?<td class=\"num tight\">2대</td>")
                .doesNotContain("CVE-2099-1004");
        assertThat(appendix.split("CVE-2099-1001", -1)).as("한 줄이다").hasSize(2);
    }

    @Test
    @DisplayName("CVE 상세 — 취약점 설명을 원문 그대로 전부 싣는다")
    void theCveDetailShowsTheWholeDescription() throws Exception {
        String html = flat(page("/vulns/CVE-2099-1001"));
        assertThat(html)
                .contains("<th>취약점 설명</th>")
                .contains("OpenSSL has a flaw in X (e.g. Y). Attackers can Z.");
    }

    // --- 씨앗 · 읽기 ------------------------------------------------------------

    private Asset asset(String prefix) {
        Asset a = new Asset();
        a.setName(prefix + System.nanoTime());
        a.setZone(zone);
        return assets.saveAndFlush(a);
    }

    private Scan scanOf(Asset asset) {
        Scan scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        scan.setCreatedAt(Instant.now());
        return scans.saveAndFlush(scan);
    }

    private void finding(Scan scan, String cve, String pkg, String severity, Boolean kev,
                         Double cvss, String description) {
        Finding f = new Finding(scan, cve + "|" + pkg, cve, pkg);
        f.setPackageVersion("1.0");
        f.setSeverity(severity);
        f.setKev(kev);
        f.setCvssScore(cvss == null ? null : BigDecimal.valueOf(cvss));
        f.setFixState("fixed");
        f.setFixedVersion("1.1");
        f.setDescription(description);
        findings.saveAndFlush(f);
        scan.setFindingCount(scan.getFindingCount() + 1);
        scans.saveAndFlush(scan);
    }

    private String page(String url) throws Exception {
        return mvc.perform(get(url).with(user("tester").roles("ADMIN")))
                  .andExpect(status().isOk())
                  .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    /** 부록 장만 — 다른 장의 같은 번호에 속지 않게. */
    private static String appendix(String html) {
        int start = html.indexOf("<h2>부록");
        assertThat(start).as("부록이 없다").isNotNegative();
        return html.substring(start, html.indexOf("</section>", start));
    }

    private static String flat(String html) {
        return html.replaceAll("\\s+", " ");
    }
}
