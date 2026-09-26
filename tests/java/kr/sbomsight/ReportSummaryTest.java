package kr.sbomsight;

import kr.sbomsight.domain.Asset;
import kr.sbomsight.domain.Finding;
import kr.sbomsight.domain.Scan;
import kr.sbomsight.domain.ScanStatus;
import kr.sbomsight.domain.Zone;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.FindingRepository;
import kr.sbomsight.repo.ScanRepository;
import kr.sbomsight.service.ReportService;
import kr.sbomsight.service.ZoneReportService;
import kr.sbomsight.service.ZoneService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * <b>보고서 첫 쪽 — 요약.</b>
 *
 * <p>앞서 첫 쪽에는 문서 정보와 1장 다섯 줄뿐이었고, 심각도 · 조치 대상은
 * 둘째 쪽부터였다. 요약은 <b>뒤 장들이 센 수를 그대로</b> 모은다 — 새로 세면
 * 한 문서 안에서 수가 갈라지는 날이 온다. 그래서 요약의 수를 모델(뒤 장이
 * 찍는 값)과 맞대 본다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class ReportSummaryTest {

    @Autowired MockMvc mvc;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired ZoneService zoneService;

    private Zone zone;
    private Scan scan;

    @BeforeEach
    void seed() {
        zone = zoneService.create("요약-" + System.nanoTime(), "#6f7e8d", "");
        Asset asset = new Asset();
        asset.setName("summary-" + System.nanoTime());
        asset.setZone(zone);
        assets.saveAndFlush(asset);
        scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        scan.setCreatedAt(Instant.now());
        scans.saveAndFlush(scan);

        // 올려서 해소되는 패키지 일곱 — 요약에는 3장 순위의 앞 다섯만 선다.
        // CVSS 로 순위를 가른다(원격 접근 · 실제 악용이 모두 같다).
        for (int i = 0; i < 7; i++) {
            finding("CVE-2099-20" + i, "pkg" + i, i < 2 ? "Critical" : "High", "fixed", 9.0 - i);
        }
        finding("CVE-2099-2100", "stuck", "Medium", "not-fixed", 5.0);
    }

    @Test
    @DisplayName("자산 보고서 — 요약이 1장 앞에 서고, 수는 뒤 장의 값 그대로")
    void theAssetReportOpensWithTheSummary() throws Exception {
        MvcResult r = open("/reports/scan/" + scan.getId());
        String html = flat(r.getResponse().getContentAsString(StandardCharsets.UTF_8));
        ReportService.Report report = (ReportService.Report) r.getModelAndView().getModel().get("report");

        assertThat(html.indexOf("<h2>요약</h2>")).as("요약이 없다").isNotNegative()
                .isLessThan(html.indexOf("<h2>1. "));
        String summary = section(html, "<h2>요약</h2>");
        assertThat(summary)
                .contains("<b>" + report.overview().findingCount() + "건</b>")
                .contains(report.summary().severityOf("critical") + "건 · "
                          + report.summary().severityOf("high") + "건")
                .contains(report.targets().fixTargets().size() + "개 패키지 · 해소 "
                          + report.targets().resolvableFindings() + "건")
                .contains(report.targets().noFixRows().size() + "개 패키지 · "
                          + report.targets().blockedFindings() + "건")
                .contains("미등록 " + report.progress().untracked() + "개")
                .contains("첫 검사 — 대조 없음");

        List<String> expected = report.progress().rows().stream().limit(5)
                .map(row -> row.action().packageName()).toList();
        assertThat(packagesIn(summary)).as("3장 순위의 앞 다섯").isEqualTo(expected);
        assertThat(expected).hasSize(5);
    }

    @Test
    @DisplayName("구역 보고서 — 요약이 1장 앞에 서고, 상위 다섯은 4장 순위 그대로")
    void theZoneReportOpensWithTheSummary() throws Exception {
        MvcResult r = open("/reports/zone?zone=" + zone.getId());
        String html = flat(r.getResponse().getContentAsString(StandardCharsets.UTF_8));
        ZoneReportService.ZoneReport report =
                (ZoneReportService.ZoneReport) r.getModelAndView().getModel().get("report");

        assertThat(html.indexOf("<h2>요약</h2>")).as("요약이 없다").isNotNegative()
                .isLessThan(html.indexOf("<h2>1. "));
        String summary = section(html, "<h2>요약</h2>");
        assertThat(summary)
                .contains("<b>1대</b>")
                .contains(report.judgement().actions().size() + "개 패키지 · 해소 "
                          + report.judgement().resolvableFindings() + "건")
                .contains("대조 불가 — 기간 이전 검사 없음");
        List<String> expected = report.judgement().actions().stream().limit(5)
                .map(ZoneReportService.ZonePackageAction::packageName).toList();
        assertThat(packagesIn(summary)).as("4장 순위의 앞 다섯").isEqualTo(expected);
    }

    @Test
    @DisplayName("기간 안에 검사한 자산이 없으면 요약을 싣지 않는다 — 전부 0 은 깨끗하다로 읽힌다")
    void noSummaryWhenNothingWasScanned() throws Exception {
        LocalDate longAgo = LocalDate.now().minusYears(5);
        String html = open("/reports/zone?zone=" + zone.getId() + "&from=" + longAgo
                           + "&to=" + longAgo.plusDays(1))
                .getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(html).doesNotContain("<h2>요약</h2>").contains("<h2>1. ");
    }

    // --- 씨앗 · 읽기 ------------------------------------------------------------

    private void finding(String cve, String pkg, String severity, String fixState, double cvss) {
        Finding f = new Finding(scan, cve + "|" + pkg, cve, pkg);
        f.setPackageVersion("1.0");
        f.setSeverity(severity);
        f.setFixState(fixState);
        f.setFixedVersion("fixed".equals(fixState) ? "1.1" : "");
        f.setCvssScore(BigDecimal.valueOf(cvss));
        findings.saveAndFlush(f);
        scan.setFindingCount(scan.getFindingCount() + 1);
        scans.saveAndFlush(scan);
    }

    private MvcResult open(String url) throws Exception {
        MvcResult r = mvc.perform(get(url).with(user("tester").roles("ADMIN"))).andReturn();
        assertThat(r.getResponse().getStatus()).as(url).isEqualTo(200);
        return r;
    }

    private static String section(String html, String head) {
        int start = html.indexOf(head);
        return html.substring(start, html.indexOf("</section>", start));
    }

    /** 요약의 상위 표에 찍힌 패키지 이름, 찍힌 순서대로. */
    private static List<String> packagesIn(String summary) {
        Matcher m = Pattern.compile("<td><b>([^<]+)</b></td>").matcher(summary);
        List<String> out = new java.util.ArrayList<>();
        while (m.find()) {
            out.add(m.group(1));
        }
        return out;
    }

    private static String flat(String html) {
        return html.replaceAll("\\s+", " ");
    }
}
