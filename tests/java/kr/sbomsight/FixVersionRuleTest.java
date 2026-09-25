package kr.sbomsight;

import kr.sbomsight.domain.*;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.AuditLogRepository;
import kr.sbomsight.repo.FindingRepository;
import kr.sbomsight.repo.RemediationRepository;
import kr.sbomsight.repo.ScanRepository;
import kr.sbomsight.service.FindingAnalysisService;
import kr.sbomsight.service.ReportService;
import kr.sbomsight.service.ZoneReportService;
import kr.sbomsight.service.ZoneService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * <b>수정 버전은 하나로 고르지 않는다 — 조치 화면 · 보고서 · CSV 가 같은 규칙.</b>
 *
 * <p>같은 패키지의 목표를 셋이 제각각 골랐다. 이 시험의 자료로 고치기 전
 * 코드를 돌리면 보고서 3장과 구역 보고서 4장은 `9.0.90`(글자로 가장 큰 것),
 * 조치는 `9.0.68`(CVSS 가 가장 높은 건의 것)이었다. 어느 쪽으로 올려도 남는
 * 건이 있다(`9.0.107` 이 필요하다). 사용자 결정: 여럿이면 여럿을 — `수정
 * 버전 N가지` 와 그 목록({@link FixVersions}).
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class FixVersionRuleTest {

    private static final List<String> ALL = List.of("9.0.107", "9.0.68", "9.0.90");

    @Autowired MockMvc mvc;
    @Autowired ReportService reports;
    @Autowired ZoneReportService zoneReports;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired RemediationRepository remediations;
    @Autowired FindingAnalysisService analyses;
    @Autowired AuditLogRepository audit;
    @Autowired ZoneService zoneService;

    private Zone zone;
    private Asset asset;
    private Scan scan;

    @BeforeEach
    void setUp() {
        zone = zoneService.create("수정버전-" + System.nanoTime(), "#123456", "");
        asset = new Asset();
        asset.setName("fixv-" + System.nanoTime());
        asset.setZone(zone);
        assets.saveAndFlush(asset);

        scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        scan.setCreatedAt(Instant.now());
        scans.saveAndFlush(scan);

        // 글자 순과 버전 순이 다르다: 글자로는 9.0.90 이 가장 크다.
        finding("CVE-2099-1", "tomcat-coyote", "fixed", "9.0.68", "9.8");   // CVSS 가 가장 높다
        finding("CVE-2099-2", "tomcat-coyote", "fixed", "9.0.90", "7.5");
        finding("CVE-2099-3", "tomcat-coyote", "fixed", "9.0.107", "5.3");
        finding("CVE-2099-4", "tomcat-coyote", "fixed", "9.0.68", "6.1");   // 같은 버전이 둘
        finding("CVE-2099-5", "tomcat-coyote", "fixed", "9.0.200", "4.0");  // 해당 없음으로 뺀다
        finding("CVE-2099-6", "tomcat-coyote", "not-fixed", "", "3.1");     // 수정 버전 없음
        // 수정 버전이 하나뿐인데 수정 버전 없는 건이 섞인 패키지
        finding("CVE-2099-7", "zlib", "fixed", "1.2.13", "7.0");
        finding("CVE-2099-8", "zlib", "not-fixed", "", "5.0");
        scan.setFindingCount(8);
        scans.saveAndFlush(scan);

        analyses.record(asset, "CVE-2099-5", "tomcat-coyote", AnalysisState.NOT_AFFECTED,
                        AnalysisJustification.CODE_NOT_PRESENT, null, "시험", "", "", null, "tester");
    }

    private void finding(String cve, String pkg, String fixState, String fixed, String cvss) {
        Finding f = new Finding(scan, cve + "|" + pkg, cve, pkg);
        f.setPackageVersion("tomcat-coyote".equals(pkg) ? "9.0.50" : "1.2.11");
        f.setPackageType("java-archive");
        f.setSeverity("High");
        f.setFixState(fixState);
        f.setFixedVersion(fixed);
        f.setCvssScore(new BigDecimal(cvss));
        findings.saveAndFlush(f);
    }

    @Test
    @DisplayName("보고서 3장 · 구역 보고서 4장 · 조치 · CSV · 감사 로그가 같은 목록을 적는다")
    void everyPlaceListsTheSameVersions() throws Exception {
        ReportService.PackageAction row = reports.build(scan).targets().fixTargets().stream()
                .filter(a -> a.packageName().equals("tomcat-coyote")).findFirst().orElseThrow();
        assertThat(row.fixVersions())
                .as("보고서 3장이 하나를 골랐거나, 해당 없음 · 수정 버전 없는 건의 값을 넣었다")
                .containsExactlyElementsOf(ALL);

        LocalDate today = LocalDate.now();
        ZoneReportService.ZonePackageAction zoneRow = zoneReports
                .build(zone.getId(), today.minusDays(1), today.plusDays(1))
                .judgement().actions().stream()
                .filter(a -> a.packageName().equals("tomcat-coyote")).findFirst().orElseThrow();
        assertThat(zoneRow.fixVersions()).containsExactlyElementsOf(ALL);

        mvc.perform(post("/assets/" + asset.getId() + "/remediations")
                            .param("packageName", "tomcat-coyote")
                            .with(user("tester").roles("ADMIN")).with(csrf()));
        Remediation opened = remediations
                .findByAssetIdAndPackageName(asset.getId(), "tomcat-coyote").orElseThrow();
        assertThat(opened.getToVersions())
                .as("조치가 보고서와 다른 목표를 적었다")
                .containsExactlyElementsOf(ALL);

        String described = "수정 버전 3가지: 9.0.107 · 9.0.68 · 9.0.90";
        assertThat(open("/actions/export.csv")).contains(described);
        assertThat(audit.search(null, AuditEvent.REMEDIATION_CREATED, null, null, "tomcat-coyote",
                                PageRequest.of(0, 5)).getContent())
                .extracting(AuditLog::getDetail)
                .anySatisfy(d -> assertThat(d).contains(described));

        // 화면 — 조치 목록 · 조치 상세 · 자산의 조치 탭 · 보고서가 같은 꼴로 그린다.
        for (String url : List.of("/actions", "/actions/" + opened.getId(),
                                  "/assets/" + asset.getId() + "?tab=actions",
                                  "/reports/scan/" + scan.getId())) {
            String html = open(url);
            assertThat(html).as(url).contains("수정 버전 3가지");
            ALL.forEach(v -> assertThat(html).as(url).contains("<span>" + v + "</span>"));
        }
    }

    @Test
    @DisplayName("수정 버전이 하나면 그 버전 — 수정 버전 없는 건의 빈 값을 한 가지로 세지 않는다")
    void oneVersionIsTheVersion() throws Exception {
        LocalDate today = LocalDate.now();
        ZoneReportService.ZonePackageAction zlib = zoneReports
                .build(zone.getId(), today.minusDays(1), today.plusDays(1))
                .judgement().actions().stream()
                .filter(a -> a.packageName().equals("zlib")).findFirst().orElseThrow();
        // 앞서 COUNT(DISTINCT fixedVersion) 이 빈 값까지 세어 2 — `자산별 확인` 으로 적었다.
        assertThat(zlib.fixVersions()).containsExactly("1.2.13");

        String zoneHtml = open("/reports/zone?zone=" + zone.getId()
                               + "&from=" + today.minusDays(1) + "&to=" + today.plusDays(1));
        assertThat(zoneHtml).contains("<b class=\"ver\">1.2.13</b>").doesNotContain("자산별 확인");
    }

    private String open(String url) throws Exception {
        return mvc.perform(get(url).with(user("tester").roles("ADMIN")))
                  .andReturn().getResponse().getContentAsString();
    }
}
