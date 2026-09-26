package kr.sbomsight;

import kr.sbomsight.domain.*;
import kr.sbomsight.repo.AssetRepository;
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
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * <b>조치 화면도 보고서와 같은 말로 — 완료 · 탐지 남음.</b>
 *
 * <p>보고서 5장 · 구역 보고서 6장은 완료로 닫았는데 최신 검사에 해소 건수가
 * 남은 조치를 `완료 · 탐지 남음` 으로 따로 센다. 조치 화면은 같은 조치를 그냥
 * `완료` 로 적고 줄을 흐리게 그렸다 — 보고서가 "남았다" 고 한 조치가 조치
 * 화면에서는 끝난 일로 보였다. 조치 목록 · 검토 결과 탭 · 조치 상세 · 자산의
 * 조치 탭 · 취약점 표 · 조치 CSV 가 보고서와 <b>같은 규칙</b>으로 가른다:
 * 해소 건수 = 수정 버전이 있는 탐지, 해당 없음 · 오탐은 뺀다, 자산의 최신
 * 완료 검사에서.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class DoneRemainingScreenTest {

    @Autowired MockMvc mvc;
    @Autowired ReportService reports;
    @Autowired ZoneReportService zoneReports;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired RemediationRepository remediations;
    @Autowired FindingAnalysisService analyses;
    @Autowired ZoneService zoneService;

    private Zone zone;
    private Asset asset;
    private Scan latest;
    private final Map<String, Remediation> byPackage = new HashMap<>();

    @BeforeEach
    void setUp() {
        zone = zoneService.create("탐지남음-" + System.nanoTime(), "#123456", "");
        asset = new Asset();
        asset.setName("left-" + System.nanoTime());
        asset.setZone(zone);
        assets.saveAndFlush(asset);

        // 지난 검사에만 있던 것 — 최신 검사가 기준이다.
        Scan older = scan(Instant.now().minus(2, ChronoUnit.DAYS));
        finding(older, "CVE-2099-10", "pg-older", "fixed");

        latest = scan(Instant.now());
        finding(latest, "CVE-2099-1", "pg-done", "fixed");
        finding(latest, "CVE-2099-2", "pg-done", "fixed");
        finding(latest, "CVE-2099-3", "pg-done", "fixed");
        finding(latest, "CVE-2099-4", "pg-done", "not-fixed");
        finding(latest, "CVE-2099-5", "pg-nofix", "not-fixed");   // 올려서 해소될 것이 없다
        finding(latest, "CVE-2099-6", "pg-na", "fixed");          // 해당 없음으로 뺀다
        finding(latest, "CVE-2099-7", "pg-open", "fixed");
        latest.setFindingCount(7);
        scans.saveAndFlush(latest);

        analyses.record(asset, "CVE-2099-6", "pg-na", AnalysisState.NOT_AFFECTED,
                        AnalysisJustification.CODE_NOT_PRESENT, null, "시험", "", "", null, "tester");
        analyses.record(asset, "CVE-2099-1", "pg-done", AnalysisState.IN_TRIAGE,
                        null, null, "보는 중", "", "", null, "tester");

        for (String pkg : new String[]{"pg-done", "pg-nofix", "pg-na", "pg-older"}) {
            remediation(pkg, RemediationStatus.DONE);
        }
        remediation("pg-open", RemediationStatus.OPEN);
    }

    private Scan scan(Instant at) {
        Scan s = new Scan(asset, "tester");
        s.setStatus(ScanStatus.DONE);
        s.setCreatedAt(at);
        return scans.saveAndFlush(s);
    }

    private void finding(Scan scan, String cve, String pkg, String fixState) {
        Finding f = new Finding(scan, cve + "|" + pkg, cve, pkg);
        f.setPackageVersion("1.0");
        f.setSeverity("High");
        f.setFixState(fixState);
        f.setFixedVersion("fixed".equals(fixState) ? "1.1" : "");
        findings.saveAndFlush(f);
    }

    private void remediation(String pkg, RemediationStatus status) {
        Remediation r = new Remediation(asset, pkg, "tester");
        r.moveTo(RemediationStatus.OPEN, "tester", "조치 등록");
        if (status != RemediationStatus.OPEN) {
            r.moveTo(status, "tester", "");
        }
        byPackage.put(pkg, remediations.saveAndFlush(r));
    }

    @Test
    @DisplayName("보고서가 `완료 · 탐지 남음` 으로 센 조치를 조치 화면들도 같은 말로 적는다")
    void everyScreenSaysWhatTheReportSays() throws Exception {
        // 기준: 두 보고서가 센 것 — pg-done 하나.
        ReportService.Progress asset5 = reports.build(latest).progress();
        assertThat(asset5.tracking()).filteredOn(ReportService.TrackedRow::isDoneRemaining)
                .extracting(t -> t.remediation().getPackageName()).containsExactly("pg-done");
        LocalDate today = LocalDate.now();
        assertThat(zoneReports.build(zone.getId(), today.minusDays(1), today.plusDays(1))
                              .action().doneRemaining()).isEqualTo(1);

        Remediation done = byPackage.get("pg-done");
        String label = "완료 · 탐지 남음";

        // 조치 목록 — 그 줄만, 흐리게 그리지 않는다.
        String list = open("/actions?zone=" + zone.getId());
        assertThat(count(list, label)).isEqualTo(1);
        assertThat(row(list, "href=\"/actions/" + done.getId() + "\"")).contains(label).doesNotContain("opacity");
        for (String pkg : new String[]{"pg-nofix", "pg-na", "pg-older"}) {
            assertThat(row(list, "href=\"/actions/" + byPackage.get(pkg).getId() + "\""))
                    .as(pkg).doesNotContain(label).contains("opacity");
        }

        // 자산의 조치 탭
        assertThat(count(open("/assets/" + asset.getId() + "?tab=actions"), label)).isEqualTo(1);

        // 조치 상세 — 남은 해소 건수까지. 해당 없음으로 뺀 것 · 수정 버전 없는 것은 아니다.
        assertThat(open("/actions/" + done.getId())).contains(label + " — 해소 건수 3건");
        assertThat(open("/actions/" + byPackage.get("pg-nofix").getId())).doesNotContain(label);
        assertThat(open("/actions/" + byPackage.get("pg-na").getId())).doesNotContain(label);

        // 검토 결과 탭의 조치 칸
        assertThat(open("/actions?tab=analyses&zone=" + zone.getId())).contains(">" + label + "</a>");

        // 취약점 표의 조치 칸 — pg-done 의 네 줄(수정 버전 없는 줄도 같은 조치를 가리킨다)
        String vulns = open("/assets/" + asset.getId() + "?tab=vulns");
        assertThat(count(vulns, ">" + label + "</a>")).isEqualTo(4);
        assertThat(vulns).contains(">완료</a>");   // pg-nofix

        // 조치 CSV — 화면과 같은 말
        String csv = open("/actions/export.csv?zone=" + zone.getId());
        assertThat(csv).contains("\"pg-done\"").contains("\"" + label + "\"");
        assertThat(count(csv, label)).isEqualTo(1);
    }

    private String open(String url) throws Exception {
        return mvc.perform(get(url).with(user("tester").roles("ADMIN")))
                  .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    /** {@code marker} 가 든 표 줄 하나. */
    private static String row(String html, String marker) {
        int at = html.indexOf(marker);
        assertThat(at).as(marker + " 가 없다").isNotNegative();
        int start = html.lastIndexOf("<tr", at);
        return html.substring(start, html.indexOf("</tr>", at));
    }

    private static int count(String text, String needle) {
        int n = 0;
        for (int i = text.indexOf(needle); i >= 0; i = text.indexOf(needle, i + needle.length())) {
            n++;
        }
        return n;
    }
}
