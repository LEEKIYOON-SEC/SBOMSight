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
import kr.sbomsight.service.ReportService.TrendRow;
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

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * <b>보고서가 검사 한 번 너머를 말하는가.</b>
 *
 * <p>자산 보고서 6장은 바로 앞 검사 하나와만 댔다 — 줄다가 다시 느는 것이
 * 보이지 않았다. 구역 보고서는 자산마다 기간 안의 마지막 <b>완료</b> 검사로
 * 세면서, 그 뒤에 검사가 실패했다는 것을 말하지 않았다(수가 실패 전 상태인데
 * 최신으로 읽힌다). 그리고 실패만 한 자산을 "검사 기록이 없는" 자산으로 적었다 —
 * 기록은 있고, 고칠 곳이 다르다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class ReportTrendTest {

    private static final ZoneId WALL = ZoneId.systemDefault();
    private static final DateTimeFormatter MINUTE =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(WALL);

    @Autowired MockMvc mvc;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired ZoneService zoneService;

    private Zone zone;

    @BeforeEach
    void seed() {
        zone = zoneService.create("추이-" + System.nanoTime(), "#6f7e8d", "");
    }

    // --- 자산 보고서 6장 --------------------------------------------------------

    @Test
    @DisplayName("자산 보고서 — 이 검사까지 완료 검사를 오래된 것부터, 실패한 검사와 뒤 검사는 빼고")
    void theAssetReportListsRecentDoneScans() throws Exception {
        Asset a = asset("trend");
        Instant now = Instant.now().truncatedTo(ChronoUnit.MINUTES);
        Scan first = done(a, now.minus(4, ChronoUnit.DAYS), "Critical", "Critical", "High");
        failed(a, now.minus(3, ChronoUnit.DAYS));
        Scan again = done(a, now.minus(2, ChronoUnit.DAYS), "Critical");
        again.setRescanOf(first.getId());
        scans.saveAndFlush(again);
        Scan base = done(a, now.minus(1, ChronoUnit.DAYS), "High", "High", "Low");
        Scan later = done(a, now, "Critical");

        MvcResult r = open("/reports/scan/" + base.getId());
        ReportService.Report report = (ReportService.Report) r.getModelAndView().getModel().get("report");

        assertThat(report.trend()).extracting(t -> t.scan().getId())
                .as("오래된 것부터 이 검사까지 — 실패한 검사 · 이 검사 뒤의 검사는 없다")
                .containsExactly(first.getId(), again.getId(), base.getId())
                .doesNotContain(later.getId());
        assertThat(report.trend()).extracting(TrendRow::critical).containsExactly(2L, 1L, 0L);
        assertThat(report.trend()).extracting(TrendRow::high).containsExactly(1L, 0L, 2L);
        assertThat(report.trend()).extracting(TrendRow::current).containsExactly(false, false, true);
        assertThat(report.trend().get(1).scan().getId())
                .as("끝에서 둘째 줄이 위 표의 `이전 검사` 다")
                .isEqualTo(report.targets().diff().previous().getId());

        String chapter = section(flat(html(r)), "<h2>6. ");
        assertThat(chapter).contains("<h3>최근 검사 추이</h3>");
        String table = chapter.substring(chapter.indexOf("<h3>최근 검사 추이</h3>"));
        assertThat(count(table, "<tr>")).as("머리 한 줄 + 검사 세 줄").isEqualTo(4);
        assertThat(count(table, "· 다시 검사")).isEqualTo(1);
        assertThat(count(table, "· 이번 검사")).isEqualTo(1);
        assertThat(table.indexOf(MINUTE.format(first.getCreatedAt())))
                .isNotNegative()
                .isLessThan(table.indexOf(MINUTE.format(again.getCreatedAt())));
        assertThat(table.indexOf(MINUTE.format(again.getCreatedAt())))
                .isLessThan(table.indexOf(MINUTE.format(base.getCreatedAt())));
        assertThat(table).doesNotContain(MINUTE.format(later.getCreatedAt()));
    }

    @Test
    @DisplayName("자산 보고서 — 여섯 번까지만, 가장 최근 것부터 자른다")
    void theTrendKeepsTheLatestSix() throws Exception {
        Asset a = asset("six");
        Instant now = Instant.now().truncatedTo(ChronoUnit.MINUTES);
        Scan oldest = null;
        Scan last = null;
        for (int i = 8; i >= 1; i--) {
            last = done(a, now.minus(i, ChronoUnit.DAYS), "High");
            if (oldest == null) {
                oldest = last;
            }
        }
        ReportService.Report report = (ReportService.Report)
                open("/reports/scan/" + last.getId()).getModelAndView().getModel().get("report");

        assertThat(report.trend()).hasSize(6);
        assertThat(report.trend().get(5).scan().getId()).isEqualTo(last.getId());
        assertThat(report.trend()).extracting(t -> t.scan().getId()).doesNotContain(oldest.getId());
    }

    @Test
    @DisplayName("자산 보고서 — 첫 검사면 추이 표가 없다(한 줄짜리 추이는 없다)")
    void noTrendForTheFirstScan() throws Exception {
        Asset a = asset("first");
        Instant now = Instant.now().truncatedTo(ChronoUnit.MINUTES);
        failed(a, now.minus(2, ChronoUnit.DAYS));
        Scan only = done(a, now.minus(1, ChronoUnit.DAYS), "High");

        MvcResult r = open("/reports/scan/" + only.getId());
        ReportService.Report report = (ReportService.Report) r.getModelAndView().getModel().get("report");
        assertThat(report.trend()).isEmpty();
        assertThat(html(r)).doesNotContain("최근 검사 추이").contains("이 자산의 첫 검사");
    }

    // --- 구역 보고서 ------------------------------------------------------------

    private final LocalDate from = LocalDate.of(2026, 9, 1);
    private final LocalDate to = LocalDate.of(2026, 9, 30);

    @Test
    @DisplayName("구역 보고서 — 안 돌린 자산 · 실패만 한 자산 · 완료 뒤 실패한 자산을 가른다")
    void theZoneReportSaysWhatFailed() throws Exception {
        Asset afterDone = asset("after");      // 완료 → 실패: 수는 실패 전 상태
        Scan base = done(afterDone, at(10), "Critical");
        Scan failedLater = failed(afterDone, at(20));

        Asset onlyFailed = asset("onlyfail");  // 실패만 두 번
        failed(onlyFailed, at(5));
        failed(onlyFailed, at(6));

        Asset never = asset("never");          // 이 기간에 아무것도 안 돌렸다

        Asset recovered = asset("recovered");  // 실패 → 완료: 기준 검사가 더 나중이다
        failed(recovered, at(3));
        done(recovered, at(4), "High");

        failed(asset("outside"), LocalDate.of(2026, 8, 31).atTime(LocalTime.NOON).atZone(WALL).toInstant());

        MvcResult r = open("/reports/zone?zone=" + zone.getId() + "&from=" + from + "&to=" + to);
        ZoneReportService.ZoneReport report =
                (ZoneReportService.ZoneReport) r.getModelAndView().getModel().get("report");
        ZoneReportService.Scope scope = report.scope();

        assertThat(scope.neverScanned()).extracting(Asset::getId)
                .as("기간 밖에서만 실패한 자산도 이 기간에는 돌리지 않은 자산이다")
                .containsExactlyInAnyOrder(never.getId(), assetNamed("outside").getId());
        assertThat(scope.failedOnly()).extracting(Asset::getId).containsExactly(onlyFailed.getId());
        assertThat(scope.failuresOf(onlyFailed.getId()).count()).isEqualTo(2);
        assertThat(scope.failedRuns()).as("기간 안의 실패만 — 1 + 2 + 1").isEqualTo(4);
        assertThat(scope.failedAfter(base)).isTrue();
        assertThat(scope.failedAfter(scans.findFirstByAssetIdAndStatusOrderByCreatedAtDesc(
                recovered.getId(), ScanStatus.DONE).orElseThrow()))
                .as("실패가 기준 검사 앞이면 수는 최신이다").isFalse();

        String html = flat(html(r));
        String summary = section(html, "<h2>요약</h2>");
        assertThat(summary).contains("· 검사 기록 없음 2대").contains("· 검사 모두 실패 1대");

        String scope1 = section(html, "<h2>1. ");
        assertThat(scope1)
                .contains("<td>검사 기록이 없는 자산</td>")
                .contains("<td>검사가 모두 실패한 자산</td>")
                .contains("<td>실패한 검사</td> <td class=\"num tight\">4회</td>")
                .contains("2대는 이 기간에 검사 기록이 없습니다.")
                .contains("1대는 이 기간의 검사가 모두 실패했습니다.")
                .contains(onlyFailed.getName() + "</span><span> (실패 2회)</span>");

        String rows = section(html, "<h2>3. ");
        assertThat(rows)
                .contains("이후 검사 실패 " + MINUTE.format(failedLater.getCreatedAt()))
                .contains("이 기간의 검사 2회 모두 실패")
                .contains("이 기간에 검사 없음");
        assertThat(count(rows, "이후 검사 실패")).as("실패 → 완료 자산에는 붙지 않는다").isEqualTo(1);
    }

    // --- 씨앗 · 읽기 ------------------------------------------------------------

    private Asset asset(String name) {
        Asset a = new Asset();
        a.setName(name + "-" + System.nanoTime());
        a.setZone(zone);
        return assets.saveAndFlush(a);
    }

    private Asset assetNamed(String prefix) {
        return assets.findAll().stream()
                .filter(a -> a.getZone().getId().equals(zone.getId()) && a.getName().startsWith(prefix + "-"))
                .findFirst().orElseThrow();
    }

    /** 9월 {@code day} 일 정오(벽시계). */
    private Instant at(int day) {
        return LocalDate.of(2026, 9, day).atTime(LocalTime.NOON).atZone(WALL).toInstant();
    }

    private Scan done(Asset asset, Instant when, String... severities) {
        Scan s = new Scan(asset, "tester");
        s.setStatus(ScanStatus.DONE);
        s.setSbomFilename("sbom.json");
        s.setGrypeVersion("0.87.0");
        s.setCreatedAt(when);
        scans.saveAndFlush(s);
        int n = 0;
        for (String severity : severities) {
            n++;
            Finding f = new Finding(s, "CVE-2099-3" + n + "|p" + n, "CVE-2099-3" + n, "p" + n);
            f.setPackageVersion("1.0");
            f.setSeverity(severity);
            f.setFixState("fixed");
            f.setFixedVersion("1.1");
            findings.saveAndFlush(f);
        }
        s.setFindingCount(severities.length);
        return scans.saveAndFlush(s);
    }

    private Scan failed(Asset asset, Instant when) {
        Scan s = new Scan(asset, "tester");
        s.setStatus(ScanStatus.FAILED);
        s.setSbomFilename("sbom.json");
        s.setErrorMessage("grype 가 끝나지 않음");
        s.setCreatedAt(when);
        return scans.saveAndFlush(s);
    }

    private MvcResult open(String url) throws Exception {
        MvcResult r = mvc.perform(get(url).with(user("tester").roles("ADMIN"))).andReturn();
        assertThat(r.getResponse().getStatus()).as(url).isEqualTo(200);
        return r;
    }

    private static String html(MvcResult r) throws Exception {
        return r.getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    private static String section(String html, String head) {
        int start = html.indexOf(head);
        assertThat(start).as(head + " 가 없다").isNotNegative();
        return html.substring(start, html.indexOf("</section>", start));
    }

    private static int count(String text, String needle) {
        int n = 0;
        for (int i = text.indexOf(needle); i >= 0; i = text.indexOf(needle, i + needle.length())) {
            n++;
        }
        return n;
    }

    private static String flat(String html) {
        return html.replaceAll("\\s+", " ");
    }
}
