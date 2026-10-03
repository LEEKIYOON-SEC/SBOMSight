package kr.sbomsight;

import kr.sbomsight.domain.*;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.FindingAnalysisRepository;
import kr.sbomsight.repo.FindingRepository;
import kr.sbomsight.repo.ScanRepository;
import kr.sbomsight.service.FindingAnalysisService;
import kr.sbomsight.service.ReportService;
import kr.sbomsight.service.Reviewed;
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
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * <b>취약점 번호 규칙은 하나다</b>(R6) — 탐지의 주 식별자나 함께 온 CVE 와 같은 번호로
 * 적힌 검토 결과가 그 탐지의 것이고, 그런 행이 둘이면 <b>나중에 고친 것</b>이다(D4).
 *
 * <p>앞서 찾는 순서가 두 벌이었다. 표는 CVE 번호를 먼저 찾고, 서비스 · SQL 은 주
 * 식별자(GHSA)를 먼저 찾았다. 저장은 보낸 번호로만 찾아 없으면 새 행을 만들었다.
 * 그래서 GHSA 로만 오던 탐지에 나중에 CVE 가 붙고 표에서 고치면 행이 둘로 갈렸고
 * (재현 시험 P3), 고친 결정(해당됨)은 표에만 보이고 목록 · 보고서는 옛 결정(해당
 * 없음)으로 그 건을 뺐다.
 *
 * <p>보고서 6장 · 구역 7장의 증감 대조도 주 식별자 하나로 맞대어, 같은 취약점의 주
 * 식별자가 바뀌면 "해소 1 + 신규 1" 로 갈렸다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AnalysisIdentifierTest {

    @Autowired MockMvc mvc;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired FindingAnalysisRepository analysisRows;
    @Autowired FindingAnalysisService analyses;
    @Autowired ReportService reports;
    @Autowired ZoneReportService zoneReports;
    @Autowired ZoneService zoneService;

    private Zone zone;
    private Asset asset;

    @BeforeEach
    void setUp() {
        zone = zoneService.create("번호-" + System.nanoTime(), "", "");
        asset = asset("ids");
    }

    private Asset asset(String name) {
        Asset a = new Asset();
        a.setName(name + "-" + System.nanoTime());
        a.setZone(zone);
        return assets.saveAndFlush(a);
    }

    private Scan done(Asset a, Instant at) {
        Scan s = new Scan(a, "tester");
        s.setCreatedAt(at);
        s.setStatus(ScanStatus.DONE);
        return scans.saveAndFlush(s);
    }

    private Finding finding(Scan s, String cve, String related, String pkg) {
        Finding f = new Finding(s, cve + "|" + pkg + "|1.0", cve, pkg);
        f.setRelatedCve(related);
        f.setPackageVersion("1.0");
        f.setSeverity("High");
        f.setFixState("fixed");
        f.setFixedVersion("1.1");
        Finding saved = findings.saveAndFlush(f);
        s.setFindingCount(s.getFindingCount() + 1);
        scans.saveAndFlush(s);
        return saved;
    }

    /** 표 · CVE 상세의 `작성`/`수정` 이 보내는 것 — 탐지 번호와 화면에 찍는 번호. */
    private MockHttpServletRequestBuilder recordFor(Asset a, Finding f, String state) {
        return post("/analyses").with(user("tester").roles("ADMIN")).with(csrf())
                .param("assetId", a.getId().toString())
                .param("findingId", f.getId().toString())
                .param("cve", f.getDisplayId())
                .param("packageName", f.getPackageName())
                .param("state", state);
    }

    /** 이미 둘로 갈린 행을 만든다 — 앞서 그렇게 쌓였다(V11 이 옮긴 행 · 표에서 고친 행). */
    private FindingAnalysis row(String cve, String pkg, AnalysisState state, Instant updatedAt) {
        FindingAnalysis a = analyses.record(asset, cve, pkg, state,
                state == AnalysisState.NOT_AFFECTED ? AnalysisJustification.CODE_NOT_PRESENT : null,
                null, "시험", "", "", null, "tester");
        a.setUpdatedAt(updatedAt);
        return analysisRows.saveAndFlush(a);
    }

    private List<FindingAnalysis> rowsOf(String pkg) {
        return analysisRows.findByAsset(asset.getId()).stream()
                .filter(a -> a.getPackageName().equals(pkg)).toList();
    }

    private Set<String> listed(Scan s) {
        return findings.findInBySeverity(List.of(s.getId()), null, null, null, null,
                                         false, false, PageRequest.of(0, 100))
                       .stream().map(Finding::getPackageName).collect(Collectors.toSet());
    }

    private String open(String url) throws Exception {
        return mvc.perform(get(url).with(user("tester").roles("ADMIN")))
                  .andExpect(status().isOk())
                  .andReturn().getResponse().getContentAsString();
    }

    // --- 저장 ---------------------------------------------------------------------

    @Test
    @DisplayName("GHSA 로 적은 뒤 CVE 가 붙어도, 표에서 고치면 같은 행을 고친다 — 둘로 갈리지 않는다")
    void editingAfterTheCveArrivesKeepsOneRow() throws Exception {
        Instant now = Instant.now();
        Scan s1 = done(asset, now.minus(10, ChronoUnit.DAYS));
        Finding before = finding(s1, "GHSA-p3aa-bbbb-cccc", "", "lodash");
        mvc.perform(recordFor(asset, before, "NOT_AFFECTED").param("justification", "CODE_NOT_REACHABLE"))
           .andExpect(status().is3xxRedirection());

        // 새 결과에는 CVE 가 함께 온다 — 표가 크게 찍는 번호가 CVE 로 바뀐다.
        Scan s2 = done(asset, now);
        Finding after = finding(s2, "GHSA-p3aa-bbbb-cccc", "CVE-2025-9999", "lodash");
        assertThat(after.getDisplayId()).isEqualTo("CVE-2025-9999");
        mvc.perform(recordFor(asset, after, "EXPLOITABLE").param("response", "UPDATE"))
           .andExpect(status().is3xxRedirection());

        List<FindingAnalysis> rows = rowsOf("lodash");
        assertThat(rows).as("같은 취약점의 검토 결과가 둘로 갈렸다").hasSize(1);
        FindingAnalysis only = rows.get(0);
        assertThat(only.getState()).isEqualTo(AnalysisState.EXPLOITABLE);
        assertThat(only.getCve()).as("있던 행을 고친다 — 번호를 바꿔 새로 만들지 않는다")
                                 .isEqualTo("GHSA-p3aa-bbbb-cccc");
        assertThat(analysisRows.findDetail(only.getId()).orElseThrow().getEvents())
                .extracting(FindingAnalysisEvent::getAfter)
                .as("두 번 적은 것이 한 행의 이력에 차례로 남는다")
                .contains("해당 없음", "해당됨");

        // 목록 · 보고서가 고친 결정을 말한다 — 옛 결정(해당 없음)으로 빼지 않는다.
        assertThat(listed(s2)).contains("lodash");
        ReportService.Report report = reports.build(scans.findWithAsset(s2.getId()).orElseThrow());
        assertThat(report.summary().reviewOf(AnalysisState.EXPLOITABLE)).isEqualTo(1);
        assertThat(report.summary().reviewOf(AnalysisState.NOT_AFFECTED)).isZero();
        assertThat(report.overview().excludedByAnalysis()).isZero();
    }

    @Test
    @DisplayName("탐지 번호가 다른 자산 · 다른 패키지의 것이면 적지 않는다")
    void refusesAFindingThatIsNotThisRow() throws Exception {
        Asset other = asset("ids-other");
        Finding theirs = finding(done(other, Instant.now()), "CVE-2025-1111", "", "openssl");

        mvc.perform(recordFor(asset, theirs, "NOT_AFFECTED").param("justification", "CODE_NOT_PRESENT"))
           .andExpect(status().is3xxRedirection())
           .andExpect(flash().attributeExists("error"));
        assertThat(analysisRows.findByAsset(asset.getId())).as("남의 탐지로 이 자산에 적혔다").isEmpty();
        assertThat(analysisRows.findByAsset(other.getId())).as("보낸 자산이 아닌 곳에 적혔다").isEmpty();

        Finding mine = finding(done(asset, Instant.now()), "CVE-2025-2222", "", "zlib");
        mvc.perform(post("/analyses").with(user("tester").roles("ADMIN")).with(csrf())
                            .param("assetId", asset.getId().toString())
                            .param("findingId", mine.getId().toString())
                            .param("cve", mine.getDisplayId())
                            .param("packageName", "openssl")
                            .param("state", "NOT_AFFECTED").param("justification", "CODE_NOT_PRESENT"))
           .andExpect(status().is3xxRedirection())
           .andExpect(flash().attributeExists("error"));
        assertThat(analysisRows.findByAsset(asset.getId())).as("패키지가 다른데 적혔다").isEmpty();
    }

    // --- 읽기 ---------------------------------------------------------------------

    @Test
    @DisplayName("이미 둘로 갈린 행은 나중에 고친 것을 따른다 — 목록 · 보고서 · 표가 같은 것을 말한다")
    void splitRowsFollowTheLaterEdit() throws Exception {
        Instant now = Instant.now();
        // 주 식별자 쪽이 옛 결정, CVE 쪽이 나중 결정
        row("GHSA-aaaa-1111-0001", "pkg-a", AnalysisState.NOT_AFFECTED, now.minus(2, ChronoUnit.HOURS));
        row("CVE-2025-0001", "pkg-a", AnalysisState.EXPLOITABLE, now.minus(1, ChronoUnit.HOURS));
        // CVE 쪽이 옛 결정, 주 식별자 쪽이 나중 결정
        row("CVE-2025-0002", "pkg-b", AnalysisState.NOT_AFFECTED, now.minus(2, ChronoUnit.HOURS));
        row("GHSA-bbbb-2222-0002", "pkg-b", AnalysisState.EXPLOITABLE, now.minus(1, ChronoUnit.HOURS));

        Scan s = done(asset, now);
        finding(s, "GHSA-aaaa-1111-0001", "CVE-2025-0001", "pkg-a");
        finding(s, "GHSA-bbbb-2222-0002", "CVE-2025-0002", "pkg-b");

        assertThat(listed(s)).as("목록(SQL)이 옛 결정으로 뺐다").containsExactlyInAnyOrder("pkg-a", "pkg-b");
        assertThat(findings.countReviewedOut(List.of(s.getId()), null, null, null, null, null)).isZero();

        ReportService.Report report = reports.build(scans.findWithAsset(s.getId()).orElseThrow());
        assertThat(report.summary().reviewOf(AnalysisState.EXPLOITABLE))
                .as("보고서 2.4 가 옛 결정을 센다").isEqualTo(2);
        assertThat(report.summary().reviewOf(AnalysisState.NOT_AFFECTED)).isZero();

        // 표 — 적기 단추에 실린 값이 그 행이 고른 검토 결과다.
        String table = open("/vulns?scan=" + s.getId() + "&includeDone=true");
        assertThat(table).as("표가 옛 결정을 보여 준다")
                         .doesNotContain("data-state=\"NOT_AFFECTED\"");
        assertThat(table.split("data-state=\"EXPLOITABLE\"", -1).length - 1).isEqualTo(2);

        // CVE 상세도 같은 조각 · 같은 규칙.
        String detail = open("/vulns/CVE-2025-0002?includeDone=true");
        assertThat(detail).contains("data-state=\"EXPLOITABLE\"")
                          .doesNotContain("data-state=\"NOT_AFFECTED\"");
    }

    @Test
    @DisplayName("묶어 보는 화면의 `검토 n/N` 도 표와 같은 행을 본다")
    void groupedCountsUseTheSameRow() throws Exception {
        Instant now = Instant.now();
        // 옛 행은 검토 중, 나중 행은 손대지 않은 상태(미검토 · 대응 없음)로 되돌렸다.
        row("GHSA-cccc-3333-0003", "pkg-c", AnalysisState.IN_TRIAGE, now.minus(2, ChronoUnit.HOURS));
        row("CVE-2025-0003", "pkg-c", AnalysisState.NOT_SET, now.minus(1, ChronoUnit.HOURS));
        Scan s = done(asset, now);
        finding(s, "GHSA-cccc-3333-0003", "CVE-2025-0003", "pkg-c");

        String table = open("/vulns?scan=" + s.getId());
        assertThat(table).as("표는 나중 행(미검토)을 보여 준다").doesNotContain("data-state=\"IN_TRIAGE\"");

        @SuppressWarnings("unchecked")
        Map<String, Reviewed> byCve = (Map<String, Reviewed>) mvc
                .perform(get("/vulns?scan=" + s.getId() + "&group=cve").with(user("tester").roles("ADMIN")))
                .andReturn().getModelAndView().getModel().get("reviewed");
        assertThat(byCve.get("CVE-2025-0003"))
                .as("표는 `작성` 인데 묶은 줄은 `검토됨` 으로 센다")
                .isEqualTo(new Reviewed(0, 1));
    }

    // --- 증감 대조 ----------------------------------------------------------------

    @Test
    @DisplayName("주 식별자가 바뀐 같은 취약점은 `유지` 다 — 해소 1 + 신규 1 로 갈리지 않는다(보고서 6장)")
    void theScanDiffFollowsTheSameRule() {
        Instant now = Instant.now();
        Scan s1 = done(asset, now.minus(10, ChronoUnit.DAYS));
        finding(s1, "CVE-2024-1111", "", "libx");        // 같은 취약점 — 그때는 CVE 로
        finding(s1, "CVE-2024-0000", "", "libz");        // 사라진 것
        Scan s2 = done(asset, now);
        finding(s2, "GHSA-xxxx-yyyy-zzzz", "CVE-2024-1111", "libx");   // 지금은 GHSA 로
        finding(s2, "CVE-2024-2222", "", "liby");        // 새로 생긴 것

        ReportService.Diff diff = reports.build(scans.findWithAsset(s2.getId()).orElseThrow())
                                         .targets().diff();
        assertThat(diff.previous().getId()).isEqualTo(s1.getId());
        assertThat(List.of(diff.added(), diff.resolved(), diff.kept()))
                .as("신규 · 해소 · 유지").containsExactly(1L, 1L, 1L);
    }

    @Test
    @DisplayName("구역 보고서 7장(기간 시작 대비)도 같은 규칙으로 맞댄다")
    void theZoneMovementFollowsTheSameRule() {
        Instant now = Instant.now();
        Scan s1 = done(asset, now.minus(10, ChronoUnit.DAYS));
        finding(s1, "CVE-2024-1111", "", "libx");
        finding(s1, "CVE-2024-0000", "", "libz");
        Scan s2 = done(asset, now);
        finding(s2, "GHSA-xxxx-yyyy-zzzz", "CVE-2024-1111", "libx");
        finding(s2, "CVE-2024-2222", "", "liby");

        LocalDate today = LocalDate.now();
        ZoneReportService.Movement movement = zoneReports.build(zone.getId(), today.minusDays(1), today.plusDays(1))
                                                         .judgement().movement();
        assertThat(movement.assetsCompared()).isEqualTo(1);
        assertThat(List.of(movement.added(), movement.resolved(), movement.kept()))
                .as("신규 · 해소 · 유지").containsExactly(1L, 1L, 1L);
    }
}
