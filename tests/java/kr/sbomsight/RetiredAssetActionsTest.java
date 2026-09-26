package kr.sbomsight;

import kr.sbomsight.domain.AnalysisResponse;
import kr.sbomsight.domain.AnalysisState;
import kr.sbomsight.domain.Asset;
import kr.sbomsight.domain.Finding;
import kr.sbomsight.domain.FindingAnalysis;
import kr.sbomsight.domain.Remediation;
import kr.sbomsight.domain.RemediationStatus;
import kr.sbomsight.domain.Scan;
import kr.sbomsight.domain.ScanStatus;
import kr.sbomsight.domain.Zone;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.FindingAnalysisRepository;
import kr.sbomsight.repo.FindingRepository;
import kr.sbomsight.repo.RemediationRepository;
import kr.sbomsight.repo.ScanRepository;
import kr.sbomsight.service.FindingAnalysisService;
import kr.sbomsight.service.ReportService;
import kr.sbomsight.service.ZoneService;
import kr.sbomsight.web.AssetController;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * <b>운영 종료한 자산의 조치 · 검토 결과는 현황 숫자와 대응 목록에서 빠진다.</b>
 *
 * <p>운영 종료 단추는 "목록과 현황 숫자에서 빠집니다" 라고 말하고, 자산 목록 ·
 * 취약점 · 패키지 · 보고서는 실제로 뺐다. 그런데 대응 화면(목록 · 탭 숫자 ·
 * CSV), 기둥의 `대응` 배지, 자산 목록 요약 줄의 `기한 지난 조치` ·
 * `재검토일 지난 검토 결과` 는 그 자산 것까지 셌다(B28). 띄운 앱에서 web-01 을
 * 운영 종료하니 자산 목록에서는 사라졌는데 배지 1 과 `재검토일 지난 검토 결과 1`
 * 은 그대로였다 — 누르면 목록에 없는 자산의 건으로 간다.
 *
 * <p>보려면 대응 화면의 {@code 운영 종료 자산 포함} 을 켠다(자산 목록과 같은
 * 이름 · 같은 주소 값 {@code archived=true}). 저장된 것은 바꾸지 않는다 —
 * 운영 재개하면 저절로 다시 센다.
 *
 * <p>숫자는 <b>그 자산을 운영 종료했을 때와 되살렸을 때의 차이</b>로 잰다.
 * 다른 시험이 남긴 자료가 있어도 차이는 이 자산 몫뿐이다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class RetiredAssetActionsTest {

    @Autowired MockMvc mvc;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired RemediationRepository remediations;
    @Autowired FindingAnalysisService analyses;
    @Autowired FindingAnalysisRepository analysisRepository;
    @Autowired ZoneService zoneService;

    private Zone zone;
    private Asset live;
    private Asset retired;
    private Scan retiredScan;

    @BeforeEach
    void seed() {
        // 목록은 이 구역으로 거른다 — 쪽 하나(100줄)에 다른 시험의 줄이 섞여도
        // 이 두 자산이 밀려나지 않는다. 탭 숫자는 거르기 전 전체라 차이로 잰다.
        zone = zoneService.create("운영종료-" + System.nanoTime(), "#6f7e8d", "");
        live = asset("live-");
        retired = asset("retired-");
        scanOf(live, Instant.now());
        // 운영 종료한 자산은 SBOM 이 더 올라오지 않는다 — 마지막 검사가 오래됐고
        // 그 검사의 심각 한 건이 남아 있다. 요약 줄이 이것을 세면 안 된다.
        retiredScan = scanOf(retired, Instant.now().minus(40, ChronoUnit.DAYS));
        Finding critical = new Finding(retiredScan, "CVE-2099-0002|zlib", "CVE-2099-0002", "zlib");
        critical.setSeverity("Critical");
        findings.saveAndFlush(critical);
        retiredScan.setFindingCount(1);
        retiredScan = scans.saveAndFlush(retiredScan);
        overdueRemediation(live);
        overdueRemediation(retired);
        overdueReview(live);
        overdueReview(retired);
        retire(true);
    }

    @Test
    @DisplayName("기둥의 대응 배지는 운영 종료 자산의 조치 · 검토 결과를 세지 않는다")
    void theSidebarLeavesRetiredAssetsOut() throws Exception {
        Map<String, Object> whileRetired = model("/");
        retire(false);
        Map<String, Object> whileLive = model("/");

        assertThat(number(whileLive, "navActionOverdue") - number(whileRetired, "navActionOverdue"))
                .as("운영 종료한 자산의 기한 지난 조치 · 재검토일 지난 검토 결과가 배지에 남았다")
                .isEqualTo(2);
        assertThat(number(whileLive, "navActionOpen") - number(whileRetired, "navActionOpen"))
                .as("운영 종료한 자산의 대기 조치가 배지에 남았다")
                .isEqualTo(1);
    }

    /**
     * <b>요약 줄은 현황이다 — 운영 종료 자산 포함을 켜도 운영 중인 자산만 센다.</b>
     *
     * <p>앞서(d8ede4e) 켜면 요약 줄도 운영 종료 자산까지 세게 만들었다. 그런데
     * 숫자를 누르면 가는 취약점 화면과 거른 자산 목록은 운영 종료 자산을 빼서,
     * 누른 숫자와 뜬 건수가 달랐다. 운영 종료 단추가 말하는 대로("현황 숫자에서
     * 빠집니다") 요약 줄은 언제나 운영 중인 자산만 세고, 체크는 목록에 줄을
     * 보여 줄 뿐이다. 켰을 때는 그 사실을 요약 줄이 말한다.
     */
    @Test
    @DisplayName("자산 목록 요약 줄은 운영 종료 자산 포함을 켜도 운영 중인 자산만 센다")
    void theAssetSummaryCountsOnlyAssetsInOperation() throws Exception {
        AssetController.Summary hidden = summary("/");
        AssetController.Summary toggled = summary("/?archived=true");
        retire(false);
        AssetController.Summary back = summary("/");

        // 되살리면 그 자산 몫이 늘어난다 — 운영 종료 중에는 빠져 있었다는 뜻이다.
        assertThat(back.actionOverdue() - hidden.actionOverdue()).isEqualTo(1);
        assertThat(back.reviewOverdue() - hidden.reviewOverdue()).isEqualTo(1);
        assertThat(back.critical() - hidden.critical()).isEqualTo(1);
        assertThat(back.stale() - hidden.stale()).isEqualTo(1);

        // 켜도 같다.
        assertThat(toggled)
                .as("운영 종료 자산 포함을 켜자 요약 줄이 운영 종료 자산까지 셌다 — 누르면 가는 화면은 빼고 센다")
                .isEqualTo(hidden);
    }

    @Test
    @DisplayName("요약 줄의 링크는 늘 기본 화면으로 가고, 켰을 때는 운영 중인 자산만 센 숫자라고 말한다")
    void theSummaryLinksGoToTheDefaultScreens() throws Exception {
        String on = html("/?archived=true");
        assertThat(on)
                .contains("href=\"/actions\"")
                .contains("href=\"/actions?tab=analyses\"")
                .doesNotContain("/actions?archived=true")
                .contains("운영 중인 자산만 센 숫자");

        assertThat(html("/")).doesNotContain("운영 중인 자산만 센 숫자");
    }

    @Test
    @DisplayName("대응 화면 조치 탭 — 목록 · 기한 지난 목록 · 탭 숫자에서 빼고, 체크하면 함께 보인다")
    void theRemediationTabLeavesRetiredAssetsOut() throws Exception {
        Map<String, Object> hidden = model("/actions?zone=" + zone.getId());
        Map<String, Object> shown = model("/actions?zone=" + zone.getId() + "&archived=true");

        assertThat(remediationAssets(hidden)).contains(live.getName()).doesNotContain(retired.getName());
        assertThat(overdueAssets(hidden)).contains(live.getName()).doesNotContain(retired.getName());
        assertThat(remediationAssets(shown)).contains(live.getName(), retired.getName());
        assertThat(overdueAssets(shown)).contains(live.getName(), retired.getName());

        assertThat(number(shown, "remediationCount") - number(hidden, "remediationCount"))
                .as("탭 숫자가 운영 종료 자산의 조치까지 센다")
                .isEqualTo(1);
        assertThat(number(shown, "analysisCount") - number(hidden, "analysisCount"))
                .as("다른 탭의 숫자도 같은 범위로 센다")
                .isEqualTo(1);
    }

    @Test
    @DisplayName("대응 화면 검토 결과 탭 — 목록 · 재검토일 지난 목록에서 빼고, 체크하면 함께 보인다")
    void theAnalysisTabLeavesRetiredAssetsOut() throws Exception {
        Map<String, Object> hidden = model("/actions?tab=analyses&zone=" + zone.getId());
        Map<String, Object> shown = model("/actions?tab=analyses&zone=" + zone.getId() + "&archived=true");

        assertThat(analysisAssets(hidden)).contains(live.getName()).doesNotContain(retired.getName());
        assertThat(overdueAssets(hidden)).contains(live.getName()).doesNotContain(retired.getName());
        assertThat(analysisAssets(shown)).contains(live.getName(), retired.getName());
        assertThat(overdueAssets(shown)).contains(live.getName(), retired.getName());
    }

    @Test
    @DisplayName("체크의 이름은 자산 목록과 같고, 탭 · CSV 링크가 켠 상태를 이어 간다")
    void theToggleIsNamedLikeTheAssetListAndCarried() throws Exception {
        String off = html("/actions");
        assertThat(off).contains("운영 종료 자산 포함");

        String on = html("/actions?archived=true");
        assertThat(on)
                .as("켠 채로 다른 탭으로 가면 탭 숫자와 목록의 범위가 달라진다")
                .contains("href=\"/actions?tab=analyses&amp;archived=true\"")
                .contains("/actions/export.csv?archived=true");
    }

    @Test
    @DisplayName("대응 CSV 도 같은 규칙이다")
    void theCsvFollowsTheSameRule() throws Exception {
        assertThat(csv("/actions/export.csv")).contains(live.getName()).doesNotContain(retired.getName());
        assertThat(csv("/actions/export.csv?archived=true")).contains(live.getName(), retired.getName());
        assertThat(csv("/actions/export.csv?tab=analyses"))
                .contains(live.getName()).doesNotContain(retired.getName());
        assertThat(csv("/actions/export.csv?tab=analyses&archived=true"))
                .contains(live.getName(), retired.getName());
    }

    /**
     * 운영 종료한 자산의 <b>제 보고서</b>는 그대로다. 보고서는 검토 결과 목록을
     * 대응 화면과 같은 함수로 모으므로, 그 함수의 기본값을 바꾸면 여기서
     * 조용히 빠진다.
     */
    @Test
    @DisplayName("운영 종료한 자산의 제 보고서는 그 자산의 검토 결과를 그대로 싣는다")
    void aRetiredAssetsOwnReportKeepsItsReviews() throws Exception {
        ReportService.Report report = (ReportService.Report) model("/reports/scan/" + retiredScan.getId())
                .get("report");
        assertThat(report.progress().explained())
                .extracting(a -> a.getAsset().getName())
                .contains(retired.getName());
    }

    // --- 씨앗 -------------------------------------------------------------------

    private Asset asset(String prefix) {
        Asset asset = new Asset();
        asset.setName(prefix + System.nanoTime());
        asset.setZone(zone);
        return assets.saveAndFlush(asset);
    }

    private Scan scanOf(Asset asset, Instant at) {
        Scan scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        scan.setCreatedAt(at);
        return scans.saveAndFlush(scan);
    }

    private void overdueRemediation(Asset asset) {
        Remediation r = new Remediation(asset, "openssl", "tester");
        r.moveTo(RemediationStatus.OPEN, "tester", "조치 등록");
        r.setDueDate(LocalDate.now().minusDays(1));
        remediations.saveAndFlush(r);
    }

    /** 재검토일은 오늘 이후로만 적힌다 — 날이 지나 지난 것이 된 것으로 만든다. */
    private void overdueReview(Asset asset) {
        FindingAnalysis a = analyses.record(asset, "CVE-2099-0001", "openssl",
                AnalysisState.EXPLOITABLE, null, AnalysisResponse.WILL_NOT_FIX,
                "업스트림에 수정 버전 없음", "", "", LocalDate.now().plusDays(30), "tester");
        a.setReviewBy(LocalDate.now().minusDays(1));
        analysisRepository.saveAndFlush(a);
    }

    private void retire(boolean on) {
        retired.setArchivedAt(on ? Instant.now() : null);
        retired = assets.saveAndFlush(retired);
    }

    // --- 읽기 -------------------------------------------------------------------

    private Map<String, Object> model(String url) throws Exception {
        return mvc.perform(get(url).with(user("tester").roles("ADMIN")))
                  .andExpect(status().isOk())
                  .andReturn().getModelAndView().getModel();
    }

    private String html(String url) throws Exception {
        return mvc.perform(get(url).with(user("tester").roles("ADMIN")))
                  .andExpect(status().isOk())
                  .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    private String csv(String url) throws Exception {
        return html(url);
    }

    private AssetController.Summary summary(String url) throws Exception {
        return (AssetController.Summary) model(url).get("summary");
    }

    private static long number(Map<String, Object> model, String key) {
        return ((Number) model.get(key)).longValue();
    }

    @SuppressWarnings("unchecked")
    private static List<String> remediationAssets(Map<String, Object> model) {
        return ((Page<Remediation>) model.get("remediations")).getContent().stream()
                .map(r -> r.getAsset().getName()).toList();
    }

    @SuppressWarnings("unchecked")
    private static List<String> analysisAssets(Map<String, Object> model) {
        return ((Page<FindingAnalysis>) model.get("analyses")).getContent().stream()
                .map(a -> a.getAsset().getName()).toList();
    }

    /** 맨 위 `기한이 지난 조치` · `재검토일이 지난 것` 알림에 뜨는 자산. */
    private static List<String> overdueAssets(Map<String, Object> model) {
        return ((List<?>) model.get("overdue")).stream()
                .map(o -> o instanceof Remediation r ? r.getAsset().getName()
                        : ((FindingAnalysis) o).getAsset().getName())
                .toList();
    }
}
