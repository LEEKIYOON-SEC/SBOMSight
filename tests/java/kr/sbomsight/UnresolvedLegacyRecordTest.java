package kr.sbomsight;

import kr.sbomsight.domain.*;
import kr.sbomsight.repo.*;
import kr.sbomsight.service.FindingAnalysisService;
import kr.sbomsight.service.RemediationService;
import kr.sbomsight.service.ReportService;
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

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * <b>V24 가 어느 패키지의 것인지 가르지 못한 옛 기록</b>(식별자가 빈 검토 결과 · 조치).
 *
 * <p>같은 자산에 groupId 만 다른 dom4j 둘이 같은 번호에 걸렸다. 옛 앱은 이름으로 적어 그 검토
 * 결과가 둘 다를 목록에서 뺐고, 조치는 둘의 탐지를 함께 셌다. 어느 쪽에 적은 것인지 가를 근거가
 * 없어 V24 는 식별자를 비운다(tests/check-migrations.sh 가 SQL 을 본다). 여기서는 그렇게 비운
 * 기록을 앱이 어떻게 다루는지 본다.
 *
 * <ul>
 *   <li>어느 탐지에도 붙지 않는다 — 목록 · 빠진 건수 · 표의 검토 칸 · 보고서 1 · 5장.</li>
 *   <li>지우지 않고 보인다 — 대응 화면 · CSV 에 `패키지 확인 필요`.</li>
 *   <li>고쳐도 아무 탐지에도 닿지 않으므로 고치지 않는다 — 그 패키지의 탐지에서 새로 적는다.
 *       새로 적은 것 · 새로 연 조치는 옛 기록과 따로 선다.</li>
 * </ul>
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class UnresolvedLegacyRecordTest {

    static final String OLD = "pkg:maven/dom4j/dom4j";
    static final String NEW = "pkg:maven/org.dom4j/dom4j";

    @Autowired MockMvc mvc;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired FindingAnalysisRepository analysisRows;
    @Autowired RemediationRepository remediations;
    @Autowired FindingAnalysisService analyses;
    @Autowired RemediationService remediationService;
    @Autowired ReportService reports;
    @Autowired ZoneService zoneService;

    private Asset asset;
    private Scan scan;
    private FindingAnalysis legacyReview;
    private Remediation legacyRemediation;

    @BeforeEach
    void setUp() {
        asset = new Asset();
        asset.setName("legacy-" + System.nanoTime());
        asset.setZone(zoneService.create("옛기록-" + System.nanoTime(), "", ""));
        assets.saveAndFlush(asset);
        scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        scan.setCreatedAt(Instant.now());
        scans.saveAndFlush(scan);
        finding("pkg:maven/dom4j/dom4j@1.6.1");
        finding("pkg:maven/org.dom4j/dom4j@2.1.1");

        // V24 가 비운 그대로 — 이름은 있고 식별자는 없다.
        legacyReview = new FindingAnalysis(asset, "CVE-2020-10683", "dom4j", null);
        legacyReview.setState(AnalysisState.NOT_AFFECTED);
        legacyReview.setJustification(AnalysisJustification.CODE_NOT_REACHABLE);
        legacyReview.setUpdatedBy("tester");
        analysisRows.saveAndFlush(legacyReview);
        legacyRemediation = remediations.saveAndFlush(new Remediation(asset, "dom4j", null, "tester"));
    }

    @Test
    @DisplayName("어느 탐지에도 붙지 않는다 — 목록 · 빠진 건수 · 표의 규칙 · 보고서 1 · 5장")
    void itAppliesToNoFinding() {
        assertThat(findings.findInBySeverity(List.of(scan.getId()), null, null, null, null, null,
                                             false, false, PageRequest.of(0, 10)).getContent())
                .as("가르지 못한 해당 없음이 두 dom4j 중 하나라도 목록에서 뺐다")
                .extracting(Finding::getPackageKey).containsExactlyInAnyOrder(OLD, NEW);
        assertThat(findings.countReviewedOut(List.of(scan.getId()), null, null, null, null, null, null)).isZero();

        Map<String, FindingAnalysis> byAssetKey = analyses.byAssetKey(List.of(asset.getId()));
        assertThat(byAssetKey).isEmpty();
        // 옛 조치는 제 칸(`자산|#번호`)에 선다 — 목록에서 사라지지 않되 탐지 줄의 키에는 걸리지 않는다.
        assertThat(remediationService.byAssetPackage(List.of(asset.getId())))
                .containsOnlyKeys(asset.getId() + "|#" + legacyRemediation.getId());

        ReportService.Report report = reports.build(scan);
        assertThat(report.overview().excludedByAnalysis()).isZero();
        assertThat(report.progress().rows())
                .extracting(r -> r.action().packageKey(), ReportService.ActionRow::isTracked)
                .containsExactlyInAnyOrder(org.assertj.core.groups.Tuple.tuple(OLD, false),
                                           org.assertj.core.groups.Tuple.tuple(NEW, false));
        // 셀 패키지가 없다 — 0 이라 하면 다 고친 것으로 읽힌다.
        assertThat(remediationService.remainingCounts(asset.getId(), scan))
                .containsEntry(legacyRemediation.getId(), -1L);
    }

    @Test
    @DisplayName("지우지 않고 보인다 — 대응 화면 두 탭 · 두 CSV 에 `패키지 확인 필요`")
    void itStaysVisible() throws Exception {
        String reviewsTab = page("/actions?tab=analyses&includeDone=true");
        assertThat(reviewsTab).contains("패키지 확인 필요").contains("※ 패키지 확인 필요 1건");
        String actionsTab = page("/actions");
        assertThat(actionsTab).contains("패키지 확인 필요").contains("※ 패키지 확인 필요 1건");
        assertThat(page("/analyses/" + legacyReview.getId())).contains("어느 탐지에도 적용되지 않음");

        assertThat(page("/actions/export.csv?tab=analyses&includeDone=true"))
                .contains("\"CVE-2020-10683\"").contains("\"dom4j\",\"패키지 확인 필요\"");
        assertThat(page("/actions/export.csv")).contains("\"dom4j\",\"패키지 확인 필요\"");
    }

    @Test
    @DisplayName("고치지 않는다 — 탐지에서 새로 적은 것 · 새로 연 조치는 옛 기록과 따로 선다")
    void newRecordsStandApart() throws Exception {
        // 상세의 고치기가 보내는 꼴(탐지 번호 없음) — 식별자가 비었다.
        mvc.perform(post("/analyses").with(admin()).with(csrf())
                            .param("assetId", asset.getId().toString())
                            .param("cve", "CVE-2020-10683").param("packageKey", "")
                            .param("state", "EXPLOITABLE"))
           .andExpect(status().is3xxRedirection())
           .andExpect(flash().attributeExists("error"));
        assertThat(analysisRows.findById(legacyReview.getId()).orElseThrow().getState())
                .isEqualTo(AnalysisState.NOT_AFFECTED);

        // 그 패키지의 탐지 줄에서 — org.dom4j 쪽에만.
        Finding chosen = findings.findByScanIdAndPackageKeyOrderByCvssScoreDesc(scan.getId(), NEW).get(0);
        mvc.perform(post("/analyses").with(admin()).with(csrf())
                            .param("assetId", asset.getId().toString())
                            .param("findingId", chosen.getId().toString())
                            .param("cve", chosen.getDisplayId()).param("packageKey", NEW)
                            .param("state", "NOT_AFFECTED").param("justification", "CODE_NOT_REACHABLE"))
           .andExpect(status().is3xxRedirection())
           .andExpect(flash().attributeExists("message"));
        assertThat(analysisRows.findByAsset(asset.getId()))
                .extracting(FindingAnalysis::getPackageKey).containsExactlyInAnyOrder(null, NEW);
        assertThat(findings.findInBySeverity(List.of(scan.getId()), null, null, null, null, null,
                                             false, false, PageRequest.of(0, 10)).getContent())
                .extracting(Finding::getPackageKey).containsExactly(OLD);

        mvc.perform(post("/assets/" + asset.getId() + "/remediations").with(admin()).with(csrf())
                            .param("packageKey", OLD).param("packageName", "dom4j"))
           .andExpect(status().is3xxRedirection());
        Remediation opened = remediations.findLatest(asset.getId(), OLD).orElseThrow();
        assertThat(opened.getId()).as("옛 조치를 이어받지 않고 새로 연다").isNotEqualTo(legacyRemediation.getId());
        assertThat(opened.getRoundNo()).isEqualTo(1);
        assertThat(opened.getFromVersions()).containsExactly("1.6.1");
        assertThat(RemediationService.latestPerPackage(remediations.findByAssets(List.of(asset.getId()))))
                .as("옛 조치와 새 조치가 한 칸에 모여 하나가 사라졌다").hasSize(2);
    }

    // -----------------------------------------------------------------------

    private void finding(String purl) {
        Finding f = new Finding(scan, "GHSA-hwj3-m3p6-hj38|" + purl, "GHSA-hwj3-m3p6-hj38", "dom4j");
        f.setRelatedCve("CVE-2020-10683");
        f.setPackageVersion(purl.substring(purl.indexOf('@') + 1));
        f.setPackageType("java-archive");
        f.setPackagePurl(purl);
        f.setSeverity("Critical");
        f.setFixState("fixed");
        f.setFixedVersion("2.1.3");
        findings.saveAndFlush(f);
        scan.setFindingCount(scan.getFindingCount() + 1);
        scans.saveAndFlush(scan);
    }

    private String page(String url) throws Exception {
        return mvc.perform(get(url).with(admin()))
                  .andExpect(status().isOk())
                  .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    private static org.springframework.test.web.servlet.request.RequestPostProcessor admin() {
        return user("tester").roles("ADMIN");
    }
}
