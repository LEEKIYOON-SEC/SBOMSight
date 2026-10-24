package kr.sbomsight;

import kr.sbomsight.domain.*;
import kr.sbomsight.repo.*;
import kr.sbomsight.service.AssetService;
import kr.sbomsight.service.FindingAnalysisService;
import kr.sbomsight.service.GrypeRunner;
import kr.sbomsight.service.PackageService;
import kr.sbomsight.service.RemediationService;
import kr.sbomsight.service.ReportService;
import kr.sbomsight.service.ZoneService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.domain.PageRequest;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * <b>classifier · type 만 다른 Maven 아티팩트는 다른 패키지다</b>(V25 — 식별자에 한정자).
 *
 * <p>한 자산에 netty 의 네이티브 jar 둘(linux-x86_64 · linux-aarch_64)과 순수 jar, 그리고 같은
 * 라이브러리의 test-jar 와 jar 가 깔렸다. V24 는 purl 의 한정자를 통째로 버려 이들이 한 식별자였다 —
 * x86_64 쪽에 적은 `해당 없음` 이 aarch_64 · 순수 jar 의 같은 번호 탐지까지 목록 · 보고서에서 뺐고,
 * test-jar 에 연 조치가 jar 의 탐지를 등록 당시 건수 · 버전에 넣었다. {@code ?type=jar} 는 Maven 의
 * 기본값이라 적지 않은 것과 같은 패키지다.
 *
 * <p>업로드 → 뒤에서 검사 → 저장 → 검토 결과 · 조치 등록(화면이 보내는 그 요청) → 목록 · 보고서 ·
 * 패키지 화면까지 앱의 코드가 돈다. grype 만 {@link FakeGrype} 다({@code fake-grype/sbom-classifier.json}).
 */
@SpringBootTest
@AutoConfigureMockMvc
class PackageVariantTest {

    static final String X86 = "pkg:maven/io.netty/netty-transport-native-epoll?classifier=linux-x86_64";
    static final String AARCH = "pkg:maven/io.netty/netty-transport-native-epoll?classifier=linux-aarch_64";
    static final String PLAIN = "pkg:maven/io.netty/netty-transport-native-epoll";
    static final String TEST_JAR = "pkg:maven/org.example/qk-lib?type=test-jar";
    static final String JAR = "pkg:maven/org.example/qk-lib";

    static final String SBOM = """
            {"artifacts":[
              {"name":"netty-transport-native-epoll","version":"4.1.100.Final","type":"java-archive",
               "purl":"pkg:maven/io.netty/netty-transport-native-epoll@4.1.100.Final?classifier=linux-x86_64"},
              {"name":"netty-transport-native-epoll","version":"4.1.100.Final","type":"java-archive",
               "purl":"pkg:maven/io.netty/netty-transport-native-epoll@4.1.100.Final?classifier=linux-aarch_64"},
              {"name":"netty-transport-native-epoll","version":"4.1.100.Final","type":"java-archive",
               "purl":"pkg:maven/io.netty/netty-transport-native-epoll@4.1.100.Final"},
              {"name":"qk-lib","version":"1.0","type":"java-archive",
               "purl":"pkg:maven/org.example/qk-lib@1.0?type=test-jar"},
              {"name":"qk-lib","version":"1.0","type":"java-archive",
               "purl":"pkg:maven/org.example/qk-lib@1.0?type=jar"}],
             "marker":"sbom-classifier"}
            """;

    @Autowired MockMvc mvc;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired FindingAnalysisRepository analysisRows;
    @Autowired RemediationRepository remediations;
    @Autowired RemediationTargetRepository targets;
    @Autowired FindingAnalysisService analyses;
    @Autowired RemediationService remediationService;
    @Autowired ReportService reports;
    @Autowired PackageService packages;
    @Autowired AssetService assetService;
    @Autowired ZoneService zoneService;

    @MockBean GrypeRunner grype;

    private Zone zone;
    private Asset asset;
    private Scan scan;

    @BeforeEach
    void upload() throws Exception {
        FakeGrype.on(grype);
        zone = zoneService.create("변형-" + System.nanoTime(), "#6f7e8d", "");
        asset = new Asset();
        asset.setName("variants-" + System.nanoTime());
        asset.setZone(zone);
        assets.saveAndFlush(asset);
        mvc.perform(multipart("/assets/" + asset.getId() + "/sbom")
                            .file(new MockMultipartFile("file", "app.syft.json", "application/json",
                                                        SBOM.getBytes(StandardCharsets.UTF_8)))
                            .with(admin()).with(csrf()))
           .andExpect(status().is3xxRedirection());
        Long id = scans.findByAssetIdOrderByCreatedAtDesc(asset.getId()).get(0).getId();
        assertThat(FakeGrype.awaitFinished(scans, id).getStatus()).isEqualTo(ScanStatus.DONE);
        scan = scans.findWithAsset(id).orElseThrow();
    }

    @AfterEach
    void cleanUp() {
        // 검사가 뒤에서 돌아 트랜잭션 없이 커밋된다 — 손으로 치운다.
        assetService.delete(assets.findById(asset.getId()).orElseThrow(), "tester");
    }

    @Test
    @DisplayName("classifier · type 이 다르면 다른 식별자 — 탐지 · 패키지 화면의 줄 · 묶은 줄이 갈린다")
    void variantsAreSeparatePackages() throws Exception {
        assertThat(all()).extracting(Finding::getPackageKey)
                .containsExactlyInAnyOrder(X86, AARCH, PLAIN, TEST_JAR, JAR);

        Map<String, Long> rows = packages.list(zone.getId(), null, null, false, false, 0, 100)
                .rows().getContent().stream()
                .collect(Collectors.toMap(PackageService.PackageRow::packageKey,
                                          PackageService.PackageRow::findingCount));
        assertThat(rows).as("한정자가 다른 변형이 한 줄로 합쳐졌거나 남의 탐지를 셌다")
                .containsExactlyInAnyOrderEntriesOf(Map.of(X86, 1L, AARCH, 1L, PLAIN, 1L, TEST_JAR, 1L, JAR, 1L));

        assertThat(page("/vulns?scan=" + scan.getId() + "&group=package&includeDone=true"))
                .contains(">" + X86 + "<").contains(">" + AARCH + "<").contains(">" + PLAIN + "<")
                .contains(">" + TEST_JAR + "<").contains(">" + JAR + "<");
    }

    @Test
    @DisplayName("x86_64 네이티브에 적은 `해당 없음` 은 aarch_64 · 순수 jar 의 같은 번호 탐지를 빼지 않는다")
    void aReviewStaysWithItsVariant() throws Exception {
        Finding x86 = one(X86);
        mvc.perform(post("/analyses").with(admin()).with(csrf())
                            .param("assetId", asset.getId().toString())
                            .param("findingId", x86.getId().toString())
                            .param("cve", x86.getDisplayId())
                            .param("packageKey", x86.getPackageKey())
                            .param("state", "NOT_AFFECTED").param("justification", "CODE_NOT_REACHABLE"))
           .andExpect(status().is3xxRedirection());

        assertThat(analysisRows.findByAsset(asset.getId()))
                .extracting(FindingAnalysis::getPackageKey).containsExactly(X86);
        assertThat(listed(false)).extracting(Finding::getPackageKey)
                .as("한 변형에 적은 결정이 다른 변형의 탐지를 목록에서 뺐다")
                .containsExactlyInAnyOrder(AARCH, PLAIN, TEST_JAR, JAR);
        assertThat(findings.countReviewedOut(List.of(scan.getId()), null, null, null, null, null, null))
                .isEqualTo(1);

        Map<String, FindingAnalysis> byAssetKey = analyses.byAssetKey(List.of(asset.getId()));
        assertThat(FindingAnalysisService.analysisOf(byAssetKey, x86)).isNotNull();
        assertThat(FindingAnalysisService.analysisOf(byAssetKey, one(AARCH))).isNull();
        assertThat(FindingAnalysisService.analysisOf(byAssetKey, one(PLAIN))).isNull();

        // 보고서 — 제외는 한 건, 3장에는 남은 두 변형이 제 건수로(뺀 것만 남은 x86_64 는 줄이 없다).
        ReportService.Report report = reports.build(scan);
        assertThat(report.overview().excludedByAnalysis()).isEqualTo(1);
        assertThat(report.targets().fixTargets()).extracting(ReportService.PackageAction::packageKey)
                .doesNotContain(X86);
        assertThat(report.targets().fixTargets())
                .extracting(ReportService.PackageAction::packageKey, ReportService.PackageAction::reachableCount)
                .contains(tuple(AARCH, 1L), tuple(PLAIN, 1L));
    }

    @Test
    @DisplayName("test-jar 에 연 조치는 jar 의 탐지 · 버전 · 조치 대상에 닿지 않는다 — ?type=jar 는 jar 와 같은 패키지")
    void aRemediationStaysWithItsVariant() throws Exception {
        mvc.perform(post("/assets/" + asset.getId() + "/remediations").with(admin()).with(csrf())
                            .param("packageKey", TEST_JAR).param("packageName", "qk-lib"))
           .andExpect(status().is3xxRedirection());

        Remediation opened = remediations.findLatest(asset.getId(), TEST_JAR).orElseThrow();
        assertThat(remediations.findLatest(asset.getId(), JAR))
                .as("jar 에 test-jar 의 조치가 붙었다").isEmpty();
        assertThat(opened.getOpenedCount()).as("등록 당시 건수에 jar 의 탐지가 들었다").isEqualTo(1);
        assertThat(opened.getFromVersions()).containsExactly("1.0");
        assertThat(targets.findByRemediation(opened.getId()))
                .extracting(RemediationTarget::getCve, RemediationTarget::getPackageVersion)
                .containsExactly(tuple("CVE-2099-3102", "1.0"));
        assertThat(remediationService.byAssetPackage(List.of(asset.getId())))
                .containsOnlyKeys(asset.getId() + "|" + TEST_JAR);

        ReportService.Report report = reports.build(scan);
        assertThat(report.progress().rows())
                .extracting(r -> r.action().packageKey(), ReportService.ActionRow::isTracked)
                .contains(tuple(TEST_JAR, true), tuple(JAR, false));
    }

    // -----------------------------------------------------------------------

    private List<Finding> all() {
        return listed(true);
    }

    private List<Finding> listed(boolean includeReviewed) {
        return findings.findInBySeverity(List.of(scan.getId()), null, null, null, null, null,
                                         includeReviewed, false, PageRequest.of(0, 100)).getContent();
    }

    /** 목록 질의는 검사 · 자산을 함께 읽어 온다 — 표가 줄마다 쓰는 규칙(analysisOf)이 그것을 읽는다. */
    private Finding one(String packageKey) {
        return all().stream().filter(f -> f.getPackageKey().equals(packageKey)).findFirst().orElseThrow();
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
