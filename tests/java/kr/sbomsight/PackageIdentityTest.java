package kr.sbomsight;

import kr.sbomsight.domain.*;
import kr.sbomsight.repo.*;
import kr.sbomsight.service.AssetService;
import kr.sbomsight.service.FindingAnalysisService;
import kr.sbomsight.service.GrypeRunner;
import kr.sbomsight.service.PackageService;
import kr.sbomsight.service.RemediationService;
import kr.sbomsight.service.ReportService;
import kr.sbomsight.service.ZoneReportService;
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
import java.time.LocalDate;
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
 * <b>같은 이름의 다른 패키지가 서로의 검토 결과 · 조치를 가져가지 않는다</b>(V24 — 패키지 식별자).
 *
 * <p>한 자산에 이름이 같은 패키지가 둘씩 깔렸다 — npm 의 {@code semver} 와 PyPI 의 {@code semver},
 * groupId 만 다른 두 {@code jackson-databind}. 앞서 검토 결과 · 조치는 이름으로 붙어, npm 쪽에
 * 적은 `해당 없음` 이 PyPI 쪽의 같은 번호 탐지까지 목록 · 보고서에서 뺐고, 한 쪽에 연 조치가
 * 두 패키지의 탐지를 등록 당시 건수 · 버전에 넣었다.
 *
 * <p>업로드 → 뒤에서 검사 → 저장 → 검토 결과 · 조치 등록(화면이 보내는 그 요청) → 목록 · 보고서
 * · 구역 보고서 · 패키지 화면 · CSV 까지 앱의 코드가 돈다. grype 만 {@link FakeGrype} 다
 * ({@code fake-grype/sbom-same-name.json}).
 */
@SpringBootTest
@AutoConfigureMockMvc
class PackageIdentityTest {

    static final String NPM = "pkg:npm/semver";
    static final String PYPI = "pkg:pypi/semver";
    static final String FASTERXML = "pkg:maven/com.fasterxml.jackson.core/jackson-databind";
    static final String CODEHAUS = "pkg:maven/org.codehaus.jackson/jackson-databind";

    static final String SBOM = """
            {"artifacts":[
              {"name":"semver","version":"7.5.1","type":"npm","purl":"pkg:npm/semver@7.5.1"},
              {"name":"semver","version":"2.13.0","type":"python","purl":"pkg:pypi/semver@2.13.0"},
              {"name":"jackson-databind","version":"2.9.8","type":"java-archive",
               "purl":"pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.8"},
              {"name":"jackson-databind","version":"1.9.13","type":"java-archive",
               "purl":"pkg:maven/org.codehaus.jackson/jackson-databind@1.9.13"}],
             "marker":"sbom-same-name"}
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
    @Autowired ZoneReportService zoneReports;
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
        zone = zoneService.create("식별자-" + System.nanoTime(), "#6f7e8d", "");
        asset = new Asset();
        asset.setName("same-name-" + System.nanoTime());
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
    @DisplayName("탐지 · 인벤토리가 같은 식별자를 받는다 — 이름이 같아도 유형 · groupId 로 갈린다")
    void findingsAndInventoryCarryTheSameIdentifier() {
        assertThat(all()).extracting(Finding::getPackageKey, Finding::getCve)
                .containsExactlyInAnyOrder(tuple(NPM, "CVE-2099-3001"), tuple(NPM, "CVE-2099-3003"),
                                           tuple(PYPI, "CVE-2099-3001"),
                                           tuple(FASTERXML, "CVE-2099-3002"), tuple(CODEHAUS, "CVE-2099-3002"));

        // 패키지 화면 — 한 줄이 식별자 하나. 탐지 수는 제 식별자의 것만.
        Map<String, Long> rows = packages.list(zone.getId(), null, null, false, false, 0, 100)
                .rows().getContent().stream()
                .collect(Collectors.toMap(PackageService.PackageRow::packageKey,
                                          PackageService.PackageRow::findingCount));
        assertThat(rows).containsExactlyInAnyOrderEntriesOf(
                Map.of(NPM, 2L, PYPI, 1L, FASTERXML, 1L, CODEHAUS, 1L));
    }

    @Test
    @DisplayName("npm semver 에 적은 `해당 없음` 은 PyPI semver 의 같은 번호 탐지를 빼지 않는다 — 목록 · 보고서 · 검토 결과")
    void aReviewStaysWithItsPackage() throws Exception {
        Finding npm = one(NPM, "CVE-2099-3001");
        Finding pypi = one(PYPI, "CVE-2099-3001");

        // 표의 `작성` 이 보내는 그 요청 — 탐지 번호 · 화면의 번호 · 패키지 식별자.
        mvc.perform(post("/analyses").with(admin()).with(csrf())
                            .param("assetId", asset.getId().toString())
                            .param("findingId", npm.getId().toString())
                            .param("cve", npm.getDisplayId())
                            .param("packageKey", npm.getPackageKey())
                            .param("state", "NOT_AFFECTED").param("justification", "CODE_NOT_PRESENT"))
           .andExpect(status().is3xxRedirection());

        List<FindingAnalysis> written = analysisRows.findByAsset(asset.getId());
        assertThat(written).singleElement().satisfies(a -> {
            assertThat(a.getPackageKey()).isEqualTo(NPM);
            assertThat(a.getPackageName()).isEqualTo("semver");
        });

        // 목록(SQL) — npm 의 그 건만 빠진다. 빠진 건수도 그 하나.
        assertThat(listed(false)).extracting(Finding::getPackageKey, Finding::getCve)
                .contains(tuple(PYPI, "CVE-2099-3001"))
                .doesNotContain(tuple(NPM, "CVE-2099-3001"));
        assertThat(findings.countReviewedOut(List.of(scan.getId()), null, null, null, null, null, null))
                .isEqualTo(1);

        // 표 · CVE 상세가 줄마다 쓰는 규칙(자바) — 같은 식별자의 탐지에만 붙는다.
        Map<String, FindingAnalysis> byAssetKey = analyses.byAssetKey(List.of(asset.getId()));
        assertThat(FindingAnalysisService.analysisOf(byAssetKey, npm)).isNotNull();
        assertThat(FindingAnalysisService.analysisOf(byAssetKey, pypi))
                .as("npm 쪽에 적은 결정이 PyPI 쪽 탐지에 붙었다").isNull();

        // 보고서 — 2.4 · 1장의 제외는 한 건, 3장의 줄은 식별자마다 제 건수.
        ReportService.Report report = reports.build(scan);
        assertThat(report.summary().reviewOf(AnalysisState.NOT_AFFECTED)).isEqualTo(1);
        assertThat(report.overview().excludedByAnalysis()).isEqualTo(1);
        assertThat(report.targets().fixTargets())
                .extracting(ReportService.PackageAction::packageKey, ReportService.PackageAction::fixableCount,
                            ReportService.PackageAction::reachableCount)
                .contains(tuple(NPM, 1L, 0L), tuple(PYPI, 1L, 1L));

        // 구역 보고서 — 같은 규칙.
        ZoneReportService.ZoneReport zoned = zoneReports.build(zone.getId(), LocalDate.now().minusDays(1),
                                                               LocalDate.now().plusDays(1));
        assertThat(zoned.aggregate().excludedFromLists()).isEqualTo(1);
        assertThat(zoned.judgement().actions())
                .extracting(ZoneReportService.ZonePackageAction::packageKey,
                            ZoneReportService.ZonePackageAction::fixableCount)
                .contains(tuple(NPM, 1L), tuple(PYPI, 1L));

        // 항목별로 패키지 하나만(`pkg`) — 묶은 줄의 `항목별로 보기` 가 보내는 주소.
        assertThat(page("/vulns?scan=" + scan.getId() + "&pkg=" + PYPI)).contains("CVE-2099-3001");
        assertThat(page("/vulns?scan=" + scan.getId() + "&pkg=" + NPM))
                .contains("CVE-2099-3003").doesNotContain("CVE-2099-3001");
        // 패키지별 — 두 semver 가 제 식별자의 줄로 선다.
        assertThat(page("/vulns?scan=" + scan.getId() + "&group=package&includeDone=true"))
                .contains(">" + NPM + "<").contains(">" + PYPI + "<");

        // 검토 결과 상세 · 이력 — 그 패키지의 것. 최신 검사의 `이 탐지` 도 그 패키지의 건만.
        FindingAnalysis review = written.get(0);
        assertThat(analysisRows.findDetail(review.getId()).orElseThrow().getEvents()).isNotEmpty();
        assertThat(page("/analyses/" + review.getId()).replaceAll("\\s+", " "))
                .contains(NPM).contains("이 탐지 <b>1건</b>");

        // CSV — 이름 옆에 식별자. 둘이 엑셀에서 한 패키지로 읽히지 않는다.
        String csv = page("/vulns/export.csv?scan=" + scan.getId() + "&includeDone=true");
        assertThat(csv).contains("\"패키지 식별자\"").contains("\"" + NPM + "\"").contains("\"" + PYPI + "\"");
    }

    @Test
    @DisplayName("groupId 만 다른 jackson-databind — 한 쪽에 연 조치는 다른 쪽의 탐지 · 집계에 닿지 않는다")
    void aRemediationStaysWithItsPackage() throws Exception {
        // 표 · 검토 결과 탭의 `조치 등록` 이 보내는 그 요청.
        mvc.perform(post("/assets/" + asset.getId() + "/remediations").with(admin()).with(csrf())
                            .param("packageKey", FASTERXML).param("packageName", "jackson-databind"))
           .andExpect(status().is3xxRedirection());

        Remediation opened = remediations.findLatest(asset.getId(), FASTERXML).orElseThrow();
        assertThat(remediations.findLatest(asset.getId(), CODEHAUS))
                .as("다른 groupId 의 jackson-databind 에 조치가 붙었다").isEmpty();
        assertThat(opened.getFromVersions())
                .as("등록 당시 버전에 다른 패키지(1.9.13)가 들었다").containsExactly("2.9.8");
        assertThat(opened.getToVersions()).containsExactly("2.9.10.8");
        assertThat(opened.getOpenedCount()).isEqualTo(1);
        assertThat(targets.findByRemediation(opened.getId()))
                .extracting(RemediationTarget::getCve, RemediationTarget::getPackageVersion)
                .containsExactly(tuple("CVE-2099-3002", "2.9.8"));

        // 표의 `조치` 칸이 고르는 지도 — 그 식별자에만.
        assertThat(remediationService.byAssetPackage(List.of(asset.getId())))
                .containsOnlyKeys(asset.getId() + "|" + FASTERXML);

        // 보고서 5장 — 수정 버전 있는 다섯 건 중 대기 · 진행 1, 미등록 4(다른 jackson 1 · semver 3).
        ReportService.Report report = reports.build(scan);
        assertThat(report.progress().rows())
                .extracting(r -> r.action().packageKey(), ReportService.ActionRow::isTracked)
                .contains(tuple(FASTERXML, true), tuple(CODEHAUS, false));
        assertThat(report.progress().openFindings()).isEqualTo(1);
        assertThat(report.progress().untrackedFindings()).isEqualTo(4);

        // 구역 보고서 6장 — 같은 갈래.
        ZoneReportService.Action action = zoneReports.build(zone.getId(), LocalDate.now().minusDays(1),
                                                            LocalDate.now().plusDays(1)).action();
        assertThat(action.openFindings()).isEqualTo(1);
        assertThat(action.untrackedFindings()).isEqualTo(4);

        // 조치 상세 · 최신 검사의 이 패키지 탐지 수 — 그 식별자의 것만.
        assertThat(page("/actions/" + opened.getId()).replaceAll("\\s+", " "))
                .contains(FASTERXML).contains("이 패키지 탐지 <b>1건</b>");
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
    private Finding one(String packageKey, String cve) {
        return all().stream().filter(f -> f.getPackageKey().equals(packageKey) && f.getCve().equals(cve))
                    .findFirst().orElseThrow();
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
