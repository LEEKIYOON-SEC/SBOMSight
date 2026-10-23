package kr.sbomsight;

import kr.sbomsight.domain.Asset;
import kr.sbomsight.domain.Scan;
import kr.sbomsight.domain.ScanStatus;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.ScanRepository;
import kr.sbomsight.service.AssetService;
import kr.sbomsight.service.GrypeRunner;
import kr.sbomsight.service.ZoneService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * <b>엉뚱한 자산에 올린 SBOM 을 가린다</b> — SBOM 대상이 자산 이름과 다르면 경고한다.
 *
 * <p>syft 를 {@code dir:/} 로만 돌리면 SBOM 대상은 모든 서버에서 {@code /} 라서 무엇을
 * 떴는지 SBOM 이 말해 주지 않는다. {@code --source-name <자산 이름>} 을 주면 SBOM 안에
 * 그 이름이 남는다(syft 1.52.0 으로 확인 — CycloneDX metadata.component.name · SPDX
 * name · syft JSON source.name). 가이드가 그 명령을 내고, 올린 SBOM 의 대상이 자산
 * 이름과 다르면 알린다. <b>막지는 않는다</b> — 이미지 이름 그대로 쓰는 곳도 있다.
 */
@SpringBootTest
@AutoConfigureMockMvc
class SbomTargetTest {

    @Autowired MockMvc mvc;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired ZoneService zoneService;
    @Autowired AssetService assetService;

    @MockBean GrypeRunner grype;

    private final List<Long> made = new ArrayList<>();

    @BeforeEach
    void fakeGrype() {
        FakeGrype.on(grype);
    }

    @AfterEach
    void cleanUp() {
        made.forEach(id -> assets.findById(id).ifPresent(a -> assetService.delete(a, "tester")));
    }

    @Test
    @DisplayName("SBOM 생성 가이드는 이 자산의 이름을 --source-name 으로 넣은 명령을 낸다")
    void theGuideNamesTheAsset() throws Exception {
        Asset asset = asset("guide");
        String guide = guide(page("/assets/" + asset.getId()));
        assertThat(guide).contains("syft dir:/ --source-name " + asset.getName() + " -o cyclonedx-json")
                         .contains("syft dir:C:\\ --source-name " + asset.getName() + " -o cyclonedx-json=");
    }

    @Test
    @DisplayName("SBOM 대상이 자산 이름과 다르면 업로드 뒤에 경고한다 — 막지는 않는다")
    void aForeignTargetIsFlagged() throws Exception {
        Asset asset = asset("web-01");
        Scan scan = upload(asset, "web-02");
        assertThat(scan.getStatus()).as("막지 않는다 — 검사는 끝까지 돈다").isEqualTo(ScanStatus.DONE);

        String overview = page("/assets/" + asset.getId());
        assertThat(overview).contains("id=\"target-mismatch\"").contains("web-02");
        assertThat(docinfo(page("/reports/scan/" + scan.getId()))).contains("자산 이름과 다름");
    }

    @Test
    @DisplayName("SBOM 대상이 경로(dir:/)이거나 자산 이름과 같으면 경고하지 않는다")
    void aPathOrTheSameNameIsNotFlagged() throws Exception {
        Asset byPath = asset("path");
        Scan pathScan = upload(byPath, "/");
        assertThat(page("/assets/" + byPath.getId())).doesNotContain("id=\"target-mismatch\"");
        assertThat(docinfo(page("/reports/scan/" + pathScan.getId()))).doesNotContain("자산 이름과 다름");

        Asset byName = asset("named");
        upload(byName, byName.getName().toUpperCase());   // 대소문자만 다르다 — 같은 이름
        assertThat(page("/assets/" + byName.getId())).doesNotContain("id=\"target-mismatch\"");
    }

    // --- 씨앗 -------------------------------------------------------------------------

    private Asset asset(String prefix) {
        Asset asset = new Asset();
        asset.setName(prefix + "-" + System.nanoTime());
        asset.setZone(zoneService.unassigned());
        asset = assets.saveAndFlush(asset);
        made.add(asset.getId());
        return asset;
    }

    /** SBOM 대상이 {@code target} 인 CycloneDX — syft 1.52.0 의 짜임 그대로. */
    private Scan upload(Asset asset, String target) throws Exception {
        String sbom = SbomMetadataTest.cyclonedx(
                Instant.now().minus(1, ChronoUnit.DAYS).truncatedTo(ChronoUnit.MINUTES), target);
        mvc.perform(multipart("/assets/" + asset.getId() + "/sbom")
                            .file(new MockMultipartFile("file", "web.cdx.json", "application/json",
                                                        sbom.getBytes(StandardCharsets.UTF_8)))
                            .with(user("tester").roles("ADMIN")).with(csrf()))
           .andExpect(status().is3xxRedirection());
        return FakeGrype.awaitFinished(scans,
                scans.findByAssetIdOrderByCreatedAtDesc(asset.getId()).get(0).getId());
    }

    private String page(String url) throws Exception {
        return mvc.perform(get(url).with(user("tester").roles("ADMIN")))
                  .andExpect(status().isOk())
                  .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    /** 자산 개요의 SBOM 생성 가이드 상자만. */
    private static String guide(String page) {
        Matcher m = Pattern.compile("(?s)<summary>SBOM 생성 가이드</summary>(.*?)</details>").matcher(page);
        assertThat(m.find()).as("SBOM 생성 가이드가 없다").isTrue();
        return m.group(1).replace("&gt;", ">");
    }

    private static String docinfo(String report) {
        Matcher m = Pattern.compile("(?s)<table class=\"table docinfo\">(.*?)</table>").matcher(report);
        assertThat(m.find()).as("보고서에 문서 정보 표가 없다").isTrue();
        return m.group(1);
    }
}
