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
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * <b>오래된 자산은 SBOM 생성 시각으로 가른다</b>(R4) — 검사가 돈 시각이 아니다.
 *
 * <p>앞서 `30일 넘은 자산` 은 마지막 검사가 돈 시각으로 셌다. 40일 전에 뜬 SBOM 을
 * 오늘 다시 검사하면 그 자산이 목록에서 빠졌다(재현 시험 P5) — 서버를 다시 본 것이
 * 아니라 옛 SBOM 을 새 취약점 DB 로 돌렸을 뿐인데. 예전에 떠 둔 SBOM 을 오늘 올려도
 * 같았다.
 */
@SpringBootTest
@AutoConfigureMockMvc
class StalenessTest {

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

    static final DateTimeFormatter WHEN =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(ZoneId.systemDefault());

    @Test
    @DisplayName("SBOM 생성 시각이 30일을 넘으면 오늘 올렸어도 30일 넘은 자산이다")
    void anOldSbomUploadedTodayIsStale() throws Exception {
        Asset asset = asset("stale-upload");
        upload(asset, minutes(Instant.now().minus(40, ChronoUnit.DAYS)));

        assertThat(page("/?filter=stale")).contains(asset.getName());
    }

    @Test
    @DisplayName("다시 검사해도 30일 넘은 자산에서 빠지지 않는다 — SBOM 은 그대로다")
    void aRescanDoesNotMakeAnAssetFresh() throws Exception {
        Asset asset = asset("stale-rescan");
        Scan scan = upload(asset, minutes(Instant.now().minus(40, ChronoUnit.DAYS)));

        mvc.perform(post("/scans/" + scan.getId() + "/rescan")
                            .with(user("tester").roles("ADMIN")).with(csrf()))
           .andExpect(status().is3xxRedirection());
        Scan copy = FakeGrype.awaitFinished(scans,
                scans.findByAssetIdOrderByCreatedAtDesc(asset.getId()).get(0).getId());
        assertThat(copy.getId()).isNotEqualTo(scan.getId());

        assertThat(page("/?filter=stale")).contains(asset.getName());
    }

    @Test
    @DisplayName("SBOM 생성 시각이 30일 안이면 30일 넘은 자산이 아니다")
    void aRecentSbomIsNotStale() throws Exception {
        Asset asset = asset("fresh");
        upload(asset, minutes(Instant.now().minus(3, ChronoUnit.DAYS)));

        assertThat(page("/?filter=stale")).doesNotContain(asset.getName());
    }

    @Test
    @DisplayName("자산 목록의 열은 SBOM 생성 시각이다 — 그 값으로 줄 세운다")
    void theListShowsAndSortsBySbomTime() throws Exception {
        Asset fresh = asset("sort-fresh");
        Asset stale = asset("sort-stale");
        Instant freshAt = minutes(Instant.now().minus(2, ChronoUnit.DAYS));
        Instant staleAt = minutes(Instant.now().minus(50, ChronoUnit.DAYS));
        upload(fresh, freshAt);
        upload(stale, staleAt);   // 나중에 올렸지만 SBOM 은 더 옛것

        String list = page("/?sort=scanned&dir=asc");
        assertThat(list).contains("SBOM 생성 시각").contains(WHEN.format(freshAt)).contains(WHEN.format(staleAt));
        assertThat(list.indexOf(stale.getName()))
                .as("SBOM 이 더 옛것이 먼저 — 올린 차례가 아니다")
                .isLessThan(list.indexOf(fresh.getName()));
    }

    @Test
    @DisplayName("자산 머리는 SBOM 생성 시각과 검사 시각을 따로 적는다")
    void theAssetHeaderShowsBothTimes() throws Exception {
        Asset asset = asset("header");
        Instant made = minutes(Instant.now().minus(12, ChronoUnit.DAYS));
        Scan scan = upload(asset, made);

        String header = page("/assets/" + asset.getId());
        assertThat(header).contains("SBOM 생성 시각").contains(WHEN.format(made))
                          .contains("검사 시각").contains(WHEN.format(scan.getCreatedAt()));
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

    private Scan upload(Asset asset, Instant sbomAt) throws Exception {
        String sbom = CurrentScanRuleTest.cyclonedx(sbomAt, "1.1.1k", CurrentScanRuleTest.V1);
        mvc.perform(multipart("/assets/" + asset.getId() + "/sbom")
                            .file(new MockMultipartFile("file", "web.cdx.json", "application/json",
                                                        sbom.getBytes(StandardCharsets.UTF_8)))
                            .with(user("tester").roles("ADMIN")).with(csrf()))
           .andExpect(status().is3xxRedirection());
        Scan scan = FakeGrype.awaitFinished(scans,
                scans.findByAssetIdOrderByCreatedAtDesc(asset.getId()).get(0).getId());
        assertThat(scan.getStatus()).as(scan.getErrorMessage()).isEqualTo(ScanStatus.DONE);
        return scan;
    }

    private String page(String url) throws Exception {
        return mvc.perform(get(url).with(user("tester").roles("ADMIN")))
                  .andExpect(status().isOk())
                  .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    private static Instant minutes(Instant at) {
        return at.truncatedTo(ChronoUnit.MINUTES);
    }
}
