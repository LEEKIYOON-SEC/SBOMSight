package kr.sbomsight;

import kr.sbomsight.domain.Asset;
import kr.sbomsight.domain.Scan;
import kr.sbomsight.domain.ScanStatus;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.ComponentRepository;
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
import org.springframework.data.domain.Pageable;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

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
 * <b>자산의 최신 검사는 SBOM 생성 시각으로 고른다</b>(D1) — 검사가 돈 시각이 아니다.
 *
 * <p>앞서 최신 검사는 가장 나중에 <i>돈</i> 완료 검사였다. 그래서
 * <ul>
 *   <li>옛 줄에서 `다시 검사` 를 누르면 옛 SBOM 이 최신이 됐고(재현 시험 P4),</li>
 *   <li>예전에 떠 둔 SBOM 을 늦게 올려도 그것이 최신이 됐다.</li>
 * </ul>
 * 둘 다 서버의 상태가 거꾸로 돌아간 것처럼 보였다 — 패키지 목록 · 취약점 · 보고서가
 * 한꺼번에 옛 상태를 말한다.
 *
 * <p>`다시 검사` 단추는 최신 검사 줄과 실패한 줄에만 둔다(D2). 옛 SBOM 을 다시 검사할
 * 까닭이 없고, 누를 수 있으면 누른다.
 */
@SpringBootTest
@AutoConfigureMockMvc
class CurrentScanRuleTest {

    @Autowired MockMvc mvc;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired ComponentRepository components;
    @Autowired ZoneService zoneService;
    @Autowired AssetService assetService;

    @MockBean GrypeRunner grype;

    private final List<Long> made = new ArrayList<>();

    @BeforeEach
    void fakeGrype() {
        FakeGrype.on(grype);
    }

    /** 검사가 뒤에서 돌아 커밋된다 — 트랜잭션으로 되돌릴 수 없어 손으로 치운다. */
    @AfterEach
    void cleanUp() {
        made.forEach(id -> assets.findById(id).ifPresent(a -> assetService.delete(a, "tester")));
    }

    static final DateTimeFormatter WHEN =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(ZoneId.systemDefault());

    /** syft 1.52.0 CycloneDX 의 짜임 — 시각과 openssl 판, 가짜 grype 결과만 고른다. */
    static String cyclonedx(Instant timestamp, String openssl, String marker) {
        return """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "version": 1,
                  "metadata": {
                    "timestamp": "%s",
                    "tools": {"components": [{"type": "application", "author": "anchore", "name": "syft", "version": "1.52.0"}]},
                    "component": {"bom-ref": "4ce576eff7727d8a", "type": "file", "name": "/"}
                  },
                  "components": [
                    {"type": "library", "name": "openssl", "version": "%s", "purl": "pkg:deb/debian/openssl@%s"},
                    {"type": "library", "name": "lodash", "version": "4.17.0", "purl": "pkg:npm/lodash@4.17.0"}
                  ],
                  "marker": "%s"
                }
                """.formatted(timestamp, openssl, openssl, marker);
    }

    static final String V1 = "sbom-v1";   // openssl 1.1.1k
    static final String V2 = "sbom-v2";   // openssl 1.1.1n

    // --- 최신 검사 ------------------------------------------------------------------

    @Test
    @DisplayName("예전에 떠 둔 SBOM 을 늦게 올려도 최신 검사가 바뀌지 않는다 — 그렇다고 알린다")
    void anOlderSbomUploadedLaterDoesNotBecomeLatest() throws Exception {
        Asset asset = asset("late");
        Instant fresh = minutes(Instant.now().minus(1, ChronoUnit.DAYS));
        Instant stale = minutes(Instant.now().minus(10, ChronoUnit.DAYS));
        Scan newer = upload(asset, cyclonedx(fresh, "1.1.1n", V2));
        Scan older = upload(asset, cyclonedx(stale, "1.1.1k", V1));   // 나중에 올렸다

        assertThat(scans.currentOf(asset.getId()).map(Scan::getId))
                .as("SBOM 생성 시각이 늦은 쪽이 최신이다 — 늦게 올린 쪽이 아니다")
                .contains(newer.getId());
        assertThat(inventory(asset))
                .as("패키지 목록도 최신 검사 것이다")
                .containsExactlyInAnyOrder("openssl@1.1.1n", "lodash@4.17.0");

        String overview = page("/assets/" + asset.getId());
        assertThat(overview).contains("id=\"older-sbom\"")
                            .contains(WHEN.format(stale)).contains(WHEN.format(fresh));
        assertThat(older.getId()).isNotEqualTo(newer.getId());
    }

    @Test
    @DisplayName("옛 SBOM 을 다시 검사한 줄(업그레이드 전에 만든 것)은 최신 검사가 되지 않는다")
    void aRescanOfAnOldSbomIsNotLatest() throws Exception {
        Asset asset = asset("p4");
        Scan old = upload(asset, cyclonedx(minutes(Instant.now().minus(20, ChronoUnit.DAYS)), "1.1.1k", V1));
        Scan latest = upload(asset, cyclonedx(minutes(Instant.now().minus(2, ChronoUnit.DAYS)), "1.1.1n", V2));

        // 앞서 모든 줄에 `다시 검사` 가 있던 때 옛 줄에서 누른 결과 — 같은 SBOM 을 물려받고
        // 검사 시각만 지금이다(ScanService.rescan 과 같은 꼴).
        Scan copy = new Scan(asset, "tester");
        copy.inheritSbomFrom(old);
        copy.setRescanOf(old.getId());
        copy.setStatus(ScanStatus.DONE);
        scans.saveAndFlush(copy);

        assertThat(scans.currentOf(asset.getId()).map(Scan::getId)).contains(latest.getId());
        assertThat(scans.findLatestDonePerAsset())
                .filteredOn(s -> s.getAsset().getId().equals(asset.getId()))
                .extracting(Scan::getId).containsExactly(latest.getId());
    }

    // --- 다시 검사 단추 (D2) ---------------------------------------------------------

    @Test
    @DisplayName("다시 검사 단추는 최신 검사 줄에만 — 옛 줄에는 두지 않고, 서버도 거절한다")
    void onlyTheLatestRowCanBeRescanned() throws Exception {
        Asset asset = asset("d2");
        Scan old = upload(asset, cyclonedx(minutes(Instant.now().minus(20, ChronoUnit.DAYS)), "1.1.1k", V1));
        Scan latest = upload(asset, cyclonedx(minutes(Instant.now().minus(2, ChronoUnit.DAYS)), "1.1.1n", V2));

        String history = page("/assets/" + asset.getId() + "?tab=history");
        assertThat(history).contains("/scans/" + latest.getId() + "/rescan")
                           .doesNotContain("/scans/" + old.getId() + "/rescan");

        MvcResult refused = mvc.perform(post("/scans/" + old.getId() + "/rescan")
                                                .with(user("tester").roles("ADMIN")).with(csrf()))
                               .andExpect(status().is3xxRedirection()).andReturn();
        assertThat((String) refused.getFlashMap().get("error"))
                .contains("최신 검사와 실패한 검사만 다시 검사할 수 있습니다");
        assertThat(scans.findByAssetIdOrderByCreatedAtDesc(asset.getId())).hasSize(2);
    }

    // --- 보고서 ------------------------------------------------------------------------

    @Test
    @DisplayName("보고서의 '지난 검사 대비' 는 SBOM 생성 시각으로 앞 검사를 고른다")
    void theReportComparesWithTheOlderSbom() throws Exception {
        Asset asset = asset("diff");
        Instant fresh = minutes(Instant.now().minus(1, ChronoUnit.DAYS));
        Instant stale = minutes(Instant.now().minus(10, ChronoUnit.DAYS));
        Scan newer = upload(asset, cyclonedx(fresh, "1.1.1n", V2));
        Scan older = upload(asset, cyclonedx(stale, "1.1.1k", V1));   // 나중에 올렸다

        assertThat(page("/reports/scan/" + newer.getId()))
                .as("최신 검사의 앞은 예전 SBOM 이다 — 늦게 올렸어도")
                .contains("<td class=\"tight\">이전 검사")
                .doesNotContain("대조할 이전 검사 없음");
        assertThat(page("/reports/scan/" + older.getId()))
                .as("가장 옛 SBOM 에는 앞 검사가 없다")
                .contains("대조할 이전 검사 없음");
    }

    // --- 씨앗 ----------------------------------------------------------------------------

    private Asset asset(String prefix) {
        Asset asset = new Asset();
        asset.setName(prefix + "-" + System.nanoTime());
        asset.setZone(zoneService.unassigned());
        asset = assets.saveAndFlush(asset);
        made.add(asset.getId());
        return asset;
    }

    private Scan upload(Asset asset, String sbom) throws Exception {
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

    private List<String> inventory(Asset asset) {
        return components.findByAsset(asset.getId(), null, Pageable.unpaged())
                         .map(c -> c.getName() + "@" + c.getVersion()).toList();
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
