package kr.sbomsight;

import kr.sbomsight.domain.Asset;
import kr.sbomsight.domain.Scan;
import kr.sbomsight.domain.ScanStatus;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.ComponentRepository;
import kr.sbomsight.repo.ScanRepository;
import kr.sbomsight.service.AssetService;
import kr.sbomsight.service.ComponentInventoryService;
import kr.sbomsight.service.GrypeRunner;
import kr.sbomsight.service.SbomStorage;
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
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

import static kr.sbomsight.NewSbomKeepsDecisionsTest.SBOM_V1;
import static kr.sbomsight.NewSbomKeepsDecisionsTest.SBOM_V2;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * <b>같은 자산의 검사가 겹쳐도 패키지 목록이 비지 않는가.</b>
 *
 * <p>검사는 SBOM 을 읽으며 그 자산의 패키지를 담고, 끝나면 <b>그 자산의 다른
 * 검사에서 온 행</b>을 지웠다. 아직 도는 검사가 이미 담아 둔 행도 거기 든다.
 * 그래서 `다시 검사` 를 연달아 두 번 누르면 — 또는 두 사람이 — 먼저 끝난 쪽이
 * 나중 것의 행을, 나중 것이 먼저 것의 행을 지워 <b>검사 셋이 다 완료인데 패키지가
 * 0행</b>이 됐다. 업로드를 두 번 해도 같았다. 둘 다 재현 시험으로 먼저 확인했다.
 *
 * <p>지키는 것: 같은 자산에 도는 검사는 하나다(겹치면 거절하고 말한다) · 늦게
 * 끝난 검사가 지금의 패키지 목록을 지우지 않는다.
 */
@SpringBootTest
@AutoConfigureMockMvc
class ScanOverlapTest {

    @Autowired MockMvc mvc;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired ComponentRepository components;
    @Autowired ComponentInventoryService inventory;
    @Autowired SbomStorage storage;
    @Autowired AssetService assetService;
    @Autowired ZoneService zoneService;

    @MockBean GrypeRunner grype;

    private FakeGrype fake;
    private final List<Long> cleanup = new ArrayList<>();

    @BeforeEach
    void fakeGrype() {
        fake = FakeGrype.on(grype);
    }

    @AfterEach
    void cleanUp() throws InterruptedException {
        fake.release();
        // 트랜잭션 없이 커밋되는 시험이 있다(검사가 뒤에서 돈다). 손으로 치운다.
        for (Long id : cleanup) {
            for (Scan scan : scans.findByAssetIdOrderByCreatedAtDesc(id)) {
                FakeGrype.awaitFinished(scans, scan.getId());
            }
            assets.findById(id).ifPresent(a -> assetService.delete(a, "tester"));
        }
        cleanup.clear();
    }

    // --- 겹치면 거절한다 ---------------------------------------------------------

    @Test
    @DisplayName("검사가 도는 동안 같은 자산에 업로드하면 거절하고 그렇다고 말한다")
    void uploadWhileScanningIsRefused() throws Exception {
        Asset asset = committedAsset("overlap-upload");
        fake.hold();
        upload(asset, SBOM_V1);
        Scan first = scans.findByAssetIdOrderByCreatedAtDesc(asset.getId()).get(0);

        MvcResult second = upload(asset, SBOM_V2);

        assertThat((String) second.getFlashMap().get("error"))
                .as("겹친 업로드를 받으면 먼저 것이 담아 둔 패키지를 나중 것이 지운다")
                .contains("업로드하지 못했습니다")
                .contains("검사가 아직 진행 중");
        assertThat(scans.findByAssetIdOrderByCreatedAtDesc(asset.getId())).hasSize(1);

        fake.release();
        assertThat(FakeGrype.awaitFinished(scans, first.getId()).getStatus()).isEqualTo(ScanStatus.DONE);
        assertThat(current(asset)).containsExactly("lodash@4.17.0", "openssl@1.1.1k");
    }

    @Test
    @DisplayName("검사가 도는 동안 다시 검사를 또 누르면 거절한다 — 패키지 목록이 남는다")
    void rescanWhileScanningIsRefused() throws Exception {
        Asset asset = committedAsset("overlap-rescan");
        upload(asset, SBOM_V1);
        Scan done = FakeGrype.awaitFinished(scans,
                scans.findByAssetIdOrderByCreatedAtDesc(asset.getId()).get(0).getId());

        fake.hold();
        MvcResult first = rescan(done);
        MvcResult again = rescan(done);

        assertThat((String) first.getFlashMap().get("error")).isNull();
        assertThat((String) again.getFlashMap().get("error"))
                .contains("다시 검사하지 못했습니다")
                .contains("검사가 아직 진행 중");
        assertThat(scans.findByAssetIdOrderByCreatedAtDesc(asset.getId()))
                .as("두 번째 다시 검사가 새 검사를 만들었다")
                .hasSize(2);

        fake.release();
        for (Scan scan : scans.findByAssetIdOrderByCreatedAtDesc(asset.getId())) {
            FakeGrype.awaitFinished(scans, scan.getId());
        }
        assertThat(current(asset))
                .as("다시 검사 뒤에 그 자산의 패키지 목록이 비었다")
                .containsExactly("lodash@4.17.0", "openssl@1.1.1k");
    }

    // --- 늦게 끝난 검사 ----------------------------------------------------------

    /**
     * 겹치는 길을 막아도 이미 돌고 있던 것(업그레이드 직전에 올린 것)은 있을 수
     * 있다. 그때도 <b>늦게 끝난 쪽이 지금의 목록을 지우지 않는다</b> — 지금의
     * 검사가 아니면 제 것을 버린다.
     */
    @Test
    @DisplayName("먼저 올린 검사가 나중에 끝나도 지금의 패키지 목록을 지우지 않는다")
    @Transactional
    void aLateFinisherKeepsTheCurrentInventory() throws Exception {
        Asset asset = asset("late");
        Scan older = new Scan(asset, "tester");
        older.setStatus(ScanStatus.RUNNING);
        older.setCreatedAt(Instant.now().minus(1, ChronoUnit.HOURS));
        scans.saveAndFlush(older);
        Scan newer = new Scan(asset, "tester");
        newer.setStatus(ScanStatus.DONE);
        scans.saveAndFlush(newer);

        ingest(asset, older, "late-old");
        ingest(asset, newer, "late-new");
        inventory.makeCurrent(asset.getId(), newer.getId());

        older.setStatus(ScanStatus.DONE);
        scans.saveAndFlush(older);
        inventory.makeCurrent(asset.getId(), older.getId());

        assertThat(current(asset))
                .as("나중에 올린 검사가 지금의 검사다 — 그 목록이 남아야 한다")
                .containsExactly("late-new@1.0");
        assertThat(components.countByAssetId(asset.getId()))
                .as("지금의 검사가 아닌 쪽의 행이 남았다")
                .isEqualTo(1);
    }

    // --- 화면 -------------------------------------------------------------------

    @Test
    @DisplayName("검사가 도는 동안에는 업로드 · 다시 검사 단추를 열어 두지 않는다")
    @Transactional
    void theButtonsCloseWhileScanning() throws Exception {
        Asset asset = asset("buttons");
        Scan done = new Scan(asset, "tester");
        done.setStatus(ScanStatus.DONE);
        done.setCreatedAt(Instant.now().minus(1, ChronoUnit.HOURS));
        scans.saveAndFlush(done);
        Scan running = new Scan(asset, "tester");
        running.setStatus(ScanStatus.RUNNING);
        scans.saveAndFlush(running);

        String history = page("/assets/" + asset.getId() + "?tab=history");
        assertThat(history)
                .as("눌러도 거절될 단추를 열어 두면 누른 사람은 고장으로 읽는다")
                .doesNotContain("action=\"/scans/" + done.getId() + "/rescan\"");

        String overview = page("/assets/" + asset.getId());
        assertThat(overview).contains("검사가 진행 중이라 지금은 업로드할 수 없습니다");
    }

    // --- 거들 -------------------------------------------------------------------

    private Asset asset(String name) {
        Asset asset = new Asset();
        asset.setName(name + "-" + System.nanoTime());
        asset.setZone(zoneService.unassigned());
        return assets.saveAndFlush(asset);
    }

    /** 트랜잭션 없이 커밋되는 자산 — 끝나면 지운다. */
    private Asset committedAsset(String name) {
        Asset asset = asset(name);
        cleanup.add(asset.getId());
        return asset;
    }

    private MvcResult upload(Asset asset, String sbom) throws Exception {
        return mvc.perform(multipart("/assets/" + asset.getId() + "/sbom")
                                   .file(new MockMultipartFile("file", "web.sbom.json", "application/json",
                                                               sbom.getBytes(StandardCharsets.UTF_8)))
                                   .with(admin()).with(csrf()))
                  .andExpect(status().is3xxRedirection())
                  .andReturn();
    }

    private MvcResult rescan(Scan source) throws Exception {
        return mvc.perform(post("/scans/" + source.getId() + "/rescan").with(admin()).with(csrf()))
                  .andExpect(status().is3xxRedirection())
                  .andReturn();
    }

    /** 패키지 하나짜리 SBOM 을 읽어 그 검사의 행으로 담는다 — ScanService.run 이 하는 대로. */
    private void ingest(Asset asset, Scan scan, String name) throws Exception {
        Path file = Files.createTempFile("sbom-", ".json");
        Files.writeString(file, """
                { "artifacts": [ { "name": "%s", "version": "1.0", "type": "rpm",
                                   "purl": "pkg:rpm/rocky/%s@1.0" } ] }
                """.formatted(name, name));
        try (ComponentInventoryService.Sink sink = inventory.open(asset.getId(), scan.getId())) {
            storage.inspect(file, sink);
        } finally {
            Files.deleteIfExists(file);
        }
    }

    /** 지금의 패키지 목록 — 화면의 `패키지` 탭이 읽는 것. */
    private List<String> current(Asset asset) {
        return components.findByAsset(asset.getId(), null, Pageable.unpaged()).getContent().stream()
                         .map(c -> c.getName() + "@" + c.getVersion())
                         .toList();
    }

    private String page(String url) throws Exception {
        return mvc.perform(get(url).with(admin()))
                  .andExpect(status().isOk())
                  .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    private static RequestPostProcessor admin() {
        return user("tester").roles("ADMIN");
    }
}
