package kr.sbomsight;

import kr.sbomsight.domain.Asset;
import kr.sbomsight.domain.AuditEvent;
import kr.sbomsight.domain.AuditLog;
import kr.sbomsight.domain.Scan;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.AuditLogRepository;
import kr.sbomsight.repo.ComponentRepository;
import kr.sbomsight.repo.ScanRepository;
import kr.sbomsight.service.AssetService;
import kr.sbomsight.service.ComponentInventoryService;
import kr.sbomsight.service.GrypeRunner;
import kr.sbomsight.service.ZoneService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.data.domain.Pageable;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static kr.sbomsight.NewSbomKeepsDecisionsTest.SBOM_V1;
import static kr.sbomsight.NewSbomKeepsDecisionsTest.SBOM_V2;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * <b>검사를 지워도 패키지 목록이 비지 않는가.</b>
 *
 * <p>패키지 목록은 자산마다 지금 검사 것만 둔다 — 새 검사가 끝나면 그 전 검사의
 * 행을 지운다. 그래서 지금 검사를 지우면(엉뚱한 자산에 올린 SBOM 을 지울 때가
 * 그렇다) 취약점 화면은 그 전 검사를 말하는데 패키지 목록은 0행이었다.
 *
 * <p>지키는 것: 지금 검사를 지우면 그 전 검사의 보관 SBOM 에서 다시 담고 그렇다고
 * 말한다 · 지금 검사가 아닌 것을 지우면 패키지 목록을 건드리지 않는다 · 다시
 * 담지 못해도 지운 것은 지운 것이다(보관 파일은 이미 지운 뒤다) — 까닭을 말하고
 * 감사 기록을 남긴다.
 */
@SpringBootTest
@AutoConfigureMockMvc
class ScanDeleteInventoryTest {

    @Autowired MockMvc mvc;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired ComponentRepository components;
    @Autowired AuditLogRepository auditLogs;
    @Autowired AssetService assetService;
    @Autowired ZoneService zoneService;

    @MockBean GrypeRunner grype;

    /** 진짜 빈을 쓰되 다시 담기만 터지게 바꿔 놓는 시험이 있다. */
    @SpyBean ComponentInventoryService inventory;

    private FakeGrype fake;
    private final List<Long> cleanup = new ArrayList<>();

    @BeforeEach
    void fakeGrype() {
        fake = FakeGrype.on(grype);
    }

    @AfterEach
    void cleanUp() throws InterruptedException {
        fake.release();
        // 검사가 뒤에서 돌아 트랜잭션 없이 커밋된다. 손으로 치운다.
        for (Long id : cleanup) {
            for (Scan scan : scans.findByAssetIdOrderByCreatedAtDesc(id)) {
                FakeGrype.awaitFinished(scans, scan.getId());
            }
            assets.findById(id).ifPresent(a -> assetService.delete(a, "tester"));
        }
        cleanup.clear();
    }

    @Test
    @DisplayName("지금 검사를 지우면 그 전 검사의 SBOM에서 패키지 목록을 다시 담는다")
    void deletingTheCurrentScanRestoresTheInventory() throws Exception {
        Asset asset = committedAsset("restore");
        Scan v1 = scanned(asset, SBOM_V1);
        Scan v2 = scanned(asset, SBOM_V2);
        assertThat(current(asset)).containsExactly("lodash@4.17.0", "openssl@1.1.1n");

        MvcResult result = delete(v2);

        assertThat(current(asset))
                .as("지운 뒤 취약점은 그 전 검사를 말하는데 패키지 목록이 비었다")
                .containsExactly("lodash@4.17.0", "openssl@1.1.1k");
        assertThat(components.findByAsset(asset.getId(), null, Pageable.unpaged()).getContent())
                .allMatch(c -> c.getScan().getId().equals(v1.getId()));
        assertThat((String) result.getFlashMap().get("message"))
                .contains("그 전 검사(")
                .contains("패키지 2개를 다시 담았습니다");
        assertThat(deletionRecords(asset)).singleElement()
                .extracting(AuditLog::getDetail).asString()
                .contains("패키지 2개를 다시 담았습니다");
    }

    /**
     * 지금 검사의 행이 없는 자산이 있다 — 패키지 목록이 생기기 전(V13)에 돈 검사가
     * 지금 검사인 자산이다. 거기서 <b>오래된 검사</b>를 지웠다고 "그 전 검사에서
     * 다시 담았다" 고 하면 지운 것과 담은 것이 맞지 않는다. 다시 담는 것은 지금
     * 검사를 지웠을 때뿐이다.
     */
    @Test
    @DisplayName("지금 검사가 아닌 것을 지우면 패키지 목록을 건드리지 않는다")
    void deletingAnOlderScanLeavesTheInventoryAlone() throws Exception {
        Asset asset = committedAsset("older");
        Scan v1 = scanned(asset, SBOM_V1);
        Scan v2 = scanned(asset, SBOM_V2);
        inventory.discard(v2.getId());          // 패키지 목록이 생기기 전에 돈 검사처럼

        MvcResult result = delete(v1);

        assertThat(scans.findById(v1.getId())).isEmpty();
        assertThat((String) result.getFlashMap().get("message")).doesNotContain("다시 담았습니다");
        assertThat((String) result.getFlashMap().get("error")).isNull();
        assertThat(components.countByScanId(v2.getId()))
                .as("오래된 검사를 지웠는데 지금 검사의 패키지 목록이 채워졌다")
                .isZero();
    }

    @Test
    @DisplayName("그 전 검사의 SBOM이 없으면 지우고, 다시 담지 못한 까닭을 말한다")
    void aMissingStoredSbomIsSaidNotHidden() throws Exception {
        Asset asset = committedAsset("missing");
        Scan v1 = scanned(asset, SBOM_V1);
        Scan v2 = scanned(asset, SBOM_V2);
        Files.delete(Path.of(v1.getSbomPath()));

        MvcResult result = delete(v2);

        assertThat(scans.findById(v2.getId())).isEmpty();
        assertThat((String) result.getFlashMap().get("error"))
                .contains("패키지 목록을 그 전 검사에서 다시 담지 못했습니다")
                .contains("보관 SBOM 파일이 없습니다");
        assertThat(current(asset)).isEmpty();
        assertThat(deletionRecords(asset)).singleElement()
                .extracting(AuditLog::getDetail).asString()
                .contains("패키지 목록을 다시 담지 못함");
    }

    /**
     * 다시 담기가 지우기와 한 트랜잭션이면, 다시 담다가 터질 때 지운 것까지
     * 되돌려진다 — 그런데 보관 파일은 그때 이미 지운 뒤다. 행은 남고 파일은 없는
     * 검사가 되고, 화면은 500 이며, 감사 기록도 남지 않는다.
     */
    @Test
    @DisplayName("다시 담다가 터져도 지운 것은 되돌리지 않는다 — 까닭을 말하고 감사 기록을 남긴다")
    void aFailedRestoreDoesNotUndoTheDeletion() throws Exception {
        Asset asset = committedAsset("boom");
        scanned(asset, SBOM_V1);
        Scan v2 = scanned(asset, SBOM_V2);
        Mockito.doThrow(new IllegalStateException("디스크가 가득 찼습니다"))
               .when(inventory).restoreCurrent(Mockito.anyLong());

        MvcResult result = delete(v2);

        assertThat(scans.findById(v2.getId()))
                .as("보관 파일은 지웠는데 검사 행이 되살아났다")
                .isEmpty();
        assertThat(Files.exists(Path.of(v2.getSbomPath()))).isFalse();
        assertThat((String) result.getFlashMap().get("error"))
                .contains("패키지 목록을 그 전 검사에서 다시 담지 못했습니다")
                .contains("디스크가 가득 찼습니다");
        assertThat(deletionRecords(asset)).hasSize(1);
    }

    // --- 거들 -------------------------------------------------------------------

    /** 트랜잭션 없이 커밋되는 자산 — 끝나면 지운다. */
    private Asset committedAsset(String name) {
        Asset asset = new Asset();
        asset.setName(name + "-" + System.nanoTime());
        asset.setZone(zoneService.unassigned());
        asset = assets.saveAndFlush(asset);
        cleanup.add(asset.getId());
        return asset;
    }

    /** 올리고 끝날 때까지 기다린다. */
    private Scan scanned(Asset asset, String sbom) throws Exception {
        mvc.perform(multipart("/assets/" + asset.getId() + "/sbom")
                            .file(new MockMultipartFile("file", "web.sbom.json", "application/json",
                                                        sbom.getBytes(StandardCharsets.UTF_8)))
                            .with(admin()).with(csrf()))
           .andExpect(status().is3xxRedirection());
        return FakeGrype.awaitFinished(scans,
                scans.findByAssetIdOrderByCreatedAtDesc(asset.getId()).get(0).getId());
    }

    private MvcResult delete(Scan scan) throws Exception {
        return mvc.perform(post("/scans/" + scan.getId() + "/delete").with(admin()).with(csrf()))
                  .andExpect(status().is3xxRedirection())
                  .andReturn();
    }

    /** 지금의 패키지 목록 — 화면의 `패키지` 탭이 읽는 것. */
    private List<String> current(Asset asset) {
        return components.findByAsset(asset.getId(), null, Pageable.unpaged()).getContent().stream()
                         .map(c -> c.getName() + "@" + c.getVersion())
                         .toList();
    }

    private List<AuditLog> deletionRecords(Asset asset) {
        return auditLogs.export(null, AuditEvent.SCAN_DELETED, null, null, asset.getName());
    }

    private static RequestPostProcessor admin() {
        return user("tester").roles("ADMIN");
    }
}
