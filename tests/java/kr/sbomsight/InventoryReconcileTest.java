package kr.sbomsight;

import kr.sbomsight.domain.Asset;
import kr.sbomsight.domain.Scan;
import kr.sbomsight.domain.ScanStatus;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.ComponentRepository;
import kr.sbomsight.repo.ScanRepository;
import kr.sbomsight.service.AssetService;
import kr.sbomsight.service.ComponentInventoryService;
import kr.sbomsight.service.InventoryReconciler;
import kr.sbomsight.service.SbomStorage;
import kr.sbomsight.service.ZoneService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Pageable;
import org.springframework.mock.web.MockMultipartFile;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * <b>최신 검사를 고르는 규칙이 바뀐 뒤 — 패키지 목록이 최신 검사의 것인가.</b>
 *
 * <p>V17 전에는 가장 나중에 돈 완료 검사가 최신이었다. 옛 SBOM 을 다시 검사한 줄이
 * 그랬던 자산은 그 줄의 패키지 목록을 쥐고 있다. 새 규칙(SBOM 생성 시각)으로는 다른
 * 검사가 최신이라, 그대로 두면 취약점 화면과 패키지 화면이 서로 다른 SBOM 을 말한다.
 * 기동할 때 그런 자산을 찾아 맞춘다(InventoryReconciler).
 */
@SpringBootTest
class InventoryReconcileTest {

    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired ComponentRepository components;
    @Autowired ComponentInventoryService inventory;
    @Autowired SbomStorage storage;
    @Autowired AssetService assetService;
    @Autowired ZoneService zoneService;
    @Autowired InventoryReconciler reconciler;

    private final List<Long> made = new ArrayList<>();

    @AfterEach
    void cleanUp() {
        made.forEach(id -> assets.findById(id).ifPresent(a -> assetService.delete(a, "tester")));
    }

    @Test
    @DisplayName("옛 규칙으로 최신이던 다시 검사의 목록이 남았으면 최신 검사의 보관 SBOM 에서 다시 담는다")
    void theInventoryFollowsTheNewLatestScan() throws Exception {
        Asset asset = asset("reconcile");
        Scan rescanOfOld = oldRuleLatest(asset, true);

        assertThat(inventory(asset)).as("앞선 규칙의 최신 검사 목록").containsExactly("old-pkg@1.0");

        reconciler.reconcile();

        assertThat(inventory(asset)).as("최신 검사의 SBOM 에서 다시 담았다").containsExactly("fresh-pkg@2.0");
        assertThat(components.countByScanId(rescanOfOld.getId())).isZero();
    }

    @Test
    @DisplayName("최신 검사의 보관 SBOM 이 없으면 옛 목록을 버린다 — 다른 SBOM 의 목록을 말하지 않는다")
    void withoutTheSbomTheStaleListIsDropped() throws Exception {
        Asset asset = asset("reconcile-nofile");
        Scan rescanOfOld = oldRuleLatest(asset, false);

        reconciler.reconcile();

        assertThat(inventory(asset)).isEmpty();
        assertThat(components.countByScanId(rescanOfOld.getId())).isZero();
    }

    @Test
    @DisplayName("목록이 이미 최신 검사의 것이면 건드리지 않는다")
    void aConsistentAssetIsLeftAlone() throws Exception {
        Asset asset = asset("reconcile-ok");
        Scan latest = done(asset, Instant.now().minus(1, ChronoUnit.DAYS));
        ingest(asset, latest, "fresh-pkg", "2.0");

        reconciler.reconcile();

        assertThat(inventory(asset)).containsExactly("fresh-pkg@2.0");
    }

    // --- 씨앗 -------------------------------------------------------------------------

    /**
     * 업그레이드 직전의 모습 — 원본 둘(10일 전 SBOM · 어제 SBOM)과, 그 뒤에 옛 원본을 다시
     * 검사한 줄. 옛 규칙(검사 시각)으로는 다시 검사한 줄이 최신이라 패키지 목록이 그 줄의
     * 것이다. 새 규칙으로는 어제 SBOM 이 최신이다.
     *
     * @param stored 어제 SBOM 의 보관 파일을 둘 것인가
     * @return 옛 규칙의 최신 검사 — 옛 SBOM 을 다시 검사한 줄
     */
    private Scan oldRuleLatest(Asset asset, boolean stored) throws Exception {
        Scan old = done(asset, Instant.now().minus(10, ChronoUnit.DAYS));
        Scan fresh = done(asset, Instant.now().minus(1, ChronoUnit.DAYS));
        if (stored) {
            String sbom = """
                    { "artifacts": [ { "name": "fresh-pkg", "version": "2.0", "type": "rpm",
                                       "purl": "pkg:rpm/rocky/fresh-pkg@2.0" } ] }
                    """;
            SbomStorage.Stored kept = storage.storeSbom(asset.getId(), fresh.getId(),
                    new MockMultipartFile("file", "fresh.json", "application/json",
                                          sbom.getBytes(StandardCharsets.UTF_8)));
            fresh.setSbomPath(kept.path().toString());
            scans.saveAndFlush(fresh);
        }
        Scan copy = new Scan(asset, "tester");
        copy.inheritSbomFrom(old);
        copy.setRescanOf(old.getId());
        copy.setStatus(ScanStatus.DONE);
        scans.saveAndFlush(copy);
        ingest(asset, copy, "old-pkg", "1.0");

        assertThat(scans.currentOf(asset.getId()).map(Scan::getId))
                .as("새 규칙의 최신 검사는 어제 SBOM 이다").contains(fresh.getId());
        return copy;
    }

    private Asset asset(String prefix) {
        Asset asset = new Asset();
        asset.setName(prefix + "-" + System.nanoTime());
        asset.setZone(zoneService.unassigned());
        asset = assets.saveAndFlush(asset);
        made.add(asset.getId());
        return asset;
    }

    /** 완료된 업로드 — SBOM 생성 시각은 {@code sbomAt}. */
    private Scan done(Asset asset, Instant sbomAt) {
        Scan scan = new Scan(asset, "tester");
        scan.resolveSbomTime(sbomAt);
        scan.setStatus(ScanStatus.DONE);
        return scans.saveAndFlush(scan);
    }

    /** 패키지 하나를 그 검사의 행으로 담는다 — ScanService.run 이 하는 대로. */
    private void ingest(Asset asset, Scan scan, String name, String version) throws Exception {
        Path file = Files.createTempFile("sbom-", ".json");
        Files.writeString(file, """
                { "artifacts": [ { "name": "%s", "version": "%s", "type": "rpm",
                                   "purl": "pkg:rpm/rocky/%s@%s" } ] }
                """.formatted(name, version, name, version));
        try (ComponentInventoryService.Sink sink = inventory.open(asset.getId(), scan.getId())) {
            storage.inspect(file, sink);
        } finally {
            Files.deleteIfExists(file);
        }
    }

    private List<String> inventory(Asset asset) {
        return components.findByAsset(asset.getId(), null, Pageable.unpaged())
                         .map(c -> c.getName() + "@" + c.getVersion()).toList();
    }
}
