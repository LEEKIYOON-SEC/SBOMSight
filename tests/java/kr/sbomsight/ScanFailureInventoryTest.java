package kr.sbomsight;

import kr.sbomsight.domain.Asset;
import kr.sbomsight.domain.Component;
import kr.sbomsight.domain.Scan;
import kr.sbomsight.domain.ScanStatus;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.ComponentRepository;
import kr.sbomsight.repo.ScanRepository;
import kr.sbomsight.service.ComponentInventoryService;
import kr.sbomsight.service.SbomStorage;
import kr.sbomsight.service.ScanService;
import kr.sbomsight.service.ZoneService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Pageable;
import org.springframework.mock.web.MockMultipartFile;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * <b>grype 이 실패해도 그 자산의 패키지 목록이 남는가.</b>
 *
 * <p>검사는 SBOM 을 읽으며 새 인벤토리를 담고, 앞서는 <b>담자마자</b> 이전
 * 검사의 인벤토리를 지웠다. 그 뒤 grype 이 실패하면(설치·DB 문제, 시간 초과)
 * 새로 담은 것도 버리므로 <b>그 자산의 패키지 목록이 통째로 사라졌다</b> —
 * 마지막 완료 검사는 여전히 "패키지 79개" 라고 말하는데 패키지 탭은
 * "아직 담긴 패키지가 없습니다" 였다. 띄운 앱에서 grype 을 치워 재현했다.
 *
 * <p>grype 경로를 없는 파일로 못 박는다. 이 PC 에 grype 이 깔려 있든
 * 아니든 같은 결과가 나와야 시험이다.
 */
@SpringBootTest(properties = "sbomsight.grype-path=./target/no-such-grype")
class ScanFailureInventoryTest {

    @Autowired ScanService scanService;
    @Autowired ComponentInventoryService inventory;
    @Autowired SbomStorage storage;
    @Autowired ComponentRepository components;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired ZoneService zoneService;

    private static final String BEFORE = """
            { "artifacts": [
                { "name": "fail-openssl", "version": "3.0.7-24", "type": "rpm",
                  "purl": "pkg:rpm/rocky/fail-openssl@3.0.7-24" },
                { "name": "fail-log4j", "version": "2.14.1",
                  "purl": "pkg:maven/org.apache.logging.log4j/fail-log4j@2.14.1" } ] }
            """;

    private static final String AFTER = """
            { "artifacts": [
                { "name": "fail-openssl", "version": "3.0.7-25", "type": "rpm",
                  "purl": "pkg:rpm/rocky/fail-openssl@3.0.7-25" },
                { "name": "fail-log4j", "version": "2.17.1",
                  "purl": "pkg:maven/org.apache.logging.log4j/fail-log4j@2.17.1" },
                { "name": "fail-zlib", "version": "1.2.13",
                  "purl": "pkg:rpm/rocky/fail-zlib@1.2.13" } ] }
            """;

    @Test
    @DisplayName("grype 이 실패하면 이전 검사의 패키지 목록이 그대로 남는다")
    void aFailedGrypeKeepsThePreviousInventory() throws Exception {
        Asset asset = new Asset();
        asset.setName("fail-" + System.nanoTime());
        asset.setZone(zoneService.unassigned());
        assets.saveAndFlush(asset);

        Scan good = new Scan(asset, "tester");
        good.setStatus(ScanStatus.DONE);
        scans.saveAndFlush(good);
        Scan next = null;
        try {
            Path file = Files.createTempFile("sbom-", ".json");
            Files.writeString(file, BEFORE);
            try (ComponentInventoryService.Sink sink = inventory.open(asset.getId(), good.getId())) {
                storage.inspect(file, sink);
            }
            inventory.makeCurrent(asset.getId(), good.getId());
            Files.deleteIfExists(file);

            // 실제 업로드 길 — 파일을 보관하고 뒤에서 돌린다.
            next = scanService.submit(asset, new MockMultipartFile(
                    "file", "sbom.json", "application/json", AFTER.getBytes()), "tester");
            scanService.runAsync(next.getId());

            // 다른 스레드에서 돈다. 실패 처리는 상태를 먼저 적고 담은 것을
            // 나중에 버리므로, 상태만 보고 기다리면 버리기 전에 깨어난다.
            ScanStatus status = null;
            long rows = -1;
            for (int i = 0; i < 200; i++) {
                status = scans.findById(next.getId()).orElseThrow().getStatus();
                rows = components.countByAssetId(asset.getId());
                if (status == ScanStatus.FAILED && rows <= 2) {
                    break;
                }
                Thread.sleep(50);
            }
            assertThat(status).as("grype 이 없는데 검사가 실패로 끝나지 않았다")
                              .isEqualTo(ScanStatus.FAILED);

            List<Component> current = components.findByAsset(asset.getId(), null, Pageable.unpaged())
                                                .getContent();
            assertThat(current)
                    .as("grype 이 실패했는데 이전 검사의 패키지 목록이 사라졌다")
                    .extracting(Component::getVersion)
                    .containsExactly("2.14.1", "3.0.7-24");
            final Long goodId = good.getId();
            assertThat(current).allMatch(c -> c.getScan().getId().equals(goodId));
        } finally {
            // 트랜잭션 없이 커밋된다. 남기면 다른 시험이 흔들린다.
            inventory.discard(good.getId());
            if (next != null) {
                inventory.discard(next.getId());
                scans.deleteById(next.getId());
            }
            scans.deleteById(good.getId());
            assets.deleteById(asset.getId());
        }
    }
}
