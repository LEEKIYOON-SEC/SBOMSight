package kr.sbomsight;

import kr.sbomsight.config.SbomSightProperties;
import kr.sbomsight.domain.*;
import kr.sbomsight.repo.*;
import kr.sbomsight.service.ScanService;
import kr.sbomsight.service.ZoneService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.GZIPOutputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 재검사 — 보관된 SBOM 을 갱신된 grype DB 로 다시 돌린다.
 *
 * <p>어제 없던 취약점이 오늘 생긴다. SBOM 이 아니라 취약점 DB 가 바뀌기
 * 때문이다. syft 와 grype 을 나눠 둔 구조의 가장 큰 이점인데 지금까지 쓰지
 * 않고 있었다.
 *
 * <p>여기서 고정하는 것:
 * <ol>
 *   <li><b>원본을 건드리지 않는다.</b> 덮어쓰면 "그때 무엇을 봤는지" 가
 *       사라진다 — 그 결과로 이미 결재가 올라갔을 수도 있다.</li>
 *   <li>파일이 독립이다. 경로를 함께 가리키면 한쪽을 지울 때 나머지가
 *       파일을 잃는다.</li>
 * </ol>
 */
@SpringBootTest
class RescanTest {

    @Autowired ScanService scanService;
    @Autowired ScanRepository scans;
    @Autowired AssetRepository assets;
    @Autowired ZoneService zoneService;
    @Autowired SbomSightProperties properties;

    /** 보관된 SBOM 이 있는 완료 스캔을 하나 만든다. */
    private Scan storedScan() throws IOException {
        Asset asset = new Asset();
        asset.setName("rescan-" + System.nanoTime());
        asset.setZone(zoneService.unassigned());
        assets.save(asset);

        Scan scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        scan.setSbomFilename("web-01.sbom.json");
        scan.setSbomFormat("cyclonedx-json");
        scan.setSbomBytes(1234);
        scans.saveAndFlush(scan);

        Path dir = properties.scanDir(asset.getId(), scan.getId());
        Files.createDirectories(dir);
        Path gz = dir.resolve("sbom.json.gz");
        try (OutputStream out = new GZIPOutputStream(Files.newOutputStream(gz))) {
            out.write("{\"bomFormat\":\"CycloneDX\",\"components\":[]}".getBytes());
        }
        scan.setSbomPath(gz.toString());
        return scans.saveAndFlush(scan);
    }

    @Test
    @DisplayName("새 스캔으로 쌓이고 원본은 그대로다")
    void createsANewScanAndLeavesTheOriginal() throws Exception {
        Scan source = storedScan();
        int before = source.getFindingCount();

        Scan copy = scanService.rescan(source, "tester");

        assertThat(copy.getId()).isNotEqualTo(source.getId());
        assertThat(copy.getStatus()).isEqualTo(ScanStatus.QUEUED);
        assertThat(copy.getRescanOf()).isEqualTo(source.getId());
        assertThat(copy.isRescan()).isTrue();
        assertThat(copy.getAsset().getId()).isEqualTo(source.getAsset().getId());
        // 같은 SBOM 을 돌리는 것이므로 파일 정보는 그대로 따라간다.
        assertThat(copy.getSbomFilename()).isEqualTo(source.getSbomFilename());

        Scan reloaded = scans.findById(source.getId()).orElseThrow();
        assertThat(reloaded.getStatus()).as("원본 스캔이 바뀌었다").isEqualTo(ScanStatus.DONE);
        assertThat(reloaded.getFindingCount()).isEqualTo(before);
        assertThat(reloaded.isRescan()).isFalse();
    }

    /**
     * 경로를 함께 가리키게 하면 둘 중 하나를 지울 때 deleteScanDir 이
     * 디렉터리를 통째로 지우므로 나머지가 파일을 잃는다.
     */
    @Test
    @DisplayName("보관 파일이 서로 독립이다")
    void theStoredFilesAreIndependent() throws Exception {
        Scan source = storedScan();
        Scan copy = scanService.rescan(source, "tester");

        assertThat(copy.getSbomPath()).isNotEqualTo(source.getSbomPath());
        assertThat(Files.exists(Path.of(copy.getSbomPath()))).isTrue();
        assertThat(Files.exists(Path.of(source.getSbomPath()))).isTrue();
        // 바이트도 같아야 한다 — "같은 SBOM 을 다시 돌렸다" 가 사실이어야 한다.
        assertThat(Files.readAllBytes(Path.of(copy.getSbomPath())))
                .isEqualTo(Files.readAllBytes(Path.of(source.getSbomPath())));

        // 원본 스캔을 지워도 재검사본의 파일은 남는다.
        scanService.delete(scans.findById(source.getId()).orElseThrow());
        assertThat(Files.exists(Path.of(copy.getSbomPath())))
                .as("원본을 지웠더니 재검사본의 파일까지 사라졌다").isTrue();
    }

    @Test
    @DisplayName("원본 스캔이 지워져도 재검사 결과는 남는다")
    void survivesTheOriginalBeingDeleted() throws Exception {
        Scan source = storedScan();
        Scan copy = scanService.rescan(source, "tester");
        Long copyId = copy.getId();

        scanService.delete(scans.findById(source.getId()).orElseThrow());

        // 원본이 사라졌다고 그 결과까지 지우면 그때 무엇을 봤는지 설명할 수 없다.
        assertThat(scans.findById(copyId)).isPresent();
    }

    @Test
    @DisplayName("보관된 SBOM 이 없으면 거절한다")
    void refusesWhenThereIsNoStoredSbom() {
        Asset asset = new Asset();
        asset.setName("nofile-" + System.nanoTime());
        asset.setZone(zoneService.unassigned());
        assets.save(asset);
        Scan scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        scans.saveAndFlush(scan);

        assertThatThrownBy(() -> scanService.rescan(scan, "tester"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("보관된 SBOM 이 없어");
    }

    @Test
    @DisplayName("파일이 사라졌으면 그렇다고 말한다")
    void refusesWhenTheFileIsGone() throws Exception {
        Scan source = storedScan();
        Files.delete(Path.of(source.getSbomPath()));

        // 조용히 빈 결과를 내면 "취약점이 사라졌다" 로 읽힌다.
        assertThatThrownBy(() -> scanService.rescan(source, "tester"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("찾을 수 없습니다");
    }
}
