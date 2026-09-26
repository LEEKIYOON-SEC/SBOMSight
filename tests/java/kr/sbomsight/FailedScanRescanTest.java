package kr.sbomsight;

import kr.sbomsight.config.SbomSightProperties;
import kr.sbomsight.domain.Asset;
import kr.sbomsight.domain.Scan;
import kr.sbomsight.domain.ScanStatus;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.ScanRepository;
import kr.sbomsight.service.ScanService;
import kr.sbomsight.service.ZoneService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.zip.GZIPOutputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * <b>실패한 검사도 다시 검사할 수 있다 — SBOM 은 보관되어 있다.</b>
 *
 * <p>앞서 `다시 검사` 는 완료된 검사에만 있었다. 실패한 검사의 SBOM 도 올린
 * 순간 보관되는데, 서버가 다시 시작되어 중단된 검사는 "SBOM 을 다시 업로드해
 * 주세요" 라고 안내했다 — 가진 것을 다시 받아 오라는 말이었다.
 *
 * <p>또 실패는 진행 표시에 잠깐 떴다가 화면을 새로 그리며 사라져, 개요 탭에는
 * 흔적이 없고 머리의 `마지막 검사` 는 그 전 완료 검사를 가리킨 채였다. 그 자산의
 * 가장 최근 검사가 실패했으면 개요가 그것을 말하고 `다시 검사` 를 둔다.
 *
 * <p>다시 검사도 올릴 때와 같은 형식 검사를 거친다 — 예전에 받은 XML 검사를
 * 다시 돌리면 패키지 목록을 읽지 못한 채 완료되어, 그 자산의 패키지 목록이
 * 지워지는 길이 남아 있었다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class FailedScanRescanTest {

    private static final String ERROR = "grype가 비정상 종료했습니다(종료 코드 1).";

    @Autowired MockMvc mvc;
    @Autowired ScanService scanService;
    @Autowired ScanRepository scans;
    @Autowired AssetRepository assets;
    @Autowired ZoneService zoneService;
    @Autowired SbomSightProperties properties;

    @Test
    @DisplayName("검사 이력의 실패한 줄에도 다시 검사가 있다")
    void theFailedRowOffersARescan() throws Exception {
        Asset asset = asset();
        Scan failed = failedScan(asset, Instant.now(), json());

        String history = html("/assets/" + asset.getId() + "?tab=history");
        assertThat(history)
                .as("실패한 검사의 SBOM 은 보관되어 있는데 다시 검사할 길이 없다")
                .contains("action=\"/scans/" + failed.getId() + "/rescan\"");
    }

    @Test
    @DisplayName("가장 최근 검사가 실패했으면 개요가 사유와 다시 검사를 보여 준다")
    void theOverviewSaysTheLastAttemptFailed() throws Exception {
        Asset asset = asset();
        Scan done = doneScan(asset, Instant.now().minus(1, ChronoUnit.HOURS));
        Scan failed = failedScan(asset, Instant.now(), json());

        String overview = html("/assets/" + asset.getId());
        assertThat(overview)
                .contains("id=\"last-failed\"")
                .contains(ERROR)
                .contains("action=\"/scans/" + failed.getId() + "/rescan\"");
        // 보이는 숫자가 어느 검사 것인지 말한다 — 실패한 검사의 것이 아니다.
        assertThat(overview).contains("그 전 완료 검사");
        assertThat(done.getId()).isNotNull();
    }

    @Test
    @DisplayName("실패 뒤에 완료된 검사가 있으면 알림은 없다")
    void aLaterCompletedScanClearsTheNotice() throws Exception {
        Asset asset = asset();
        failedScan(asset, Instant.now().minus(1, ChronoUnit.HOURS), json());
        doneScan(asset, Instant.now());

        assertThat(html("/assets/" + asset.getId())).doesNotContain("id=\"last-failed\"");
    }

    @Test
    @DisplayName("조회 계정에게도 실패는 보이고, 다시 검사 단추는 관리자에게만 있다")
    void viewersSeeTheNoticeWithoutTheButton() throws Exception {
        Asset asset = asset();
        Scan failed = failedScan(asset, Instant.now(), json());

        String overview = mvc.perform(get("/assets/" + asset.getId()).with(user("viewer").roles("VIEWER")))
                             .andExpect(status().isOk())
                             .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(overview).contains("id=\"last-failed\"")
                            .doesNotContain("action=\"/scans/" + failed.getId() + "/rescan\"");
    }

    @Test
    @DisplayName("실패한 검사를 다시 검사하면 같은 SBOM 으로 새 검사가 생긴다")
    void aFailedScanCanBeRescanned() throws Exception {
        Scan failed = failedScan(asset(), Instant.now(), json());

        Scan copy = scanService.rescan(failed, "tester");

        assertThat(copy.getStatus()).isEqualTo(ScanStatus.QUEUED);
        assertThat(copy.getRescanOf()).isEqualTo(failed.getId());
        assertThat(scans.findById(failed.getId()).orElseThrow().getStatus())
                .as("실패한 검사는 그대로 남는다 — 실패했다는 사실도 이력이다")
                .isEqualTo(ScanStatus.FAILED);
    }

    @Test
    @DisplayName("보관된 SBOM 이 JSON 이 아니면 다시 검사하지 않는다 — 패키지 목록을 지키려고")
    void aNonJsonSbomIsNotRescanned() throws Exception {
        Asset asset = asset();
        Scan xml = doneScan(asset, Instant.now());
        store(xml, "<?xml version=\"1.0\"?><bom xmlns=\"http://cyclonedx.org/schema/bom/1.5\"/>");
        long before = scans.findByAssetIdOrderByCreatedAtDesc(asset.getId()).size();

        assertThatThrownBy(() -> scanService.rescan(xml, "tester"))
                .isInstanceOf(ScanService.UnsupportedSbomException.class);

        MvcResult result = mvc.perform(post("/scans/" + xml.getId() + "/rescan")
                                               .with(user("tester").roles("ADMIN")).with(csrf()))
                              .andExpect(status().is3xxRedirection())
                              .andReturn();
        assertThat((String) result.getFlashMap().get("error"))
                .contains("다시 검사하지 못했습니다")
                .contains("JSON");
        assertThat(scans.findByAssetIdOrderByCreatedAtDesc(asset.getId()))
                .as("거절했는데 새 검사가 생겼다")
                .hasSize((int) before);
    }

    @Test
    @DisplayName("서버가 다시 시작되어 중단된 검사는 다시 업로드가 아니라 다시 검사를 안내한다")
    void aStaleScanPointsAtRescan() {
        Scan running = new Scan(asset(), "tester");
        running.setStatus(ScanStatus.RUNNING);
        scans.saveAndFlush(running);

        scanService.reapStale();

        String message = scans.findById(running.getId()).orElseThrow().getErrorMessage();
        assertThat(message)
                .contains("다시 검사")
                .doesNotContain("다시 업로드");
    }

    // --- 씨앗 -------------------------------------------------------------------

    private Asset asset() {
        Asset asset = new Asset();
        asset.setName("failed-" + System.nanoTime());
        asset.setZone(zoneService.unassigned());
        return assets.saveAndFlush(asset);
    }

    private Scan doneScan(Asset asset, Instant at) {
        Scan scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        scan.setSbomFilename("done.sbom.json");
        scan.setCreatedAt(at);
        return scans.saveAndFlush(scan);
    }

    private Scan failedScan(Asset asset, Instant at, String sbom) throws IOException {
        Scan scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.FAILED);
        scan.setErrorMessage(ERROR);
        scan.setSbomFilename("failed.sbom.json");
        scan.setCreatedAt(at);
        scans.saveAndFlush(scan);
        return store(scan, sbom);
    }

    /** 올릴 때처럼 gzip 으로 보관한다. */
    private Scan store(Scan scan, String content) throws IOException {
        Path dir = properties.scanDir(scan.getAsset().getId(), scan.getId());
        Files.createDirectories(dir);
        Path gz = dir.resolve("sbom.json.gz");
        try (OutputStream out = new GZIPOutputStream(Files.newOutputStream(gz))) {
            out.write(content.getBytes(StandardCharsets.UTF_8));
        }
        scan.setSbomPath(gz.toString());
        return scans.saveAndFlush(scan);
    }

    private static String json() {
        return "{\"bomFormat\":\"CycloneDX\",\"components\":[]}";
    }

    private String html(String url) throws Exception {
        return mvc.perform(get(url).with(user("tester").roles("ADMIN")))
                  .andExpect(status().isOk())
                  .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
    }
}
