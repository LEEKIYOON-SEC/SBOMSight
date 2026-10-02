package kr.sbomsight;

import kr.sbomsight.domain.Asset;
import kr.sbomsight.domain.Scan;
import kr.sbomsight.domain.ScanStatus;
import kr.sbomsight.domain.Zone;
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
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 구역 보고서 1장 — <b>이 기간에 서버를 새로 본 자산과, 옛 SBOM 을 다시 검사만 한 자산을
 * 가른다</b>(R4 · D11).
 *
 * <p>앞서 1장은 `이 기간에 검사한 자산` 한 줄로 셌다. 40일 전에 뜬 SBOM 을 이번 달에
 * 다시 검사해도 그 자산이 "이번 기간에 검사함" 에 들어가(재현 시험 P5), 구역의 몇
 * 대를 이번 기간에 실제로 봤는지 읽을 수 없었다. 가르는 기준은 최신 검사의 SBOM 생성
 * 시각이 기간 안에 있는가다.
 *
 * <p>세 번째 경우가 있다 — 기간이 시작되기 전에 떠 둔 SBOM 을 기간 안에 올렸다. 서버는
 * 이번 기간에 새로 보지 않았고, 다시 검사만 한 것도 아니다.
 */
@SpringBootTest
@AutoConfigureMockMvc
class ZoneCoverageTest {

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
    @DisplayName("1장은 SBOM 이 이 기간에 생성된 자산 · 기간 전 SBOM 을 올린 자산 · 다시 검사만 한 자산을 가른다")
    void chapterOneSplitsTheScannedAssets() throws Exception {
        Zone zone = zoneService.create("범위구역-" + System.nanoTime(), "", "");
        LocalDate from = LocalDate.now().minusDays(7);
        LocalDate to = LocalDate.now();
        Instant now = Instant.now();

        // 기간 안에 뜬 SBOM 을 올렸다.
        upload(asset(zone, "fresh"), now.minus(2, ChronoUnit.DAYS));

        // 40일 전에 뜬 SBOM 을 30일 전에 올렸고, 이번 기간에는 다시 검사만 했다.
        Asset rescanOnly = asset(zone, "rescan-only");
        Scan old = upload(rescanOnly, now.minus(40, ChronoUnit.DAYS));
        old.setCreatedAt(now.minus(30, ChronoUnit.DAYS));
        scans.saveAndFlush(old);
        mvc.perform(post("/scans/" + old.getId() + "/rescan")
                            .with(user("tester").roles("ADMIN")).with(csrf()))
           .andExpect(status().is3xxRedirection());
        FakeGrype.awaitFinished(scans, scans.findByAssetIdOrderByCreatedAtDesc(rescanOnly.getId()).get(0).getId());

        // 20일 전(기간 전)에 뜬 SBOM 을 이번 기간에 올렸다.
        upload(asset(zone, "late"), now.minus(20, ChronoUnit.DAYS));

        // 아무것도 하지 않았다.
        asset(zone, "never");

        String report = page("/reports/zone?zone=" + zone.getId() + "&from=" + from + "&to=" + to);
        assertThat(report).containsPattern(row("이 기간에 검사한 자산", "<b>3</b>대"));
        assertThat(report).containsPattern(row("└ 이 기간에 SBOM이 생성된 자산", "1대"));
        assertThat(report).containsPattern(row("└ 이 기간 전에 생성된 SBOM을 업로드한 자산", "1대"));
        assertThat(report).containsPattern(row("└ 이 기간에 다시 검사만 한 자산", "1대"));
        assertThat(report).containsPattern(row("검사 기록이 없는 자산", "1대"));
    }

    @Test
    @DisplayName("3장의 자산 줄은 기준이 된 검사의 SBOM 생성 시각을 함께 적는다")
    void chapterThreeShowsTheSbomTime() throws Exception {
        Zone zone = zoneService.create("범위구역-" + System.nanoTime(), "", "");
        upload(asset(zone, "row"), Instant.now().minus(40, ChronoUnit.DAYS));

        String report = page("/reports/zone?zone=" + zone.getId()
                             + "&from=" + LocalDate.now().minusDays(7) + "&to=" + LocalDate.now());
        assertThat(report).contains("<th class=\"tight\">SBOM 생성 시각</th>");
    }

    // --- 씨앗 -------------------------------------------------------------------------

    /** 1장 표의 한 줄 — 이름 칸 다음 칸에 그 값. 칸 안의 꾸밈은 건너뛴다. */
    private static Pattern row(String label, String value) {
        return Pattern.compile("(?s)<td[^>]*>\\s*" + Pattern.quote(label) + "\\s*</td>\\s*<td[^>]*>\\s*"
                               + Pattern.quote(value));
    }

    private Asset asset(Zone zone, String prefix) {
        Asset asset = new Asset();
        asset.setName(prefix + "-" + System.nanoTime());
        asset.setZone(zone);
        asset = assets.saveAndFlush(asset);
        made.add(asset.getId());
        return asset;
    }

    private Scan upload(Asset asset, Instant sbomAt) throws Exception {
        String sbom = CurrentScanRuleTest.cyclonedx(sbomAt.truncatedTo(ChronoUnit.MINUTES), "1.1.1k",
                                                    CurrentScanRuleTest.V1);
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
}
