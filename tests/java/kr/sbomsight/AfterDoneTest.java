package kr.sbomsight;

import kr.sbomsight.domain.Asset;
import kr.sbomsight.domain.Scan;
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
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

import static kr.sbomsight.RemediationSteps.idOf;
import static kr.sbomsight.RemediationSteps.row;
import static kr.sbomsight.RemediationSteps.tight;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * <b>완료한 조치의 패키지에 해소 건수가 남았을 때 — 세 갈래</b>(R10 · D11).
 *
 * <ul>
 *   <li><b>완료 · 탐지 남음</b> — 고친 뒤의 SBOM 에 조치 대상이 남았다. 조치가 덜 됐다.</li>
 *   <li><b>완료 · 신규 탐지</b> — 고친 뒤의 SBOM 에 남은 것이 조치 대상이 아니었다. 조치는
 *       됐고 새 조치가 필요하다 — 그 옆에 `조치 등록` 을 둔다.</li>
 *   <li><b>완료 · 검증 대기</b> — 지금 SBOM 이 조치 완료보다 앞이다. 고치기 전의 서버를 보고
 *       있으니 남는 것이 당연하고, 새 SBOM 을 올리면 풀린다.</li>
 * </ul>
 *
 * <p>앞서는 셋을 가르지 못해 모두 `완료 · 탐지 남음` 이었다 — 조치는 했는데 SBOM 을 아직
 * 못 뜬 자산이 "조치가 안 됐다" 로 읽혔다(재현 시험 P10). 조치 상세 · 조치 목록 · 자산의
 * 조치 탭 · 취약점 표 · 조치 CSV · 자산 보고서 5장 · 구역 보고서 6장이 같은 규칙으로 말한다.
 */
@SpringBootTest
@AutoConfigureMockMvc
class AfterDoneTest {

    /** 탐지가 하나도 없는 검사 결과(fake-grype/sbom-none.json). */
    private static final String NONE = "sbom-none";

    @Autowired MockMvc mvc;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired AssetService assetService;
    @Autowired ZoneService zoneService;

    @MockBean GrypeRunner grype;

    private RemediationSteps steps;
    private Zone zone;
    private final List<Long> made = new ArrayList<>();

    @BeforeEach
    void setUp() {
        FakeGrype.on(grype);
        steps = new RemediationSteps(mvc, scans);
        zone = zoneService.create("완료뒤-" + System.nanoTime(), "#123456", "");
    }

    @AfterEach
    void cleanUp() {
        made.forEach(id -> assets.findById(id).ifPresent(a -> assetService.delete(a, "tester")));
        zoneService.delete(zone.getId());
    }

    @Test
    @DisplayName("고친 뒤의 SBOM 에 조치 대상이 남았다 — 완료 · 탐지 남음")
    void aTargetLeftAfterTheFixSaysRemaining() throws Exception {
        Asset asset = asset("remain");
        steps.upload(asset, Instant.now().minus(10, ChronoUnit.DAYS), "1.1.1k", CurrentScanRuleTest.V1);
        long id = idOf(steps.register(asset, "openssl"));
        steps.save(id, "DONE", "1.1.1n 적용");
        // 올렸다고 했는데 다시 뜬 SBOM 에 그대로다.
        steps.uploadNow(asset, "1.1.1k", CurrentScanRuleTest.V1);

        everyScreenSays(asset, id, "완료 · 탐지 남음", "CVE-2023-0001");
        assertThat(steps.page("/actions/" + id)).doesNotContain("완료 · 신규 탐지").doesNotContain("완료 · 검증 대기");
    }

    @Test
    @DisplayName("고친 뒤의 SBOM 에 남은 것이 조치 대상이 아니다 — 완료 · 신규 탐지, 옆에 조치 등록")
    void onlyNewFindingsSayNew() throws Exception {
        Asset asset = asset("new");
        steps.upload(asset, Instant.now().minus(10, ChronoUnit.DAYS), "1.1.1k", CurrentScanRuleTest.V1);
        long id = idOf(steps.register(asset, "openssl"));
        steps.save(id, "DONE", "1.1.1n 적용");
        // 1.1.1n 으로 올랐다 — CVE-2023-0001 은 사라지고 CVE-2024-0002 가 새로 나왔다.
        steps.uploadNow(asset, "1.1.1n", CurrentScanRuleTest.V2);

        everyScreenSays(asset, id, "완료 · 신규 탐지", "CVE-2024-0002");

        // 새 조치는 그 옆 단추로 연다 — 조치 상세와 취약점 표.
        String register = "action=\"/assets/" + asset.getId() + "/remediations\"";
        assertThat(steps.page("/actions/" + id)).contains(register);
        assertThat(row(steps.page("/assets/" + asset.getId() + "?tab=vulns"), ">CVE-2024-0002<"))
                .contains(register).contains("조치 등록");
        assertThat(idOf(steps.register(asset, "openssl"))).as("새 조치(2회차)를 연다").isNotEqualTo(id);
    }

    @Test
    @DisplayName("지금 SBOM 이 조치 완료보다 앞이다 — 완료 · 검증 대기 (다시 검사해도 SBOM 은 그대로)")
    void anSbomOlderThanTheCompletionSaysPending() throws Exception {
        Asset asset = asset("pending");
        Scan old = steps.upload(asset, Instant.now().minus(40, ChronoUnit.DAYS), "1.1.1k",
                                CurrentScanRuleTest.V1);
        long id = idOf(steps.register(asset, "openssl"));
        steps.save(id, "DONE", "1.1.1n 적용 — SBOM 은 아직 못 뜸");
        // 취약점 DB 가 바뀌어 최신 줄을 다시 검사했다 — 서버를 다시 읽은 것이 아니다.
        steps.rescan(asset, old);

        everyScreenSays(asset, id, "완료 · 검증 대기", "CVE-2023-0001");
        assertThat(steps.page("/actions/" + id)).doesNotContain("완료 · 탐지 남음")
                .as("어떻게 풀리는지 말한다").contains("새 SBOM을 업로드하면 풀림");

        // 고친 뒤에 뜬 SBOM 을 업로드하면 그것으로 다시 가른다 — 1.1.1n, 남은 것은 새 취약점.
        steps.uploadNow(asset, "1.1.1n", CurrentScanRuleTest.V2);
        assertThat(steps.page("/actions/" + id))
                .contains("완료 · 신규 탐지 — 해소 건수 1건").doesNotContain("완료 · 검증 대기");
    }

    /**
     * 등록할 때 그 패키지에 탐지가 없었다 — 검토 결과 탭의 `조치 등록` 은 지금 검사에 없는
     * 패키지도 연다. 조치 대상이 <b>없다고 알려진</b> 조치라, 남은 것은 모두 조치 대상이
     * 아니다. 대상을 <b>모르는</b> 옛 조치(등록한 검사가 지워짐 — 등록 당시 건수는 있다)와
     * 다르다 — 그쪽은 가를 근거가 없어 탐지 남음이다. 상세 화면이 `등록 당시 탐지 없음` 이라
     * 적으면서 상태는 `탐지 남음` 이라 말하면 한 화면이 두 말을 한다.
     */
    @Test
    @DisplayName("등록할 때 탐지가 없던 조치 — 남은 것은 모두 조치 대상이 아니다: 완료 · 신규 탐지")
    void nothingTargetedSaysNew() throws Exception {
        Asset asset = asset("none");
        steps.upload(asset, Instant.now().minus(10, ChronoUnit.DAYS), "1.1.1n", NONE);
        long id = idOf(steps.register(asset, "openssl"));
        assertThat(steps.page("/actions/" + id)).contains("등록 당시 탐지 없음");
        steps.save(id, "DONE", "점검 창에서 확인");
        steps.uploadNow(asset, "1.1.1n", CurrentScanRuleTest.V2);

        everyScreenSays(asset, id, "완료 · 신규 탐지", "CVE-2024-0002");
    }

    /** 조치 상세 · 조치 목록 · 자산의 조치 탭 · 취약점 표 · CSV · 두 보고서가 같은 말. */
    private void everyScreenSays(Asset asset, long id, String label, String cve) throws Exception {
        assertThat(steps.page("/actions/" + id)).as("조치 상세").contains(label + " — 해소 건수 1건");
        assertThat(row(steps.page("/actions?zone=" + zone.getId()), "href=\"/actions/" + id + "\""))
                .as("조치 목록").contains(label);
        assertThat(row(steps.page("/assets/" + asset.getId() + "?tab=actions"), "href=\"/actions/" + id + "\""))
                .as("자산의 조치 탭").contains(label);
        assertThat(row(steps.page("/assets/" + asset.getId() + "?tab=vulns"), ">" + cve + "<"))
                .as("취약점 표의 조치 칸").contains(">" + label + "</a>");
        assertThat(steps.page("/actions/export.csv?zone=" + zone.getId()))
                .as("조치 CSV").contains("\"" + label + "\"");

        Scan latest = scans.currentOf(asset.getId()).orElseThrow();
        assertThat(tight(steps.page("/reports/scan/" + latest.getId())))
                .as("자산 보고서 5장").contains(label + "</td><td class=\"num tight\">1개</td>");
        LocalDate today = LocalDate.now();
        assertThat(tight(steps.page("/reports/zone?zone=" + zone.getId() + "&from=" + today + "&to=" + today)))
                .as("구역 보고서 6장").contains(label + "</td><td class=\"num tight\">1개</td>");
    }

    private Asset asset(String prefix) {
        Asset asset = new Asset();
        asset.setName(prefix + "-" + System.nanoTime());
        asset.setZone(zone);
        asset = assets.saveAndFlush(asset);
        made.add(asset.getId());
        return asset;
    }
}
