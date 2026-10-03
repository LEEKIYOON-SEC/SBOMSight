package kr.sbomsight;

import kr.sbomsight.domain.Asset;
import kr.sbomsight.domain.RemediationStatus;
import kr.sbomsight.domain.Zone;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.RemediationRepository;
import kr.sbomsight.repo.ScanRepository;
import kr.sbomsight.service.AssetService;
import kr.sbomsight.service.GrypeRunner;
import kr.sbomsight.service.ZoneReportService;
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
import org.springframework.test.web.servlet.MvcResult;

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
 * <b>조치 회차</b>(R7 · D5) — 닫힌 조치가 있는 패키지에 `조치 등록` 을 누르면 새 조치를 연다.
 * 새 조치는 이전 조치를 가리킨다. `다시 열기` 는 잘못 닫은 것을 바로잡을 때만 쓴다.
 *
 * <p>앞서 조치는 (자산, 패키지)에 하나뿐이었다(유일 키). 완료한 뒤 같은 패키지에 새
 * 취약점이 나오면 `조치 등록` 은 그 완료된 조치로 보냈고 목표 버전도 옛것이었다.
 * 담당자는 완료를 다시 열 수밖에 없었고, 다시 열면 완료 시각이 지워져 구역 보고서의
 * `기간 중 완료` 에서 그 완료가 사라졌다(재현 시험 P2).
 *
 * <p>업로드부터 화면까지 실제 길로 돈다 — 검사는 {@link FakeGrype} 의 미리 만든 결과다.
 * sbom-v1 은 openssl 1.1.1k(CVE-2023-0001 → 1.1.1n), sbom-v2 는 1.1.1n 으로 올린 뒤
 * (CVE-2023-0001 은 사라지고 CVE-2024-0002 → 1.1.1w)다.
 */
@SpringBootTest
@AutoConfigureMockMvc
class RemediationRoundTest {

    @Autowired MockMvc mvc;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired RemediationRepository remediations;
    @Autowired AssetService assetService;
    @Autowired ZoneService zoneService;
    @Autowired ZoneReportService zoneReports;

    @MockBean GrypeRunner grype;

    private RemediationSteps steps;
    private Zone zone;
    private final List<Long> made = new ArrayList<>();

    @BeforeEach
    void setUp() {
        FakeGrype.on(grype);
        steps = new RemediationSteps(mvc, scans);
        zone = zoneService.create("회차-" + System.nanoTime(), "#123456", "");
    }

    @AfterEach
    void cleanUp() {
        made.forEach(id -> assets.findById(id).ifPresent(a -> assetService.delete(a, "tester")));
        zoneService.delete(zone.getId());
    }

    @Test
    @DisplayName("닫힌 조치가 있는 패키지에 조치 등록 — 2회차가 이전 조치를 가리키고, 앞 회차의 완료는 그대로 센다")
    void aClosedRemediationOpensTheNextRound() throws Exception {
        Asset asset = asset("round");
        steps.upload(asset, Instant.now().minus(10, ChronoUnit.DAYS), "1.1.1k", CurrentScanRuleTest.V1);
        long first = idOf(steps.register(asset, "openssl"));
        steps.save(first, "DONE", "1.1.1n 적용");

        // 고친 뒤의 SBOM — CVE-2023-0001 은 사라지고 CVE-2024-0002 가 새로 나왔다.
        steps.uploadNow(asset, "1.1.1n", CurrentScanRuleTest.V2);
        MvcResult again = steps.register(asset, "openssl");
        long second = idOf(again);
        assertThat(second).as("완료한 조치로 보냈다 — 새 조치를 열지 않았다").isNotEqualTo(first);
        assertThat(again.getFlashMap().get("message")).isEqualTo("openssl 조치를 2회차로 등록했습니다.");

        String detail = tight(steps.page("/actions/" + second));
        assertThat(detail).contains("조치 회차</th><td>2</td>")
                          .contains("이전 조치</th><td><a href=\"/actions/" + first + "\"");
        assertThat(remediations.findById(second).orElseThrow().getToVersions())
                .as("새 회차의 목표는 지금 검사의 수정 버전").containsExactly("1.1.1w");
        assertThat(remediations.findById(first).orElseThrow().getStatus())
                .as("앞 회차는 완료 그대로").isEqualTo(RemediationStatus.DONE);

        LocalDate today = LocalDate.now();
        ZoneReportService.Action action = zoneReports.build(zone.getId(), today, today).action();
        assertThat(action.closedInPeriod()).as("앞 회차의 완료가 기간 중 완료에서 사라졌다").isEqualTo(1);
        assertThat(action.openedInPeriod()).isEqualTo(2);

        // 열린 회차가 있으면 그것으로 보낸다 — 두 번 눌러도 3회차가 생기지 않는다.
        MvcResult third = steps.register(asset, "openssl");
        assertThat(idOf(third)).isEqualTo(second);
        assertThat(third.getFlashMap().get("message")).isEqualTo("openssl 조치는 이미 등록되어 있습니다.");
        assertThat(remediations.findByAssetIdOrderByStatusAscPackageNameAsc(asset.getId())).hasSize(2);

        // 조치 목록은 회차를 칸으로 적는다(패키지 바로 뒤) — 같은 패키지의 두 줄이 구별된다.
        String list = steps.page("/actions?zone=" + zone.getId());
        assertThat(tight(row(list, "href=\"/actions/" + second + "\"")))
                .contains(">openssl</a></td><td class=\"num tight\">2</td>");
        assertThat(tight(row(list, "href=\"/actions/" + first + "\"")))
                .contains(">openssl</a></td><td class=\"num tight\">1</td>");
    }

    @Test
    @DisplayName("다시 열기는 최신 회차만 — 뒤 회차가 이어받은 조치는 다시 열지 않는다")
    void onlyTheLatestRoundCanBeReopened() throws Exception {
        Asset asset = asset("reopen");
        steps.upload(asset, Instant.now().minus(10, ChronoUnit.DAYS), "1.1.1k", CurrentScanRuleTest.V1);
        long first = idOf(steps.register(asset, "openssl"));
        steps.save(first, "DONE", "");
        steps.uploadNow(asset, "1.1.1n", CurrentScanRuleTest.V2);
        long second = idOf(steps.register(asset, "openssl"));
        assertThat(second).isNotEqualTo(first);

        MvcResult refused = steps.save(first, "IN_PROGRESS", "다시 엶");
        assertThat((String) refused.getFlashMap().get("error"))
                .as("뒤 회차가 있는데 앞 회차를 다시 열었다 — 열린 조치가 둘이 된다")
                .contains("다시 열 수 없습니다");
        assertThat(remediations.findById(first).orElseThrow().getStatus()).isEqualTo(RemediationStatus.DONE);

        // 최신 회차는 잘못 닫은 것을 바로잡을 수 있다.
        steps.save(second, "DONE", "");
        steps.save(second, "IN_PROGRESS", "잘못 닫음");
        assertThat(remediations.findById(second).orElseThrow().getStatus())
                .isEqualTo(RemediationStatus.IN_PROGRESS);
    }

    @Test
    @DisplayName("기간 중 완료는 이력의 완료 줄로 센다 — 다시 열어도 그 완료는 있었던 일이다")
    void completionsInThePeriodComeFromHistory() throws Exception {
        Asset asset = asset("closed");
        steps.upload(asset, Instant.now().minus(10, ChronoUnit.DAYS), "1.1.1k", CurrentScanRuleTest.V1);
        long id = idOf(steps.register(asset, "openssl"));
        steps.save(id, "DONE", "");
        steps.save(id, "IN_PROGRESS", "덜 됐다 — 다시 엶");

        LocalDate today = LocalDate.now();
        assertThat(zoneReports.build(zone.getId(), today, today).action().closedInPeriod())
                .as("완료 시각 칸으로 세어, 다시 연 순간 그 완료가 사라졌다")
                .isEqualTo(1);
    }

    @Test
    @DisplayName("조치는 등록 당시의 탐지를 대상으로 남긴다 — 최신 검사에 아직 있는지 함께")
    void registrationKeepsItsTargets() throws Exception {
        Asset asset = asset("targets");
        steps.upload(asset, Instant.now().minus(10, ChronoUnit.DAYS), "1.1.1k", CurrentScanRuleTest.V1);
        long id = idOf(steps.register(asset, "openssl"));

        String before = steps.page("/actions/" + id);
        assertThat(before).contains("<h2>조치 대상</h2>");
        assertThat(tight(row(before, ">CVE-2023-0001<")))
                .contains(">1.1.1k<").contains(">1.1.1n<").contains("<td>있음</td>");

        // 올린 뒤 — 대상은 그대로, 최신 검사에는 없다.
        steps.uploadNow(asset, "1.1.1n", CurrentScanRuleTest.V2);
        String after = steps.page("/actions/" + id);
        assertThat(tight(row(after, ">CVE-2023-0001<"))).contains("<td>없음</td>");
        assertThat(after).as("대상은 등록 당시의 것 — 나중 검사의 탐지를 더하지 않는다")
                         .doesNotContain(">CVE-2024-0002<");
    }

    /**
     * 표는 화면에 찍는 번호(함께 온 CVE)를 크게 쓰므로 그 순서로 싣는다. 주 식별자(GHSA)
     * 순으로 실으면 CVE-2026 줄이 CVE-2025 줄보다 먼저 오는 등 읽는 순서가 어긋났다
     * (실제 앱 확인에서 lodash 2회차). 결과 파일(fake-grype/sbom-two.json)은 GHSA 순과
     * CVE 순이 반대인 탐지 둘이다.
     */
    @Test
    @DisplayName("조치 대상은 화면에 찍는 번호 순이다 — 주 식별자(GHSA) 순이 아니다")
    void targetsAreInTheOrderOfTheNumbersShown() throws Exception {
        Asset asset = asset("order");
        steps.upload(asset, Instant.now().minus(10, ChronoUnit.DAYS), "1.1.1k", "sbom-two");
        long id = idOf(steps.register(asset, "openssl"));

        String html = steps.page("/actions/" + id);
        int older = html.indexOf(">CVE-2021-2222<");
        int newer = html.indexOf(">CVE-2025-1111<");
        assertThat(older).as("두 대상이 다 실려야 한다").isPositive();
        assertThat(newer).isPositive();
        assertThat(older).as("CVE-2021 줄이 CVE-2025 줄보다 앞이어야 한다").isLessThan(newer);
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
