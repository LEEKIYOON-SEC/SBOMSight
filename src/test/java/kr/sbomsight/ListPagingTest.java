package kr.sbomsight;

import kr.sbomsight.domain.*;
import kr.sbomsight.repo.*;
import kr.sbomsight.service.Paging;
import kr.sbomsight.service.ZoneService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 목록은 <b>전부 같은 방식으로 끝난다.</b>
 *
 * <p>앞서는 화면마다 달랐다. 취약점과 감사 로그만 쪽 넘김이 있었고, 패키지는
 * <b>앞 200개에서 말없이 잘렸으며</b>, 자산의 패키지 탭·CVE별·패키지별·조치·
 * 검토 결과·보고서 만들기·CVE 상세는 몇 천 줄이든 한 쪽에 쏟아졌다. 어느
 * 화면에서 무엇이 잘렸는지 알 방법이 없었고, 4천 줄짜리 표는 끝나지 않았다.
 *
 * <p>여기서 고정하는 것 셋.
 *
 * <ol>
 *   <li><b>목록이 있는 화면에는 건수 줄과 쪽 넘김이 있다.</b> 한 곳만 빠져도
 *       그 화면에서는 뒤가 안 보인다.</li>
 *   <li><b>거르개는 자르기 전에 걸린다.</b> 자른 뒤에 걸면 201번째 이후에
 *       있는 것은 거르개에 걸리지도, 수에 들어가지도 않는다.</li>
 *   <li><b>머리의 수는 거른 뒤 전체다.</b> 쪽에 실린 줄 수를 찍으면 `100건`
 *       인데 쪽이 다섯인 화면이 된다.</li>
 * </ol>
 *
 * <p><b>{@code @Transactional} 이다.</b> 240개 넘는 씨앗을 남기면 다른 시험의
 * 목록·건수가 흔들린다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class ListPagingTest {

    @Autowired MockMvc mvc;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired ComponentRepository components;
    @Autowired ZoneRepository zones;
    @Autowired ZoneService zoneService;

    private Zone zone;

    @BeforeEach
    void setUp() {
        zone = zones.findByName("DMZ").orElseGet(() -> zoneService.create("DMZ", "#a71922", ""));
    }

    // --- Paging.slice ---------------------------------------------------------

    /**
     * <b>범위를 넘은 쪽 번호는 마지막 쪽으로.</b>
     *
     * <p>3쪽을 보다가 거르개를 좁히거나 한 줄을 지우면 주소에 남은
     * {@code page=2} 가 갈 곳을 잃는다. 그때 빈 표를 내밀면 "조건에 맞는
     * 것이 없다" 로 읽힌다 — 실제로는 있고, 한 쪽 앞에 있다.
     */
    @Test
    @DisplayName("범위를 넘은 쪽 번호는 마지막 쪽으로 되돌린다")
    void outOfRangePageFallsBackToTheLastOne() {
        List<Integer> all = new ArrayList<>();
        for (int i = 0; i < 25; i++) {
            all.add(i);
        }

        assertThat(Paging.slice(all, 0, 10).getContent()).containsExactly(0, 1, 2, 3, 4, 5, 6, 7, 8, 9);
        assertThat(Paging.slice(all, 2, 10).getContent()).containsExactly(20, 21, 22, 23, 24);

        var beyond = Paging.slice(all, 9, 10);
        assertThat(beyond.getNumber()).as("갈 곳 없는 쪽은 마지막 쪽으로").isEqualTo(2);
        assertThat(beyond.getContent()).containsExactly(20, 21, 22, 23, 24);
        assertThat(beyond.getTotalElements()).isEqualTo(25);

        assertThat(Paging.slice(List.of(), 3, 10).getContent()).isEmpty();
        assertThat(Paging.slice(List.of(), 3, 10).getNumber()).isZero();
    }

    /** 고를 수 있는 값만 받는다 — 손으로 적은 `size=50000` 이 질의로 들어가면 안 된다. */
    @Test
    @DisplayName("쪽 크기는 고를 수 있는 값만 받는다")
    void onlyOfferedSizesAreHonoured() {
        assertThat(Paging.PAGE_SIZES).containsExactly(10, 30, 50, 100);
        for (int offered : Paging.PAGE_SIZES) {
            assertThat(Paging.sizeOf(offered)).isEqualTo(offered);
        }
        for (Integer bad : new Integer[] {null, 0, -1, 7, 50_000}) {
            assertThat(Paging.sizeOf(bad)).isEqualTo(Paging.PAGE_SIZE);
        }
    }

    // --- 화면 ------------------------------------------------------------------

    /**
     * <b>목록이 있는 화면은 전부 쪽으로 끝난다.</b>
     *
     * <p>한 화면만 빠져도 그 화면에서는 뒤가 안 보인다 — 그리고 빠진 화면은
     * 누가 열어 보기 전까지 아무도 모른다. 조합을 하나씩 눌러 보지 않는다.
     */
    @Test
    @DisplayName("목록 화면에는 건수 줄과 쪽 넘김이 있다")
    void everyListScreenPages() throws Exception {
        Asset asset = seedAsset("pg");
        Scan scan = seedScan(asset);
        for (int i = 0; i < 14; i++) {
            seedFinding(scan, "CVE-2024-%05d".formatted(i), "pkg-" + i);
            seedComponent(asset, scan, "pkg-" + i, "1.0." + i);
        }

        List<String> screens = List.of(
                "/?size=10",                                  // 자산 목록
                "/vulns?size=10",                             // 항목별
                "/vulns?group=cve&size=10",                   // CVE별
                "/vulns?group=package&size=10",               // 패키지별
                "/vulns/CVE-2024-00000?size=10",              // CVE 상세
                "/packages?size=10",                          // 패키지
                "/assets/" + asset.getId() + "?tab=vulns&size=10",
                "/assets/" + asset.getId() + "?tab=packages&size=10",
                "/assets/" + asset.getId() + "?tab=history&size=10",
                "/actions?size=10",
                "/actions?tab=analyses&size=10",
                "/reports?size=10",
                "/settings/audit?size=10");

        for (String url : screens) {
            String html = open(url);
            assertThat(html)
                    .as("%s — 건수 줄(쪽 크기 고르개)이 없다", url)
                    .contains("페이지 사이즈");
        }

        // 열넷은 한 쪽(10)에 안 들어간다 — 그러면 쪽 넘김이 그려져야 한다.
        for (String url : List.of("/vulns?size=10", "/vulns?group=cve&size=10",
                                  "/vulns?group=package&size=10",
                                  "/assets/" + asset.getId() + "?tab=vulns&size=10",
                                  "/assets/" + asset.getId() + "?tab=packages&size=10",
                                  "/packages?size=10")) {
            assertThat(open(url))
                    .as("%s — 14줄인데 쪽 넘김이 없다. 10줄만 보이고 나머지는 갈 곳이 없다", url)
                    .contains("name=\"jump\"");
        }
    }

    /**
     * <b>묶어 세는 화면의 단위는 `건` 이 아니다.</b>
     *
     * <p>CVE별 머리에 `14건` 이라고 적으면 탐지 건수로 읽힌다 — 한 가지가
     * 자산 열 대에 있으면 탐지는 열 건이다. 두 수가 같은 것으로 읽히면
     * 보고받는 사람이 어느 쪽을 믿을지 물을 자리가 없다.
     */
    @Test
    @DisplayName("묶어 세는 화면은 세는 단위를 말한다")
    void groupedScreensNameWhatTheyCount() throws Exception {
        Asset asset = seedAsset("unit");
        Scan scan = seedScan(asset);
        seedFinding(scan, "CVE-2024-11111", "openssl");

        assertThat(open("/vulns?group=cve")).contains("가지");
        assertThat(open("/vulns?group=package")).contains("개");
    }

    /**
     * <b>같은 `패키지` 를 세는 세 화면이 세는 단위를 말한다.</b>
     *
     * <p>쓰는 사람이 물었다 — "취약점탭에서 결국 패키지별로 볼 수 있는데
     * 패키지탭은 왜 별도로 있는거야? 근데 왜 서로 개수가 달라?"
     *
     * <pre>
     *   /packages                  인벤토리의 **이름** 수
     *   /assets/{id}?tab=packages  그 자산의 **설치 줄** 수 (이름+버전+경로)
     *   /vulns?group=package       grype 이 **탐지를 낸 이름** 수
     * </pre>
     *
     * <p>셋 다 맞는 수다. 무엇을 세는지 화면이 말하지 않으면 어느 쪽이
     * 맞는지 물어볼 자리가 없고, 그 순간 세 수가 다 못 미덥게 된다.
     */
    @Test
    @DisplayName("패키지를 세는 세 화면이 세는 단위를 말한다")
    void threePackageScreensSayWhatTheyCount() throws Exception {
        Asset asset = seedAsset("unit3");
        Scan scan = seedScan(asset);
        seedComponent(asset, scan, "openssl", "3.0.7");
        seedFinding(scan, "CVE-2024-22222", "openssl");

        assertThat(open("/packages"))
                .as("패키지 화면이 이름을 센다는 말이 없다").contains("패키지 이름")
                .as("탐지가 없는 것도 여기 있다는 말이 없다").contains("깔린 것 전부");
        assertThat(open("/vulns?group=package"))
                .as("탐지가 난 것만 센다는 말이 없다").contains("탐지가 난 패키지 이름");
        assertThat(open("/assets/" + asset.getId() + "?tab=packages"))
                .as("설치 줄을 센다는 말이 없다").contains("설치된 줄");
    }

    /**
     * <b>구역을 고르면 머리의 수도 그 구역 것이다.</b>
     *
     * <p>자산 목록의 구역 칩은 거르개다. 앞서 줄 목록은 구역을 보지 않았고,
     * 구역을 좁히는 일은 화면을 그리는 쪽에서만 했다 — 세는 자리가 없을
     * 때는 티가 안 났는데, 건수 줄을 붙이자 구역을 고른 화면 머리에 전체
     * 자산 수가 적히고 표에는 그 구역 것만 남았다. 어느 쪽이 맞는지 물어볼
     * 자리가 없다.
     *
     * <p><b>구역 카드 보기는 자르지 않는다.</b> 카드 한 장이 곧 구역 하나의
     * 요약이라, 자르면 자산이 뒷쪽에 있는 구역의 카드가 통째로 사라진다.
     */
    @Test
    @DisplayName("구역을 고르면 머리의 수와 표의 줄 수가 같다")
    void pickingAZoneNarrowsTheCountToo() throws Exception {
        Zone other = zones.findByName("내부업무")
                          .orElseGet(() -> zoneService.create("내부업무", "#c3571a", ""));
        Asset here = seedAsset("in-dmz");
        Asset there = seedAsset("in-other");
        there.setZone(other);
        assets.save(there);

        String html = open("/?zone=" + other.getId() + "&size=10");
        int shown = html.split("zone-item", -1).length - 1;
        assertThat(html)
                .as("고른 구역의 자산이 안 보인다")
                .contains(there.getName())
                .as("다른 구역의 자산이 섞여 나온다")
                .doesNotContain(here.getName());

        // 머리의 수 = 그 구역의 자산 수. 표에 실린 줄 수와 같아야 한다.
        long inOther = assets.findLiveWithZone().stream()
                             .filter(a -> a.getZone().getId().equals(other.getId()))
                             .count();
        assertThat(html)
                .as("구역을 골랐는데 머리에 전체 자산 수가 적혀 있다 (표에는 %d줄)", shown)
                .contains(">" + inOther + "</b>");

        // 카드 보기는 자르지 않는다 — 구역이 다 있어야 한다.
        assertThat(open("/?view=zones"))
                .as("구역 카드에서 구역 하나가 사라졌다")
                .contains(zone.getName()).contains(other.getName());
    }

    /**
     * <b>거르개는 자르기 전에 걸린다.</b>
     *
     * <p>이것이 이 판에서 고친 가장 조용한 버그다. 앞서 패키지 화면은 이름
     * 전체를 자산 수 순으로 줄 세운 뒤 <b>앞 200개를 자르고, 그러고 나서</b>
     * `취약점 있는 것만` 을 걸었다. 그래서 201번째 이후에 있는 취약한
     * 패키지는 화면에도 수에도 나오지 않았다 — 잘렸다는 각주는 있었지만,
     * 각주는 "거르개가 전부를 보지 못한다" 는 말까지 하지는 않는다.
     *
     * <p>취약한 패키지 하나를 <b>자산 수가 가장 적게</b> 두어 줄의 맨 뒤로
     * 보낸다. 고치기 전 코드에서는 이 시험이 그 패키지를 찾지 못한다.
     */
    @Test
    @DisplayName("취약점 거르개는 앞 200개가 아니라 전부에서 찾는다")
    void theVulnerableFilterLooksPastTheFirstPage() throws Exception {
        // 자산 둘. 흔한 패키지는 둘 다에, 찾는 것은 한 대에만 — 자산 수
        // 내림차순이라 찾는 것이 맨 뒤로 간다.
        Asset busy = seedAsset("busy");
        Asset lone = seedAsset("lone");
        Scan busyScan = seedScan(busy);
        Scan loneScan = seedScan(lone);

        for (int i = 0; i < 240; i++) {
            String name = "filler-%03d".formatted(i);
            seedComponent(busy, busyScan, name, "1.0.0");
            seedComponent(lone, loneScan, name, "1.0.0");
        }
        // 줄의 맨 뒤 — 자산 한 대에만 깔려 있다.
        seedComponent(lone, loneScan, "zzz-buried", "1.0.0");
        seedFinding(loneScan, "CVE-2024-99999", "zzz-buried");

        String html = open("/packages?vulnerable=true");
        assertThat(html)
                .as("앞 200개를 자른 뒤에 걸러서, 241번째에 있는 취약한 패키지를 못 찾았다")
                .contains("zzz-buried");
    }

    // --- 씨앗 --------------------------------------------------------------------

    private String open(String url) throws Exception {
        return mvc.perform(get(url).with(user("tester").roles("ADMIN")))
                  .andExpect(status().isOk())
                  .andReturn().getResponse().getContentAsString();
    }

    private Asset seedAsset(String prefix) {
        Asset a = new Asset();
        a.setName(prefix + "-" + System.nanoTime());
        a.setZone(zone);
        return assets.save(a);
    }

    private Scan seedScan(Asset asset) {
        Scan s = new Scan(asset, "tester");
        s.setStatus(ScanStatus.DONE);
        s.setCreatedAt(Instant.now());
        return scans.saveAndFlush(s);
    }

    private void seedFinding(Scan scan, String cve, String pkg) {
        Finding f = new Finding(scan, cve + "|" + pkg + "|" + scan.getId(), cve, pkg);
        f.setPackageVersion("1.0.0");
        f.setPackageType("rpm");
        f.setSeverity("High");
        f.setFixState("fixed");
        f.setFixedVersion("1.0.1");
        f.setCvssScore(BigDecimal.valueOf(7.5));
        findings.save(f);
    }

    private void seedComponent(Asset asset, Scan scan, String name, String version) {
        components.save(new Component(asset, scan, name, version, "rpm",
                                      "pkg:rpm/rocky/" + name + "@" + version,
                                      "/usr/lib/" + name));
    }
}
