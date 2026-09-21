package kr.sbomsight;

import kr.sbomsight.domain.*;
import kr.sbomsight.repo.*;
import kr.sbomsight.service.FindingAnalysisService;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 검토에서 조치로 — <b>같은 일의 앞뒤다.</b>
 *
 * <p>앞서는 조치를 여는 자리가 <b>보고서 3장 하나뿐</b>이었다. 취약점 화면에서
 * 건을 보고 검토 결과를 적은 다음 그것을 조치로 올리려면, 보고서를 새로 만들어
 * 3장까지 내려가야 했다. 화면에는 그 길이 어디에도 적혀 있지 않았고, 대응
 * 화면의 빈 화면은 "취약점 화면에서 패키지를 골라 조치로 등록" 이라고
 * <b>있지도 않은 길을 안내하고 있었다.</b>
 *
 * <p>여기서 고정하는 것 셋.
 *
 * <ol>
 *   <li><b>취약점 표와 검토 결과에서 조치를 연다.</b> 그 화면에는 검사 번호가
 *       없으므로 자산의 최신 완료 검사를 서버가 찾는다.</li>
 *   <li><b>조치는 (자산, 패키지) 하나에 하나다.</b> 같은 패키지의 검토 세 건이
 *       같은 조치 하나를 가리킨다 — 두 번 눌러도 조치가 늘지 않는다.</li>
 *   <li><b>조회 권한은 열 수 없다.</b></li>
 * </ol>
 */
@SpringBootTest
@AutoConfigureMockMvc
/**
 * <b>{@code @Transactional} 이다.</b> 남긴 줄이 그대로 쌓이면 다른 시험이
 * 흔들린다 — 여기서 만든 {@code CVE-2021-44228} 이 남아 "CVE 번호로도
 * 찾힌다" 가 1건 대신 2건을 보게 했다.
 */
@Transactional
class ReviewToActionTest {

    @Autowired MockMvc mvc;
    @Autowired FindingAnalysisService analyses;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired RemediationRepository remediations;
    @Autowired ZoneService zoneService;

    private Asset asset;
    private Scan scan;

    /**
     * 패키지 이름을 판마다 새로 만든다.
     *
     * <p>이 시험은 {@code @Transactional} 이 아니라 남긴 줄이 그대로 쌓인다.
     * 흔한 이름({@code log4j-core})을 쓰면 다른 시험이 남긴 같은 이름의 건이
     * 패키지별 묶음에 함께 세어져, `전부 1건` 이어야 할 자리가 `1 / 4건` 이
     * 된다 — 시험이 제 것만 보게 한다.
     */
    private String pkg;

    @BeforeEach
    void setUp() {
        asset = new Asset();
        asset.setName("r2a-" + System.nanoTime());
        asset.setZone(zoneService.unassigned());
        assets.save(asset);
        pkg = "r2a-pkg-" + System.nanoTime();

        scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        scan.setCreatedAt(Instant.now());
        scans.saveAndFlush(scan);

        Finding f = new Finding(scan, "CVE-2021-44228|" + pkg + "|" + scan.getId(),
                                "CVE-2021-44228", pkg);
        f.setPackageVersion("2.14.1");
        f.setPackageType("java-archive");
        f.setSeverity("Critical");
        f.setFixState("fixed");
        f.setFixedVersion("2.17.0");
        f.setCvssScore(BigDecimal.valueOf(10.0));
        findings.save(f);
    }

    /**
     * 화면에 검사 번호가 없어도 조치를 연다.
     *
     * <p>보고서는 <b>그 검사</b>를 놓고 말하지만 취약점 화면과 검토 결과는
     * <b>지금 상태</b>를 놓고 말한다. 거기서 검사 번호를 물으면 화면이 답할
     * 것이 없다 — 자산의 최신 완료 검사가 곧 지금이다.
     */
    @Test
    @DisplayName("자산에서 조치를 연다 — 등록 당시 버전은 최신 검사 것으로 남는다")
    void anActionOpensFromTheAsset() throws Exception {
        mvc.perform(post("/assets/" + asset.getId() + "/remediations")
                            .param("packageName", pkg)
                            .with(user("tester").roles("ADMIN")).with(csrf()))
           .andExpect(status().is3xxRedirection())
           .andExpect(redirectedUrlPattern("/actions/*"));

        Remediation opened = remediations
                .findByAssetIdAndPackageName(asset.getId(), pkg)
                .orElseThrow(() -> new AssertionError("조치가 안 열렸습니다"));

        assertThat(opened.getFromVersion()).isEqualTo("2.14.1");
        assertThat(opened.getToVersion()).isEqualTo("2.17.0");
        assertThat(opened.getOpenedScanId()).isEqualTo(scan.getId());
        assertThat(opened.getStatus()).isEqualTo(RemediationStatus.OPEN);
    }

    /**
     * <b>두 번 눌러도 조치가 늘지 않는다.</b>
     *
     * <p>조치는 {@code (자산, 패키지)} 하나에 하나다. 검토 결과는
     * {@code (자산, CVE, 패키지)} 하나에 하나라 같은 패키지에 검토가 여럿
     * 달린다 — 그 줄마다 `조치 등록` 이 있으니 두 번 눌리는 것은 예외가
     * 아니라 보통이다. 늘어나면 담당이 갈리고 이력이 쪼개진다.
     */
    @Test
    @DisplayName("같은 패키지에 두 번 눌러도 조치는 하나다")
    void openingTwiceKeepsOneAction() throws Exception {
        for (int i = 0; i < 2; i++) {
            mvc.perform(post("/assets/" + asset.getId() + "/remediations")
                                .param("packageName", pkg)
                                .with(user("tester").roles("ADMIN")).with(csrf()))
               .andExpect(status().is3xxRedirection());
        }
        assertThat(remediations.findByAssetIdOrderByStatusAscPackageNameAsc(asset.getId()))
                .as("두 번 눌러 조치가 둘이 됐다 — 담당이 갈리고 이력이 쪼개진다")
                .hasSize(1);
    }

    /** 등록은 관리자만. 조회 권한에게는 단추도 안 보인다. */
    @Test
    @DisplayName("조회 권한은 조치를 열 수 없다")
    void viewersCannotOpenAnAction() throws Exception {
        mvc.perform(post("/assets/" + asset.getId() + "/remediations")
                            .param("packageName", pkg)
                            .with(user("viewer").roles("VIEWER")).with(csrf()))
           .andExpect(status().isForbidden());

        assertThat(remediations.findByAssetIdAndPackageName(asset.getId(), pkg))
                .isEmpty();
    }

    /**
     * <b>화면에 그 길이 있다.</b>
     *
     * <p>길이 있어도 화면이 안내하지 않으면 없는 것과 같다. 실제로 그랬다 —
     * 조치를 여는 길은 보고서 3장뿐인데 대응 화면은 "취약점 화면에서 패키지를
     * 골라 조치로 등록" 이라고 적고 있었다.
     */
    @Test
    @DisplayName("취약점 표와 검토 결과에 조치 단추가 있다")
    void bothScreensOfferTheButton() throws Exception {
        analyses.record(asset, "CVE-2021-44228", pkg,
                        AnalysisState.EXPLOITABLE, null, AnalysisResponse.UPDATE,
                        "2.17.0 으로 올립니다", "", "", null, "admin");

        String vulns = open("/vulns");
        assertThat(vulns)
                .as("취약점 표에서 조치를 열 수 없다 — 검토를 적은 그 자리에 길이 있어야 한다")
                .contains("/assets/" + asset.getId() + "/remediations");

        String review = open("/actions?tab=analyses");
        assertThat(review)
                .as("검토 결과에서 조치로 넘어갈 수 없다")
                .contains("/assets/" + asset.getId() + "/remediations");

        // 열고 나면 같은 자리가 `조치 등록` 이 아니라 그 조치를 가리킨다.
        mvc.perform(post("/assets/" + asset.getId() + "/remediations")
                            .param("packageName", pkg)
                            .with(user("tester").roles("ADMIN")).with(csrf()));
        Remediation opened = remediations
                .findByAssetIdAndPackageName(asset.getId(), pkg).orElseThrow();

        assertThat(open("/actions?tab=analyses"))
                .as("이미 연 조치가 있는데 `조치 등록` 이 또 떠 있다")
                .contains("/actions/" + opened.getId());
    }

    /**
     * <b>묶은 줄은 검토를 몇 건 중 몇 건 받았는지 말한다.</b>
     *
     * <p>CVE별·패키지별 한 줄은 자산 여러 대·건 여러 개를 묶은 줄이라 검토
     * 결과 하나를 붙일 수 없다. 앞서는 그 칸이 아예 없어서, 그 줄이 검토를
     * 받았는지 알려면 항목별로 돌아가 하나씩 세어야 했다.
     */
    @Test
    @DisplayName("CVE별·패키지별은 검토 진행을 세고 항목별로 보내는 길을 둔다")
    void groupedRowsCountReviewsAndLinkToItems() throws Exception {
        assertThat(open("/vulns?group=cve"))
                .as("CVE별에 검토 진행이 없다").contains("미검토")
                .as("CVE별에서 항목별로 갈 길이 없다").contains("항목별로 보기");

        analyses.record(asset, "CVE-2021-44228", pkg,
                        AnalysisState.IN_TRIAGE, null, null, "", "", "", null, "admin");

        assertThat(open("/vulns?group=package"))
                .as("검토를 적었는데 패키지별 줄이 여전히 미검토라고 말한다")
                .contains("전부 1건");
    }

    private String open(String url) throws Exception {
        return mvc.perform(get(url).with(user("tester").roles("ADMIN")))
                  .andExpect(status().isOk())
                  .andReturn().getResponse().getContentAsString();
    }
}
