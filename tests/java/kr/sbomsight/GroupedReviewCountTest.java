package kr.sbomsight;

import kr.sbomsight.domain.*;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.FindingRepository;
import kr.sbomsight.repo.ScanRepository;
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

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * <b>묶은 줄의 `검토` 칸은 그 줄의 수를 말한다</b> — 취약점 화면의 CVE별.
 *
 * <p>줄과 세는 키가 달랐다. CVE별 줄은 (번호, 심각도)인데 수는 번호로만 셌다. 그래서 같은
 * 번호가 심각도로 두 줄로 갈리면 두 줄이 같은 `1 / 2건` 을 말했다 — 한 줄에는 없는 검토가
 * 있다고.
 *
 * <p>여기서 적는 검토 결과의 번호는 그 패키지에만 있어 이름으로 붙어도 다른 패키지에 닿지
 * 않는다. 틀리는 것은 세는 키뿐이다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class GroupedReviewCountTest {

    @Autowired MockMvc mvc;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired FindingAnalysisService analyses;
    @Autowired ZoneService zoneService;

    private Asset asset;
    private Scan scan;

    @BeforeEach
    void setUp() {
        asset = new Asset();
        asset.setName("grouped-" + System.nanoTime());
        asset.setZone(zoneService.create("묶음-" + System.nanoTime(), "", ""));
        assets.saveAndFlush(asset);
        scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        scan.setCreatedAt(Instant.now());
        scans.saveAndFlush(scan);

        // 같은 번호를 두 패키지가 서로 다른 심각도로 받았다 — grype 은 패키지의 생태계마다
        // 그 생태계의 권고문 심각도를 준다.
        finding("CVE-2099-5001", "alpha", "npm", "pkg:npm/alpha@1.0.0", "High");
        finding("CVE-2099-5001", "beta", "python", "pkg:pypi/beta@1.0.0", "Medium");
    }

    @Test
    @DisplayName("CVE별 — 심각도로 갈린 같은 번호의 두 줄이 서로의 검토 수를 합치지 않는다")
    void cveRowsCountTheirOwnRow() throws Exception {
        notAffected("CVE-2099-5001", "alpha");

        String html = open("/vulns?scan=" + scan.getId() + "&group=cve&includeDone=true");
        assertThat(row(html, ">CVE-2099-5001</a>", "<span>높음</span>"))
                .as("검토한 줄(높음)").contains("전부 1건");
        assertThat(row(html, ">CVE-2099-5001</a>", "<span>보통</span>"))
                .as("검토하지 않은 줄(보통)이 옆 줄의 검토를 제 것처럼 말한다")
                .contains("미검토").doesNotContain("/ 2건");
    }

    // -----------------------------------------------------------------------

    private void finding(String cve, String name, String type, String purl, String severity) {
        Finding f = new Finding(scan, cve + "|" + name + "|" + type, cve, name);
        f.setPackageType(type);
        f.setPackagePurl(purl);
        f.setPackageVersion(purl.substring(purl.lastIndexOf('@') + 1));
        f.setSeverity(severity);
        f.setFixState("fixed");
        f.setFixedVersion("9.9.9");
        findings.saveAndFlush(f);
        scan.setFindingCount(scan.getFindingCount() + 1);
        scans.saveAndFlush(scan);
    }

    private void notAffected(String cve, String name) {
        analyses.record(asset, cve, name, AnalysisState.NOT_AFFECTED,
                        AnalysisJustification.CODE_NOT_PRESENT, null, "시험", "", "", null, "tester");
    }

    /** 표의 몸통에서 글자 둘을 다 든 줄 하나 — 없거나 둘이면 시험이 틀린 것이다. */
    private static String row(String html, String first, String second) {
        String body = html.substring(html.indexOf("<tbody>"));
        List<String> rows = Arrays.stream(body.split("<tr"))
                .filter(r -> r.contains(first) && r.contains(second)).toList();
        assertThat(rows).as("%s · %s 줄", first, second).hasSize(1);
        return rows.get(0).replaceAll("\\s+", " ");
    }

    private String open(String url) throws Exception {
        return mvc.perform(get(url).with(user("tester").roles("ADMIN")))
                  .andExpect(status().isOk())
                  .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
    }
}
