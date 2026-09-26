package kr.sbomsight;

import kr.sbomsight.domain.AnalysisJustification;
import kr.sbomsight.domain.AnalysisState;
import kr.sbomsight.domain.Asset;
import kr.sbomsight.domain.Finding;
import kr.sbomsight.domain.FindingAnalysis;
import kr.sbomsight.domain.Scan;
import kr.sbomsight.domain.ScanStatus;
import kr.sbomsight.domain.Zone;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * <b>CVE 상세 — 시안의 줄과 칸을 채운다.</b>
 *
 * <p>승인한 시안의 CVE 상세에는 자산 표의 {@code 검토 결과} 칸과 취약점 정보의
 * {@code 접근 경로} 줄이 있었는데 앱에는 없었다. 번호 하나를 받아 들고 "몇
 * 대에 있나" 다음에 묻는 것이 "그중 어디를 봤나" 인데, 그것을 보려면 자산을
 * 하나씩 열어야 했다.
 *
 * <p>그리고 {@code 대조 방식} 은 대표 한 건의 값을 CVE 의 것처럼 찍었다 — 방식은
 * 탐지마다 다르다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class CveDetailTest {

    private static final String CVE = "CVE-2099-4242";

    @Autowired MockMvc mvc;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired FindingAnalysisService analyses;
    @Autowired ZoneService zoneService;

    private Asset web;
    private Asset db;
    private FindingAnalysis reviewed;

    @BeforeEach
    void seed() {
        Zone zone = zoneService.create("CVE상세-" + System.nanoTime(), "#6f7e8d", "");
        web = asset("web-", zone);
        db = asset("db-", zone);
        // web 은 패키지 이름으로, db 는 소스 패키지(openssl)로 걸렸다.
        finding(web, "libssl3", "exact-direct-match");
        finding(db, "libssl3", "exact-indirect-match");
        reviewed = analyses.record(web, CVE, "libssl3", AnalysisState.NOT_AFFECTED,
                                   AnalysisJustification.CODE_NOT_REACHABLE, null,
                                   "", "", "", null, "tester");
    }

    @Test
    @DisplayName("자산 표의 검토 결과 칸 — 적어 둔 것은 딱지(상세로), 없으면 미검토")
    void theAssetTableShowsReviews() throws Exception {
        String html = flat(page("/vulns/" + CVE + "?includeDone=true", "ADMIN"));
        assertThat(html).contains("<th class=\"tight\">검토 결과</th>");
        assertThat(html)
                .as("web 줄 — 해당 없음 딱지가 그 검토 결과의 상세로 간다")
                .contains("href=\"/analyses/" + reviewed.getId() + "\"")
                .contains("해당 없음");
        assertThat(html)
                .as("db 줄 — 적어 둔 것이 없다")
                .contains("<span class=\"faint\">미검토</span>");
        // 목록과 같은 팝업으로 그 자리에서 적는다.
        assertThat(html).contains("id=\"analysis-dialog\"").contains("analysis-link");
    }

    @Test
    @DisplayName("조회 계정도 검토 결과 칸을 본다 — 적는 링크 · 팝업은 없다")
    void viewersSeeReviewsButNoEditing() throws Exception {
        String html = page("/vulns/" + CVE + "?includeDone=true", "VIEWER");
        assertThat(html)
                .contains("<th class=\"tight\">검토 결과</th>")
                .contains("href=\"/analyses/" + reviewed.getId() + "\"")
                .doesNotContain("analysis-link")
                .doesNotContain("id=\"analysis-dialog\"");
    }

    @Test
    @DisplayName("접근 경로 — 벡터의 글자를 옮기고, 원격 접근 · 영향 범위 변경은 보고서와 같은 이름")
    void theAccessPathComesFromTheVector() throws Exception {
        String html = flat(page("/vulns/" + CVE + "?includeDone=true", "ADMIN"));
        assertThat(html)
                .contains("<th>접근 경로</th>")
                .contains("원격 접근")
                .contains("네트워크 · 인증 불필요 · 사용자 개입 불필요")
                .contains("영향 범위 변경");

        // 서버 안에서 · 권한을 가지고 · 사람이 거들어야 하는 것 — 이름을 붙이지 않는다.
        Finding local = finding(asset("local-", web.getZone()), "bash", "exact-direct-match", "CVE-2099-4244");
        local.setCvssVector("CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
        findings.saveAndFlush(local);
        assertThat(flat(page("/vulns/CVE-2099-4244", "ADMIN")))
                .contains("접근 경로</th> <td> <span>로컬 · 낮은 권한 필요 · 사용자 개입 필요</span> </td>");
    }

    @Test
    @DisplayName("3.x 벡터가 아니면 접근 경로는 판단 불가")
    void anOldVectorIsNotGuessed() throws Exception {
        Asset old = asset("old-", web.getZone());
        Finding f = finding(old, "zlib", "exact-direct-match", "CVE-2099-4243");
        f.setCvssVector("AV:N/AC:L/Au:N/C:P/I:P/A:P");
        findings.saveAndFlush(f);
        assertThat(flat(page("/vulns/CVE-2099-4243", "ADMIN"))).contains("판단 불가 — CVSS 3.x 벡터 없음");
    }

    @Test
    @DisplayName("대조 방식은 대표 한 건이 아니라 방식마다 센다")
    void matchTypesAreCountedAcrossRows() throws Exception {
        String html = flat(page("/vulns/" + CVE + "?includeDone=true", "ADMIN"));
        assertThat(html)
                .contains("패키지 이름으로 대조</span> <span class=\"mono faint\">exact-direct-match</span> <span class=\"faint\">1건</span>")
                .contains("소스 패키지 이름으로 대조</span> <span class=\"mono faint\">exact-indirect-match</span> <span class=\"faint\">1건</span>");
    }

    // --- 씨앗 · 읽기 ------------------------------------------------------------

    private Asset asset(String prefix, Zone zone) {
        Asset a = new Asset();
        a.setName(prefix + System.nanoTime());
        a.setZone(zone);
        return assets.saveAndFlush(a);
    }

    private Finding finding(Asset asset, String pkg, String matchType) {
        return finding(asset, pkg, matchType, CVE);
    }

    private Finding finding(Asset asset, String pkg, String matchType, String cve) {
        Scan scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        scan.setCreatedAt(Instant.now());
        scans.saveAndFlush(scan);
        Finding f = new Finding(scan, cve + "|" + pkg, cve, pkg);
        f.setPackageVersion("3.0.2");
        f.setSeverity("Critical");
        f.setMatchType(matchType);
        f.setCvssVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
        return findings.saveAndFlush(f);
    }

    private String page(String url, String role) throws Exception {
        return mvc.perform(get(url).with(user("tester").roles(role)))
                  .andExpect(status().isOk())
                  .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    private static String flat(String html) {
        return html.replaceAll("\\s+", " ");
    }
}
