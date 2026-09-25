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
import org.springframework.data.domain.PageRequest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * <b>해당 없음 · 오탐은 탐지 목록의 기본에서 빠진다</b> — 그리고 그 규칙은 하나다.
 *
 * <p>문서(개편 계획서 · operations.md · README)와 보고서 1장이 "검토를
 * 마쳐 목록에서 제외" 라고 적어 두었는데 어느 목록도 빼지 않았다(띄운 앱에서
 * 취약점 화면 1,425건 = 전체). 사용자 결정: 문서대로 뺀다.
 *
 * <p>빼는 규칙은 SQL(목록은 DB 에서 쪽을 나누므로)과 자바
 * ({@link FindingAnalysisService#stateOf} — 보고서 2.4 · 검토 표시)에 한 벌씩
 * 있다. <b>둘이 갈라지면 같은 건이 목록에서는 빠지고 보고서에서는 미검토로
 * 센다.</b> 여기서 갈래마다 둘을 맞대 본다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class ReviewedOutRuleTest {

    @Autowired MockMvc mvc;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired FindingAnalysisService analyses;
    @Autowired ZoneService zoneService;

    private Asset asset;
    private Asset other;
    private Scan scan;

    @BeforeEach
    void setUp() {
        asset = asset("rule");
        other = asset("rule-other");
        scan = done(asset);
        done(other);
    }

    private Asset asset(String name) {
        Asset a = new Asset();
        a.setName(name + "-" + System.nanoTime());
        a.setZone(zoneService.unassigned());
        return assets.saveAndFlush(a);
    }

    private Scan done(Asset a) {
        Scan s = new Scan(a, "tester");
        s.setStatus(ScanStatus.DONE);
        return scans.saveAndFlush(s);
    }

    private Finding finding(String cve, String related, String pkg) {
        Finding f = new Finding(scan, cve + "|" + pkg, cve, pkg);
        f.setRelatedCve(related);
        f.setSeverity("High");
        f.setFixState("fixed");
        f.setFixedVersion("9.9.9");
        return findings.saveAndFlush(f);
    }

    private void review(Asset a, String cve, String pkg, AnalysisState state) {
        analyses.record(a, cve, pkg, state,
                        state == AnalysisState.NOT_AFFECTED ? AnalysisJustification.CODE_NOT_PRESENT : null,
                        state == AnalysisState.EXPLOITABLE ? AnalysisResponse.WILL_NOT_FIX : null,
                        "시험", "", "",
                        state == AnalysisState.EXPLOITABLE ? LocalDate.now().plusDays(30) : null,
                        "tester");
    }

    @Test
    @DisplayName("SQL 의 제외 규칙과 stateOf 가 갈래마다 같다")
    void theSqlRuleMatchesStateOf() {
        // 주 식별자로 적은 것
        finding("CVE-R-1", "", "p-na");            review(asset, "CVE-R-1", "p-na", AnalysisState.NOT_AFFECTED);
        finding("CVE-R-2", "", "p-fp");            review(asset, "CVE-R-2", "p-fp", AnalysisState.FALSE_POSITIVE);
        // 위험 수용(해당됨 · 조치 안 함)은 끝난 것이 아니다 — 남는다
        finding("CVE-R-3", "", "p-accept");        review(asset, "CVE-R-3", "p-accept", AnalysisState.EXPLOITABLE);
        finding("CVE-R-4", "", "p-triage");        review(asset, "CVE-R-4", "p-triage", AnalysisState.IN_TRIAGE);
        // 주 식별자가 GHSA 이고 사람은 CVE 번호로 적었다
        finding("GHSA-r-5", "CVE-R-5", "p-ghsa");  review(asset, "CVE-R-5", "p-ghsa", AnalysisState.NOT_AFFECTED);
        // 두 번호 모두 적혀 있으면 주 식별자 쪽이 이긴다
        finding("GHSA-r-6", "CVE-R-6", "p-both");
        review(asset, "GHSA-r-6", "p-both", AnalysisState.IN_TRIAGE);
        review(asset, "CVE-R-6", "p-both", AnalysisState.NOT_AFFECTED);
        // 다른 자산의 검토는 이 자산의 탐지를 빼지 않는다
        finding("CVE-R-7", "", "p-elsewhere");     review(other, "CVE-R-7", "p-elsewhere", AnalysisState.NOT_AFFECTED);
        // 적은 것이 없다
        finding("CVE-R-8", "", "p-none");

        Set<String> shown = findings.findInBySeverity(List.of(scan.getId()), null, null, null, null,
                                                      false, false, PageRequest.of(0, 100))
                                    .stream().map(Finding::getPackageName).collect(Collectors.toSet());

        Map<String, FindingAnalysis> byKey = analyses.byKey(asset.getId());
        Set<String> openByJava = findings.findKeyRows(scan.getId()).stream()
                .filter(k -> FindingAnalysisService.stateOf(byKey, k.getCve(), k.getRelatedCve(),
                                                            k.getPackageName()).isOpen())
                .map(FindingRepository.FindingKey::getPackageName)
                .collect(Collectors.toSet());

        assertThat(shown)
                .as("SQL 이 남긴 것과 stateOf 가 열려 있다고 본 것이 다르다")
                .isEqualTo(openByJava)
                .containsExactlyInAnyOrder("p-accept", "p-triage", "p-both", "p-elsewhere", "p-none");

        assertThat(findings.countReviewedOut(List.of(scan.getId()), null, null, null, null, null))
                .as("빠진 건수")
                .isEqualTo(3);   // p-na · p-fp · p-ghsa
    }

    @Test
    @DisplayName("목록은 기본에서 빼고, 체크하면 넣고, 빠진 건수를 이름표에 적는다")
    void theListHidesThemByDefaultAndSaysHowMany() throws Exception {
        finding("CVE-L-1", "", "l-na");     review(asset, "CVE-L-1", "l-na", AnalysisState.NOT_AFFECTED);
        finding("CVE-L-2", "", "l-open");

        String byDefault = open("/vulns?scan=" + scan.getId());
        assertThat(byDefault).contains("l-open").doesNotContain("l-na");
        assertThat(byDefault).contains("해당 없음·오탐 포함 (1건)");

        String included = open("/vulns?scan=" + scan.getId() + "&includeDone=true");
        assertThat(included).contains("l-open").contains("l-na");

        // 자산 상세의 취약점 탭 — 같은 조각, 같은 규칙. 탭의 숫자는 탭이
        // 처음 보여 주는 줄 수다.
        String tab = open("/assets/" + asset.getId() + "?tab=vulns");
        assertThat(tab).contains("l-open").doesNotContain(">l-na<");
        assertThat(tab.replaceAll("\\s+", " "))
                .as("취약점 탭의 숫자가 탭이 보여 주는 줄 수와 다르다")
                .contains("<span>취약점</span> <span class=\"badge bg-secondary-lt ms-1\">1</span>");

        // 내려받기는 화면과 같은 것을 담는다.
        String csv = mvc.perform(get("/vulns/export.csv?scan=" + scan.getId())
                                         .with(user("tester").roles("ADMIN")))
                        .andReturn().getResponse().getContentAsString();
        assertThat(csv).contains("l-open").doesNotContain("l-na");
        String csvAll = mvc.perform(get("/vulns/export.csv?scan=" + scan.getId() + "&includeDone=true")
                                            .with(user("tester").roles("ADMIN")))
                           .andReturn().getResponse().getContentAsString();
        assertThat(csvAll).contains("l-na");
    }

    @Test
    @DisplayName("CVE 상세는 CVE별 목록과 같은 수를 말한다 — 전부 빠졌으면 넣어서 보여 준다")
    void theCveDetailAgreesWithTheCveList() throws Exception {
        // 두 패키지에 같은 CVE — 하나는 해당 없음.
        finding("CVE-D-1", "", "d-a");
        finding("CVE-D-1", "", "d-b");  review(asset, "CVE-D-1", "d-b", AnalysisState.NOT_AFFECTED);

        String detail = open("/vulns/CVE-D-1?includeDone=false");
        assertThat(detail.replaceAll("\\s+", " "))
                .as("상세가 기본에서 빠진 건까지 센다")
                .contains("탐지 <b>1</b>건")
                .contains("해당 없음·오탐 포함 (1건)");

        // 걸린 것이 전부 해당 없음이면 404 가 아니라 넣어서 보여 준다 —
        // 검토 결과의 CVE 번호를 누르면 여기로 온다.
        finding("CVE-D-2", "", "d-c");  review(asset, "CVE-D-2", "d-c", AnalysisState.FALSE_POSITIVE);
        mvc.perform(get("/vulns/CVE-D-2").with(user("tester").roles("ADMIN")))
           .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                              .redirectedUrl("/vulns/CVE-D-2?includeDone=true"));
    }

    private String open(String url) throws Exception {
        return mvc.perform(get(url).with(user("tester").roles("ADMIN")))
                  .andReturn().getResponse().getContentAsString();
    }
}
