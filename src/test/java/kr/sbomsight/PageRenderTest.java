package kr.sbomsight;

import kr.sbomsight.domain.Asset;
import kr.sbomsight.domain.Finding;
import kr.sbomsight.domain.Remediation;
import kr.sbomsight.domain.Scan;
import kr.sbomsight.domain.ScanStatus;
import kr.sbomsight.domain.Zone;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.FindingRepository;
import kr.sbomsight.repo.RemediationRepository;
import kr.sbomsight.repo.ScanRepository;
import kr.sbomsight.service.RiskAcceptanceService;
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
import java.time.LocalDate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 화면이 실제로 그려지는가 — <b>전부.</b>
 *
 * <p><b>왜 있는가.</b> 타임리프의 잘못된 식은 컴파일에 걸리지 않는다. 자바는
 * 멀쩡히 빌드되고, 시험도 통과하고, 그 화면을 여는 순간 500 으로 터진다.
 * 실제로 한 줄짜리 식을 두 줄로 나눠 썼다가 로그인 뒤 모든 화면이 죽었고,
 * 그때까지 어떤 시험도 그것을 잡지 못했다 — 보고서 화면만 보고 있었다.
 *
 * <p>그래서 여기서는 <b>사람이 눌러서 갈 수 있는 모든 주소</b>를 한 번씩
 * 열어 본다. 내용이 맞는지는 각 기능의 시험이 보고, 여기서는 "열린다" 만
 * 본다. 화면을 하나 더하면 이 목록에도 한 줄을 더한다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class PageRenderTest {

    @Autowired MockMvc mvc;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired RemediationRepository remediations;
    @Autowired RiskAcceptanceService acceptances;
    @Autowired ZoneService zoneService;

    private Asset asset;
    private Scan scan;
    private Remediation remediation;

    @BeforeEach
    void seed() {
        Zone zone = zoneService.create("구역-" + System.nanoTime(), "#a71922", "대외 구간");

        asset = new Asset();
        asset.setName("web-" + System.nanoTime());
        asset.setZone(zone);
        asset.setOsName("Rocky Linux 9.3");
        asset.setNote("대외 웹");
        assets.saveAndFlush(asset);

        scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        scan.setGrypeVersion("0.87.0");
        scan.setSbomFilename("sbom.json");
        scan.setComponentCount(1284);
        scans.saveAndFlush(scan);

        Finding f = new Finding(scan, "CVE-2024-3094|xz", "CVE-2024-3094", "xz");
        f.setPackageVersion("5.6.0");
        f.setPackageType("rpm");
        f.setSeverity("Critical");
        f.setFixState("fixed");
        f.setFixedVersion("5.6.2");
        f.setCvssScore(BigDecimal.valueOf(10.0));
        f.setCvssVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
        f.setKev(Boolean.TRUE);
        f.setInstallPath("/usr/lib64/liblzma.so.5");
        findings.saveAndFlush(f);

        scan.setMatchCount(1);
        scan.setFindingCount(1);
        scans.saveAndFlush(scan);

        remediation = new Remediation(asset, "xz", "tester");
        remediation.setFromVersion("5.6.0");
        remediation.setToVersion("5.6.2");
        remediation.setOwner("인프라운영팀");
        remediation.setDueDate(LocalDate.now().minusDays(3));
        remediations.saveAndFlush(remediation);

        acceptances.accept(asset, "CVE-2024-2961", "glibc",
                           "업스트림 수정본 없음. 해당 기능은 외부에 노출되지 않는다.",
                           "WAF 에서 해당 경로 차단", "정보보호팀장",
                           LocalDate.now().plusDays(30), "tester");
    }

    private String open(String url) throws Exception {
        return mvc.perform(get(url).with(user("tester").roles("ADMIN")))
                  .andExpect(status().isOk())
                  .andReturn().getResponse().getContentAsString();
    }

    // --- 목록과 상세 ----------------------------------------------------------

    @Test
    @DisplayName("자산 목록 · 구역 거르기")
    void assetList() throws Exception {
        String html = open("/");
        assertThat(html).contains(asset.getName());
        // 왼쪽 기둥이 붙었는가. 없으면 화면 사이를 오갈 길이 사라진다.
        assertThat(html).contains("class=\"side\"");
        assertThat(html).contains(asset.getZone().getName());

        open("/?zone=" + asset.getZone().getId());
    }

    /**
     * 목록의 보기·거르개·정렬.
     *
     * <p>전부 주소에 남는 값이라 사람이 링크로 밟을 수 있다. 하나라도 500 이면
     * 그 링크는 막다른 길이다 — 표 머리를 눌렀을 뿐인데 화면이 죽는다.
     */
    @Test
    @DisplayName("자산 목록의 보기·거르개·정렬이 전부 열린다")
    void assetListControls() throws Exception {
        // 구역 카드 보기 — 카드 안에 그 구역의 자산이 들어 있어야 한다.
        assertThat(open("/?view=zones")).contains(asset.getName());

        // 거르개. 걸리는 것이 없을 때도 화면은 열려야 한다.
        open("/?filter=noscan");
        open("/?filter=stale");

        // 정렬 네 가지 × 두 방향.
        for (String sort : new String[] { "name", "scanned", "findings", "critical" }) {
            open("/?sort=" + sort + "&dir=asc");
            open("/?sort=" + sort + "&dir=desc");
        }

        // 보관된 자산도 함께.
        open("/?archived=true");
        // 구역 카드 + 구역 거르개가 겹칠 때.
        open("/?view=zones&zone=" + asset.getZone().getId());
    }

    /**
     * 조각이 <b>안 나와야 할 때 안 나오는가.</b>
     *
     * <p>타임리프는 {@code th:replace} 를 {@code th:if} 보다 먼저 처리한다
     * (우선순위 100 대 300). 같은 태그에 둘을 걸면 조각이 그 태그를 통째로
     * 갈아치우면서 조건까지 함께 사라진다 — 조건은 <b>있는데 안 먹는다.</b>
     *
     * <p>실제로 자산이 세 대 있는데 "등록된 자산이 없습니다" 가 함께 떠 있었고,
     * 표 보기인데 구역 카드가 같이 그려졌고, 검사가 없는 자산에도 심각도
     * 막대가 붙었다. 조각을 쓰는 화면이 늘수록 다시 나올 자리라 못 박아 둔다.
     */
    @Test
    @DisplayName("조건이 걸린 조각은 조건이 아닐 때 나오지 않는다")
    void conditionalFragmentsStayHidden() throws Exception {
        // 검사가 한 번도 없는 자산을 하나 더 둔다.
        Asset fresh = new Asset();
        fresh.setName("noscan-" + System.nanoTime());
        fresh.setZone(asset.getZone());
        assets.saveAndFlush(fresh);

        String table = open("/");
        assertThat(table)
                .as("자산이 있는데 빈 화면 문구가 함께 뜨면 th:if 가 안 먹은 것이다")
                .doesNotContain("등록된 자산이 없습니다");
        assertThat(table)
                .as("표 보기인데 구역 카드가 같이 그려지면 th:if 가 안 먹은 것이다")
                .doesNotContain("zonegrid");

        // 심각도 막대는 검사가 있고 탐지가 있는 자산에만. 자산 둘 중 하나는
        // 검사가 없으므로 막대도 하나여야 한다.
        assertThat(table.split("class=\"sevbar\"", -1).length - 1)
                .as("검사 없는 자산에 심각도 막대가 붙으면 안 된다")
                .isEqualTo(1);

        // 구역 보기에서는 반대로 카드가 있고 표가 없어야 한다.
        String cards = open("/?view=zones");
        assertThat(cards).contains("zonegrid");
        assertThat(cards).doesNotContain("asset-table");
    }

    /** 요약 줄의 숫자는 링크다. 누른 자리가 열리지 않으면 숫자만 보여 준 셈이다. */
    @Test
    @DisplayName("요약 줄이 가리키는 자리가 전부 열린다")
    void summaryLinksOpen() throws Exception {
        String html = open("/");
        // 기한이 지난 조치를 씨앗으로 넣어 두었으므로 줄이 그려져야 한다.
        assertThat(html).contains("summaryline");

        open("/?filter=noscan");
        open("/?filter=stale");
        mvc.perform(get("/actions").with(user("tester").roles("ADMIN")))
           .andExpect(status().is3xxRedirection());
        mvc.perform(get("/vulns").with(user("tester").roles("ADMIN")))
           .andExpect(status().is3xxRedirection());
    }

    @Test
    @DisplayName("자산 상세 · 취약점 목록")
    void assetAndScan() throws Exception {
        assertThat(open("/assets/" + asset.getId())).contains(asset.getName());
        assertThat(open("/scans/" + scan.getId())).contains("CVE-2024-3094");
    }

    @Test
    @DisplayName("전사 조회")
    void lookup() throws Exception {
        open("/lookup");
        assertThat(open("/lookup?q=xz")).contains("CVE-2024-3094");
    }

    @Test
    @DisplayName("조치 목록과 상세")
    void remediationPages() throws Exception {
        assertThat(open("/remediations")).contains("xz");
        assertThat(open("/remediations/" + remediation.getId())).contains("xz");
    }

    @Test
    @DisplayName("위험 수용")
    void acceptancePages() throws Exception {
        assertThat(open("/acceptances")).contains("CVE-2024-2961");
        open("/acceptances?revoked=true");
    }

    @Test
    @DisplayName("설정 네 탭 · 일괄 등록")
    void adminPages() throws Exception {
        // 탭 선택은 주소에 남는다. 탭마다 실제로 열리는지 하나씩 본다 —
        // th:if 로 갈라 놓으면 한 탭이 비어도 나머지는 멀쩡히 그려진다.
        assertThat(open("/settings")).contains("계정");
        assertThat(open("/settings?tab=ips")).contains("접근 IP");
        assertThat(open("/settings?tab=tools")).contains("grype");
        assertThat(open("/settings/audit")).contains("감사 로그");
        open("/assets/import");
    }

    /**
     * 옛 주소와, 아직 안 만든 화면의 새 주소.
     *
     * <p>기둥에는 최종 주소를 먼저 걸어 두고 그 화면은 뒤 단계에서 만든다.
     * 그동안 <b>새 주소가 어디로도 가지 않으면 기둥이 고장 난 것</b>이므로,
     * 지금은 옛 화면으로 이어 둔다. 진짜 화면이 생기면 방향이 뒤집힌다.
     */
    @Test
    @DisplayName("기둥의 주소가 전부 어딘가로 이어진다")
    void navLinksAllGoSomewhere() throws Exception {
        // 영구 — 감사 로그가 설정 안으로 옮겨 갔다.
        mvc.perform(get("/audit").with(user("tester").roles("ADMIN")))
           .andExpect(status().is3xxRedirection())
           .andExpect(redirectedUrl("/settings/audit"));

        // 임시 다리 — 해당 단계에서 지우고 반대 방향으로 바꾼다.
        for (String[] pair : new String[][] {
                { "/vulns", "/lookup" },
                { "/actions", "/remediations" },
                { "/reports", "/report/zone" },
                { "/me", "/password" } }) {
            mvc.perform(get(pair[0]).with(user("tester").roles("ADMIN")))
               .andExpect(status().is3xxRedirection())
               .andExpect(redirectedUrl(pair[1]));
        }
    }

    @Test
    @DisplayName("보고서 두 가지")
    void reportPages() throws Exception {
        assertThat(open("/report/" + scan.getId())).contains("취약점 대응 검토");
        assertThat(open("/report/zone")).contains("취약점 현황");
        open("/report/zone?zone=" + asset.getZone().getId());
    }

    @Test
    @DisplayName("로그인 · 비밀번호 변경")
    void gatePages() throws Exception {
        mvc.perform(get("/login")).andExpect(status().isOk());
        assertThat(open("/password")).contains("새 비밀번호");
    }

    // --- 내려받기 -------------------------------------------------------------

    @Test
    @DisplayName("CSV 내려받기는 화면이 아니라 파일로 나온다")
    void downloads() throws Exception {
        mvc.perform(get("/scans/" + scan.getId() + "/export.csv").with(user("tester").roles("ADMIN")))
           .andExpect(status().isOk());
        mvc.perform(get("/remediations/export.csv").with(user("tester").roles("ADMIN")))
           .andExpect(status().isOk());
        mvc.perform(get("/assets/import/template.csv").with(user("tester").roles("ADMIN")))
           .andExpect(status().isOk());
    }

    // --- 조회 권한 -------------------------------------------------------------

    /**
     * 조회 계정으로도 화면이 열려야 한다. 관리자에게만 있는 조각을
     * {@code sec:authorize} 로 감췄는데 그 안쪽에서 관리자용 값을 읽으면
     * 조회 계정에서만 터진다 — 관리자로 시험하면 끝까지 안 보인다.
     */
    @Test
    @DisplayName("조회 계정으로도 모든 화면이 열린다")
    void viewerCanOpenEveryPage() throws Exception {
        for (String url : new String[] {
                "/", "/assets/" + asset.getId(), "/scans/" + scan.getId(), "/lookup",
                "/remediations", "/remediations/" + remediation.getId(),
                "/acceptances", "/report/" + scan.getId(), "/report/zone", "/password" }) {
            mvc.perform(get(url).with(user("viewer").roles("VIEWER")))
               .andExpect(status().isOk());
        }
    }
}
