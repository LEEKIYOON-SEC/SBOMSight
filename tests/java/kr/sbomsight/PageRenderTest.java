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
import java.time.LocalDate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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
    @Autowired FindingAnalysisService analyses;
    @Autowired ZoneService zoneService;
    @Autowired kr.sbomsight.repo.AppUserRepository appUsers;
    @Autowired kr.sbomsight.repo.FindingAnalysisRepository analysisRepository;

    private Asset asset;
    private Scan scan;
    private Remediation remediation;

    @BeforeEach
    void seed() {
        // `.with(user("tester"))` 는 인증된 주체를 꽂을 뿐 계정을 만들지 않는다.
        // 내 계정 화면은 진짜 계정을 찾으므로 여기 하나 둔다.
        if (!appUsers.existsByUsername("tester")) {
            appUsers.saveAndFlush(new kr.sbomsight.domain.AppUser(
                    "tester", "{noop}unused", kr.sbomsight.domain.Role.ADMIN));
        }
        if (!appUsers.existsByUsername("viewer")) {
            appUsers.saveAndFlush(new kr.sbomsight.domain.AppUser(
                    "viewer", "{noop}unused", kr.sbomsight.domain.Role.VIEWER));
        }

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

        // 앞서의 '위험 수용' 에 해당하는 조합 — 해당됨 · 조치 안 함.
        analyses.record(asset, "CVE-2024-2961", "glibc",
                        kr.sbomsight.domain.AnalysisState.EXPLOITABLE, null,
                        kr.sbomsight.domain.AnalysisResponse.WILL_NOT_FIX,
                        "업스트림에 수정 버전이 없고 해당 기능은 외부에 노출되지 않습니다",
                        "WAF 에서 해당 경로 차단", "보안-2026-0143",
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
        // (Tabler 의 세로 기둥 — `navbar navbar-vertical`.)
        assertThat(html).contains("navbar-vertical");
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

        // 운영 종료한 자산까지 함께.
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
                .doesNotContain("zone-cards");

        // 심각도 막대는 검사가 있고 탐지가 있는 자산에만. 자산 둘 중 하나는
        // 검사가 없으므로 막대도 하나여야 한다.
        assertThat(table.split("class=\"sevbar\"", -1).length - 1)
                .as("검사 없는 자산에 심각도 막대가 붙으면 안 된다")
                .isEqualTo(1);

        // 구역 보기에서는 반대로 카드가 있고 표가 없어야 한다.
        //
        // **표의 class 를 본다.** 구역 접기 스크립트가 같은 이름으로 표를
        // 찾으므로(`querySelector('.asset-table')`) 이름만 찾으면 표가
        // 없어도 걸린다 — 그러면 이 시험은 아무것도 지키지 못한다.
        String cards = open("/?view=zones");
        assertThat(cards).contains("zone-cards");
        assertThat(cards).doesNotContain("table-sticky asset-table");
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
        open("/vulns");
        open("/actions");
    }

    /**
     * <b>기한 지난 조치와 재검토일 지난 검토 결과를 따로 센다.</b>
     *
     * <p>요약 줄의 `기한 지난 조치` 가 두 가지를 합친 수였다 — 조치 기한이 지난
     * 것과 검토 결과의 재검토일이 지난 것. 누르면 조치 탭으로 가는데 그 탭에는
     * 재검토일 지난 것이 없다. 띄운 앱에서 `1 기한 지난 조치` 를 눌렀더니 기한
     * 지난 조치는 0건이었다.
     */
    @Test
    @DisplayName("요약 줄은 기한 지난 조치와 재검토일 지난 검토 결과를 따로 세고 각자의 탭으로 보낸다")
    void overdueActionsAndOverdueReviewsAreSeparate() throws Exception {
        // 씨앗의 위험 수용(재검토일 30일 뒤)을 지난 것으로 만든다. 화면으로는
        // 지난 날짜를 적을 수 없다 — 날이 지나서 그렇게 되는 것이다.
        var accepted = analyses.byKey(asset.getId()).get("CVE-2024-2961|glibc");
        accepted.setReviewBy(LocalDate.now().minusDays(1));
        analysisRepository.saveAndFlush(accepted);

        long overdueActions = remediations.countOverdue(LocalDate.now());
        long overdueReviews = analyses.reviewOverdue().size();
        assertThat(overdueActions).isPositive();
        assertThat(overdueReviews).isPositive();

        String html = open("/").replaceAll("\\s+", " ");
        assertThat(html)
                .as("조치 기한이 지난 것만 `기한 지난 조치` 로 세야 한다")
                .contains("href=\"/actions\"> <b>" + overdueActions + "</b> 기한 지난 조치");
        assertThat(html)
                .as("재검토일 지난 검토 결과가 따로 없거나 검토 결과 탭으로 가지 않는다")
                .contains("href=\"/actions?tab=analyses\"> <b>" + overdueReviews
                          + "</b> 재검토일 지난 검토 결과");
    }

    /**
     * 요약 줄과 구역 머리줄의 <b>실제 악용</b> 건수.
     *
     * <p>심각도와 다른 축이라 따로 센다 — 심각도가 `보통` 인데 실제로 악용되고
     * 있는 건이 `심각` 100건보다 급하다.
     *
     * <p><b>{@code kev} 가 NULL 인 건을 세면 안 된다.</b> grype 이 값을 주지
     * 않은 것은 "아니다" 가 아니라 "모른다" 이고, 그것을 악용 확인으로 세면
     * 아무도 확인하지 않은 판정이 화면 맨 앞에 붉게 뜬다.
     */
    @Test
    @DisplayName("실제 악용은 kev=true 만 센다 — 모르는 것은 세지 않는다")
    void theExploitedCountOnlyCountsWhatGrypeConfirmed() throws Exception {
        // 씨앗에 kev=true 가 한 건 있다. 여기에 모르는 것과 아닌 것을 더한다.
        for (Boolean kev : new Boolean[] { null, Boolean.FALSE }) {
            Finding f = new Finding(scan, "CVE-9999-" + System.nanoTime() + "|zlib",
                                    "CVE-9999-0001", "zlib");
            f.setSeverity("Critical");
            f.setFixState("fixed");
            f.setKev(kev);
            findings.saveAndFlush(f);
        }

        String html = open("/");
        assertThat(html)
                .as("요약 줄에 실제 악용이 없다")
                .contains("실제 악용");
        // `<b>1</b> 실제 악용` — 숫자가 1 이어야 한다. 3 이면 NULL·false 까지 센 것이다.
        assertThat(html.replaceAll("\\s+", ""))
                .as("모르는 것(NULL)이나 아닌 것(false)까지 실제 악용으로 셌다")
                .contains("<b>1</b>실제악용");
    }

    /**
     * 이력의 <b>다시 검사</b> 줄이 원본을 어떻게 가리키는가.
     *
     * <p>앞서 `다시 검사 (원본 1)` 로 <b>스캔 번호</b>를 찍었다. 내부 번호라
     * 사람이 아는 값이 아니고, 이력이 쌓이면 그 번호로 어느 줄인지 찾을 수도
     * 없다. 원본의 <b>시각</b>을 찍는다 — 이력 표의 첫 칸이 그 시각이므로
     * 눈으로 바로 짝이 맞는다.
     */
    @Test
    @DisplayName("다시 검사는 원본을 번호가 아니라 시각으로 가리킨다")
    void aRescanPointsAtTheOriginalByTime() throws Exception {
        Scan again = new Scan(asset, "tester");
        again.setStatus(ScanStatus.DONE);
        again.setSbomFilename("sbom.json");
        again.setRescanOf(scan.getId());
        scans.saveAndFlush(again);

        String history = open("/assets/" + asset.getId() + "?tab=history");
        String when = java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")
                .withZone(java.time.ZoneId.systemDefault())
                .format(scan.getCreatedAt());

        assertThat(history)
                .as("원본을 스캔 번호로 가리키고 있다")
                .doesNotContain("원본 " + scan.getId() + ")");
        assertThat(history)
                .as("원본의 시각이 없다 — 어느 줄이 원본인지 알 수 없다")
                .contains("다시 검사 · 원본")
                .contains(when);
    }

    @Test
    @DisplayName("자산 상세 · 취약점 목록")
    void assetAndScan() throws Exception {
        assertThat(open("/assets/" + asset.getId())).contains(asset.getName());
        assertThat(open("/vulns?scan=" + scan.getId())).contains("CVE-2024-3094");
    }

    /**
     * 자산 상세의 탭.
     *
     * <p>탭마다 내용이 갈려 있어서, 한 탭이 깨져도 나머지는 멀쩡히 그려진다 —
     * 그래서 하나씩 열어 봐야 한다. 탭 선택은 주소에 남는다.
     */
    @Test
    @DisplayName("자산 상세의 탭이 하나씩 열린다")
    void assetDetailTabs() throws Exception {
        String overview = open("/assets/" + asset.getId());
        assertThat(overview).contains("기본 정보");
        assertThat(overview).contains("SBOM 업로드");
        assertThat(overview).contains("운영 종료");

        String history = open("/assets/" + asset.getId() + "?tab=history");
        assertThat(history).contains("이전 대비");

        // 행 액션이 **전부 같은 버튼**인가. '열기' 만 맨 글자였고 옆은 버튼이라
        // 한 칸에서 두 가지 모양이 놀던 자리다. 맨 링크로 되돌아가면 여기서 깨진다.
        assertThat(history)
                .as("완료된 검사에는 열기·다시 검사가 둘 다 버튼으로 있어야 한다")
                .contains("class=\"btn btn-sm\" href=\"/vulns?scan=" + scan.getId() + "\">열기</a>")
                .contains("class=\"btn btn-sm\"")
                .contains("다시 검사");

        assertThat(open("/assets/" + asset.getId() + "?tab=actions")).contains("xz");

        // 취약점 탭. 자산 상세 안에서 끝나야 한다 — 전체 화면으로 튕기면
        // 한 자산 이야기를 보러 들어온 사람이 목록으로 쫓겨난다.
        //
        // `넓게 보기` 단추는 뗐다. 이 탭이 `/vulns` 와 **같은 표·같은 정렬·
        // 같은 페이지 넘김**을 쓰므로 넘어가서 달라지는 것이 자산 칸 하나뿐
        // 이었다. 대신 그 조각들이 여기 있는지를 본다.
        String vulns = open("/assets/" + asset.getId() + "?tab=vulns");
        assertThat(vulns).contains("CVE-2024-3094");
        assertThat(vulns)
                .as("취약점 탭이 전체 화면과 같은 표·정렬·페이지 넘김을 쓰지 않는다")
                .contains("sortable")
                .contains("페이지 사이즈");
    }

    /**
     * 모르는 탭 이름이 와도 <b>빈 화면이 뜨지 않는가.</b>
     *
     * <p>화면이 {@code th:if} 로 갈라져 있어서 아무 것에도 맞지 않는 값이 오면
     * 탭 줄만 있고 본문이 없는 화면이 <b>200 으로</b> 뜬다. 실제로
     * {@code ?tab=scans}(이력 탭의 이름은 {@code history} 다)로 그랬고,
     * {@link #everyScreen()} 이 그 주소를 들고 있었으면서 200 만 보고 있었다 —
     * 즉 <b>이력 탭은 한 번도 열어 본 적이 없었다.</b>
     */
    @Test
    @DisplayName("모르는 탭 이름은 개요로 되돌린다 (빈 화면 금지)")
    void unknownTabFallsBackToOverview() throws Exception {
        String bogus = open("/assets/" + asset.getId() + "?tab=scans");
        assertThat(bogus)
                .as("본문이 없는 화면이 200 으로 떴다")
                .contains("기본 정보")
                .contains("SBOM 업로드");

        // 이력 탭은 이름이 history 다. 내용이 실제로 있어야 한다.
        assertThat(open("/assets/" + asset.getId() + "?tab=history"))
                .contains("이전 대비")
                .contains("0.87.0");
    }

    /** 보관해 둔 SBOM 원본을 꺼내 볼 수 있어야 grype 의 판정을 대조할 수 있다. */
    @Test
    @DisplayName("보관된 SBOM 이 없으면 404, 있으면 파일로 나온다")
    void sbomDownload() throws Exception {
        // 씨앗 스캔에는 보관 경로가 없다 — 없는데 200 을 주면 빈 파일이 떨어진다.
        mvc.perform(get("/scans/" + scan.getId() + "/sbom").with(user("tester").roles("ADMIN")))
           .andExpect(status().isNotFound());
    }

    /**
     * <b>운영 종료</b>는 지우는 것과 다르다 — 목록·현황 숫자에서 빠지고
     * 검사 이력은 남는다. (앞서 화면에서 `보관` 이라고 부른 것이다.)
     */
    @Test
    @DisplayName("운영 종료하면 목록에서 빠지고, 포함해서 보면 나온다")
    void archiveHidesFromList() throws Exception {
        mvc.perform(post("/assets/" + asset.getId() + "/archive")
                        .with(user("tester").roles("ADMIN")).with(csrf()))
           .andExpect(status().is3xxRedirection());

        assertThat(open("/")).doesNotContain(asset.getName());
        assertThat(open("/?archived=true")).contains(asset.getName());
        // 결과는 그대로 있다.
        assertThat(open("/assets/" + asset.getId() + "?tab=history")).contains("0.87.0");
    }

    @Test
    @DisplayName("취약점 — 범위 없이도, 검색어 없이도 답한다")
    void vulns() throws Exception {
        // 앞서 전사 조회는 검색어를 넣어야만 답했다. 그래서 "우리 전체에
        // 심각이 몇 건인가" 를 물을 자리가 없었다.
        assertThat(open("/vulns")).contains("CVE-2024-3094");
        assertThat(open("/vulns?q=xz")).contains("CVE-2024-3094");
    }

    @Test
    @DisplayName("대응 — 조치 탭과 상세")
    void actionPages() throws Exception {
        assertThat(open("/actions")).contains("xz");
        assertThat(open("/actions/" + remediation.getId())).contains("xz");
        // 상태 거르개도 주소에 남는다.
        open("/actions?status=OPEN");
        open("/actions?zone=" + asset.getZone().getId());
    }

    @Test
    @DisplayName("검토 결과")
    void analysisPages() throws Exception {
        assertThat(open("/actions?tab=analyses")).contains("CVE-2024-2961");
        // 볼 일이 끝난 것까지 켜서 보는 거르개. 켜고 끄는 것은 이것 하나다.
        open("/actions?tab=analyses&includeDone=true");
        open("/actions?tab=analyses&zone=" + asset.getZone().getId());
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
        // 영구 — 화면이 자리를 옮겼다. 적어 둔 주소가 죽지 않아야 한다.
        for (String[] pair : new String[][] {
                { "/audit", "/settings/audit" },
                { "/lookup", "/vulns" },
                { "/lookup?q=xz", "/vulns?q=xz" },
                { "/lookup/export.csv?q=xz", "/vulns/export.csv?q=xz" },
                { "/scans/" + scan.getId(), "/vulns?scan=" + scan.getId() },
                // N5 — 조치와 검토 결과가 대응 화면의 두 탭이 됐다.
                { "/remediations", "/actions" },
                { "/remediations/" + remediation.getId(), "/actions/" + remediation.getId() },
                { "/remediations/export.csv", "/actions/export.csv" },
                { "/analyses", "/actions?tab=analyses" },
                { "/acceptances", "/actions?tab=analyses" },
                // N7 — 보고서 주소가 /reports/ 아래로 모였다. 한 글자 차이로
                // 갈라진 두 접두사(/report 와 /reports)를 아무도 기억 못 한다.
                { "/report/" + scan.getId(), "/reports/scan/" + scan.getId() },
                { "/report/zone", "/reports/zone" },
                { "/report/zone?zone=" + asset.getZone().getId(),
                  "/reports/zone?zone=" + asset.getZone().getId() } }) {
            mvc.perform(get(pair[0]).with(user("tester").roles("ADMIN")))
               .andExpect(status().is3xxRedirection())
               .andExpect(redirectedUrl(pair[1]));
        }

        // 한 자산짜리 범위는 통합 화면에 없다 — 그 자산 안에서 끝난다.
        mvc.perform(get("/vulns?asset=" + asset.getId()).with(user("tester").roles("ADMIN")))
           .andExpect(redirectedUrl("/assets/" + asset.getId() + "?tab=vulns"));

        // 마지막 임시 다리였던 /reports 는 N7 에서 진짜 화면이 됐다.
        // 302 가 아니라 200 이어야 한다 — 다리가 남아 있으면 여기서 걸린다.
        mvc.perform(get("/reports").with(user("tester").roles("ADMIN")))
           .andExpect(status().isOk());
    }

    /**
     * 패키지 화면 — <b>빈 것과 안 본 것을 구분해서 말하는가.</b>
     *
     * <p>V13 은 이미 쌓인 SBOM 을 되읽지 않으므로 다시 검사하기 전에는
     * 인벤토리가 비어 있다. 그 상태를 "패키지가 없습니다" 라고 말하면 거짓이다 —
     * 없는 것이 아니라 아직 안 본 것이다.
     */
    @Test
    @DisplayName("인벤토리가 비면 '없다' 가 아니라 '아직 안 담겼다' 고 말한다")
    void emptyInventorySaysNotYetRead() throws Exception {
        String html = open("/packages");
        assertThat(html).contains("아직 담긴 패키지가 없습니다");
        assertThat(html)
                .as("담긴 것이 없는 것과 패키지가 없는 것은 다른 말이다")
                .doesNotContain("조건에 맞는 패키지가 없습니다");
    }

    /**
     * 탭 줄이 <b>본문과 같은 칸 안에</b> 있는가.
     *
     * <p>대응 화면의 탭 줄만 감싸는 칸이 없어 화면 맨 왼쪽에 붙어 있었고,
     * 그 아래 카드보다 16px 왼쪽에서 시작했다 — 화면을 옮길 때 눈이 자리를
     * 다시 찾는다. 탭이 있는 화면(대응 · 설정 · 감사 로그 · 자산 상세)은
     * 전부 {@code page-header > container-xl > ul.nav-tabs} 여야 한다.
     *
     * <p>렌더한 HTML 에서 잰다. 탭 줄 바로 앞의 {@code container-xl} 부터
     * 탭 줄까지 {@code <div>} 와 {@code </div>} 를 세어, 닫은 것이 더 많으면
     * 그 칸은 <b>이미 닫혔고</b> 탭은 칸 밖이다. (자산 상세는 머리글과 탭이
     * 같은 칸을 쓰되 그 사이에 줄 하나가 열리고 닫힌다 — 닫는 태그가 있다는
     * 것만으로는 밖이라고 말할 수 없다.)
     */
    @Test
    @DisplayName("탭 줄은 본문과 같은 칸 안에서 시작한다")
    void tabRowsSitInsideTheContainer() throws Exception {
        for (String url : List.of("/actions", "/actions?tab=analyses",
                                  "/settings", "/settings/audit",
                                  "/assets/" + asset.getId())) {
            String html = open(url);
            int tabs = html.indexOf("nav nav-tabs");
            assertThat(tabs).as("%s 에 탭 줄", url).isGreaterThan(0);

            int container = html.lastIndexOf("container-xl", tabs);
            assertThat(container).as("%s — 탭 줄 앞에 칸이 열려 있다", url).isGreaterThan(0);

            String between = html.substring(container, tabs);
            int opened = count(between, "<div");
            int closed = count(between, "</div");
            assertThat(opened)
                    .as("%s — 칸이 닫힌 뒤에 탭 줄이 있다 (열림 %d · 닫힘 %d)", url, opened, closed)
                    .isGreaterThanOrEqualTo(closed);
        }
    }

    @Test
    @DisplayName("보고서 두 가지")
    void reportPages() throws Exception {
        // 고르는 자리에 두 가지가 다 있어야 한다. 앞서 기둥의 `보고서` 가
        // 구역 보고서로 직행해서, 자산 보고서가 있다는 것을 알 길이 없었다.
        String picker = open("/reports");
        assertThat(picker).contains("구역 · 기간").contains("자산");
        assertThat(picker).contains("/reports/scan/" + scan.getId());

        assertThat(open("/reports/scan/" + scan.getId())).contains("취약점 점검 결과 보고");
        assertThat(open("/reports/zone")).contains("취약점 현황");
        open("/reports/zone?zone=" + asset.getZone().getId());
    }

    @Test
    @DisplayName("로그인 · 비밀번호 변경 · 내 계정")
    void gatePages() throws Exception {
        mvc.perform(get("/login")).andExpect(status().isOk());
        assertThat(open("/password")).contains("새 비밀번호");

        // 앞서 기둥의 계정 이름이 곧바로 비밀번호 변경으로 갔다. 이제 갈 곳이 있다.
        String me = open("/me");
        assertThat(me).contains("계정 정보").contains("마지막 로그인").contains("그 전 로그인");
    }

    /**
     * 템플릿에 <b>글자 그대로 적힌 내부 링크</b>가 전부 열리는가.
     *
     * <p>빈 화면 조각은 단추 주소를 인자로 받는다({@code empty(…, '/assets', …)}).
     * 그 화면이 빈 상태로 그려질 때만 보이는 단추라, 자료가 있는 시험에서는
     * 한 번도 눌리지 않는다. 보고서 화면의 빈 화면 단추가 {@code GET /assets}
     * 로 가서 405(영문 오류 화면)를 냈다 — 자산 목록은 {@code /} 다.
     *
     * <p>자리값이 들어간 주소({@code ${…}})는 여기서 보지 않는다. 그것은
     * 화면마다의 시험이 실제 값으로 연다.
     */
    @Test
    @DisplayName("템플릿에 적힌 내부 링크가 전부 열린다")
    void everyLiteralLinkInTheTemplatesOpens() throws Exception {
        java.util.regex.Pattern[] patterns = {
                // th:href="@{/reports/zone(from=…)}" → /reports/zone
                java.util.regex.Pattern.compile("th:href=\"@\\{(/[^(}'\"$]*)"),
                // href="/password"
                java.util.regex.Pattern.compile("[^:]href=\"(/[^\"#?$]*)\""),
                // empty('제목', '설명', '/', '단추') — 인자 전체가 글자일 때만.
                // '/assets/' + ${asset.id} 처럼 이어 붙인 것은 자리값이 있다.
                java.util.regex.Pattern.compile("::\\s*empty\\([^)]*?'(/[^']*)'\\s*,")
        };
        java.util.Set<String> paths = new java.util.TreeSet<>();
        try (var files = java.nio.file.Files.walk(java.nio.file.Path.of("src/main/resources/templates"))) {
            for (java.nio.file.Path file : files.filter(p -> p.toString().endsWith(".html")).toList()) {
                // 개발자 주석(<!--/* … */-->) 안의 예시는 링크가 아니다.
                String html = java.nio.file.Files.readString(file)
                        .replaceAll("(?s)<!--.*?-->", "");
                for (java.util.regex.Pattern pattern : patterns) {
                    java.util.regex.Matcher m = pattern.matcher(html);
                    while (m.find()) {
                        paths.add(m.group(1));
                    }
                }
            }
        }
        assertThat(paths).as("템플릿에서 링크를 하나도 못 찾았다 — 정규식이 틀렸다")
                         .contains("/password", "/reports/zone");

        for (String path : paths) {
            int code = mvc.perform(get(path).with(user("tester").roles("ADMIN")))
                          .andReturn().getResponse().getStatus();
            assertThat(code).as("템플릿의 링크 %s 가 %d 를 낸다", path, code).isLessThan(400);
        }
    }

    // --- 내려받기 -------------------------------------------------------------

    @Test
    @DisplayName("CSV 내려받기는 화면이 아니라 파일로 나온다")
    void downloads() throws Exception {
        // 검사 하나의 탐지 — 화면(취약점 · 자산 상세의 취약점 탭)이 거는 주소다.
        // 앞서 따로 있던 /scans/{id}/export.csv 는 어느 화면도 걸지 않아 지웠다.
        mvc.perform(get("/vulns/export.csv?scan=" + scan.getId()).with(user("tester").roles("ADMIN")))
           .andExpect(status().isOk());
        mvc.perform(get("/actions/export.csv").with(user("tester").roles("ADMIN")))
           .andExpect(status().isOk());
        // 내려받기는 보고 있는 탭의 것이다.
        mvc.perform(get("/actions/export.csv?tab=analyses").with(user("tester").roles("ADMIN")))
           .andExpect(status().isOk());
        // 패키지 — 거르개를 들고 가는 주소도 열려야 한다. 인벤토리가 비어
        // 있어도 빈 파일이 나와야 하고 500 이면 안 된다.
        mvc.perform(get("/packages/export.csv").with(user("tester").roles("ADMIN")))
           .andExpect(status().isOk());
        mvc.perform(get("/packages/export.csv?mixed=true&vulnerable=true&q=xz")
                            .with(user("tester").roles("ADMIN")))
           .andExpect(status().isOk());
        mvc.perform(get("/assets/import/template.csv").with(user("tester").roles("ADMIN")))
           .andExpect(status().isOk());
    }

    // --- 페이지 머리 (§5-12) ---------------------------------------------------

    /**
     * 머리의 버튼 묶음이 <b>한 번만</b> 그려지는가.
     *
     * <p>모든 화면에서 두 번 그려지고 있었다. 원인은
     * {@code <div th:fragment="actions" th:remove="tag">} 였다 —
     * {@code th:remove="tag"} 는 감싼 태그만 없애고 <b>그 안의 단추는 문서에
     * 그대로 남긴다.</b> 그래서 같은 단추가 머리에 한 번, 그 아래에 또 한 번
     * 찍혔다. 화면은 멀쩡히 뜨고 시험 249개가 전부 통과했다 — 띄워 보고서야
     * 찾았다.
     */
    @Test
    @DisplayName("머리의 버튼이 한 번만 그려진다")
    void pageHeadActionsRenderOnce() throws Exception {
        // 화면 → 그 화면 머리에만 있는 단추 글자
        var heads = java.util.Map.of(
                "/vulns", "CSV 내려받기",
                "/actions", "CSV 내려받기",
                "/packages", "CSV 내려받기",
                "/settings/audit", "CSV 내려받기",
                "/assets/import", "CSV 서식 내려받기");

        for (var head : heads.entrySet()) {
            String html = open(head.getKey());
            assertThat(count(html, head.getValue()))
                    .as("%s 의 '%s' 단추", head.getKey(), head.getValue())
                    .isEqualTo(1);
            // 머리 줄 자체도 하나여야 한다.
            assertThat(count(html, "class=\"page-title\""))
                    .as("%s 의 페이지 머리", head.getKey())
                    .isEqualTo(1);
        }
    }

    private static int count(String text, String needle) {
        int n = 0;
        for (int i = text.indexOf(needle); i >= 0; i = text.indexOf(needle, i + needle.length())) {
            n++;
        }
        return n;
    }

    // --- 두 권한 × 전 주소 -----------------------------------------------------

    /**
     * <b>두 권한이 도는 주소 목록은 하나다.</b>
     *
     * <p>앞서 관리자용 걸음과 조회용 걸음이 각자 목록을 들고 있었다. 새 화면을
     * 하나 만들면 한쪽에만 넣게 되고, 어느 쪽이 빠졌는지는 아무도 모른다.
     * 목록을 한 군데 두어 둘이 갈라지지 않게 한다 (N8).
     *
     * <p>관리자만 쓰는 주소({@code /settings*})는 여기 넣지 않는다 — 조회
     * 계정에는 403 이 정답이고, 그것은 {@link #viewerIsRefusedAdminPages()}
     * 가 따로 본다.
     */
    private List<String> everyScreen() {
        return List.of(
                "/",
                "/?view=zones",
                "/assets/" + asset.getId(),
                "/assets/" + asset.getId() + "?tab=vulns",
                "/assets/" + asset.getId() + "?tab=history",
                "/assets/" + asset.getId() + "?tab=actions",
                "/vulns",
                "/vulns?scan=" + scan.getId(),
                "/vulns?group=package",
                "/vulns?group=cve",
                "/vulns/CVE-2024-3094",
                "/packages",
                "/packages?vulnerable=true",
                "/packages?mixed=true",
                "/assets/" + asset.getId() + "?tab=packages",
                "/actions",
                "/actions/" + remediation.getId(),
                "/actions?tab=analyses",
                "/reports",
                "/reports/scan/" + scan.getId(),
                "/reports/zone",
                "/password",
                "/me");
    }

    @Test
    @DisplayName("관리자 계정으로 전 화면이 열린다")
    void adminCanOpenEveryScreen() throws Exception {
        for (String url : everyScreen()) {
            mvc.perform(get(url).with(user("tester").roles("ADMIN")))
               .andExpect(status().isOk());
        }
    }

    /**
     * 조회 계정으로도 화면이 열려야 한다. 관리자에게만 있는 조각을
     * {@code sec:authorize} 로 감췄는데 그 안쪽에서 관리자용 값을 읽으면
     * 조회 계정에서만 터진다 — 관리자로 시험하면 끝까지 안 보인다.
     */
    @Test
    @DisplayName("조회 계정으로도 전 화면이 열린다")
    void viewerCanOpenEveryPage() throws Exception {
        for (String url : everyScreen()) {
            mvc.perform(get(url).with(user("viewer").roles("VIEWER")))
               .andExpect(status().isOk());
        }
    }

    /**
     * 화면 소스에 <b>우리끼리 하는 이야기</b>가 실려 나가지 않는다.
     *
     * <p>타임리프에서 {@code <!-- ... -->} 는 그대로 브라우저로 간다. 한 화면에
     * 백 개가 넘게 실려 있었고, 그 안에는 시험 클래스 이름과 "그때 이래서 이렇게
     * 고쳤다" 같은 개발 메모가 들어 있었다. 쓰는 사람에게는 보이지 않지만
     * <b>소스 보기를 누르면 그대로 보인다</b> — 납품물에 개발 노트가 붙어 있는
     * 셈이다.
     *
     * <p>여는 자리를 {@code <!--} 대신 {@code <!--}+{@code /*} 로 적으면(닫는 자리도
     * 짝을 맞춘다) 타임리프가 파싱하면서 걷어내므로 <b>소스에는 남고 화면에는
     * 나가지 않는다.</b> 주석을 지우는 것이 아니라 나가는 곳만 막는 것이다.
     */
    @Test
    @DisplayName("화면 소스에 개발자 주석이 실려 나가지 않는다")
    void noDeveloperCommentsReachTheBrowser() throws Exception {
        for (String url : everyScreen()) {
            String html = mvc.perform(get(url).with(user("tester").roles("ADMIN")))
                    .andReturn().getResponse().getContentAsString();

            assertThat(html)
                    .as("%s 의 소스에 주석이 남아 있다 — <!--/* 로 적으면 나가지 않는다", url)
                    .doesNotContain("<!--");
        }
    }

    /** 조회 계정에 관리자 화면은 열리지 않는다. 여기서는 403 이 정답이다. */
    @Test
    @DisplayName("조회 계정에 관리자 화면은 막힌다")
    void viewerIsRefusedAdminPages() throws Exception {
        for (String url : new String[] { "/settings", "/settings?tab=ips",
                                         "/settings?tab=tools", "/settings/audit" }) {
            mvc.perform(get(url).with(user("viewer").roles("VIEWER")))
               .andExpect(status().isForbidden());
        }
    }
}
