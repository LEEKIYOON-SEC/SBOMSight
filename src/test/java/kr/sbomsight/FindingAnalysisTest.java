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
import java.time.LocalDate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 검토 결과.
 *
 * <p>여기서 고정하는 것 중 가장 중요한 것: <b>검토 결과는 grype 의 판정을
 * 바꾸지 않는다.</b> {@code 해당 없음} 을 적었다고 그 건이 탐지에서 빠지거나
 * 심각도가 내려가면, 그 순간 보고서는 실제보다 안전해 보이는 숫자를 말하게
 * 된다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class FindingAnalysisTest {

    @Autowired MockMvc mvc;
    @Autowired FindingAnalysisService service;
    @Autowired FindingAnalysisRepository repo;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired ZoneService zoneService;

    private Asset asset;

    @BeforeEach
    void setUp() {
        asset = new Asset();
        asset.setName("analysis-" + System.nanoTime());
        asset.setZone(zoneService.unassigned());
        assets.save(asset);
    }

    private LocalDate future() {
        return LocalDate.now().plusMonths(3);
    }

    /** 앞서의 '위험 수용' 에 해당하는 조합. */
    private FindingAnalysis acceptRisk(String cve, String pkg) {
        return service.record(asset, cve, pkg,
                              AnalysisState.EXPLOITABLE, null, AnalysisResponse.WILL_NOT_FIX,
                              "업스트림에 수정 버전이 없고 해당 기능을 쓰지 않습니다",
                              "내부망에서만 접근", "보안-2026-0143", future(), "tester");
    }

    // --- 규칙 ---------------------------------------------------------------

    /**
     * "해당 없음" 만 적고 끝내면 점검에서 답할 것이 없다. 아홉 가지 중 하나를
     * 고를 수 없다면 아직 해당 없다고 말할 단계가 아니다.
     */
    @Test
    @DisplayName("해당 없음은 근거를 골라야 적힌다")
    void notAffectedNeedsAJustification() {
        assertThatThrownBy(() -> service.record(asset, "CVE-1", "openssl",
                                                AnalysisState.NOT_AFFECTED, null, null,
                                                "", "", "", null, "tester"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("근거");

        FindingAnalysis ok = service.record(asset, "CVE-1", "openssl",
                AnalysisState.NOT_AFFECTED, AnalysisJustification.CODE_NOT_REACHABLE, null,
                "", "", "", null, "tester");
        assertThat(ok.getJustification()).isEqualTo(AnalysisJustification.CODE_NOT_REACHABLE);
    }

    /** 다른 상태로 바꾸면 앞서 고른 근거가 조용히 따라오면 안 된다. */
    @Test
    @DisplayName("해당 없음이 아니게 되면 근거는 지워진다")
    void justificationIsClearedWhenTheStateMovesOn() {
        service.record(asset, "CVE-1", "openssl",
                       AnalysisState.NOT_AFFECTED, AnalysisJustification.CODE_NOT_PRESENT, null,
                       "", "", "", null, "tester");

        FindingAnalysis moved = service.record(asset, "CVE-1", "openssl",
                AnalysisState.EXPLOITABLE, AnalysisJustification.CODE_NOT_PRESENT,
                AnalysisResponse.UPDATE, "", "", "", null, "tester");

        assertThat(moved.getJustification())
                .as("해당됨인데 '취약한 코드가 들어 있지 않음' 이 붙어 있다")
                .isNull();
    }

    /**
     * 고치지 않고 두기로 한 것에 기한이 없으면 방치와 구분되지 않는다.
     * 고치기로 한 것은 조치 자체에 기한이 있으므로 여기서 또 묻지 않는다.
     */
    @Test
    @DisplayName("조치 불가·조치 안 함은 재검토일을 받아야 한다")
    void leavingItAloneNeedsAReviewDate() {
        for (AnalysisResponse r : new AnalysisResponse[] {
                AnalysisResponse.CAN_NOT_FIX, AnalysisResponse.WILL_NOT_FIX }) {
            assertThatThrownBy(() -> service.record(asset, "CVE-" + r.name(), "openssl",
                                                    AnalysisState.EXPLOITABLE, null, r,
                                                    "", "", "", null, "tester"))
                    .as("%s 에 기한 없이 통과했다", r.label())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("재검토일");
        }

        // 고치기로 한 것은 묻지 않는다.
        FindingAnalysis fixing = service.record(asset, "CVE-UP", "openssl",
                AnalysisState.EXPLOITABLE, null, AnalysisResponse.UPDATE,
                "", "", "", null, "tester");
        assertThat(fixing.getReviewBy()).isNull();
    }

    @Test
    @DisplayName("재검토일은 미래여야 한다")
    void theReviewDateMustBeInTheFuture() {
        assertThatThrownBy(() -> service.record(asset, "CVE-1", "openssl",
                AnalysisState.EXPLOITABLE, null, AnalysisResponse.WILL_NOT_FIX,
                "", "", "", LocalDate.now().minusDays(1), "tester"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("오늘 이후");
    }

    /** 기한을 받지 않는 대응으로 바꾸면 앞서 잡아 둔 날짜는 뜻이 없어진다. */
    @Test
    @DisplayName("고치기로 바꾸면 재검토일은 지워진다")
    void theReviewDateGoesWhenWeDecideToFixIt() {
        acceptRisk("CVE-1", "openssl");
        FindingAnalysis fixed = service.record(asset, "CVE-1", "openssl",
                AnalysisState.EXPLOITABLE, null, AnalysisResponse.UPDATE,
                "", "", "", future(), "tester");
        assertThat(fixed.getReviewBy()).isNull();
    }

    /**
     * 같은 건에 검토 결과는 하나다. 앞서 위험 수용은 철회하고 다시 수용할 수
     * 있어 같은 키의 행이 여럿이었고, 그래서 "지금 결정이 무엇인가" 를 세는 데
     * 늘 조건을 하나 더 달아야 했다.
     */
    @Test
    @DisplayName("같은 건을 다시 적으면 덮어쓰고 이력에 쌓인다")
    void recordingAgainReplacesAndLogs() {
        FindingAnalysis first = acceptRisk("CVE-1", "openssl");
        Long id = first.getId();

        FindingAnalysis again = service.record(asset, "CVE-1", "openssl",
                AnalysisState.NOT_AFFECTED, AnalysisJustification.PROTECTED_AT_PERIMETER, null,
                "WAF 에서 해당 경로를 막습니다", "", "", null, "tester");

        assertThat(again.getId()).as("행이 하나여야 한다").isEqualTo(id);
        assertThat(again.getState()).isEqualTo(AnalysisState.NOT_AFFECTED);
        // 상태·대응·재검토일 셋이 바뀌었다.
        assertThat(again.getEvents()).extracting(FindingAnalysisEvent::getField)
                                     .contains("상태", "대응", "재검토일");
    }

    /** 손대지 않은 칸까지 쌓으면 이력이 읽히지 않는다. */
    @Test
    @DisplayName("바뀌지 않은 칸은 이력에 쌓이지 않는다")
    void unchangedFieldsAreNotLogged() {
        FindingAnalysis first = acceptRisk("CVE-1", "openssl");
        // 처음 적을 때는 상태·대응·재검토일 셋이 빈 값에서 바뀐다.
        int afterFirst = first.getEvents().size();
        assertThat(afterFirst).isEqualTo(3);

        // 고르는 값 셋은 그대로 두고 적는 칸만 고친다.
        FindingAnalysis same = service.record(asset, "CVE-1", "openssl",
                AnalysisState.EXPLOITABLE, null, AnalysisResponse.WILL_NOT_FIX,
                "설명만 고칩니다", "내부망에서만 접근", "보안-2026-0143", future(), "tester");

        assertThat(same.getEvents())
                .as("고르는 값이 그대로인데 이력이 늘었다")
                .hasSize(afterFirst);
        assertThat(same.getNote()).isEqualTo("설명만 고칩니다");
    }

    // --- 목록에서 빠지는 것 ---------------------------------------------------

    /**
     * 감추기 체크박스를 두지 않는다. 사람이 켜고 끄게 두면 같은 상태인데
     * 어떤 건은 보이고 어떤 건은 안 보인다.
     */
    @Test
    @DisplayName("볼 일이 끝난 상태만 기본 목록에서 빠진다")
    void onlyFinishedStatesLeaveTheList() {
        assertThat(AnalysisState.NOT_SET.isOpen()).isTrue();
        assertThat(AnalysisState.IN_TRIAGE.isOpen()).isTrue();
        assertThat(AnalysisState.EXPLOITABLE.isOpen()).isTrue();
        assertThat(AnalysisState.NOT_AFFECTED.isOpen()).isFalse();
        assertThat(AnalysisState.FALSE_POSITIVE.isOpen()).isFalse();
    }

    /**
     * <b>안 고치기로 한 것은 눈앞에 남아 있어야 한다.</b> 감추는 축을 대응이
     * 아니라 상태에 둔 이유가 이것이다 — 대응에 두면 '조치 안 함' 이 목록에서
     * 사라지고, 그것이 정확히 사라지면 안 되는 것이다.
     */
    @Test
    @DisplayName("조치 안 함(위험 수용)은 기본 목록에 계속 보인다")
    void riskAcceptedItemsStayVisible() {
        acceptRisk("CVE-1", "openssl");
        assertThat(service.list(false, null))
                .extracting(FindingAnalysis::getCve)
                .contains("CVE-1");
    }

    @Test
    @DisplayName("해당 없음은 기본 목록에서 빠지고, 켜면 나온다")
    void finishedItemsHideUntilAsked() {
        service.record(asset, "CVE-2", "openssl",
                       AnalysisState.NOT_AFFECTED, AnalysisJustification.CODE_NOT_PRESENT, null,
                       "", "", "", null, "tester");

        assertThat(service.list(false, null)).extracting(FindingAnalysis::getCve)
                                             .doesNotContain("CVE-2");
        assertThat(service.list(true, null)).extracting(FindingAnalysis::getCve)
                                            .contains("CVE-2");
    }

    // --- 판정 불변 -----------------------------------------------------------

    /**
     * 이 시험이 이 기능의 핵심이다. 검토가 건수를 줄이면 그 순간 보고서는
     * 실제보다 안전해 보이는 숫자를 말하게 된다.
     */
    @Test
    @DisplayName("해당 없음으로 적어도 탐지 건수와 심각도는 그대로다")
    void analysisDoesNotChangeTheVerdict() {
        Scan scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        scans.saveAndFlush(scan);

        Finding f = new Finding(scan, "CVE-1|spring-core", "CVE-1", "spring-core");
        f.setSeverity("High");
        f.setFixState("not-fixed");
        f.setCvssScore(BigDecimal.valueOf(7.5));
        findings.save(f);
        scan.setFindingCount(1);
        scan.setMatchCount(1);
        scans.saveAndFlush(scan);

        service.record(asset, "CVE-1", "spring-core",
                       AnalysisState.NOT_AFFECTED, AnalysisJustification.CODE_NOT_REACHABLE, null,
                       "", "", "", null, "tester");

        Finding after = findings.findById(f.getId()).orElseThrow();
        assertThat(after.getSeverity()).isEqualTo("High");
        assertThat(after.getFixState()).isEqualTo("not-fixed");
        assertThat(findings.countByScanId(scan.getId())).isEqualTo(1);
        assertThat(scans.findById(scan.getId()).orElseThrow().getFindingCount()).isEqualTo(1);
    }

    @Test
    @DisplayName("검토 결과 키는 버전을 넣지 않는다")
    void theKeyIgnoresVersion() {
        // 버전을 넣으면 부분 패치로 버전이 바뀌는 순간 검토 결과가 조용히 풀린다.
        assertThat(acceptRisk("CVE-1", "openssl").key()).isEqualTo("CVE-1|openssl");
    }

    @Test
    @DisplayName("재검토일이 지나면 기한 경과로 잡힌다")
    void surfacesOverdueReviews() {
        FindingAnalysis analysis = acceptRisk("CVE-1", "openssl");
        analysis.setReviewBy(LocalDate.now().minusDays(3));
        repo.saveAndFlush(analysis);

        assertThat(analysis.isReviewOverdue()).isTrue();
        assertThat(service.reviewOverdue()).extracting(FindingAnalysis::getId)
                                           .contains(analysis.getId());
    }

    // --- 목록에 표시가 붙는가 -------------------------------------------------

    /**
     * 적어 둔 것이 <b>취약점 목록에 보여야 한다.</b>
     *
     * <p>grype 이 GHSA 를 주 식별자로 낸 건은 {@code finding.cve} 가
     * {@code GHSA-…} 이고 사람이 읽는 것은 함께 온 CVE 번호다. 결재도 보고도
     * CVE 번호로 도는데 우리만 GHSA 로 묶어 두면, <b>같은 건을 적어 놓고도
     * 목록에서는 "아직 안 적음" 으로 보인다.</b> 실제로 그랬다 — 시험 227개가
     * 전부 통과한 채로.
     */
    @Test
    @DisplayName("GHSA 로 잡힌 건도 CVE 번호로 적으면 목록에 표시가 붙는다")
    void theListShowsWhatWeRecordedEvenWhenGrypeUsesGhsa() throws Exception {
        Scan scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        scans.saveAndFlush(scan);

        // grype 의 주 식별자는 GHSA, 함께 온 CVE 번호가 따로 있다.
        Finding f = new Finding(scan, "GHSA-jfh8|log4j-core", "GHSA-jfh8-c2jp-5v3q", "log4j-core");
        f.setRelatedCve("CVE-2021-44228");
        f.setSeverity("Critical");
        f.setFixState("not-fixed");
        findings.saveAndFlush(f);
        scan.setFindingCount(1);
        scans.saveAndFlush(scan);

        // 사람이 읽고 적는 번호로 적는다.
        service.record(asset, "CVE-2021-44228", "log4j-core",
                       AnalysisState.NOT_AFFECTED, AnalysisJustification.CODE_NOT_REACHABLE, null,
                       "해당 클래스를 로드하지 않습니다", "", "", null, "tester");

        String html = mvc.perform(get("/vulns").param("scan", scan.getId().toString())
                            .with(user("tester").roles("ADMIN")))
                         .andExpect(status().isOk())
                         .andReturn().getResponse().getContentAsString();

        // **화면 전체에서 글자를 찾으면 안 된다.** 검토 결과를 적는 대화상자가
        // 같은 화면에 있고 거기에 다섯 상태와 아홉 근거가 전부 들어 있다 —
        // '해당 없음' 은 행이 비어 있어도 언제나 걸린다. 실제로 이 시험을
        // 그렇게 썼다가 고치기 전 코드에서도 통과했다.
        //
        // 행이 그린 것만 본다: 적기 단추에 붙는 값과 그 단추의 글자.
        assertThat(html)
                .as("적어 둔 것이 목록에 안 보인다 — 번호가 어긋났다")
                .contains("data-state=\"NOT_AFFECTED\"")
                .contains(">고치기</a>");
    }

    /** 옛 주 식별자로 적힌 것(위험 수용에서 옮겨 온 행)도 찾아야 한다. */
    @Test
    @DisplayName("옛 주 식별자로 적힌 것도 목록에서 찾는다")
    void theListAlsoFindsRowsKeyedByTheOldIdentifier() throws Exception {
        Scan scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        scans.saveAndFlush(scan);

        Finding f = new Finding(scan, "GHSA-old|log4j-core", "GHSA-2gwj-7jmv-h26r", "log4j-core");
        f.setRelatedCve("CVE-2021-45046");
        f.setSeverity("Critical");
        findings.saveAndFlush(f);

        // 옮겨 온 행은 그때의 주 식별자(GHSA)로 적혀 있다.
        service.record(asset, "GHSA-2gwj-7jmv-h26r", "log4j-core",
                       AnalysisState.EXPLOITABLE, null, AnalysisResponse.WILL_NOT_FIX,
                       "", "", "", future(), "tester");

        String html = mvc.perform(get("/vulns").param("scan", scan.getId().toString())
                            .with(user("tester").roles("ADMIN")))
                         .andExpect(status().isOk())
                         .andReturn().getResponse().getContentAsString();

        assertThat(html)
                .as("옛 번호로 적어 둔 것이 목록에서 사라졌다")
                .contains("data-response=\"WILL_NOT_FIX\"")
                .contains(">고치기</a>");
    }

    // --- 화면 ---------------------------------------------------------------

    @Test
    @DisplayName("목록 화면이 뜬다")
    void listRenders() throws Exception {
        acceptRisk("CVE-1", "openssl");
        String html = mvc.perform(get("/analyses").with(user("tester").roles("VIEWER")))
                         .andExpect(status().isOk())
                         .andReturn().getResponse().getContentAsString();
        assertThat(html).contains("openssl")
                        .contains("조치 안 함")
                        .contains("보안-2026-0143");
    }

    @Test
    @DisplayName("옛 위험 수용 주소는 검토 결과로 이어진다")
    void theOldAddressStillWorks() throws Exception {
        mvc.perform(get("/acceptances").with(user("tester").roles("VIEWER")))
           .andExpect(redirectedUrl("/analyses"));
    }

    @Test
    @DisplayName("조회 권한으로는 검토 결과를 적을 수 없다")
    void viewersCannotRecord() throws Exception {
        mvc.perform(post("/analyses").with(user("viewer").roles("VIEWER")).with(csrf())
                        .param("assetId", asset.getId().toString())
                        .param("cve", "CVE-1").param("packageName", "openssl")
                        .param("state", "NOT_AFFECTED")
                        .param("justification", "CODE_NOT_PRESENT"))
           .andExpect(status().isForbidden());
    }

    /**
     * 화면의 고르개는 "고르지 않음" 을 빈 값으로 보낸다. 그대로 enum 으로
     * 바꾸려 하면 400 이 나서, 적은 것이 조용히 사라진다.
     */
    @Test
    @DisplayName("고르지 않은 칸은 빈 값으로 와도 받는다")
    void emptySelectionsAreAccepted() throws Exception {
        mvc.perform(post("/analyses").with(user("admin2").roles("ADMIN")).with(csrf())
                        .param("assetId", asset.getId().toString())
                        .param("cve", "CVE-7").param("packageName", "openssl")
                        .param("state", "IN_TRIAGE")
                        .param("justification", "").param("response", "")
                        .param("reviewBy", "").param("note", "확인 중입니다"))
           .andExpect(redirectedUrl("/analyses"));

        assertThat(repo.findOne(asset.getId(), "CVE-7", "openssl")).isPresent();
    }

    /**
     * back 을 그대로 리다이렉트에 쓰면 바깥 주소를 넣어 다른 사이트로 보낼 수
     * 있다.
     */
    @Test
    @DisplayName("돌아갈 곳으로 바깥 주소를 넣을 수 없다")
    void refusesAnExternalRedirect() throws Exception {
        mvc.perform(post("/analyses").with(user("admin2").roles("ADMIN")).with(csrf())
                        .param("assetId", asset.getId().toString())
                        .param("cve", "CVE-9").param("packageName", "openssl")
                        .param("state", "IN_TRIAGE")
                        .param("back", "//evil.example.com/"))
           .andExpect(redirectedUrl("/analyses"));
    }
}
