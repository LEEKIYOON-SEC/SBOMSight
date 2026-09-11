package kr.sbomsight;

import kr.sbomsight.domain.*;
import kr.sbomsight.repo.*;
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
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 위험 수용.
 *
 * <p>여기서 고정하는 것 중 가장 중요한 것: <b>수용은 grype 의 판정을 바꾸지
 * 않는다.</b> 수용했다고 그 건이 탐지에서 빠지거나 심각도가 내려가면, 그
 * 순간 보고서는 실제보다 안전해 보이는 숫자를 말하게 된다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class RiskAcceptanceTest {

    @Autowired MockMvc mvc;
    @Autowired RiskAcceptanceService service;
    @Autowired RiskAcceptanceRepository repo;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired ZoneService zoneService;

    private Asset asset;

    @BeforeEach
    void setUp() {
        asset = new Asset();
        asset.setName("accept-" + System.nanoTime());
        asset.setZone(zoneService.unassigned());
        assets.save(asset);
    }

    private LocalDate future() {
        return LocalDate.now().plusMonths(3);
    }

    private RiskAcceptance accept(String cve, String pkg) {
        return service.accept(asset, cve, pkg, "업스트림에 수정본이 없고 해당 기능을 쓰지 않음",
                              "내부망에서만 접근", "홍길동 팀장", future(), "tester");
    }

    // --- 규칙 ---------------------------------------------------------------

    @Test
    @DisplayName("사유 없이는 수용할 수 없다")
    void requiresAReason() {
        assertThatThrownBy(() -> service.accept(asset, "CVE-1", "openssl", "  ", "", "홍길동",
                                                future(), "tester"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("사유");
    }

    @Test
    @DisplayName("승인한 사람 없이는 수용할 수 없다")
    void requiresAnApprover() {
        assertThatThrownBy(() -> service.accept(asset, "CVE-1", "openssl", "충분히 긴 사유입니다",
                                                "", "  ", future(), "tester"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("승인한 사람");
    }

    /** 기한 없는 수용은 방치와 구분되지 않는다. 과거 날짜도 같은 뜻이다. */
    @Test
    @DisplayName("다시 볼 날은 미래여야 한다")
    void requiresAFutureReviewDate() {
        assertThatThrownBy(() -> service.accept(asset, "CVE-1", "openssl", "충분히 긴 사유입니다",
                                                "", "홍길동", LocalDate.now().minusDays(1), "tester"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("오늘 이후");
    }

    @Test
    @DisplayName("같은 건을 두 번 수용할 수 없다")
    void refusesDuplicates() {
        accept("CVE-1", "openssl");
        assertThatThrownBy(() -> accept("CVE-1", "openssl"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("이미 수용된");
    }

    @Test
    @DisplayName("철회한 건은 다시 수용할 수 있다")
    void canReacceptAfterRevoking() {
        RiskAcceptance first = accept("CVE-1", "openssl");
        service.revoke(first.getId(), "정책이 바뀜", "tester");

        // 상황이 바뀌어 다시 받아들이는 일은 정상이다.
        RiskAcceptance again = accept("CVE-1", "openssl");
        assertThat(again.getId()).isNotEqualTo(first.getId());
        assertThat(again.isActive()).isTrue();
    }

    @Test
    @DisplayName("철회는 지우지 않고 흔적을 남긴다")
    void revokingKeepsTheRecord() {
        RiskAcceptance acceptance = accept("CVE-1", "openssl");
        service.revoke(acceptance.getId(), "수정본이 나옴", "tester");

        // 누가 언제 왜 거뒀는지도 점검 대상이다.
        RiskAcceptance reloaded = repo.findById(acceptance.getId()).orElseThrow();
        assertThat(reloaded.isActive()).isFalse();
        assertThat(reloaded.getRevokedBy()).isEqualTo("tester");
        assertThat(reloaded.getRevokeNote()).isEqualTo("수정본이 나옴");
        assertThat(reloaded.getRevokedAt()).isNotNull();
    }

    @Test
    @DisplayName("다시 볼 날이 지나면 기한 경과로 잡힌다")
    void surfacesOverdueReviews() {
        RiskAcceptance acceptance = accept("CVE-1", "openssl");
        acceptance.setReviewBy(LocalDate.now().minusDays(3));
        repo.save(acceptance);

        assertThat(acceptance.isReviewOverdue()).isTrue();
        assertThat(service.reviewOverdue()).extracting(RiskAcceptance::getId)
                                           .contains(acceptance.getId());
    }

    @Test
    @DisplayName("철회한 것은 기한 경과로 잡히지 않는다")
    void revokedOnesAreNotOverdue() {
        RiskAcceptance acceptance = accept("CVE-1", "openssl");
        acceptance.setReviewBy(LocalDate.now().minusDays(3));
        service.revoke(acceptance.getId(), "", "tester");

        assertThat(repo.findById(acceptance.getId()).orElseThrow().isReviewOverdue()).isFalse();
    }

    // --- 판정 불변 -----------------------------------------------------------

    /**
     * 이 시험이 이 기능의 핵심이다. 수용이 건수를 줄이면 그 순간 보고서는
     * 실제보다 안전해 보이는 숫자를 말하게 된다.
     */
    @Test
    @DisplayName("수용해도 탐지 건수와 심각도는 그대로다")
    void acceptanceDoesNotChangeTheVerdict() {
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

        accept("CVE-1", "spring-core");

        Finding after = findings.findById(f.getId()).orElseThrow();
        assertThat(after.getSeverity()).isEqualTo("High");
        assertThat(after.getFixState()).isEqualTo("not-fixed");
        assertThat(findings.countByScanId(scan.getId())).isEqualTo(1);
        assertThat(scans.findById(scan.getId()).orElseThrow().getFindingCount()).isEqualTo(1);
    }

    @Test
    @DisplayName("수용 키는 버전을 넣지 않는다")
    void theKeyIgnoresVersion() {
        // 버전을 넣으면 부분 패치로 버전이 바뀌는 순간 수용이 조용히 풀린다.
        assertThat(accept("CVE-1", "openssl").key()).isEqualTo("CVE-1|openssl");
    }

    // --- 화면 ---------------------------------------------------------------

    @Test
    @DisplayName("목록 화면이 뜬다")
    void listRenders() throws Exception {
        accept("CVE-1", "openssl");
        String html = mvc.perform(get("/acceptances").with(user("tester").roles("VIEWER")))
                         .andExpect(status().isOk())
                         .andReturn().getResponse().getContentAsString();
        assertThat(html).contains("openssl").contains("홍길동 팀장");
    }

    @Test
    @DisplayName("조회 권한으로는 수용을 등록할 수 없다")
    void viewersCannotAccept() throws Exception {
        // 수용은 결재의 결과를 적는 일이다.
        mvc.perform(post("/acceptances").with(user("viewer").roles("VIEWER")).with(csrf())
                        .param("assetId", asset.getId().toString())
                        .param("cve", "CVE-1").param("packageName", "openssl")
                        .param("reason", "충분히 긴 사유입니다").param("approvedBy", "홍길동")
                        .param("reviewBy", future().toString()))
           .andExpect(status().isForbidden());
    }

    /**
     * back 을 그대로 리다이렉트에 쓰면 바깥 주소를 넣어 다른 사이트로 보낼 수
     * 있다.
     */
    @Test
    @DisplayName("돌아갈 곳으로 바깥 주소를 넣을 수 없다")
    void refusesAnExternalRedirect() throws Exception {
        mvc.perform(post("/acceptances").with(user("admin2").roles("ADMIN")).with(csrf())
                        .param("assetId", asset.getId().toString())
                        .param("cve", "CVE-9").param("packageName", "openssl")
                        .param("reason", "충분히 긴 사유입니다").param("approvedBy", "홍길동")
                        .param("reviewBy", future().toString())
                        .param("back", "//evil.example.com/"))
           .andExpect(redirectedUrl("/acceptances"));
    }
}
