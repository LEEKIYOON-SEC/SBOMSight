package kr.sbomsight;

import kr.sbomsight.domain.*;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.FindingRepository;
import kr.sbomsight.repo.RemediationRepository;
import kr.sbomsight.repo.ScanRepository;
import kr.sbomsight.service.GrypeRunner;
import kr.sbomsight.service.ZoneService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * <b>이름이 가리키는 것과 적힌 값이 같은가</b> — 띄워 보고 찾은 말 셋.
 *
 * <p>{@link VocabularyTest} 는 글자를 읽는다. 여기는 화면을 그려서 본다 — 말은
 * 멀쩡한데 그 말이 붙은 값이 다른 것을 가리키던 자리들이다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class WordingTest {

    @Autowired MockMvc mvc;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired RemediationRepository remediations;
    @Autowired ZoneService zoneService;

    /**
     * 구역 보고서 1장의 `검사 실행 N회` 는 <b>완료된</b> 검사만 셌다
     * ({@code countDoneBetween}). 실패한 검사가 있으면 실행 횟수보다 작은 수가
     * `검사 실행` 이라는 이름으로 찍혔다.
     */
    @Test
    @DisplayName("구역 보고서 1장 — 완료된 것만 센 수를 `완료된 검사` 라고 부른다")
    void theZoneScopeNamesWhatItCounts() throws Exception {
        Zone zone = zoneService.create("문구-" + System.nanoTime(), "#123456", "");
        Asset asset = asset(zone);
        scan(asset, ScanStatus.DONE);
        scan(asset, ScanStatus.FAILED);

        LocalDate today = LocalDate.now();
        String html = open("/reports/zone?zone=" + zone.getId()
                           + "&from=" + today.minusDays(1) + "&to=" + today.plusDays(1))
                .replaceAll("\\s+", " ");

        assertThat(html).doesNotContain("검사 실행")
                        .contains("<td>완료된 검사</td> <td class=\"num tight\">1회</td>");
    }

    /**
     * 조치 이력의 첫 줄이 `대기 → 대기 · 조치 등록` 이었다. 등록은 상태를
     * 바꾼 것이 아니다 — 지금 상태만 적는다.
     */
    @Test
    @DisplayName("조치 이력의 등록 줄은 `대기 → 대기` 가 아니다")
    void theFirstHistoryRowIsNotAChange() throws Exception {
        Asset asset = asset(zoneService.unassigned());
        Scan scan = scan(asset, ScanStatus.DONE);
        Finding f = new Finding(scan, "CVE-2099-7|wording-pkg", "CVE-2099-7", "wording-pkg");
        f.setPackageVersion("1.0");
        f.setSeverity("High");
        f.setFixState("fixed");
        f.setFixedVersion("1.1");
        f.setCvssScore(BigDecimal.valueOf(7.5));
        findings.saveAndFlush(f);

        mvc.perform(post("/assets/" + asset.getId() + "/remediations").param("packageName", "wording-pkg")
                            .with(user("tester").roles("ADMIN")).with(csrf()));
        Remediation opened = remediations.findByAssetIdAndPackageName(asset.getId(), "wording-pkg")
                                         .orElseThrow();

        String html = open("/actions/" + opened.getId());
        assertThat(html).doesNotContain("대기 → 대기").contains("조치 등록");
    }

    /**
     * 설정의 도구 상태만 취약점 DB 날짜를 받은 글자 그대로
     * ({@code 2026-03-09T00:31:20Z}) 찍었다. 검사 이력 · 보고서는 날짜만 쓴다.
     */
    @Test
    @DisplayName("도구 상태의 취약점 DB 날짜를 다른 화면처럼 날짜로 적는다 — 못 읽으면 받은 그대로")
    void theToolStatusShowsTheDbDayLikeEveryOtherScreen() {
        assertThat(new GrypeRunner.Status(true, "0.87.0", "2026-03-09T12:00:00Z", "").dbBuiltDay())
                .isEqualTo("2026-03-09");
        assertThat(new GrypeRunner.Status(true, "0.87.0", "어제쯤", "").dbBuiltDay())
                .as("읽지 못하면 지어내지 않고 받은 그대로")
                .isEqualTo("어제쯤");
        assertThat(new GrypeRunner.Status(true, "0.87.0", "", "").dbBuiltDay()).isEmpty();
    }

    private Asset asset(Zone zone) {
        Asset a = new Asset();
        a.setName("wording-" + System.nanoTime());
        a.setZone(zone);
        return assets.saveAndFlush(a);
    }

    private Scan scan(Asset asset, ScanStatus status) {
        Scan s = new Scan(asset, "tester");
        s.setStatus(status);
        s.setCreatedAt(Instant.now());
        return scans.saveAndFlush(s);
    }

    private String open(String url) throws Exception {
        return mvc.perform(get(url).with(user("tester").roles("ADMIN")))
                  .andReturn().getResponse().getContentAsString();
    }
}
