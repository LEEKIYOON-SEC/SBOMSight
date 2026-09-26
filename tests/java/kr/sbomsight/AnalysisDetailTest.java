package kr.sbomsight;

import kr.sbomsight.domain.AnalysisJustification;
import kr.sbomsight.domain.AnalysisState;
import kr.sbomsight.domain.Asset;
import kr.sbomsight.domain.Finding;
import kr.sbomsight.domain.FindingAnalysis;
import kr.sbomsight.domain.Scan;
import kr.sbomsight.domain.ScanStatus;
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
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * <b>검토 결과 한 건 — 지금의 결정과 거기까지 온 길을 본다.</b>
 *
 * <p>앞서 변경 이력(FindingAnalysisEvent)은 쌓이기만 하고 볼 자리가 없었다.
 * "언제부터 해당 없음이었나" 를 물으면 DB 를 열어야 했다.
 *
 * <p>이력은 고르는 칸(검토 상태 · 근거 · 대응 방안 · 재검토일)만 남긴다 —
 * 적는 칸만 고친 것은 이력을 늘리지 않는다(FindingAnalysisTest). 화면이 그
 * 사실을 말한다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AnalysisDetailTest {

    @Autowired MockMvc mvc;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired FindingAnalysisService analyses;
    @Autowired ZoneService zoneService;

    private Asset asset;
    private Scan scan;
    private FindingAnalysis analysis;

    @BeforeEach
    void seed() {
        asset = new Asset();
        asset.setName("detail-" + System.nanoTime());
        // 목록은 이 구역으로 거른다 — 다른 시험이 남긴 줄에 밀려 쪽 밖으로 나가지 않게.
        asset.setZone(zoneService.create("검토상세-" + System.nanoTime(), "#6f7e8d", ""));
        assets.saveAndFlush(asset);
        scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        scan.setCreatedAt(Instant.now());
        scans.saveAndFlush(scan);
        Finding f = new Finding(scan, "CVE-2099-7777|zlib", "CVE-2099-7777", "zlib");
        f.setPackageVersion("1.2.11");
        f.setSeverity("High");
        findings.saveAndFlush(f);

        // 두 사람이 차례로 적었다 — 검토 중으로 두었다가, 해당 없음으로 닫으며
        // 결재 문서 번호를 적었다.
        analyses.record(asset, "CVE-2099-7777", "zlib", AnalysisState.IN_TRIAGE, null, null,
                        "", "", "", null, "alice");
        analysis = analyses.record(asset, "CVE-2099-7777", "zlib", AnalysisState.NOT_AFFECTED,
                                   AnalysisJustification.CODE_NOT_REACHABLE, null,
                                   "호출 경로 없음", "", "보안-2026-0001", null, "bob");
    }

    @Test
    @DisplayName("상세 화면이 지금의 결정과 변경 이력을 보여 준다 — 조회 계정도 본다")
    void theDetailShowsTheDecisionAndItsHistory() throws Exception {
        String html = page("/analyses/" + analysis.getId(), "VIEWER");
        assertThat(html)
                .contains("CVE-2099-7777").contains("zlib").contains(asset.getName())
                .contains("해당 없음").contains("취약한 코드를 실행하지 않음")
                .contains("호출 경로 없음").contains("보안-2026-0001");
        assertThat(flat(html))
                .as("변경 이력 — 칸 이름은 화면의 말(검토 상태)로")
                .contains("검토 상태</td> <td>미검토 → 검토 중</td> <td class=\"tight\">alice")
                .contains("검토 상태</td> <td>검토 중 → 해당 없음</td> <td class=\"tight\">bob")
                .contains("근거</td> <td>— → 취약한 코드를 실행하지 않음</td> <td class=\"tight\">bob")
                .as("이력이 무엇을 남기는지 밝힌다")
                .contains("설명 · 추가 보안 통제 · 결재 문서 번호는 지금 값만");
        // 최신 검사에 이 탐지가 아직 있다.
        assertThat(flat(html)).contains("이 탐지 <b>1건</b>");
        // 고치는 것은 관리자만.
        assertThat(html).doesNotContain("analysis-link");

        String admin = page("/analyses/" + analysis.getId(), "ADMIN");
        assertThat(admin)
                .contains("analysis-link")
                .as("적은 뒤 이 화면으로 돌아온다")
                .contains("name=\"back\" value=\"/analyses/" + analysis.getId() + "\"");
    }

    @Test
    @DisplayName("검토 상태 딱지를 누르면 상세로 간다 — 대응 · 자산 상세 · 취약점 목록")
    void everyListLinksToTheDetail() throws Exception {
        String href = "href=\"/analyses/" + analysis.getId() + "\"";
        // 해당 없음은 기본 목록에서 빠진다 — 켜서 본다.
        assertThat(page("/actions?tab=analyses&includeDone=true&zone=" + asset.getZone().getId(), "ADMIN"))
                .contains(href);
        assertThat(page("/assets/" + asset.getId() + "?tab=actions", "ADMIN")).contains(href);
        assertThat(page("/vulns?scan=" + scan.getId() + "&includeDone=true", "ADMIN")).contains(href);
    }

    @Test
    @DisplayName("없는 검토 결과는 404 와 까닭")
    void aMissingOneSaysSo() throws Exception {
        MvcResult r = mvc.perform(get("/analyses/987654321").with(user("tester").roles("ADMIN")))
                         .andReturn();
        assertThat(r.getResponse().getStatus()).isEqualTo(404);
        assertThat(r.getResolvedException()).hasMessageContaining("검토 결과를 찾을 수 없습니다");
    }

    // --- 읽기 -------------------------------------------------------------------

    private String page(String url, String role) throws Exception {
        MvcResult r = mvc.perform(get(url).with(user("tester").roles(role))).andReturn();
        assertThat(r.getResponse().getStatus()).as(url).isEqualTo(200);
        return r.getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    /** 줄바꿈 · 들여쓰기를 빈칸 하나로 — 칸 사이를 한 줄로 읽는다. */
    private static String flat(String html) {
        return html.replaceAll("\\s+", " ");
    }
}
