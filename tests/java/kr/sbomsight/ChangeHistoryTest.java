package kr.sbomsight;

import kr.sbomsight.domain.*;
import kr.sbomsight.repo.AppSettingRepository;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.RemediationRepository;
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
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

import static kr.sbomsight.RemediationSteps.tight;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * <b>이력은 적는 칸도 남긴다</b>(R8) — 조치의 담당 · 기한 · 설명, 검토 결과의 설명 · 추가
 * 보안 통제 · 결재 문서 번호.
 *
 * <p>앞서 조치 이력은 상태가 바뀔 때만, 검토 결과 이력은 고르는 칸(검토 상태 · 근거 ·
 * 대응 방안 · 재검토일)만 남겼다. "누가 기한을 밀었나" · "결재 문서 번호는 언제 바뀌었나"
 * 에 답할 것이 없었다. 이력 칸이 255자라 설명(2,000자)이 들어가지도 않았다.
 *
 * <p>모든 칸을 남기기 시작한 시각(V19) 전에 만든 것은 그 전 변경이 없다 — 그것만 각주로
 * 밝힌다. 없는 기록을 있는 것처럼 보이게 두지 않는다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class ChangeHistoryTest {

    private static final DateTimeFormatter WHEN =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(ZoneId.systemDefault());

    @Autowired MockMvc mvc;
    @Autowired AssetRepository assets;
    @Autowired RemediationRepository remediations;
    @Autowired FindingAnalysisService analyses;
    @Autowired AppSettingRepository settings;
    @Autowired ZoneService zoneService;

    private Asset asset;

    @BeforeEach
    void setUp() {
        asset = new Asset();
        asset.setName("history-" + System.nanoTime());
        asset.setZone(zoneService.unassigned());
        assets.saveAndFlush(asset);
    }

    private Remediation remediation(String pkg) {
        Remediation r = new Remediation(asset, pkg, "tester");
        r.moveTo(RemediationStatus.OPEN, "tester", "조치 등록");
        return remediations.saveAndFlush(r);
    }

    @Test
    @DisplayName("조치의 담당 · 기한 · 설명을 고치면 이력에 앞뒤 값이 남는다 — 변경 사유와 함께")
    void remediationFieldChangesAreRecorded() throws Exception {
        Remediation r = remediation("openssl");
        save(r, "OPEN", "홍길동", "2026-12-31", "정기점검 창에서 1.1.1n", "일정 확정");

        String history = tight(page("/actions/" + r.getId()));
        assertThat(history)
                .contains("<td class=\"tight\">담당</td><td>— → 홍길동</td>")
                .contains("<td class=\"tight\">기한</td><td>— → 2026-12-31</td>")
                .contains("<td class=\"tight\">설명</td><td>— → 정기점검 창에서 1.1.1n</td>")
                .contains("일정 확정")
                .as("상태 줄은 그대로 — 등록 줄").contains("<td class=\"tight\">조치 상태</td><td>대기</td>");

        // 다시 고치면 앞 값이 남는다. 상태도 함께 바꾸면 그 줄도.
        save(r, "IN_PROGRESS", "김철수", "2026-12-31", "정기점검 창에서 1.1.1n", "담당 바뀜");
        String again = tight(page("/actions/" + r.getId()));
        assertThat(again).contains("<td class=\"tight\">담당</td><td>홍길동 → 김철수</td>")
                         .contains("<td class=\"tight\">조치 상태</td><td>대기 → 진행</td>");
        assertThat(again.split("<td class=\"tight\">기한</td>", -1).length - 1)
                .as("바뀌지 않은 칸까지 쌓았다").isEqualTo(1);
    }

    @Test
    @DisplayName("검토 결과의 설명 · 추가 보안 통제 · 결재 문서 번호도 이력에 앞뒤 값이 남는다 — 줄이지 않고")
    void analysisTextChangesAreRecorded() {
        analyses.record(asset, "CVE-2099-1", "openssl", AnalysisState.IN_TRIAGE, null, null,
                        "처음 설명", "", "", null, "tester");
        String longNote = "가".repeat(2000);
        FindingAnalysis a = analyses.record(asset, "CVE-2099-1", "openssl", AnalysisState.IN_TRIAGE,
                                            null, null, longNote, "WAF 차단", "보안-2026-0143", null,
                                            "tester");

        assertThat(a.getEvents()).filteredOn(e -> e.getField().equals("설명"))
                .extracting(FindingAnalysisEvent::getBefore, FindingAnalysisEvent::getAfter)
                .as("설명이 바뀐 것이 이력에 없거나 잘렸다(255자)")
                .containsExactly(org.assertj.core.groups.Tuple.tuple("", "처음 설명"),
                                 org.assertj.core.groups.Tuple.tuple("처음 설명", longNote));
        assertThat(a.getEvents()).filteredOn(e -> e.getField().equals("추가 보안 통제"))
                .extracting(FindingAnalysisEvent::getAfter).containsExactly("WAF 차단");
        assertThat(a.getEvents()).filteredOn(e -> e.getField().equals("결재 문서 번호"))
                .extracting(FindingAnalysisEvent::getAfter).containsExactly("보안-2026-0143");
    }

    @Test
    @DisplayName("모든 칸을 남기기 시작한 뒤에 만든 것에는 각주가 없고, 그 전에 만든 것에는 그 시각을 밝힌다")
    void theFootnoteSaysWhenTheFullHistoryStarted() throws Exception {
        FindingAnalysis older = analyses.record(asset, "CVE-2099-2", "zlib", AnalysisState.IN_TRIAGE,
                                                null, null, "", "", "", null, "tester");
        Remediation olderAction = remediation("zlib");
        Thread.sleep(5);
        AppSetting since = settings.saveAndFlush(new AppSetting("history_fields_since", "V19", ""));
        Thread.sleep(5);
        FindingAnalysis newer = analyses.record(asset, "CVE-2099-3", "curl", AnalysisState.IN_TRIAGE,
                                                null, null, "", "", "", null, "tester");
        Remediation newerAction = remediation("curl");
        String at = WHEN.format(since.getUpdatedAt());

        assertThat(page("/analyses/" + older.getId()))
                .contains("※ 설명 · 추가 보안 통제 · 결재 문서 번호는 " + at + " 부터 바뀐 것만");
        assertThat(page("/analyses/" + newer.getId())).doesNotContain("부터 바뀐 것만");
        assertThat(page("/actions/" + olderAction.getId()))
                .contains("※ 담당 · 기한 · 설명은 " + at + " 부터 바뀐 것만");
        assertThat(page("/actions/" + newerAction.getId())).doesNotContain("부터 바뀐 것만");
    }

    private void save(Remediation r, String status, String owner, String due, String note,
                      String comment) throws Exception {
        mvc.perform(post("/actions/" + r.getId())
                            .param("status", status).param("owner", owner).param("dueDate", due)
                            .param("note", note).param("comment", comment)
                            .with(user("tester").roles("ADMIN")).with(csrf()))
           .andExpect(status().is3xxRedirection());
    }

    private String page(String url) throws Exception {
        return mvc.perform(get(url).with(user("tester").roles("ADMIN")))
                  .andExpect(status().isOk())
                  .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
    }
}
