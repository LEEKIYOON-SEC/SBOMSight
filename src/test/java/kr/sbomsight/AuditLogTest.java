package kr.sbomsight;

import kr.sbomsight.domain.AuditEvent;
import kr.sbomsight.domain.AuditLog;
import kr.sbomsight.repo.AuditLogRepository;
import kr.sbomsight.repo.ZoneRepository;
import kr.sbomsight.service.AuditService;
import kr.sbomsight.service.ZoneService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 감사 로그.
 *
 * <p><b>왜 필요한가.</b> "누가 지웠냐" 에 답할 수 없는 도구는 점검을 통과하지
 * 못한다. 지금까지 남는 것은 마지막 로그인 시각 하나뿐이었다.
 *
 * <p>여기서 고정하는 것 둘:
 * <ol>
 *   <li>실제로 기록된다 — 화면 어딘가에 로그가 있다는 것과 그 일이 정말
 *       기록된다는 것은 다르다.</li>
 *   <li><b>일어나지 않은 일은 기록되지 않는다.</b> 감사 기록을 별도
 *       트랜잭션으로 빼 두면 롤백된 작업이 기록에는 남고, 그 기록을 근거로
 *       점검에 답하면 틀린 말을 하게 된다.</li>
 * </ol>
 */
@SpringBootTest
@AutoConfigureMockMvc
class AuditLogTest {

    @Autowired MockMvc mvc;
    @Autowired AuditLogRepository logs;
    @Autowired AuditService audit;
    @Autowired ZoneService zoneService;
    @Autowired ZoneRepository zones;

    /**
     * DB 에 없는 이름을 쓴다.
     *
     * <p>"admin" 은 부트스트랩이 만들어 두고 mustChange=true 이므로
     * {@code MustChangePasswordInterceptor} 가 모든 요청을 /password 로
     * 돌려보낸다. 그러면 컨트롤러가 아예 돌지 않아, 기록이 없는 것을 보고
     * "기록되지 않았다" 고 잘못 읽게 된다 — 실제로 이 시험이 그렇게 한 번
     * 거짓으로 통과했다.
     */
    private static final String ADMIN = "auditor";

    private List<AuditLog> recent(AuditEvent action) {
        return logs.search(null, action, Instant.now().minus(1, ChronoUnit.HOURS), null, null,
                           PageRequest.of(0, 50)).getContent();
    }

    @Test
    @Transactional
    @DisplayName("기록한 것이 조회로 다시 나온다")
    void recordsAndReadsBack() {
        audit.recordAs("tester", AuditEvent.ZONE_CREATED, "DMZ", "시험");

        assertThat(recent(AuditEvent.ZONE_CREATED))
                .anySatisfy(row -> {
                    assertThat(row.getActor()).isEqualTo("tester");
                    assertThat(row.getTarget()).isEqualTo("DMZ");
                    assertThat(row.getDetail()).isEqualTo("시험");
                });
    }

    @Test
    @Transactional
    @DisplayName("열 폭을 넘는 값은 잘리되 기록 자체는 남는다")
    void clipsInsteadOfFailing() {
        // 한 줄이 열 폭을 넘겨 전체가 실패하면 그 작업까지 함께 롤백된다.
        // 기록을 남기려다 자산 삭제가 취소되는 것은 앞뒤가 맞지 않는다.
        String tooLong = "가".repeat(2000);
        audit.recordAs("tester", AuditEvent.SETTING_CHANGED, tooLong, tooLong);

        assertThat(recent(AuditEvent.SETTING_CHANGED))
                .anySatisfy(row -> {
                    assertThat(row.getTarget().length()).isLessThanOrEqualTo(256);
                    assertThat(row.getDetail().length()).isLessThanOrEqualTo(1000);
                });
    }

    @Test
    @DisplayName("구역을 만들면 감사 로그에 남는다")
    void zoneCreationIsRecorded() throws Exception {
        String name = "감사시험-" + System.nanoTime();

        mvc.perform(post("/zones").with(user(ADMIN).roles("ADMIN")).with(csrf())
                        .param("name", name).param("color", "#a71922"))
           .andExpect(status().is3xxRedirection());

        assertThat(recent(AuditEvent.ZONE_CREATED))
                .extracting(AuditLog::getTarget).contains(name);
    }

    /**
     * 이 시험이 핵심이다. 자산이 남은 구역은 지울 수 없다 — 그때 삭제는
     * 일어나지 않았으므로 "구역 삭제" 기록도 남아서는 안 된다.
     */
    @Test
    @DisplayName("막힌 작업은 기록되지 않는다")
    void refusedWorkLeavesNoRecord() throws Exception {
        // 미분류는 규칙상 지울 수 없다.
        Long protectedId = zoneService.unassigned().getId();
        long before = recent(AuditEvent.ZONE_DELETED).size();

        mvc.perform(post("/zones/" + protectedId + "/delete")
                        .with(user(ADMIN).roles("ADMIN")).with(csrf()))
           .andExpect(status().is3xxRedirection());

        // 구역은 그대로 있고,
        assertThat(zones.findById(protectedId)).isPresent();
        // 지웠다는 기록도 늘지 않았다.
        assertThat(recent(AuditEvent.ZONE_DELETED)).hasSize((int) before);
    }

    @Test
    @DisplayName("조회 화면과 CSV 가 뜬다")
    void screensRender() throws Exception {
        mvc.perform(get("/settings/audit").with(user(ADMIN).roles("ADMIN")))
           .andExpect(status().isOk());

        String csv = mvc.perform(get("/settings/audit/export.csv").with(user(ADMIN).roles("ADMIN")))
                        .andExpect(status().isOk())
                        .andReturn().getResponse().getContentAsString();
        // 엑셀이 UTF-8 로 읽게 하는 BOM 이 앞에 있어야 한다.
        assertThat(csv).startsWith("﻿");
        assertThat(csv).contains("접속 IP");
    }

    @Test
    @DisplayName("조회 권한만 있는 계정은 감사 로그를 볼 수 없다")
    void viewersCannotSeeTheAuditLog() throws Exception {
        // 로그 자체가 "누가 언제 어디서" 를 담고 있어서, 조회 권한을 넓히면
        // 그것이 곧 접속 현황 공개가 된다.
        mvc.perform(get("/settings/audit").with(user("viewer").roles("VIEWER")))
           .andExpect(status().isForbidden());
        // 옛 주소로 우회해도 막혀야 한다. 넘겨주는 자리에 구멍이 나기 쉽다.
        mvc.perform(get("/audit").with(user("viewer").roles("VIEWER")))
           .andExpect(status().isForbidden());
    }
}
