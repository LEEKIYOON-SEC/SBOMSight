package kr.sbomsight;

import kr.sbomsight.domain.Asset;
import kr.sbomsight.domain.AuditEvent;
import kr.sbomsight.domain.AuditLog;
import kr.sbomsight.domain.Remediation;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.AuditLogRepository;
import kr.sbomsight.repo.RemediationRepository;
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
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
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
    @Autowired AssetRepository assets;
    @Autowired RemediationRepository remediations;

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
        // 아무 행위나 된다 — 자르는 것은 값이지 행위가 아니다. 실제로
        // 기록되는 이름을 쓴다(`SETTING_CHANGED` 는 선언만 있고 아무도
        // 기록하지 않아 지웠다).
        audit.recordAs("tester", AuditEvent.IP_ALLOWLIST_CHANGED, tooLong, tooLong);

        assertThat(recent(AuditEvent.IP_ALLOWLIST_CHANGED))
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
     * <b>잘못 등록한 조치를 지울 수 있고, 지운 자취가 남는다.</b>
     *
     * <p>앞서 등록만 있고 지우는 길이 아예 없었다. 보고서의 `조치 등록` 은
     * 단추 한 번에 확인 창도 없어서, 잘못 누른 줄이 담당도 기한도 없이
     * 목록에 영영 남았다 — 그러면 `미등록 15개` 가 `14개` 로 줄어
     * <b>보고서의 수가 틀어진다.</b>
     *
     * <p>조치를 지우면 그 이력({@code remediation_events})도 함께
     * 사라진다({@code cascade = ALL}). 남는 자취는 감사 로그 한 줄뿐이라
     * 그 줄이 반드시 있어야 한다.
     */
    @Test
    @DisplayName("잘못 등록한 조치를 지우면 감사 로그에 남는다")
    void deletingARemediationIsRecorded() throws Exception {
        Asset asset = new Asset();
        asset.setName("rm-del-" + System.nanoTime());
        asset.setZone(zoneService.unassigned());
        assets.saveAndFlush(asset);

        Remediation remediation = remediations.saveAndFlush(
                new Remediation(asset, "openssl", ADMIN));
        Long id = remediation.getId();

        mvc.perform(post("/actions/" + id + "/delete")
                        .with(user(ADMIN).roles("ADMIN")).with(csrf()))
           .andExpect(status().is3xxRedirection());

        assertThat(remediations.findById(id))
                .as("지웠는데 남아 있다")
                .isEmpty();
        assertThat(recent(AuditEvent.REMEDIATION_DELETED))
                .as("지운 뒤 남는 자취는 이 줄뿐인데 없다")
                .extracting(AuditLog::getTarget)
                .anySatisfy(t -> assertThat(t).contains(asset.getName()).contains("openssl"));
    }

    /** 조회 권한만 있는 사람은 지울 수 없다. */
    @Test
    @DisplayName("조회 권한은 조치를 지우지 못한다")
    void viewersCannotDeleteARemediation() throws Exception {
        Asset asset = new Asset();
        asset.setName("rm-role-" + System.nanoTime());
        asset.setZone(zoneService.unassigned());
        assets.saveAndFlush(asset);
        Long id = remediations.saveAndFlush(new Remediation(asset, "curl", ADMIN)).getId();

        mvc.perform(post("/actions/" + id + "/delete")
                        .with(user("viewer").roles("VIEWER")).with(csrf()))
           .andExpect(status().isForbidden());

        assertThat(remediations.findById(id)).isPresent();
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

    /**
     * 감사 로그도 목록이 있는 다른 화면과 <b>같은 페이지 넘김</b>을 쓴다.
     *
     * <p>화면마다 쪽 넘김이 다르면 옮길 때마다 눈이 다시 자리를 찾는다.
     * 여기서 보는 것은 셋이다 — 페이지 사이즈가 먹는가, 페이지 번호로
     * 옮겨지는가, <b>옮기면서 거르개를 잃지 않는가.</b>
     */
    @Test
    @DisplayName("감사 로그의 페이지 사이즈와 페이지 이동이 거르개를 들고 간다")
    void theAuditPagerCarriesTheFilters() throws Exception {
        for (int i = 0; i < 12; i++) {
            audit.recordAs(ADMIN, AuditEvent.ZONE_CREATED, "쪽넘김-" + i, "");
        }

        String html = mvc.perform(get("/settings/audit?size=10")
                                .with(user(ADMIN).roles("ADMIN")))
                         .andExpect(status().isOk())
                         .andReturn().getResponse().getContentAsString();
        assertThat(html).contains("페이지 사이즈").contains("페이지");

        // 사람이 적는 값은 1부터. 주소의 page 는 0부터 세므로 서버가 환산한다.
        mvc.perform(get("/settings/audit?size=10&jump=2&action=ZONE_CREATED")
                        .with(user(ADMIN).roles("ADMIN")))
           .andExpect(redirectedUrl("/settings/audit?action=ZONE_CREATED&size=10&page=1"));
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

    /**
     * 화면의 <b>행위</b> 고르개는 {@code AuditEvent.values()} 로 만들어진다
     * ({@code AuditController:72}). 그래서 <b>선언만 하고 아무도 기록하지
     * 않는 이름은 고르면 언제나 0건인 선택지</b>가 된다.
     *
     * <p>실제로 여섯 개가 그랬다. 셋({@code REMEDIATION_CREATED} ·
     * {@code REMEDIATION_UPDATED} · {@code SETTING_CHANGED})은 어느 판에서도
     * 기록한 적이 없어 지웠고, 셋({@code RISK_ACCEPTED} ·
     * {@code RISK_ACCEPTANCE_REVOKED} · {@code USER_ROLE_CHANGED})은 옛
     * 판에서 기록했으므로 <b>남긴다</b> — {@code @Enumerated(STRING)} 이라
     * 지우면 그 이름이 든 옛 행을 읽다 터진다.
     *
     * <p>새로 더할 때도 둘 중 하나여야 한다: 기록하든가, 아래 목록에 이유와
     * 함께 적든가.
     */
    @Test
    @DisplayName("선언한 감사 행위는 기록되거나, 옛 이름으로 남긴 것이다")
    void everyAuditEventIsEitherRecordedOrHistorical() throws java.io.IOException {
        // 옛 판에서 기록했던 이름. 지우면 이미 쌓인 행을 읽을 수 없다.
        List<AuditEvent> historical = List.of(AuditEvent.RISK_ACCEPTED,
                                              AuditEvent.RISK_ACCEPTANCE_REVOKED,
                                              AuditEvent.USER_ROLE_CHANGED);

        StringBuilder code = new StringBuilder();
        try (var files = java.nio.file.Files.walk(java.nio.file.Path.of("src/main/java"))) {
            for (java.nio.file.Path file : files.filter(java.nio.file.Files::isRegularFile)
                                                .filter(f -> f.toString().endsWith(".java"))
                                                .toList()) {
                // 선언한 자리(AuditEvent.java)는 세지 않는다 — 거기 있는 것이
                // 기록했다는 뜻은 아니다.
                if (file.getFileName().toString().equals("AuditEvent.java")) {
                    continue;
                }
                code.append(java.nio.file.Files.readString(file)).append('\n');
            }
        }

        List<String> orphans = java.util.Arrays.stream(AuditEvent.values())
                .filter(e -> !historical.contains(e))
                .filter(e -> !code.toString().contains("AuditEvent." + e.name()))
                .map(Enum::name)
                .toList();

        assertThat(orphans)
                .as("선언만 되고 아무 데서도 기록하지 않는 행위입니다. 화면의 "
                    + "`행위` 고르개에 뜨지만 고르면 언제나 0건입니다. 기록하든가, "
                    + "옛 이름이면 이 시험의 historical 목록에 이유와 함께 적으세요.")
                .isEmpty();
    }
}
