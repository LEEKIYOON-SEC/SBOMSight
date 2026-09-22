package kr.sbomsight;

import kr.sbomsight.domain.*;
import kr.sbomsight.repo.*;
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
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 조치에 손댄 일이 <b>감사 로그에 남는가.</b>
 *
 * <p>상태를 바꾸는 길 스물일곱 개를 실제로 눌러 보고 {@code audit_log} 를
 * 읽었다. 스물넷은 남았고 <b>셋이 한 줄도 남지 않았다</b> — 조치를 여는 두
 * 길과 조치를 고치는 길. 지우는 것만 남고 있었다.
 *
 * <p><b>발자취로 대신할 수 없다.</b> {@code remediation_events} 는
 * {@link Remediation#moveTo} 가 부를 때만 쌓이고, 그것은 <b>상태가 바뀔 때만</b>
 * 불린다. 상태를 그대로 두고 기한만 미루면 어디에도 아무것도 남지 않았다 —
 * {@code updated_by} 한 칸이 덮어써지는 것이 전부였다. 게다가 조치를 지우면
 * 발자취는 함께 사라진다({@code cascade = ALL}).
 *
 * <p><b>{@code @Transactional} 이다.</b> 여기서 남긴 감사 줄이 쌓이면
 * {@code AuditLogTest} 처럼 전체를 세는 시험이 흔들린다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class RemediationAuditTest {

    @Autowired MockMvc mvc;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired RemediationRepository remediations;
    @Autowired AuditLogRepository logs;
    @Autowired ZoneService zoneService;

    private Asset asset;
    private Scan scan;
    private String pkg;

    @BeforeEach
    void setUp() {
        asset = new Asset();
        asset.setName("ra-" + System.nanoTime());
        asset.setZone(zoneService.unassigned());
        assets.save(asset);
        pkg = "ra-pkg-" + System.nanoTime();

        scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        scan.setCreatedAt(Instant.now());
        scans.saveAndFlush(scan);

        Finding f = new Finding(scan, "CVE-2099-0001|" + pkg, "CVE-2099-0001", pkg);
        f.setPackageVersion("1.0.0");
        f.setSeverity("Critical");
        f.setFixState("fixed");
        f.setFixedVersion("1.0.1");
        f.setCvssScore(BigDecimal.valueOf(9.8));
        findings.saveAndFlush(f);
    }

    /** 자산에서 여는 길 — 취약점 화면과 검토 결과의 `조치 등록`. */
    @Test
    @DisplayName("자산에서 조치를 열면 감사 로그에 남는다")
    void openingFromTheAssetIsRecorded() throws Exception {
        open("/assets/" + asset.getId() + "/remediations");

        AuditLog row = only(AuditEvent.REMEDIATION_CREATED);
        assertThat(row.getTarget()).contains(asset.getName()).contains(pkg);
        // 조치를 지우면 등록 당시 스냅샷이 함께 사라진다. 그 수가 이 줄에 남아야
        // "무엇을 보고 등록했나" 에 답할 수 있다.
        assertThat(row.getDetail()).contains("1건").contains("1.0.0").contains("1.0.1");
    }

    /** 검사에서 여는 길 — 보고서 3장의 `조치 등록`. */
    @Test
    @DisplayName("검사에서 조치를 열면 감사 로그에 남는다")
    void openingFromTheScanIsRecorded() throws Exception {
        open("/scans/" + scan.getId() + "/remediations");

        assertThat(only(AuditEvent.REMEDIATION_CREATED).getTarget())
                .contains(asset.getName()).contains(pkg);
    }

    /**
     * 두 번 눌러도 등록은 한 번이다.
     *
     * <p>조치는 {@code (자산, 패키지)} 하나에 하나이고 같은 패키지의 검토
     * 여러 줄이 모두 `조치 등록` 을 달고 있다 — 두 번 눌리는 것은 예외가
     * 아니라 보통이다. 그때마다 `등록` 이 남으면 감사 로그가 없던 일을 말한다.
     */
    @Test
    @DisplayName("두 번 눌러도 `조치 등록` 은 한 줄만 남는다")
    void openingTwiceIsRecordedOnce() throws Exception {
        open("/assets/" + asset.getId() + "/remediations");
        open("/assets/" + asset.getId() + "/remediations");

        assertThat(rows(AuditEvent.REMEDIATION_CREATED))
                .as("이미 있던 조치를 돌려받은 것까지 `등록` 으로 남았습니다")
                .hasSize(1);
    }

    /**
     * <b>상태를 바꾸지 않아도 남는다.</b>
     *
     * <p>이 시험이 없어서 못 봤다. 담당과 기한만 고치면 발자취에도 감사
     * 로그에도 한 줄이 없었고, 남는 것은 {@code updated_by} 한 칸이었다 —
     * 그 칸은 다음 수정이 덮어쓴다.
     */
    @Test
    @DisplayName("담당·기한만 바꿔도 `조치 변경` 이 남는다 — 발자취에는 남지 않는다")
    void changingOnlyTheOwnerIsRecorded() throws Exception {
        open("/assets/" + asset.getId() + "/remediations");
        Remediation opened = remediations.findByAssetIdAndPackageName(asset.getId(), pkg)
                                         .orElseThrow();
        int eventsBefore = opened.getEvents().size();

        mvc.perform(post("/actions/" + opened.getId())
                            .param("status", RemediationStatus.OPEN.name())
                            .param("owner", "홍길동")
                            .param("dueDate", "2099-12-31")
                            .param("note", "")
                            .param("comment", "")
                            .with(user("tester").roles("ADMIN")).with(csrf()))
           .andExpect(status().is3xxRedirection());

        AuditLog row = only(AuditEvent.REMEDIATION_UPDATED);
        assertThat(row.getDetail())
                .as("무엇이 바뀌었는지 적혀 있지 않으면 남긴 뜻이 없습니다")
                .contains("담당").contains("홍길동")
                .contains("기한").contains("2099-12-31");

        Remediation after = remediations.findDetail(opened.getId()).orElseThrow();
        assertThat(after.getEvents())
                .as("상태가 그대로면 발자취는 늘지 않는다 — 그래서 감사 로그가 필요하다")
                .hasSize(eventsBefore);
    }

    /** 상태를 바꾸면 발자취와 감사 로그 양쪽에 남는다. */
    @Test
    @DisplayName("상태를 바꾸면 `조치 변경` 에 앞뒤 상태가 적힌다")
    void changingTheStatusRecordsBothSides() throws Exception {
        open("/assets/" + asset.getId() + "/remediations");
        Remediation opened = remediations.findByAssetIdAndPackageName(asset.getId(), pkg)
                                         .orElseThrow();

        mvc.perform(post("/actions/" + opened.getId())
                            .param("status", RemediationStatus.IN_PROGRESS.name())
                            .param("owner", "")
                            .param("note", "")
                            .param("comment", "착수")
                            .with(user("tester").roles("ADMIN")).with(csrf()))
           .andExpect(status().is3xxRedirection());

        assertThat(only(AuditEvent.REMEDIATION_UPDATED).getDetail())
                .contains(RemediationStatus.OPEN.label())
                .contains(RemediationStatus.IN_PROGRESS.label());
    }

    /**
     * 바뀐 것이 없으면 남기지 않는다.
     *
     * <p>손대지 않은 칸까지 쌓으면 감사 로그가 읽히지 않는다. 눌린 적만
     * 있는 것은 일어난 일이 아니다.
     */
    @Test
    @DisplayName("고친 것이 없으면 `조치 변경` 이 남지 않는다")
    void savingWithoutAChangeIsNotRecorded() throws Exception {
        open("/assets/" + asset.getId() + "/remediations");
        Remediation opened = remediations.findByAssetIdAndPackageName(asset.getId(), pkg)
                                         .orElseThrow();

        mvc.perform(post("/actions/" + opened.getId())
                            .param("status", opened.getStatus().name())
                            .param("owner", opened.getOwner())
                            .param("note", opened.getNote())
                            .param("comment", "")
                            .with(user("tester").roles("ADMIN")).with(csrf()))
           .andExpect(status().is3xxRedirection());

        assertThat(rows(AuditEvent.REMEDIATION_UPDATED)).isEmpty();
    }

    // -----------------------------------------------------------------------

    private void open(String path) throws Exception {
        mvc.perform(post(path).param("packageName", pkg)
                              .with(user("tester").roles("ADMIN")).with(csrf()))
           .andExpect(status().is3xxRedirection());
    }

    /** 이 시험이 남긴 줄만 본다 — 대상에 제 자산 이름이 든 것. */
    private List<AuditLog> rows(AuditEvent action) {
        return logs.findAll().stream()
                   .filter(log -> log.getAction() == action)
                   .filter(log -> log.getTarget().contains(asset.getName()))
                   .toList();
    }

    private AuditLog only(AuditEvent action) {
        List<AuditLog> found = rows(action);
        assertThat(found)
                .as(action.label() + " 이 감사 로그에 남지 않았습니다 — 그 행위는 "
                    + "일어난 적이 없는 것과 같습니다")
                .hasSize(1);
        return found.get(0);
    }
}
