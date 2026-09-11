package kr.sbomsight;

import kr.sbomsight.config.SbomSightProperties;
import kr.sbomsight.domain.AppUser;
import kr.sbomsight.domain.AuditEvent;
import kr.sbomsight.domain.Role;
import kr.sbomsight.repo.AppUserRepository;
import kr.sbomsight.repo.AuditLogRepository;
import kr.sbomsight.service.LoginAttemptService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * 로그인 실패 잠금.
 *
 * <p>여기서 고정하는 것 셋:
 * <ol>
 *   <li>정해진 횟수에서 <b>실제로</b> 잠긴다.</li>
 *   <li>잠긴 계정은 <b>맞는 비밀번호로도</b> 들어오지 못한다. 이것이 핵심이다 —
 *       잠금이 화면에만 표시되고 인증을 막지 못하면 아무 통제가 아니다.</li>
 *   <li>응답으로 계정의 존재가 새지 않는다. 있는 계정과 없는 계정의 실패
 *       응답이 다르면 그 차이로 계정 목록을 알아낼 수 있다.</li>
 * </ol>
 */
@SpringBootTest
@AutoConfigureMockMvc
class LoginLockoutTest {

    private static final String NAME = "lock.test";
    private static final String PASSWORD = "바른-비밀번호-2026";

    @Autowired MockMvc mvc;
    @Autowired AppUserRepository users;
    @Autowired AuditLogRepository logs;
    @Autowired PasswordEncoder encoder;
    @Autowired LoginAttemptService attempts;
    @Autowired SbomSightProperties properties;

    @BeforeEach
    void setUp() {
        users.findByUsername(NAME).ifPresent(users::delete);
        AppUser user = new AppUser(NAME, encoder.encode(PASSWORD), Role.ADMIN);
        user.setEnabled(true);
        user.setMustChange(false);
        users.save(user);
    }

    private MvcResult attempt(String username, String password) throws Exception {
        return mvc.perform(post("/login").with(csrf())
                        .param("username", username)
                        .param("password", password))
                  .andReturn();
    }

    private AppUser reload() {
        return users.findByUsername(NAME).orElseThrow();
    }

    @Test
    @DisplayName("실패가 쌓이고 정해진 횟수에서 잠긴다")
    void locksAtTheThreshold() throws Exception {
        int max = properties.maxLoginFailures();

        for (int i = 1; i < max; i++) {
            attempt(NAME, "틀린값");
            assertThat(reload().getFailedAttempts()).isEqualTo(i);
            assertThat(attempts.isLocked(reload())).as("%d회에서는 아직 잠기지 않는다", i).isFalse();
        }

        attempt(NAME, "틀린값");
        assertThat(reload().getFailedAttempts()).isEqualTo(max);
        assertThat(attempts.isLocked(reload())).as("%d회에서 잠겨야 한다", max).isTrue();
        assertThat(reload().getLockedAt()).isNotNull();
    }

    /**
     * 이 시험이 이 기능의 존재 이유다. 잠금이 상태로만 남고 인증을 막지
     * 못하면 화면에 자물쇠 그림을 그려 둔 것과 다르지 않다.
     */
    @Test
    @DisplayName("잠긴 계정은 맞는 비밀번호로도 들어오지 못한다")
    void aLockedAccountRejectsTheCorrectPassword() throws Exception {
        for (int i = 0; i < properties.maxLoginFailures(); i++) {
            attempt(NAME, "틀린값");
        }
        assertThat(attempts.isLocked(reload())).isTrue();

        // 이 시험들은 트랜잭션 안에서 돌지 않는다(진짜 로그인 흐름을 태우려면
        // 커밋되어야 한다). 같은 클래스의 다른 시험이 남긴 LOGIN_SUCCESS 가
        // 있으므로, 기준 시각을 잡아 그 뒤만 본다.
        Instant mark = Instant.now();
        MvcResult result = attempt(NAME, PASSWORD);

        // 로그인 성공은 / 로 가고, 실패는 /login?error 로 간다.
        assertThat(result.getResponse().getRedirectedUrl())
                .as("잠긴 계정이 맞는 비밀번호로 통과했다")
                .contains("error");
        assertThat(logs.search(NAME, AuditEvent.LOGIN_SUCCESS, mark, null, null,
                              PageRequest.of(0, 5)).getContent())
                .as("잠긴 계정의 로그인 성공이 기록됐다")
                .isEmpty();
    }

    @Test
    @DisplayName("성공하면 실패 횟수가 0 으로 돌아간다")
    void successResetsTheCounter() throws Exception {
        attempt(NAME, "틀린값");
        attempt(NAME, "틀린값");
        assertThat(reload().getFailedAttempts()).isEqualTo(2);

        attempt(NAME, PASSWORD);
        assertThat(reload().getFailedAttempts()).isZero();
        assertThat(reload().getLockedAt()).isNull();
    }

    @Test
    @DisplayName("관리자가 풀면 바로 들어올 수 있다")
    void adminCanUnlock() throws Exception {
        for (int i = 0; i < properties.maxLoginFailures(); i++) {
            attempt(NAME, "틀린값");
        }
        assertThat(attempts.isLocked(reload())).isTrue();

        attempts.unlock(NAME);

        assertThat(reload().getLockedAt()).isNull();
        assertThat(reload().getFailedAttempts()).isZero();
        assertThat(attempt(NAME, PASSWORD).getResponse().getRedirectedUrl())
                .doesNotContain("error");
    }

    @Test
    @DisplayName("자동 해제 시간이 지나면 스스로 풀린다")
    void unlocksItselfAfterTheWindow() {
        AppUser user = reload();
        user.setLockedAt(Instant.now().minus(2, ChronoUnit.HOURS));
        user.setFailedAttempts(properties.maxLoginFailures());
        users.save(user);

        // 30분 창을 두 시간 전에 잠긴 계정에 적용하면 이미 지났다.
        assertThat(user.isLocked(Duration.ofMinutes(30))).isFalse();
        // 창을 쓰지 않는 설정(0 = null)이면 계속 잠긴 채다.
        assertThat(user.isLocked(null)).isTrue();
    }

    /**
     * 있는 계정과 없는 계정의 실패 응답이 같아야 한다. 다르면 그 차이로
     * 계정 목록을 알아낼 수 있다.
     */
    @Test
    @DisplayName("없는 계정과 있는 계정의 실패 응답이 같다")
    void doesNotRevealWhetherAnAccountExists() throws Exception {
        MvcResult existing = attempt(NAME, "틀린값");
        MvcResult missing = attempt("이런계정은없다-" + System.nanoTime(), "틀린값");

        assertThat(existing.getResponse().getStatus())
                .isEqualTo(missing.getResponse().getStatus());
        assertThat(existing.getResponse().getRedirectedUrl())
                .isEqualTo(missing.getResponse().getRedirectedUrl());
    }

    @Test
    @DisplayName("없는 계정으로는 행을 만들지 않는다")
    void createsNoRowForAnUnknownName() throws Exception {
        String ghost = "유령-" + System.nanoTime();
        long before = users.count();

        for (int i = 0; i < properties.maxLoginFailures() + 2; i++) {
            attempt(ghost, "아무거나");
        }

        // 시도한 이름마다 행을 만들면 표가 남의 추측으로 채워진다.
        assertThat(users.count()).isEqualTo(before);
        assertThat(users.findByUsername(ghost)).isEmpty();
    }

    @Test
    @DisplayName("잠금은 감사 로그에 남는다")
    void lockingIsRecorded() throws Exception {
        for (int i = 0; i < properties.maxLoginFailures(); i++) {
            attempt(NAME, "틀린값");
        }

        assertThat(logs.search(NAME, AuditEvent.LOGIN_BLOCKED,
                              Instant.now().minus(1, ChronoUnit.HOURS), null, null,
                              PageRequest.of(0, 5)).getContent())
                .anySatisfy(row -> assertThat(row.getDetail()).contains("잠겼습니다"));
    }

    @Test
    @DisplayName("잠금 해제 화면이 동작한다")
    void unlockThroughTheScreen() throws Exception {
        for (int i = 0; i < properties.maxLoginFailures(); i++) {
            attempt(NAME, "틀린값");
        }

        mvc.perform(post("/settings/users/" + NAME + "/unlock")
                        .with(user("unlocker").roles("ADMIN")).with(csrf()));

        assertThat(reload().getLockedAt()).isNull();
    }
}
