package kr.sbomsight;

import kr.sbomsight.domain.AppUser;
import kr.sbomsight.domain.AuditEvent;
import kr.sbomsight.domain.AuditLog;
import kr.sbomsight.domain.Role;
import kr.sbomsight.repo.AppUserRepository;
import kr.sbomsight.repo.AuditLogRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * 로그인·로그아웃이 실제로 감사 로그에 남는가.
 *
 * <p><b>왜 따로 확인하는가.</b> {@link kr.sbomsight.config.AuthEventListener} 는
 * 스프링 시큐리티가 발행하는 이벤트를 듣는다. 그 이벤트가 실제로 발행되는지는
 * 설정에 달려 있고, 발행되지 않으면 <b>조용히 아무것도 기록되지 않는다</b> —
 * 예외도 경고도 없다. 실제로 {@code LogoutSuccessEvent} 는 서블릿 필터
 * 체인에서 발행되지 않아 {@code LogoutHandler} 로 바꿔야 했다.
 *
 * <p>기록이 비어 있는 것을 "아무 일도 없었다" 로 읽으면 점검에서 틀린 말을
 * 하게 되므로, 진짜 폼 로그인을 태워 확인한다.
 */
@SpringBootTest
@AutoConfigureMockMvc
class AuthAuditTest {

    private static final String NAME = "auth.audit";
    private static final String PASSWORD = "시험-비밀번호-2026";

    @Autowired MockMvc mvc;
    @Autowired AppUserRepository users;
    @Autowired AuditLogRepository logs;
    @Autowired PasswordEncoder encoder;

    @BeforeEach
    void setUp() {
        users.findByUsername(NAME).ifPresent(users::delete);
        AppUser user = new AppUser(NAME, encoder.encode(PASSWORD), Role.ADMIN);
        user.setEnabled(true);
        user.setMustChange(false);
        users.save(user);
    }

    private List<AuditLog> recent(AuditEvent action) {
        return logs.search(NAME, action, Instant.now().minus(1, ChronoUnit.HOURS), null, null,
                           PageRequest.of(0, 20)).getContent();
    }

    @Test
    @DisplayName("폼 로그인 성공이 기록된다")
    void successIsRecorded() throws Exception {
        mvc.perform(post("/login").with(csrf())
                        .param("username", NAME)
                        .param("password", PASSWORD));

        assertThat(recent(AuditEvent.LOGIN_SUCCESS))
                .as("로그인 성공이 기록되지 않았다 — 이벤트가 발행되지 않는 것이다")
                .isNotEmpty();
    }

    @Test
    @DisplayName("비밀번호가 틀린 로그인이 기록된다")
    void failureIsRecorded() throws Exception {
        mvc.perform(post("/login").with(csrf())
                        .param("username", NAME)
                        .param("password", "틀린값"));

        assertThat(recent(AuditEvent.LOGIN_FAILURE))
                .as("로그인 실패가 기록되지 않았다")
                .isNotEmpty()
                .anySatisfy(row -> assertThat(row.getDetail()).contains("맞지 않습니다"));
    }

    @Test
    @DisplayName("로그아웃이 기록된다")
    void logoutIsRecorded() throws Exception {
        mvc.perform(post("/logout").with(user(NAME).roles("ADMIN")).with(csrf()));

        assertThat(recent(AuditEvent.LOGOUT))
                .as("로그아웃이 기록되지 않았다 — LogoutSuccessEvent 는 필터 체인에서 "
                    + "발행되지 않으므로 LogoutHandler 로 받아야 한다")
                .isNotEmpty();
    }

    @Test
    @DisplayName("중지된 계정의 로그인은 '차단' 으로 따로 기록된다")
    void disabledAccountIsRecordedAsBlocked() throws Exception {
        AppUser user = users.findByUsername(NAME).orElseThrow();
        user.setEnabled(false);
        users.save(user);

        mvc.perform(post("/login").with(csrf())
                        .param("username", NAME)
                        .param("password", PASSWORD));

        // 잠긴·중지된 계정은 '비밀번호가 틀렸다' 와 성격이 다르다. 점검에서
        // "잠금이 실제로 걸렸나" 를 묻기 때문에 구분해 남긴다.
        assertThat(recent(AuditEvent.LOGIN_BLOCKED)).isNotEmpty();
    }
}
