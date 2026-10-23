package kr.sbomsight;

import kr.sbomsight.domain.AppUser;
import kr.sbomsight.domain.Role;
import kr.sbomsight.repo.AppUserRepository;
import kr.sbomsight.service.SettingsService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 접근 허용 목록을 <b>실제 필터 체인으로</b> 지나간다.
 *
 * <p>{@link IpAllowlistTest} 는 목록이 주소를 맞게 가르는지만 본다. 그 판단이 <b>어느
 * 자리에서</b> 서는지는 아무 시험도 보지 않았다. 필터에 {@code @Order(1)} 을 달고 "시큐리티
 * 체인보다 앞" 이라고 적어 두었는데 시큐리티 체인은 -100 에 선다 — 실제로는 뒤였다.
 * 로그인 · 로그아웃은 시큐리티 체인 안에서 처리되고 끝나 이 필터에 닿지도 않았다.
 *
 * <p><b>요청마다 유효한 CSRF 토큰을 싣는다.</b> 토큰이 없으면 CSRF 가 먼저 막아 필터의
 * 자리가 드러나지 않는다. 막힌 곳은 토큰이 있는 경우다 — 허용망에서 로그인 화면을 연
 * 세션을 들고 목록 밖 주소에서 보내면, 고치기 전에는 인증까지 가서 틀린 비밀번호 다섯
 * 번에 계정이 잠겼다.
 */
@SpringBootTest
@AutoConfigureMockMvc
class IpAllowlistFilterTest {

    /** 허용 목록. 시험이 보내는 요청의 기본 주소(127.0.0.1)는 이 밖이다. */
    private static final String ALLOWED = "10.0.0.0/24";
    private static final String INSIDE = "10.0.0.5";
    private static final String PASSWORD = "Sbom!2026Check";

    @Autowired MockMvc mvc;
    @Autowired SettingsService settings;
    @Autowired AppUserRepository users;
    @Autowired PasswordEncoder encoder;

    private String username;

    @BeforeEach
    void restrict() {
        username = "ip" + System.nanoTime();
        AppUser user = new AppUser(username, encoder.encode(PASSWORD), Role.ADMIN);
        // 첫 로그인 강제 변경에 걸리면 로그인 흐름 자체를 볼 수 없다.
        user.setMustChange(false);
        user.setPasswordChangedAt(java.time.Instant.now());
        users.saveAndFlush(user);

        assertThat(settings.saveAllowedIps(ALLOWED, INSIDE, "tester")).isEmpty();
    }

    /** 같은 문맥을 다른 시험이 함께 쓴다 — 목록을 비워 두지 않으면 그 시험들이 전부 막힌다. */
    @AfterEach
    void unrestrict() {
        settings.saveAllowedIps("", INSIDE, "tester");
    }

    private static RequestPostProcessor from(String ip) {
        return request -> {
            request.setRemoteAddr(ip);
            return request;
        };
    }

    /**
     * 이 필터가 막았다 — 시큐리티의 403(CSRF 같은)과 가른다. 상태 코드만 보면 둘이
     * 같아서, 필터가 뒤에 서 있어도 시큐리티가 다른 까닭으로 막으면 통과해 버린다.
     */
    private static ResultMatcher refusedByAllowlist() {
        return result -> {
            status().isForbidden().match(result);
            content().string(containsString("이 주소에서는 접속할 수 없습니다")).match(result);
        };
    }

    @Test
    @DisplayName("허용 목록 밖에서 보낸 로그인은 인증까지 가지 않는다 — 실패 횟수도 늘지 않는다")
    void loginFromOutsideNeverReachesAuthentication() throws Exception {
        mvc.perform(post("/login").param("username", username).param("password", "틀린값")
                                  .with(csrf()))
           .andExpect(refusedByAllowlist());

        assertThat(users.findByUsername(username).orElseThrow().getFailedAttempts())
                .as("허용 목록 밖에서 틀린 비밀번호를 대어 남의 계정을 잠글 수 있다")
                .isZero();
    }

    @Test
    @DisplayName("허용 목록 밖에서는 맞는 비밀번호로도 로그인되지 않는다")
    void correctPasswordFromOutsideIsRefused() throws Exception {
        mvc.perform(post("/login").param("username", username).param("password", PASSWORD)
                                  .with(csrf()))
           .andExpect(refusedByAllowlist());

        assertThat(users.findByUsername(username).orElseThrow().getLastLoginAt())
                .as("허용 목록 밖에서 로그인이 성공했다")
                .isNull();
    }

    @Test
    @DisplayName("허용 목록 밖에서 보낸 로그아웃도 막힌다")
    void logoutFromOutsideIsRefused() throws Exception {
        mvc.perform(post("/logout").with(csrf()))
           .andExpect(refusedByAllowlist());
    }

    @Test
    @DisplayName("허용 목록 밖이면 로그인 화면으로 돌려보내지도 않는다")
    void protectedPageFromOutsideIsRefusedNotRedirected() throws Exception {
        mvc.perform(get("/").header("Accept", "text/html"))
           .andExpect(refusedByAllowlist());
    }

    @Test
    @DisplayName("허용 목록 안에서는 그대로 로그인된다")
    void loginFromInsideStillWorks() throws Exception {
        mvc.perform(post("/login").param("username", username).param("password", PASSWORD)
                                  .with(csrf()).with(from(INSIDE)))
           .andExpect(redirectedUrl("/"));
    }
}
