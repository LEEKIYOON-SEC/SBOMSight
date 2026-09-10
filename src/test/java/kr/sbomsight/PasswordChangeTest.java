package kr.sbomsight;

import kr.sbomsight.domain.AppUser;
import kr.sbomsight.domain.Role;
import kr.sbomsight.repo.AppUserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 초기 비밀번호로 로그인한 계정이 실제로 비밀번호를 바꿀 수 있는가.
 *
 * <p><b>왜 이 시험이 있는가.</b> 실 PC 에서 관리자가 비밀번호를 바꾸지 못했다.
 * 원인이 둘이었고 둘 다 "화면은 있는데 닿을 수 없다" 는 종류였다:
 *
 * <ol>
 *   <li>{@code /password} 로 가는 링크가 어느 화면에도 없었다. 주소창에 직접
 *       쳐야만 닿았다.</li>
 *   <li>{@code password.html} 은 "새 비밀번호를 정하기 전에는 다른 화면이
 *       열리지 않습니다" 라고 적어 두었는데 그렇게 만드는 코드가 없었다.
 *       초기 비밀번호(= 계정 이름)를 쓰는 계정이 그대로 돌아다닐 수 있었다.</li>
 * </ol>
 *
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class PasswordChangeTest {

    @Autowired MockMvc mvc;
    @Autowired AppUserRepository users;
    @Autowired PasswordEncoder encoder;

    private static final String NAME = "reset.user";

    @BeforeEach
    void setUp() {
        users.findByUsername(NAME).ifPresent(users::delete);
        // 초기 비밀번호 = 계정 이름. 설정 화면의 "비밀번호 초기화" 가 만드는 상태다.
        AppUser user = new AppUser(NAME, encoder.encode(NAME), Role.ADMIN);
        user.setDisplayName("초기화된 계정");
        user.setEnabled(true);
        user.setMustChange(true);
        users.save(user);
    }

    @Test
    @DisplayName("초기 비밀번호를 쓰는 계정은 어느 화면을 열어도 비밀번호 화면으로 간다")
    void lockedUserIsSentToPasswordPage() throws Exception {
        for (String path : new String[] { "/", "/remediations", "/settings" }) {
            mvc.perform(get(path).with(user(NAME).roles("ADMIN")))
               .andExpect(status().is3xxRedirection())
               .andExpect(redirectedUrl("/password"));
        }
    }

    @Test
    @DisplayName("붙잡힌 상태에서도 비밀번호 화면과 로그아웃은 열린다")
    void thePasswordPageItselfIsReachable() throws Exception {
        // 이 둘이 막히면 빠져나갈 길이 없어진다.
        mvc.perform(get("/password").with(user(NAME).roles("ADMIN")))
           .andExpect(status().isOk());
        mvc.perform(post("/logout").with(user(NAME).roles("ADMIN")).with(csrf()))
           .andExpect(status().is3xxRedirection());
    }

    @Test
    @DisplayName("비밀번호를 바꾸면 잠금이 풀리고 다른 화면이 열린다")
    void changingThePasswordReleasesTheLock() throws Exception {
        mvc.perform(post("/password").with(user(NAME).roles("ADMIN")).with(csrf())
                        .param("current", NAME)
                        .param("password", "새-비밀번호-2026")
                        .param("confirm", "새-비밀번호-2026"))
           .andExpect(redirectedUrl("/"));

        AppUser after = users.findByUsername(NAME).orElseThrow();
        assertThat(after.isMustChange()).as("바꿨는데도 잠금이 남아 있다").isFalse();
        assertThat(encoder.matches("새-비밀번호-2026", after.getPasswordHash())).isTrue();

        mvc.perform(get("/").with(user(NAME).roles("ADMIN")))
           .andExpect(status().isOk());
    }

    @Test
    @DisplayName("현재 비밀번호가 틀리면 바뀌지 않는다")
    void theCurrentPasswordMustMatch() throws Exception {
        mvc.perform(post("/password").with(user(NAME).roles("ADMIN")).with(csrf())
                        .param("current", "엉뚱한값")
                        .param("password", "새-비밀번호-2026")
                        .param("confirm", "새-비밀번호-2026"))
           .andExpect(redirectedUrl("/password"));

        AppUser after = users.findByUsername(NAME).orElseThrow();
        assertThat(after.isMustChange()).as("잠금이 풀려 버렸다").isTrue();
        assertThat(encoder.matches(NAME, after.getPasswordHash()))
                .as("비밀번호가 바뀌어 버렸다").isTrue();
    }

    @Test
    @DisplayName("확인란이 다르면 바뀌지 않는다")
    void theConfirmationMustMatch() throws Exception {
        mvc.perform(post("/password").with(user(NAME).roles("ADMIN")).with(csrf())
                        .param("current", NAME)
                        .param("password", "새-비밀번호-2026")
                        .param("confirm", "새-비밀번호-2027"))
           .andExpect(redirectedUrl("/password"));

        assertThat(users.findByUsername(NAME).orElseThrow().isMustChange()).isTrue();
    }

    @Test
    @DisplayName("잠기지 않은 계정은 아무 데나 다닐 수 있다")
    void anUnlockedUserIsNotRedirected() throws Exception {
        AppUser user = users.findByUsername(NAME).orElseThrow();
        user.setMustChange(false);
        users.save(user);

        mvc.perform(get("/").with(user(NAME).roles("ADMIN")))
           .andExpect(status().isOk());
    }

    /**
     * 실제로 막혔던 자리다. 화면과 흐름이 다 멀쩡해도 <b>거기로 가는 링크가
     * 없으면 없는 기능</b>이다. 주소창에 /password 를 직접 치라고 할 수는 없다.
     */
    @Test
    @DisplayName("보통 화면의 상단바에 비밀번호 변경으로 가는 링크가 있다")
    void everyPageLinksToThePasswordScreen() throws Exception {
        AppUser user = users.findByUsername(NAME).orElseThrow();
        user.setMustChange(false);
        users.save(user);

        String html = mvc.perform(get("/").with(user(NAME).roles("ADMIN")))
                         .andExpect(status().isOk())
                         .andReturn().getResponse().getContentAsString();

        assertThat(html)
                .as("상단바에 /password 로 가는 링크가 없다 — 화면이 있어도 닿을 수 없다")
                .contains("href=\"/password\"");
    }
}
