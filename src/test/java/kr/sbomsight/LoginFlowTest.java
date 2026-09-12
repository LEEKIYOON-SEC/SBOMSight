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
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 로그인·로그아웃을 <b>실제 필터 체인으로</b> 통과시킨다.
 *
 * <p><b>왜 따로 있는가.</b> 다른 시험은 {@code .with(user(...))} 로 인증된
 * 주체를 곧바로 꽂아 넣는다. 그러면 화면이 그려지는지는 보지만 로그인 그
 * 자체 — 튕김, 돌아갈 자리 기억, 로그아웃, 세션 — 는 <b>한 번도 지나가지
 * 않는다.</b>
 *
 * <p>그래서 다음을 못 잡았다: 글꼴을 저장소에 담으면서 {@code /fonts/**} 를
 * 열어 두지 않았고, 로그인 화면이 부른 글꼴 요청이 "로그인 없이 닿은 요청"
 * 으로 기억되어, 로그인에 성공하면 스프링이 약속대로 그리로 보냈다.
 * <b>브라우저가 woff2 파일을 내려받고 화면은 열리지 않았다.</b> 화면 시험은
 * 전부 통과한 채로.
 */
@SpringBootTest
@AutoConfigureMockMvc
class LoginFlowTest {

    /** 로그인 화면이 실제로 부르는 글꼴 하나. */
    private static final String FONT =
            "/fonts/vEFK2-VJISZe3O_rc3ZVYh4aTwNO8tfdTbzIx6SmGN7aVT6YLxnNoW0zig.111.woff2";

    private static final String PASSWORD = "Sbom!2026Check";

    @Autowired MockMvc mvc;
    @Autowired AppUserRepository users;
    @Autowired PasswordEncoder encoder;

    private String username;

    @BeforeEach
    void seed() {
        username = "tester" + System.nanoTime();
        AppUser user = new AppUser(username, encoder.encode(PASSWORD), Role.ADMIN);
        // 첫 로그인 강제 변경에 걸리면 로그인 흐름 자체를 볼 수 없다.
        user.setMustChange(false);
        user.setPasswordChangedAt(java.time.Instant.now());
        users.saveAndFlush(user);
    }


    /** 진짜 로그인 폼을 보낸다. 세션을 내가 쥐어야 앞뒤 흐름을 볼 수 있다. */
    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder
            login(MockHttpSession session) {
        return loginWith(session, username, PASSWORD);
    }

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder
            loginWith(MockHttpSession session, String user, String password) {
        var builder = post("/login").param("username", user).param("password", password)
                                    .with(csrf());
        return session == null ? builder : builder.session(session);
    }

    // --- 정적 파일 -------------------------------------------------------

    /**
     * 로그인 화면이 쓰는 정적 파일은 로그인 없이 열려야 한다.
     *
     * <p>막히면 그 요청이 '돌아갈 자리' 로 기억되어 로그인 뒤 그 파일이
     * 떨어진다.
     */
    @Test
    @DisplayName("로그인 화면이 쓰는 정적 파일은 로그인 없이 받을 수 있다")
    void staticFilesAreOpen() throws Exception {
        for (String path : new String[] { "/css/app.css", "/css/fonts.css", FONT, "/favicon.svg" }) {
            mvc.perform(get(path))
               .andExpect(status().isOk());
        }
    }

    /**
     * <b>이 시험이 이번 버그를 잡는다.</b> 글꼴을 먼저 요청해 '돌아갈 자리'
     * 를 오염시켜 놓고 로그인한다. 글꼴로 보내면 실패다.
     */
    @Test
    @DisplayName("로그인 뒤에는 언제나 화면으로 간다 — 글꼴·CSS 로 보내지 않는다")
    void neverLandsOnAnAsset() throws Exception {
        MockHttpSession session = new MockHttpSession();

        // 브라우저가 로그인 화면을 그리며 부르는 것들.
        mvc.perform(get(FONT).session(session));
        mvc.perform(get("/css/app.css").session(session));
        // 화면이 아닌데 보호된 것(진행 상태 JSON)도 섞어 본다.
        mvc.perform(get("/scans/1/status").session(session).header("Accept", "application/json"));

        MvcResult result = mvc.perform(login(session))
                              .andExpect(status().is3xxRedirection())
                              .andReturn();

        String to = result.getResponse().getRedirectedUrl();
        assertThat(to).isNotNull();
        assertThat(to)
                .as("로그인 뒤 글꼴이나 CSS 로 보내면 브라우저가 파일을 내려받고 화면은 열리지 않는다")
                .doesNotContain(".woff2").doesNotContain(".css").doesNotContain("/status");
        assertThat(to).isEqualTo("/");
    }

    /** 사람이 주소를 치고 들어왔다 튕긴 경우에는 그 자리로 돌려보내야 한다. */
    @Test
    @DisplayName("보려던 화면으로는 제대로 돌아간다")
    void returnsToThePageYouWanted() throws Exception {
        MockHttpSession session = new MockHttpSession();

        mvc.perform(get("/lookup").session(session).header("Accept", "text/html"))
           .andExpect(status().is3xxRedirection())
           .andExpect(redirectedUrl("http://localhost/login"));

        // 스프링이 절대 주소와 ?continue 표시를 붙인다. 그것까지 못 박지
        // 않는다 — 확인할 것은 "그 화면으로 갔는가" 다.
        mvc.perform(login(session))
           .andExpect(header().string("Location", org.hamcrest.Matchers.containsString("/lookup")));
    }

    // --- 로그인 · 로그아웃 -----------------------------------------------

    @Test
    @DisplayName("로그인하지 않으면 화면이 열리지 않는다")
    void protectedPagesRedirect() throws Exception {
        mvc.perform(get("/").header("Accept", "text/html"))
           .andExpect(status().is3xxRedirection())
           .andExpect(redirectedUrl("http://localhost/login"));
    }

    @Test
    @DisplayName("로그인하면 열리고, 로그아웃하면 다시 닫힌다")
    void loginThenLogout() throws Exception {
        MockHttpSession session = new MockHttpSession();

        mvc.perform(login(session))
           .andExpect(redirectedUrl("/"));
        mvc.perform(get("/").session(session).header("Accept", "text/html"))
           .andExpect(status().isOk());

        mvc.perform(post("/logout").session(session).with(csrf()))
           .andExpect(redirectedUrl("/login?logout"));

        // 로그아웃 뒤에는 같은 세션으로 다시 못 들어간다.
        mvc.perform(get("/").session(session).header("Accept", "text/html"))
           .andExpect(status().is3xxRedirection());
    }

    @Test
    @DisplayName("비밀번호가 틀리면 이유를 알려 준다")
    void wrongPassword() throws Exception {
        mvc.perform(loginWith(null, username, "틀린비밀번호"))
           .andExpect(redirectedUrl("/login?error"));

        mvc.perform(get("/login").param("error", ""))
           .andExpect(status().isOk());
    }

    // --- 세션 -------------------------------------------------------------

    /**
     * 한 계정은 한 자리에서만.
     *
     * <p>새로 로그인하면 먼저 있던 자리가 끊긴다. 끊긴 쪽은 다음 요청에서
     * 왜 끊겼는지 알게 된다 — 말없이 튕기면 "가만히 있었는데 로그아웃됐다"
     * 가 된다.
     */
    @Test
    @DisplayName("같은 계정으로 다시 로그인하면 먼저 있던 자리가 끊긴다")
    void newLoginKicksTheOldSession() throws Exception {
        MockHttpSession first = new MockHttpSession();
        mvc.perform(login(first))
           .andExpect(redirectedUrl("/"));
        mvc.perform(get("/").session(first).header("Accept", "text/html"))
           .andExpect(status().isOk());

        MockHttpSession second = new MockHttpSession();
        mvc.perform(login(second))
           .andExpect(redirectedUrl("/"));

        // 먼저 있던 자리는 이제 끊겼고, 왜 끊겼는지 알려 주는 곳으로 간다.
        mvc.perform(get("/").session(first).header("Accept", "text/html"))
           .andExpect(status().is3xxRedirection())
           .andExpect(header().string("Location", org.hamcrest.Matchers.containsString("taken")));

        // 새로 들어온 자리는 멀쩡하다.
        mvc.perform(get("/").session(second).header("Accept", "text/html"))
           .andExpect(status().isOk());
    }

    @Test
    @DisplayName("끊긴 이유가 화면에 뜬다")
    void explainsWhyItWasKicked() throws Exception {
        String html = mvc.perform(get("/login").param("taken", ""))
                         .andExpect(status().isOk())
                         .andReturn().getResponse().getContentAsString();

        assertThat(html).contains("다른 곳에서 로그인해");
    }
}
