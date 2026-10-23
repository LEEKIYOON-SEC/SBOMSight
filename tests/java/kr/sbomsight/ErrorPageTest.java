package kr.sbomsight;

import jakarta.persistence.EntityManagerFactory;
import kr.sbomsight.domain.AppUser;
import kr.sbomsight.domain.Role;
import kr.sbomsight.repo.AppUserRepository;
import org.hibernate.SessionFactory;
import org.hibernate.stat.Statistics;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.CookieManager;
import java.net.Socket;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * <b>오류 화면은 한국어로, 무엇을 하면 되는지까지 말한다.</b>
 *
 * <p>앞서 404 · 400 · 405 · 403 · 500 이 전부 스프링 부트의 영문 기본 화면
 * ({@code Whitelabel Error Page})이었다. 옛 주소를 걷은 뒤로는 옛 즐겨찾기도
 * 이 화면을 본다.
 *
 * <p><b>진짜 톰캣으로 돈다.</b> MockMvc 는 {@code sendError} 를 받아 적기만 하고
 * 오류 화면({@code /error})으로 넘기지 않는다 — 그러면 이 화면은 한 번도 그려지지
 * 않고, 오류를 넘기는 길(보안 필터 · 인터셉터 · 조언)도 지나가지 않는다.
 * 로그인도 진짜 폼으로 한다.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
                properties = "spring.jpa.properties.hibernate.generate_statistics=true")
@Import(ErrorPageTest.Boom.class)
class ErrorPageTest {

    private static final String PASSWORD = "Sbom!2026Check";

    /** 500 을 내는 자리 — 이 시험에만 붙는다(시험 클래스 안이라 다른 시험은 훑지 않는다). */
    @RestController
    static class Boom {
        @GetMapping("/test-only/boom")
        String boom() {
            throw new IllegalStateException("SELECT secret FROM findings — 이 글자가 화면에 나가면 안 된다");
        }
    }

    @LocalServerPort int port;
    @Autowired AppUserRepository users;
    @Autowired PasswordEncoder encoder;
    @Autowired EntityManagerFactory emf;

    private String admin;
    private String viewer;

    @BeforeEach
    void seed() {
        admin = account(Role.ADMIN);
        viewer = account(Role.VIEWER);
    }

    @Test
    @DisplayName("없는 주소 — 한국어 404, 영문 기본 화면이 아니다")
    void notFoundIsKorean() throws Exception {
        HttpResponse<String> r = page(signedIn(admin), "/no-such-page");
        assertThat(r.statusCode()).isEqualTo(404);
        assertThat(r.body())
                .doesNotContain("Whitelabel")
                .contains("<html lang=\"ko\"")
                .contains("찾을 수 없습니다")
                .contains("href=\"/\"");
    }

    @Test
    @DisplayName("우리가 적은 404 사유(자산을 찾을 수 없습니다)는 그대로 보여 준다")
    void ourOwnReasonIsShown() throws Exception {
        HttpResponse<String> r = page(signedIn(admin), "/assets/999999999");
        assertThat(r.statusCode()).isEqualTo(404);
        assertThat(r.body()).contains("자산을 찾을 수 없습니다");
    }

    /** 예외 종류에 박아 둔 사유(ZoneService.NoSuchZoneException)도 우리가 적은 말이다. */
    @Test
    @DisplayName("지운 구역의 주소 — 404 화면이 '구역을 찾을 수 없습니다' 라고 말한다")
    void aMissingZoneSaysSo() throws Exception {
        HttpResponse<String> r = page(signedIn(admin), "/vulns?zone=987654321");
        assertThat(r.statusCode()).isEqualTo(404);
        assertThat(r.body()).contains("구역을 찾을 수 없습니다");
    }

    @Test
    @DisplayName("주소의 값이 틀리면 400 — 무엇이 틀렸는지 말한다")
    void badRequestIsKorean() throws Exception {
        HttpResponse<String> r = page(signedIn(admin), "/assets/abc");
        assertThat(r.statusCode()).isEqualTo(400);
        assertThat(r.body()).doesNotContain("Whitelabel").contains("요청을 처리할 수 없습니다");
    }

    @Test
    @DisplayName("단추로 하는 작업의 주소를 주소창으로 열면 405 — 그렇게 말한다")
    void methodNotAllowedIsKorean() throws Exception {
        HttpResponse<String> r = page(signedIn(admin), "/scans/1/rescan");
        assertThat(r.statusCode()).isEqualTo(405);
        assertThat(r.body()).doesNotContain("Whitelabel").contains("주소창으로 열 수 없는 주소입니다");
    }

    @Test
    @DisplayName("조회 계정이 관리자 화면을 열면 403 — 관리자만 할 수 있다고 말한다")
    void forbiddenIsKorean() throws Exception {
        HttpResponse<String> r = page(signedIn(viewer), "/settings");
        assertThat(r.statusCode()).isEqualTo(403);
        assertThat(r.body())
                .doesNotContain("Whitelabel")
                .contains("권한이 없습니다")
                .contains("관리자 계정만");
    }

    /**
     * 보안 확인 값(CSRF)이 맞지 않는 403 은 권한 문제가 아니다 — 화면을 연 뒤
     * 다른 창에서 다시 로그인하면 이렇게 된다. "관리자만" 이라고 하면 관리자가
     * 자기 권한을 의심한다.
     */
    @Test
    @DisplayName("보안 확인 값이 맞지 않으면 권한 탓을 하지 않고 새로 고치라고 말한다")
    void staleFormIsNotBlamedOnPermissions() throws Exception {
        HttpClient client = signedIn(admin);
        // 화면을 한 장 열어 세션에 확인 값이 생기게 한다. 값이 아예 없으면
        // 스프링이 "세션이 끊겼다" 로 보고 로그인 화면으로 보낸다(403 이 아니다).
        assertThat(page(client, "/").statusCode()).isEqualTo(200);
        HttpResponse<String> r = client.send(HttpRequest.newBuilder(uri("/assets/1/archive"))
                        .header("Accept", "text/html")
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString("_csrf=stale-token"))
                        .build(),
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        assertThat(r.statusCode()).isEqualTo(403);
        assertThat(r.body())
                .contains("새로 고친 뒤")
                .doesNotContain("관리자 계정만");
    }

    @Test
    @DisplayName("500 — 한국어로, 기록을 찾을 시각을 주고, 안의 사정은 내보내지 않는다")
    void serverErrorIsKoreanAndSaysNothingInside() throws Exception {
        HttpResponse<String> r = page(signedIn(admin), "/test-only/boom");
        assertThat(r.statusCode()).isEqualTo(500);
        assertThat(r.body())
                .doesNotContain("Whitelabel")
                .contains("처리하지 못했습니다")
                .doesNotContain("SELECT secret")
                .doesNotContain("IllegalStateException");
        assertThat(r.body()).containsPattern("\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}");
    }

    @Test
    @DisplayName("로그인 전에 공개 경로에서 난 404 도 같은 화면이다")
    void anonymousNotFoundIsKorean() throws Exception {
        HttpResponse<String> r = page(HttpClient.newBuilder().cookieHandler(new CookieManager()).build(),
                                      "/css/no-such.css");
        assertThat(r.statusCode()).isEqualTo(404);
        assertThat(r.body()).contains("찾을 수 없습니다").doesNotContain("Whitelabel");
    }

    @Test
    @DisplayName("화면이 아닌 요청(JSON)에는 화면을 내지 않는다")
    void jsonClientsStillGetJson() throws Exception {
        HttpResponse<String> r = signedIn(admin).send(HttpRequest.newBuilder(uri("/no-such-page"))
                        .header("Accept", "application/json").GET().build(),
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        assertThat(r.statusCode()).isEqualTo(404);
        assertThat(r.headers().firstValue("Content-Type").orElse("")).contains("application/json");
        assertThat(r.body()).doesNotContain("<html");
    }

    /**
     * <b>오류 화면은 DB 를 묻지 않는다.</b> 기둥(왼쪽 메뉴)의 숫자를 채우는
     * 조언(LayoutAdvice)이 오류 화면에서도 돌면, DB 가 멈춰 난 500 에서 오류
     * 화면을 그리다가 또 멈춘다 — 그러면 톰캣의 영문 화면이 뜬다. 오류 화면은
     * 기둥을 그리지 않으므로 물을 까닭도 없다.
     */
    @Test
    @DisplayName("오류 화면은 DB 를 묻지 않는다 — 기둥을 그리지 않는다")
    void theErrorPageAsksTheDatabaseNothing() throws Exception {
        HttpClient client = signedIn(admin);
        Statistics stats = emf.unwrap(SessionFactory.class).getStatistics();
        stats.clear();
        HttpResponse<String> r = page(client, "/no-such-page");
        assertThat(r.statusCode()).isEqualTo(404);
        assertThat(r.body()).doesNotContain("navbar-vertical");
        assertThat(stats.getPrepareStatementCount())
                .as("오류 화면 한 장에 SQL 이 %d 번 나갔다", stats.getPrepareStatementCount())
                .isZero();
    }

    /**
     * 주소에 쓸 수 없는 글자가 든 요청은 톰캣이 스프링 앞에서 끊는다. 앞서 이
     * 요청에는 톰캣의 영문 화면({@code HTTP Status 400 – Bad Request})이 떴다 —
     * 브라우저가 한국어를 청해도 그랬다(톰캣에 한국어 판이 없다).
     */
    @Test
    @DisplayName("톰캣이 스프링 앞에서 끊은 주소도 한국어 400 화면이다")
    void aUrlTomcatRejectsIsKoreanToo() throws Exception {
        for (String path : new String[] {"/%", "/a%00b"}) {
            String r = raw("GET " + path + " HTTP/1.1");
            assertThat(r).as(path)
                    .startsWith("HTTP/1.1 400")
                    .contains("Content-Type: text/html;charset=UTF-8")
                    .contains("<html lang=\"ko\"")
                    .contains("오류 400")
                    .contains("주소에 쓸 수 없는 글자")
                    .contains("href=\"/\"")
                    .doesNotContain("HTTP Status")
                    .doesNotContain("Bad Request");
        }
    }

    /** 400 밖의 것은 상태를 모르고 그린 판이다 — 틀린 번호를 적지 않는다. */
    @Test
    @DisplayName("톰캣 앞단의 다른 오류도 한국어 — 모르는 상태 번호는 적지 않는다")
    void otherErrorsBeforeSpringAreKoreanWithoutANumber() throws Exception {
        String r = raw("GET / HTTP/1.2");
        assertThat(r)
                .startsWith("HTTP/1.1 505")
                .contains("<html lang=\"ko\"")
                .contains("요청을 처리할 수 없습니다")
                .contains("관리자에게 알려 주세요")
                .doesNotContain("오류 ")
                .doesNotContain("HTTP Status");
    }

    // --- 씨앗 · 요청 ------------------------------------------------------------

    /**
     * 요청 줄을 그대로 보낸다. HttpClient 는 {@code /%} 같은 주소를 만들기도 전에
     * 거절하므로 소켓으로 보낸다. 브라우저처럼 한국어를 청한다.
     */
    private String raw(String requestLine) throws Exception {
        try (Socket socket = new Socket("localhost", port)) {
            socket.getOutputStream().write((requestLine + "\r\nHost: localhost\r\nAccept: text/html"
                    + "\r\nAccept-Language: ko-KR,ko;q=0.9\r\nConnection: close\r\n\r\n")
                    .getBytes(StandardCharsets.ISO_8859_1));
            return new String(socket.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private String account(Role role) {
        String name = role.name().toLowerCase() + System.nanoTime();
        AppUser user = new AppUser(name, encoder.encode(PASSWORD), role);
        user.setMustChange(false);
        user.setPasswordChangedAt(Instant.now());
        users.saveAndFlush(user);
        return name;
    }

    private URI uri(String path) {
        return URI.create("http://localhost:" + port + path);
    }

    /** 진짜 로그인 폼으로 들어간 브라우저 하나. 되돌려 보내기는 따라가지 않는다. */
    private HttpClient signedIn(String username) throws Exception {
        HttpClient client = HttpClient.newBuilder().cookieHandler(new CookieManager())
                                      .followRedirects(HttpClient.Redirect.NEVER).build();
        String login = client.send(HttpRequest.newBuilder(uri("/login")).GET().build(),
                                   HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)).body();
        Matcher token = Pattern.compile("name=\"_csrf\" value=\"([^\"]+)\"").matcher(login);
        assertThat(token.find()).as("로그인 화면에 CSRF 값이 없다").isTrue();

        String form = "username=" + enc(username) + "&password=" + enc(PASSWORD)
                      + "&_csrf=" + enc(token.group(1));
        HttpResponse<Void> r = client.send(HttpRequest.newBuilder(uri("/login"))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(form)).build(),
                HttpResponse.BodyHandlers.discarding());
        assertThat(r.statusCode()).as("로그인 실패").isEqualTo(302);
        assertThat(r.headers().firstValue("Location").orElse("")).doesNotContain("error");
        return client;
    }

    private HttpResponse<String> page(HttpClient client, String path) throws Exception {
        return client.send(HttpRequest.newBuilder(uri(path)).header("Accept", "text/html").GET().build(),
                           HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private static String enc(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
