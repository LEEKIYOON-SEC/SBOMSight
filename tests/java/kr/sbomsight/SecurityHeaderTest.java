package kr.sbomsight;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 브라우저에 주는 지시 — <b>안 지키면 나머지 방어선이 한 겹 얇아진다.</b>
 *
 * <p>여기서 고정하는 것이 둘이다.
 *
 * <ol>
 *   <li><b>머리에 실어 보내는가.</b> {@code Content-Security-Policy} ·
 *       {@code Referrer-Policy} · {@code Permissions-Policy} ·
 *       {@code X-Frame-Options} · HSTS. 설정 한 줄이 지워져도 시험이 먼저
 *       안다 — 지워졌다는 사실은 화면을 봐서는 절대 안 보인다.</li>
 *   <li><b>CSP 를 스스로 무르지 않는가.</b> 화면에 인라인 {@code <script>}
 *       하나나 {@code onclick=} 하나가 되살아나면, 그것을 돌리려고
 *       {@code 'unsafe-inline'} 을 넣게 된다. 그 순간 CSP 가 막으려던 것을
 *       그대로 허용한다 — 끼워 넣어진 {@code <script>} 와 {@code onerror=}
 *       가 함께 돈다. <b>그래서 화면 쪽을 함께 본다.</b></li>
 * </ol>
 */
@SpringBootTest
@AutoConfigureMockMvc
class SecurityHeaderTest {

    private static final Path TEMPLATES = Path.of("src/main/resources/templates");
    private static final Path STATIC = Path.of("src/main/resources/static");

    @Autowired MockMvc mvc;

    /** 로그인 화면과 인증된 화면 양쪽에서 본다 — 필터가 갈라지는 자리다. */
    @Test
    @DisplayName("보안 머리를 다섯 다 실어 보낸다 — 로그인 화면에도")
    void everyResponseCarriesTheHeaders() throws Exception {
        // **https 로 물어본다.** HSTS 는 보안 채널에서만 나가므로, 평문으로
        // 물으면 그 머리만 null 로 와서 시험이 헛돈다. 운영은 https 전용이다.
        check(mvc.perform(get("/login").secure(true))
                 .andExpect(status().isOk()).andReturn());
        check(mvc.perform(get("/vulns").secure(true).with(user("tester").roles("ADMIN")))
                 .andExpect(status().isOk()).andReturn());
    }

    private void check(MvcResult result) {
        var headers = result.getResponse();

        assertThat(headers.getHeader("Content-Security-Policy"))
                .as("CSP 가 없습니다").isNotNull();
        assertThat(headers.getHeader("Referrer-Policy"))
                .as("주소에 자산·CVE 번호가 들어 있습니다. Referer 로 새 나가면 "
                    + "그것만으로 어느 서버에 무엇이 걸렸는지가 읽힙니다")
                .isEqualTo("no-referrer");
        assertThat(headers.getHeader("Permissions-Policy"))
                .as("안 쓰는 장치를 닫아 두지 않았습니다")
                .contains("camera=()").contains("microphone=()").contains("geolocation=()");
        assertThat(headers.getHeader("X-Frame-Options"))
                .as("이 도구는 스스로를 iframe 에 넣지 않습니다")
                .isEqualTo("DENY");
        assertThat(headers.getHeader("Strict-Transport-Security"))
                .as("https 전용입니다").contains("max-age=31536000");
        assertThat(headers.getHeader("X-Content-Type-Options")).isEqualTo("nosniff");
        // 인증된 화면이 브라우저 뒤로 가기로 되살아나면 안 된다.
        assertThat(headers.getHeader("Cache-Control")).contains("no-store");
    }

    /**
     * <b>{@code script-src} 를 무르지 않는다.</b>
     *
     * <p>{@code 'unsafe-inline'} 이나 {@code 'unsafe-eval'} 이 들어가면 CSP 를
     * 켜 둔 뜻이 없어진다. 바깥 주소도 적지 않는다 — 글꼴과 바탕 CSS 까지
     * 저장소에 넣어 우리가 내려주므로(폐쇄망) {@code 'self'} 하나로 닫힌다.
     */
    @Test
    @DisplayName("CSP 에 unsafe-inline · unsafe-eval · 바깥 주소가 없다")
    void thePolicyIsNotWatered() throws Exception {
        String csp = mvc.perform(get("/login").secure(true)).andReturn()
                        .getResponse().getHeader("Content-Security-Policy");

        assertThat(scriptSrc(csp))
                .as("script-src 에 unsafe 가 들어가면 CSP 를 켜 둔 뜻이 없습니다")
                .doesNotContain("unsafe-inline")
                .doesNotContain("unsafe-eval");
        assertThat(csp)
                .as("바깥에서 받아 오는 것이 없어야 'self' 하나로 닫힙니다")
                .doesNotContain("http://").doesNotContain("https://").doesNotContain("*");
        assertThat(csp)
                .contains("default-src 'self'")
                .contains("object-src 'none'")
                .contains("frame-ancestors 'none'")
                // 폼이 남의 서버로 제출되는 것을 막는다 — 자산 목록이 담긴 폼이다.
                .contains("form-action 'self'")
                .contains("base-uri 'self'");
    }

    private static String scriptSrc(String csp) {
        for (String part : csp.split(";")) {
            if (part.trim().startsWith("script-src")) {
                return part;
            }
        }
        throw new AssertionError("script-src 가 CSP 에 없습니다: " + csp);
    }

    /**
     * <b>화면에 인라인 스크립트가 없다.</b>
     *
     * <p>있으면 그 화면이 조용히 고장 난다(CSP 가 막는다). 고치려고
     * {@code 'unsafe-inline'} 을 넣는 것이 가장 쉬운 길이고, 그것이 이
     * 시험이 막는 것이다 — 스크립트는 {@code /js/*.js} 로 뺀다.
     */
    @Test
    @DisplayName("화면에 인라인 <script> 가 없다")
    void noInlineScriptInTemplates() throws IOException {
        List<String> found = new ArrayList<>();
        for (Path file : templates()) {
            String text = code(file);
            Matcher m = Pattern.compile("(?s)<script([^>]*)>(.*?)</script>").matcher(text);
            while (m.find()) {
                if (!m.group(2).isBlank()) {
                    found.add(TEMPLATES.relativize(file) + ":"
                              + (text.substring(0, m.start()).split("\n", -1).length));
                }
            }
        }
        assertThat(found)
                .as("인라인 <script> 는 CSP 가 막습니다. /js/*.js 로 빼고 화면에서는 "
                    + "src 로 부르세요.")
                .isEmpty();
    }

    /**
     * <b>{@code onclick=} 류가 없다.</b>
     *
     * <p>앞서 {@code onchange="this.form.submit()"} · {@code onsubmit="return
     * confirm(…)"} · {@code onclick="window.print()"} 가 열일곱 군데 있었다.
     * 전부 {@code data-autosubmit} · {@code data-confirm} · {@code data-print}
     * 로 바꾸고 하는 일은 {@code js/app.js} 한 곳에 뒀다.
     */
    @Test
    @DisplayName("화면에 onclick= 류 인라인 핸들러가 없다")
    void noInlineEventHandlersInTemplates() throws IOException {
        Pattern handler = Pattern.compile(
                "\\bon(?:click|submit|change|input|load|error|key\\w+|focus|blur|"
                + "mouse\\w+|touch\\w+)\\s*=");
        List<String> found = new ArrayList<>();
        for (Path file : templates()) {
            String text = code(file);
            Matcher m = handler.matcher(text);
            while (m.find()) {
                found.add(TEMPLATES.relativize(file) + ": " + m.group());
            }
        }
        assertThat(found)
                .as("인라인 핸들러는 script-src-attr 'unsafe-inline' 을 요구합니다. "
                    + "data-… 로 적고 동작은 js/app.js 에 두세요.")
                .isEmpty();
    }

    /**
     * 화면이 부르는 스크립트 파일이 <b>실제로 있는가.</b>
     *
     * <p>이름을 틀리면 404 다. 그 화면의 단추가 아무 일도 하지 않는데
     * 화면 시험은 전부 통과한다 — 이 저장소가 이미 당한 모양이다(검사
     * 진행 표시에 폴링이 없었다).
     */
    @Test
    @DisplayName("화면이 부르는 /js/*.js 가 전부 있다")
    void everyReferencedScriptExists() throws IOException {
        Pattern src = Pattern.compile("<script[^>]*\\bsrc=\"(/js/[^\"]+)\"");
        List<String> missing = new ArrayList<>();
        int referenced = 0;
        for (Path file : templates()) {
            Matcher m = src.matcher(code(file));
            while (m.find()) {
                referenced++;
                Path js = STATIC.resolve(m.group(1).substring(1));
                if (!Files.isRegularFile(js)) {
                    missing.add(TEMPLATES.relativize(file) + " → " + m.group(1));
                }
            }
        }
        assertThat(referenced).as("스크립트를 부르는 화면이 하나도 없다 — 시험이 헛돈다")
                              .isPositive();
        assertThat(missing).as("화면이 없는 파일을 부르고 있습니다").isEmpty();
    }

    private static List<Path> templates() throws IOException {
        try (Stream<Path> files = Files.walk(TEMPLATES)) {
            return files.filter(Files::isRegularFile)
                        .filter(f -> f.toString().endsWith(".html"))
                        .toList();
        }
    }

    /**
     * 주석을 걷어낸 화면.
     *
     * <p><b>주석은 브라우저가 실행하지 않는다.</b> 이 저장소의 주석은 왜
     * 그렇게 했는지를 적어 두는 자리이고, 거기에는 하지 말라고 적어 둔 것이
     * 그대로 인용되어 있다 — `{@code onclick=} 을 두지 않는다` 라고 쓴 줄을
     * 시험이 위반으로 집어냈다. {@code ReportProseTest} 도 같은 이유로 같은
     * 일을 한다.
     */
    private static String code(Path file) throws IOException {
        String text = Files.readString(file);
        for (Pattern comment : List.of(Pattern.compile("(?s)<!--/\\*.*?\\*/-->"),
                                       Pattern.compile("(?s)<!--.*?-->"))) {
            text = comment.matcher(text).replaceAll("");
        }
        return text;
    }
}
