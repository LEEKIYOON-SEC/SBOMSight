package kr.sbomsight;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * 글꼴과 CSS 를 브라우저가 가지고 있는가.
 *
 * <p><b>왜 있는가.</b> 실 PC 에서 "새로고침할 때마다 글자 크기와 단추 크기가
 * 들쭉날쭉하다" 는 말을 들었다. 원인은 CSS 가 아니라 <b>응답 머리</b>였다 —
 * 스프링 시큐리티가 모든 응답에 붙이는 {@code no-store} 가 정적 파일에까지
 * 붙어서, 브라우저가 새로고침마다 글꼴을 처음부터 다시 받고 있었다. 한국어
 * 글꼴은 293개 파일로 쪼개져 있어 도착 순서가 매번 달라지고, 그때마다 글자
 * 폭이 달라져 표와 단추가 다시 그려진다.
 *
 * <p>이건 브라우저에서 눈으로만 잡히던 종류가 아니다. <b>머리 한 줄로 확인할
 * 수 있는 것</b>이라 여기서 못 박는다.
 */
@SpringBootTest
@AutoConfigureMockMvc
class StaticCacheTest {

    @Autowired MockMvc mvc;

    private static String someFontFile() throws IOException {
        try (Stream<Path> files = Files.list(Path.of("src/main/resources/static/fonts"))) {
            return files.map(p -> p.getFileName().toString())
                    .filter(n -> n.endsWith(".woff2"))
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException("글꼴 파일이 하나도 없다"));
        }
    }

    @Test
    @DisplayName("글꼴은 오래 보관한다 — 이름에 내용 해시가 있어 낡을 일이 없다")
    void fontsAreCachedForALongTime() throws Exception {
        String cacheControl = mvc.perform(get("/fonts/" + someFontFile()))
                .andReturn().getResponse().getHeader("Cache-Control");

        assertThat(cacheControl)
                .as("no-store 면 새로고침마다 다시 받는다 — 그래서 화면이 흔들렸다")
                .isNotNull()
                .doesNotContain("no-store")
                .contains("max-age=31536000")
                .contains("immutable");
    }

    @Test
    @DisplayName("CSS 는 바뀌었는지 물어보되, 안 바뀌었으면 가지고 있는 것을 쓴다")
    void cssRevalidatesInsteadOfRedownloading() throws Exception {
        String cacheControl = mvc.perform(get("/css/app.css"))
                .andReturn().getResponse().getHeader("Cache-Control");

        // no-cache 는 "캐시하지 마라" 가 아니라 "쓰기 전에 물어봐라" 다.
        // 판올림하면 그 자리에서 새것을 받고, 안 바뀌었으면 304 로 끝난다.
        assertThat(cacheControl)
                .isNotNull()
                .doesNotContain("no-store")
                .contains("no-cache");
    }

    @Test
    @DisplayName("화면(HTML)은 그대로 보관하지 않는다 — 로그인한 내용이 남으면 안 된다")
    void pagesAreStillNotStored() throws Exception {
        String cacheControl = mvc.perform(get("/").with(user("admin").roles("ADMIN")))
                .andReturn().getResponse().getHeader("Cache-Control");

        assertThat(cacheControl)
                .as("정적 파일을 풀어 주다가 화면까지 함께 풀리면 안 된다")
                .isNotNull()
                .contains("no-store");
    }
}
