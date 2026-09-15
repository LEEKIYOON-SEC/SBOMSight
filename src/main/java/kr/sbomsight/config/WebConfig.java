package kr.sbomsight.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.CacheControl;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.concurrent.TimeUnit;

/** MVC 인터셉터와 정적 파일 캐시. */
@Configuration
public class WebConfig implements WebMvcConfigurer {

    private final MustChangePasswordInterceptor mustChangePassword;

    public WebConfig(MustChangePasswordInterceptor mustChangePassword) {
        this.mustChangePassword = mustChangePassword;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(mustChangePassword).addPathPatterns("/**");
    }

    /**
     * 글꼴과 CSS 를 브라우저가 가지고 있게 한다.
     *
     * <p><b>왜 필요한가.</b> 스프링 시큐리티는 기본으로 <b>모든 응답</b>에
     * {@code Cache-Control: no-cache, no-store, must-revalidate} 를 붙인다. 로그인한
     * 화면(HTML)에는 맞는 정책이지만, 그것이 <b>정적 파일에까지 붙어 있었다.</b>
     * {@code no-store} 는 "저장하지 마라" 라서 브라우저가 새로고침 때마다 글꼴을
     * 처음부터 다시 받는다.
     *
     * <p>그 결과가 화면에서는 이렇게 보인다. 글꼴이 도착하기 전에는 대체 글꼴
     * (윈도우는 맑은 고딕)로 그려지고, 도착하면 본래 글꼴로 다시 그려진다
     * ({@code font-display: swap}). 한국어 글꼴은 자모 범위별로 <b>293개 파일로
     * 쪼개져</b> 있어서 도착 순서가 매번 달라진다 — <b>새로고침할 때마다 글자 폭이
     * 달라지고, 그에 따라 표의 칸과 단추 크기가 들쭉날쭉해진다.</b> CSS 를 아무리
     * 고쳐도, 프레임워크를 바꿔도 이 현상은 그대로다. 원인이 CSS 가 아니다.
     *
     * <p>고치는 방법은 두 가지를 갈라 주는 것이다.
     *
     * <ul>
     *   <li><b>글꼴</b> — 파일 이름에 내용 해시가 들어 있다. 내용이 바뀌면 이름이
     *       바뀌므로 1년을 캐시해도 낡은 것을 보게 되지 않는다({@code immutable}).</li>
     *   <li><b>CSS</b> — 이름이 그대로라 오래 캐시하면 판올림이 반영되지 않는다.
     *       그래서 {@code no-cache} 로 둔다. 이름이 주는 인상과 달리 이것은 "캐시
     *       하지 마라" 가 아니라 <b>"쓰기 전에 바뀌었는지 물어봐라"</b> 다. 안 바뀌었으면
     *       304 한 번으로 끝나고 몸통은 캐시에서 쓴다 — 다시 내려받지 않는다.</li>
     * </ul>
     *
     * <p>둘 다 {@code private} 다. 중간의 공용 캐시에 남기지 않는다.
     *
     * <p>시큐리티의 {@code CacheControlHeadersWriter} 는 응답에 이미
     * {@code Cache-Control} 이 있으면 덮어쓰지 않는다. 그래서 여기서 정해 주면
     * 그대로 나간다 — HTML 은 손대지 않았으므로 여전히 {@code no-store} 다.
     */
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/fonts/**")
                .addResourceLocations("classpath:/static/fonts/")
                .setCacheControl(CacheControl.maxAge(365, TimeUnit.DAYS).cachePrivate().immutable());

        registry.addResourceHandler("/css/**")
                .addResourceLocations("classpath:/static/css/")
                .setCacheControl(CacheControl.noCache().cachePrivate());

        // 반입해 둔 Tabler. 이름에 판이 안 붙어 있어 CSS 와 같은 규칙으로 둔다 —
        // 694KB 라 매번 받으면 크지만, 안 바뀌었으면 304 한 번으로 끝난다.
        // (응답 압축을 켜 두어 처음 받을 때도 90KB 안팎이다.)
        registry.addResourceHandler("/vendor/**")
                .addResourceLocations("classpath:/static/vendor/")
                .setCacheControl(CacheControl.noCache().cachePrivate());
    }
}
