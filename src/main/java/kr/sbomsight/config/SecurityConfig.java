package kr.sbomsight.config;

import kr.sbomsight.service.AppUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.session.HttpSessionEventPublisher;

/**
 * 로그인·세션·권한.
 *
 * <p>이 파일이 짧은 것이 요점이다. 앞 판에서는 쿠키 수명·유휴 만료·죽은 쿠키
 * 정리·로그아웃 경로를 전부 손으로 짰고, 그중 하나만 어긋나도 "로그인은 되는데
 * 화면이 안 열리는" 상태가 됐다. 여기서는 톰캣의 세션과 스프링 시큐리티가 그
 * 일을 한다 — 유휴 만료는 {@code server.servlet.session.timeout} 한 줄이다.
 */
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    /**
     * 로그인 없이 닿아도 되는 것. 로그인 화면 자체와 <b>그 화면이 쓰는 정적
     * 파일 전부</b>다.
     *
     * <p>하나라도 빠지면 그 요청이 "로그인 없이 닿은 요청" 으로 기억되고,
     * 로그인에 성공하면 스프링이 그리로 보낸다 — 브라우저가 글꼴 파일을
     * 내려받고 화면은 열리지 않는다. 실제로 {@code /fonts/**} 를 빠뜨려
     * 그렇게 됐다.
     */
    private static final String[] PUBLIC = {
            "/login", "/css/**", "/js/**", "/fonts/**", "/vendor/**",
            "/favicon.svg", "/favicon.ico", "/error"
    };

    /**
     * <b>바깥에서 받아 오는 것이 하나도 없다.</b>
     *
     * <p>글꼴(IBM Plex)·바탕 CSS(Tabler)까지 전부 저장소에 넣어 우리가
     * 내려준다 — 폐쇄망에서 돌아야 하므로 그럴 수밖에 없었고, 그 덕에
     * {@code 'self'} 하나로 닫을 수 있다. CDN 을 하나라도 쓰기 시작하면
     * 그 주소를 여기 적어야 하고, 그때부터 이 줄이 느슨해진다.
     *
     * <p><b>{@code script-src} 에 {@code 'unsafe-inline'} 이 없다.</b> 그것을
     * 넣으면 CSP 가 막으려던 것을 그대로 허용한다 — 끼워 넣어진
     * {@code <script>} 와 {@code onerror=} 가 함께 돈다. 그래서 화면의
     * 인라인 {@code <script>} 넷과 {@code onclick=} 류 열일곱 개를 전부
     * {@code /js/*.js} 와 {@code data-…} 로 옮겼다({@code js/app.js}).
     *
     * <p><b>{@code style-src-attr} 만 {@code 'unsafe-inline'} 이다.</b> 심각도
     * 막대의 폭처럼 값이 서버에서 오는 것은 {@code style="width:37%"} 로만
     * 낼 수 있다(클래스로는 낼 수 없는 수다). 글자를 내보내는 자리는 전부
     * Thymeleaf 가 이스케이프하고({@code th:utext} 0개) 스크립트는 막혀
     * 있으므로, 남는 위험은 모양이 흐트러지는 정도다.
     *
     * <p><b>{@code form-action 'self'}</b> — 폼이 남의 서버로 가지 않는다.
     * 자산 목록과 SBOM 이 담긴 폼이 바깥으로 제출되는 것을 막는 줄이다.
     */
    private static final String CSP = String.join("; ",
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self'",
            "style-src-attr 'unsafe-inline'",
            // **`data:` 를 열어 둔다.** 바탕 CSS(Tabler)가 고르개 화살표와
            // 체크 표시를 `data:image/svg+xml` 로 박아 두었다(28곳). 막으면
            // 화면 여덟 장에서 그 표시가 사라진다 — 띄워서 콘솔을 읽고
            // 찾았다(`Refused to load the image 'data:image/svg+xml…'`).
            // 이미지 data URI 는 실행되지 않으므로 스크립트와 성격이 다르다.
            "img-src 'self' data:",
            "font-src 'self'",
            "connect-src 'self'",
            "form-action 'self'",
            "base-uri 'self'",
            "object-src 'none'",
            "frame-ancestors 'none'");

    /**
     * <b>쓰지 않는 장치를 전부 닫는다.</b>
     *
     * <p>이 도구는 카메라·마이크·위치를 쓰지 않는다. 안 쓰는 것을 열어 두면
     * 점검에서 "왜 열려 있나" 를 묻고, 답이 "안 쓴다" 면 닫아야 한다.
     */
    private static final String PERMISSIONS_POLICY = String.join(", ",
            "accelerometer=()", "camera=()", "geolocation=()", "gyroscope=()",
            "magnetometer=()", "microphone=()", "payment=()", "usb=()");

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http, AppUserDetailsService users,
                                    AuthEventListener authEvents) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(PUBLIC).permitAll()
                // 조회 권한은 읽기 전용이다. 쓰기는 전부 관리자.
                .requestMatchers("/settings/**", "/assets/*/delete").hasRole("ADMIN")
                .anyRequest().authenticated())

            // 로그인 뒤 돌아갈 자리는 '사람이 볼 화면' 만 기억한다. 경로를
            // 여는 것만으로는 이번 한 건만 막힐 뿐이다.
            .requestCache(cache -> cache.requestCache(new PageRequestCache()))

            .formLogin(form -> form
                .loginPage("/login")
                .defaultSuccessUrl("/", false)
                .failureUrl("/login?error")
                .permitAll())

            .logout(out -> out
                // 로그아웃은 **언제나 성공해야 한다.** 세션이 이미 끊긴 뒤에도
                // 눌리는 자리이고, 여기서 막히면 죽은 쿠키를 지울 길이 없어진다.
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                // 감사 로그에 남긴다. LogoutSuccessEvent 는 필터 체인에서
                // 발행되지 않으므로 핸들러로 직접 받는다.
                .addLogoutHandler(authEvents)
                .logoutSuccessUrl("/login?logout")
                .invalidateHttpSession(true)
                .deleteCookies("SBOMSIGHT_SESSION")
                .permitAll())

            // 403 의 까닭을 요청에 얹어 두고 기본 처리기에 넘긴다. 기본 처리기는
            // 오류 화면 주소를 따로 정했을 때만 얹는다 — 안 얹으면 오류 화면이
            // 폼의 보안 확인 값(CSRF)이 낡아 막힌 것과 권한이 없어 막힌 것을 가르지
            // 못하고, 관리자에게 "관리자 계정만 할 수 있습니다" 라고 말한다
            // (ErrorPages · ErrorPageTest). 막는 규칙은 그대로다.
            .exceptionHandling(denied -> denied.accessDeniedHandler((request, response, e) -> {
                request.setAttribute(WebAttributes.ACCESS_DENIED_403, e);
                new AccessDeniedHandlerImpl().handle(request, response, e);
            }))

            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                // 세션이 만료된 채로 돌아오면 왜 돌아왔는지 알려 준다. 이유 없이
                // 로그인 화면으로 튕기면 고장으로 읽힌다.
                .invalidSessionUrl("/login?expired")
                .sessionFixation(fixation -> fixation.changeSessionId())
                // 한 계정은 한 자리에서만. 같은 계정으로 새로 로그인하면
                // **먼저 있던 세션이 끊긴다.**
                //
                // 새 로그인을 막는 쪽(maxSessionsPreventsLogin=true)도 있지만
                // 쓰지 않는다 — 브라우저를 그냥 닫아 세션이 남아 있으면 본인이
                // 자기 계정에 못 들어오고, 그때 풀어 줄 사람이 없다.
                // 끊긴 쪽에는 왜 끊겼는지 알려 준다.
                .maximumSessions(1)
                    .maxSessionsPreventsLogin(false)
                    .expiredUrl("/login?taken"))

            // 화면이 전부 서버 렌더링 폼이라 CSRF 토큰이 자동으로 실린다.
            // **끄지도, 예외를 두지도 않는다.**
            //
            // 앞서 `/api/**` 를 예외로 적어 두었는데 이 저장소에 `/api` 로
            // 시작하는 길은 없다 — 쓰이지 않는 예외였고, 설정을 읽는 사람
            // (점검하는 사람이 먼저 읽는다)에게는 "CSRF 를 끈 구간이 있다" 로
            // 보였다. 나중에 정말 그런 길이 생기면 그때 함께 정한다.

            .headers(headers -> headers
                // https 전용이므로 브라우저에도 그렇게 못박는다.
                .httpStrictTransportSecurity(hsts -> hsts
                        .includeSubDomains(true).maxAgeInSeconds(31_536_000))
                // **틀에 넣지 못한다.** 이 도구는 스스로를 iframe 에 넣지
                // 않는다(`grep iframe` → 0). `SAMEORIGIN` 이던 것을 조인다 —
                // 같은 출처라도 넣을 곳이 없으면 열어 둘 이유가 없다.
                .frameOptions(frame -> frame.deny())
                // **주소를 밖으로 흘리지 않는다.** 이 도구의 주소에는 자산
                // 번호·CVE 번호·검사 번호가 들어 있다(`/assets/12?tab=vulns` ·
                // `/vulns/CVE-2021-44228`). `Referer` 로 새 나가면 그것만으로
                // 어느 서버에 무엇이 걸렸는지가 읽힌다 — 내부 정보다.
                .referrerPolicy(ref -> ref.policy(ReferrerPolicy.NO_REFERRER))
                .contentSecurityPolicy(csp -> csp.policyDirectives(CSP))
                .permissionsPolicy(pp -> pp.policy(PERMISSIONS_POLICY)))

            .userDetailsService(users);

        return http.build();
    }

    /**
     * 세션이 끝났다는 사실을 시큐리티에 알려 준다.
     *
     * <p>이것이 없으면 {@code SessionRegistry} 가 죽은 세션을 계속 들고 있어
     * 세션 수가 실제와 어긋난다. 한 자리만 허용하는 설정에서는 그 어긋남이
     * 곧 "본인이 못 들어오는" 상태가 된다.
     */
    @Bean
    HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        // BCrypt. 직접 만든 해시 형식을 쓰지 않는다 — 강도를 올릴 때 기존
        // 비밀번호를 그대로 검증할 수 있어야 하고, 그 처리는 이미 되어 있다.
        return new BCryptPasswordEncoder();
    }
}
