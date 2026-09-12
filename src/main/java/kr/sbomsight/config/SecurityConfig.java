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
            "/login", "/css/**", "/js/**", "/fonts/**",
            "/favicon.svg", "/favicon.ico", "/error"
    };

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http, AppUserDetailsService users,
                                    AuthEventListener authEvents) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(PUBLIC).permitAll()
                // 조회 권한은 읽기 전용이다. 쓰기는 전부 관리자.
                .requestMatchers("/settings/**", "/audit/**", "/assets/*/delete").hasRole("ADMIN")
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
            // 끄지 않는다 — 끄는 순간 점검에서 바로 지적된다.
            .csrf(csrf -> csrf.ignoringRequestMatchers("/api/**"))

            .headers(headers -> headers
                // https 전용이므로 브라우저에도 그렇게 못박는다.
                .httpStrictTransportSecurity(hsts -> hsts
                        .includeSubDomains(true).maxAgeInSeconds(31_536_000))
                .frameOptions(frame -> frame.sameOrigin()))

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
