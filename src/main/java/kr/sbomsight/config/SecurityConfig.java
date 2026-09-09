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

    /** 로그인 없이 닿아도 되는 것. 로그인 화면 자체와 그 화면이 쓰는 정적 파일뿐이다. */
    private static final String[] PUBLIC = {
            "/login", "/css/**", "/js/**", "/favicon.svg", "/favicon.ico", "/error"
    };

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http, AppUserDetailsService users) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(PUBLIC).permitAll()
                // 조회 권한은 읽기 전용이다. 쓰기는 전부 관리자.
                .requestMatchers("/settings/**", "/assets/*/delete").hasRole("ADMIN")
                .anyRequest().authenticated())

            .formLogin(form -> form
                .loginPage("/login")
                .defaultSuccessUrl("/", false)
                .failureUrl("/login?error")
                .permitAll())

            .logout(out -> out
                // 로그아웃은 **언제나 성공해야 한다.** 세션이 이미 끊긴 뒤에도
                // 눌리는 자리이고, 여기서 막히면 죽은 쿠키를 지울 길이 없어진다.
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
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
                // 같은 계정으로 여러 자리에서 보는 것은 막지 않는다(운영 중
                // 흔한 일이다). 대신 세션 수를 세어 두어 설정에서 볼 수 있게 한다.
                .maximumSessions(10))

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

    @Bean
    PasswordEncoder passwordEncoder() {
        // BCrypt. 직접 만든 해시 형식을 쓰지 않는다 — 강도를 올릴 때 기존
        // 비밀번호를 그대로 검증할 수 있어야 하고, 그 처리는 이미 되어 있다.
        return new BCryptPasswordEncoder();
    }
}
