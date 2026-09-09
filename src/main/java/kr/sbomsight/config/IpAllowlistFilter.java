package kr.sbomsight.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import kr.sbomsight.service.SettingsService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * 허용 대역 밖이면 로그인 화면도 보여 주지 않는다.
 *
 * <p>로그인보다 <b>먼저</b> 선다. 스캔 결과는 어느 서버에 무엇이 열려 있는지
 * 그대로 보여 주는 지도라, 내부망이라는 이유로 아무 자리에서나 문을 두드릴 수
 * 있게 두지 않는다.
 *
 * <p>판단은 <b>소켓 상대 주소로만</b> 한다. {@code X-Forwarded-For} 같은 헤더는
 * 누구든 채워 보낼 수 있어서, 그것을 믿으면 목록이 헤더 한 줄로 우회된다.
 * 이 도구는 프록시 뒤가 아니라 내부망에 직접 서는 것을 전제로 한다.
 */
@Component
@Order(1)   // 스프링 시큐리티 체인보다 앞
public class IpAllowlistFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(IpAllowlistFilter.class);

    private final SettingsService settings;

    public IpAllowlistFilter(SettingsService settings) {
        this.settings = settings;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String ip = request.getRemoteAddr();

        if (settings.allowlist().permits(ip)) {
            chain.doFilter(request, response);
            return;
        }

        log.warn("허용 목록 밖에서 접속 시도: {} {}", ip, request.getRequestURI());
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("text/html; charset=UTF-8");
        response.getWriter().write("""
                <!doctype html><html lang="ko"><meta charset="utf-8">
                <title>접속할 수 없습니다</title>
                <body style="font-family:system-ui;padding:3rem;text-align:center">
                  <h1 style="font-size:1.2rem">이 주소에서는 접속할 수 없습니다</h1>
                  <p style="color:#5b6270">접속 주소 <code>%s</code></p>
                  <p style="color:#8a919e;font-size:.85rem">
                    관리자에게 접근 허용을 요청하세요.</p>
                </body></html>
                """.formatted(escape(ip)));
    }

    /** 주소를 그대로 화면에 되돌려 주므로 최소한의 이스케이프는 한다. */
    private String escape(String value) {
        return value == null ? "알 수 없음"
                : value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
