package kr.sbomsight.config;

import kr.sbomsight.domain.AuditEvent;
import kr.sbomsight.service.AuditService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

/**
 * 로그인·로그아웃을 감사 로그에 남긴다.
 *
 * <p>스프링 시큐리티가 알려 주는 것을 받아 적는다. 컨트롤러에서 직접 쓰면
 * 폼 로그인 · 세션 만료 · 잠긴 계정 같은 경로를 하나씩 손으로 붙여야 하고,
 * 그중 하나를 빠뜨리면 그 경로의 접속은 기록에 남지 않는다.
 *
 * <p><b>실패 사유는 남기지만 계정이 있는지는 밝히지 않는다.</b> 로그에는
 * 사유를 적어도 되지만 로그인 화면의 응답은 언제나 같아야 한다 — 아니면
 * 응답만 보고 어느 계정이 실제로 있는지 알아낼 수 있다.
 */
@Component
public class AuthEventListener implements LogoutHandler {

    private final AuditService audit;

    public AuthEventListener(AuditService audit) {
        this.audit = audit;
    }

    @EventListener
    public void onSuccess(AuthenticationSuccessEvent event) {
        audit.recordAs(event.getAuthentication().getName(),
                       AuditEvent.LOGIN_SUCCESS, "", "");
    }

    @EventListener
    public void onFailure(AbstractAuthenticationFailureEvent event) {
        Object principal = event.getAuthentication().getPrincipal();
        String attempted = principal == null ? "" : principal.toString();
        Throwable cause = event.getException();

        // 잠긴·중지된 계정은 '비밀번호가 틀렸다' 와 성격이 다르다. 점검에서
        // "잠금이 실제로 걸렸나" 를 묻기 때문에 구분해 남긴다.
        AuditEvent action = (cause instanceof LockedException || cause instanceof DisabledException)
                ? AuditEvent.LOGIN_BLOCKED
                : AuditEvent.LOGIN_FAILURE;

        audit.recordAs(attempted, action, "", reasonOf(cause));
    }

    /**
     * 로그아웃.
     *
     * <p>{@code LogoutSuccessEvent} 는 서블릿 필터 체인에서 자동으로 발행되지
     * 않는다. 그 이벤트를 듣고 있으면 조용히 아무것도 기록되지 않는다 —
     * 그래서 {@link LogoutHandler} 로 직접 받는다. 세션이 이미 끊긴 뒤에도
     * 눌리는 자리이므로 인증 정보가 없을 수 있다.
     */
    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response,
                       Authentication authentication) {
        if (authentication != null) {
            audit.recordAs(authentication.getName(), AuditEvent.LOGOUT, "", "");
        }
    }

    /** 예외 메시지를 그대로 쓰지 않는다 — 판마다 문구가 달라 기록이 흔들린다. */
    private String reasonOf(Throwable cause) {
        if (cause instanceof LockedException) {
            return "계정이 잠겨 있습니다";
        }
        if (cause instanceof DisabledException) {
            return "중지된 계정입니다";
        }
        return "계정 이름 또는 비밀번호가 맞지 않습니다";
    }
}
