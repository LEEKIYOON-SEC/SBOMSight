package kr.sbomsight.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import kr.sbomsight.repo.AppUserRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * 초기 비밀번호를 쓰는 계정을 비밀번호 변경 화면에 붙잡아 둔다.
 *
 * <p><b>왜 필요한가.</b> {@code password.html} 은 "새 비밀번호를 정하기 전에는
 * 다른 화면이 열리지 않습니다" 라고 적어 두었는데, 정작 그렇게 만드는 코드가
 * 없었다. 화면이 하지 않는 일을 한다고 말하고 있었다. 초기화된 계정이 그대로
 * 돌아다닐 수 있었다는 뜻이기도 하다 — 초기 비밀번호는 계정 이름과 같으므로
 * 사실상 비밀번호가 없는 계정이다.
 *
 * <p>매 요청마다 계정을 한 번 읽는다. 이 도구는 사람 몇 명이 쓰는 사내
 * 도구이고, 로그인 세션에 값을 넣어 두었다가 관리자가 초기화한 뒤에도 옛 값이
 * 남아 통과하는 쪽이 훨씬 나쁘다.
 */
@Component
public class MustChangePasswordInterceptor implements HandlerInterceptor {

    /**
     * 붙잡힌 상태에서도 열려야 하는 것.
     *
     * <p>비밀번호 화면 자체와 로그아웃이 막히면 빠져나갈 길이 없어진다.
     * 정적 파일이 막히면 그 화면이 스타일 없이 뜬다.
     */
    private static boolean alwaysAllowed(String path) {
        return path.equals("/password")
                || path.equals("/logout")
                || path.equals("/login")
                || path.equals("/error")
                || path.startsWith("/css/")
                || path.startsWith("/js/")
                || path.startsWith("/favicon");
    }

    private final AppUserRepository users;

    public MustChangePasswordInterceptor(AppUserRepository users) {
        this.users = users;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        String path = request.getRequestURI();
        if (alwaysAllowed(path)) {
            return true;
        }

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || auth.getPrincipal().equals("anonymousUser")) {
            return true;  // 로그인 여부는 스프링 시큐리티가 판단한다.
        }

        boolean mustChange = users.findByUsername(auth.getName())
                                  .map(user -> user.isMustChange())
                                  .orElse(false);
        if (!mustChange) {
            return true;
        }

        response.sendRedirect(request.getContextPath() + "/password");
        return false;
    }
}
