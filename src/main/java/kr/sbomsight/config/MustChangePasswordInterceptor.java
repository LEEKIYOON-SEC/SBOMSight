package kr.sbomsight.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import kr.sbomsight.repo.AppUserRepository;
import kr.sbomsight.service.PasswordPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.resource.ResourceHttpRequestHandler;

/**
 * 비밀번호를 바꿔야 하는 계정을 변경 화면에 붙잡아 둔다.
 *
 * <p>붙잡는 경우는 셋이다 — 최초 로그인, 관리자 초기화, 변경 주기 도래.
 * 어느 경우인지는 {@link PasswordPolicy} 가 판단한다.
 *
 * <p><b>왜 필요한가.</b> {@code password.html} 은 "새 비밀번호를 정하기 전에는
 * 다른 화면이 열리지 않습니다" 라고 적어 두었는데, 정작 그렇게 만드는 코드가
 * 없었다. 화면이 하지 않는 일을 한다고 말하고 있었다. 초기화된 계정이 그대로
 * 돌아다닐 수 있었다는 뜻이기도 하다 — 초기·임시 비밀번호는 그 계정이 아직
 * 본인 손에 있지 않다는 뜻이고, 그 상태로 다른 화면이 열리면 안 된다.
 *
 * <p>매 요청마다 계정을 한 번 읽는다. 이 도구는 사람 몇 명이 쓰는 사내
 * 도구이고, 로그인 세션에 값을 넣어 두었다가 관리자가 초기화한 뒤에도 옛 값이
 * 남아 통과하는 쪽이 훨씬 나쁘다.
 */
@Component
public class MustChangePasswordInterceptor implements HandlerInterceptor {

    /**
     * 붙잡힌 상태에서도 열려야 하는 화면.
     *
     * <p>비밀번호 화면 자체와 로그아웃이 막히면 빠져나갈 길이 없어진다.
     * 정적 파일은 여기 적지 않는다 — {@link #preHandle} 이 처리기 종류로 먼저
     * 거른다.
     */
    private static boolean alwaysAllowed(String path) {
        return path.equals("/password")
                || path.equals("/logout")
                || path.equals("/login")
                || path.equals("/error");
    }

    private final AppUserRepository users;
    private final PasswordPolicy policy;

    public MustChangePasswordInterceptor(AppUserRepository users, PasswordPolicy policy) {
        this.users = users;
        this.policy = policy;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        // **정적 파일은 막지 않는다.** 앞서 경로를 하나씩 적어 두었는데
        // `/css/` 만 있고 `/vendor/`(Tabler)·`/fonts/` 가 빠져, 붙잡힌 계정이
        // 보는 변경 화면이 스타일 없이 떴다 — 설치 뒤 처음 보는 화면이다.
        // 경로 대신 처리기 종류로 거르면 정적 폴더가 늘어도 다시 빠지지 않는다.
        if (handler instanceof ResourceHttpRequestHandler) {
            return true;
        }
        String path = request.getRequestURI();
        if (alwaysAllowed(path)) {
            return true;
        }

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || auth.getPrincipal().equals("anonymousUser")) {
            return true;  // 로그인 여부는 스프링 시큐리티가 판단한다.
        }

        // 판단은 PasswordPolicy 한 곳에서 한다. 화면과 인터셉터가 각자
        // 판단하면 "바꾸라는데 다른 화면이 열린다" 거나 반대로 "바꿀 것이
        // 없는데 갇힌다" 가 된다.
        boolean mustChange = users.findByUsername(auth.getName())
                                  .map(policy::mustChange)
                                  .orElse(false);
        if (!mustChange) {
            return true;
        }

        response.sendRedirect(request.getContextPath() + "/password");
        return false;
    }
}
