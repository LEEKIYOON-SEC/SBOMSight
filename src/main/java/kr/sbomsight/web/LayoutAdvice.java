package kr.sbomsight.web;

import kr.sbomsight.repo.AppUserRepository;
import kr.sbomsight.service.PasswordPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

/**
 * 모든 화면의 껍데기가 쓰는 값.
 *
 * <p>지금은 하나뿐이다: 초기 비밀번호에 붙잡힌 상태인가. 붙잡혀 있으면 상단
 * 메뉴를 감춘다 — 눌러도 비밀번호 화면으로 되돌아올 뿐인 링크를 보여 주면
 * 고장으로 읽힌다.
 */
@ControllerAdvice
public class LayoutAdvice {

    private final AppUserRepository users;
    private final PasswordPolicy policy;

    public LayoutAdvice(AppUserRepository users, PasswordPolicy policy) {
        this.users = users;
        this.policy = policy;
    }

    @ModelAttribute
    public void layout(Authentication auth, Model model) {
        boolean locked = auth != null
                && auth.isAuthenticated()
                && !auth.getPrincipal().equals("anonymousUser")
                && users.findByUsername(auth.getName()).map(policy::mustChange).orElse(false);
        model.addAttribute("passwordLocked", locked);
    }
}
