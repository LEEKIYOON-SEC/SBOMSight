package kr.sbomsight.web;

import kr.sbomsight.domain.AppUser;
import kr.sbomsight.domain.AuditEvent;
import kr.sbomsight.repo.AppUserRepository;
import kr.sbomsight.service.AuditService;
import kr.sbomsight.service.PasswordPolicy;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.security.Principal;

import static org.springframework.http.HttpStatus.NOT_FOUND;

/**
 * 내 계정.
 *
 * <p><b>왜 생겼는가.</b> 기둥 아래 계정 이름을 누르면 곧바로 비밀번호 변경
 * 화면으로 갔다. "왜 비밀번호 변경으로 가지?" 가 되는 자리였다 — 누를 곳
 * 하나에 갈 곳이 셋이면 그건 링크가 아니라 메뉴이고, 메뉴에는 갈 곳이
 * 있어야 한다.
 *
 * <p>여기서 <b>스스로 바꿀 수 있는 것은 표시 이름 하나뿐이다.</b> 권한과
 * 사용 여부는 관리자가 정한다 — 본인이 자기 권한을 올릴 수 있으면 권한이
 * 아니다.
 */
@Controller
public class MeController {

    private final AppUserRepository users;
    private final PasswordPolicy policy;
    private final AuditService audit;

    public MeController(AppUserRepository users, PasswordPolicy policy, AuditService audit) {
        this.users = users;
        this.policy = policy;
        this.audit = audit;
    }

    @GetMapping("/me")
    public String me(Principal principal, Model model) {
        AppUser user = require(principal.getName());
        model.addAttribute("me", user);
        model.addAttribute("reason", policy.reasonFor(user));
        model.addAttribute("daysSinceChange", policy.daysSinceChange(user));
        model.addAttribute("daysUntilExpiry", policy.daysUntilExpiry(user));
        model.addAttribute("maxAgeDays", policy.maxAgeDays());
        return "me";
    }

    /** 표시 이름만. 권한·사용 여부는 여기서 받지 않는다. */
    @PostMapping("/me")
    public String rename(@RequestParam(required = false) String displayName,
                         Principal principal, RedirectAttributes flash) {
        AppUser user = require(principal.getName());
        String name = displayName == null ? "" : displayName.trim();
        if (name.equals(user.getDisplayName())) {
            return "redirect:/me";
        }
        user.setDisplayName(name);
        users.save(user);
        audit.record(AuditEvent.USER_UPDATED, user.getUsername(),
                     "이름 " + (name.isEmpty() ? "지움" : name));
        flash.addFlashAttribute("message", "이름을 바꿨습니다.");
        return "redirect:/me";
    }

    private AppUser require(String username) {
        return users.findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "계정을 찾을 수 없습니다."));
    }
}
