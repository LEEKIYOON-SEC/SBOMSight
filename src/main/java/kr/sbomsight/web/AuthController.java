package kr.sbomsight.web;

import kr.sbomsight.domain.AppUser;
import kr.sbomsight.domain.AuditEvent;
import kr.sbomsight.domain.PasswordChangeReason;
import kr.sbomsight.service.PasswordPolicy;
import kr.sbomsight.service.AuditService;
import kr.sbomsight.repo.AppUserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.security.Principal;

/** 로그인 화면과 비밀번호 변경. */
@Controller
public class AuthController {

    /** 8자 미만은 받지 않는다. 그 이상은 사용자가 정한다. */
    private static final int MIN_LENGTH = 8;

    private final AppUserRepository users;
    private final PasswordEncoder encoder;
    private final AuditService audit;
    private final PasswordPolicy policy;

    public AuthController(AppUserRepository users, PasswordEncoder encoder, AuditService audit,
                          PasswordPolicy policy) {
        this.users = users;
        this.encoder = encoder;
        this.audit = audit;
        this.policy = policy;
    }

    /**
     * 로그인 화면.
     *
     * <p>왜 이 화면에 왔는지 알려 준다. 이유 없이 튕기면 고장으로 읽힌다.
     */
    @GetMapping("/login")
    public String login(@RequestParam(required = false) String error,
                        @RequestParam(required = false) String logout,
                        @RequestParam(required = false) String expired,
                        Model model) {
        if (error != null) {
            model.addAttribute("notice", "계정 이름이나 비밀번호가 맞지 않습니다.");
            model.addAttribute("noticeKind", "danger");
        } else if (expired != null) {
            model.addAttribute("notice", "일정 시간 사용하지 않아 로그아웃되었습니다.");
            model.addAttribute("noticeKind", "info");
        } else if (logout != null) {
            model.addAttribute("notice", "로그아웃했습니다.");
            model.addAttribute("noticeKind", "info");
        }
        return "login";
    }

    @GetMapping("/password")
    public String passwordForm(Principal principal, Model model) {
        users.findByUsername(principal.getName()).ifPresent(user -> {
            // 온 이유에 따라 할 말과 첫 칸의 이름이 달라진다.
            PasswordChangeReason reason = policy.reasonFor(user);
            model.addAttribute("reason", reason);
            model.addAttribute("mustChange", reason.isForced());
            model.addAttribute("daysSinceChange", policy.daysSinceChange(user));
            model.addAttribute("maxAgeDays", policy.maxAgeDays());
        });
        return "password";
    }

    @PostMapping("/password")
    public String changePassword(Principal principal,
                                 @RequestParam String current,
                                 @RequestParam String password,
                                 @RequestParam String confirm,
                                 RedirectAttributes flash) {
        AppUser user = users.findByUsername(principal.getName()).orElseThrow();

        if (!encoder.matches(current, user.getPasswordHash())) {
            flash.addFlashAttribute("error", "현재 비밀번호가 맞지 않습니다.");
            return "redirect:/password";
        }
        if (password.length() < MIN_LENGTH) {
            flash.addFlashAttribute("error", MIN_LENGTH + "자 이상으로 정해 주세요.");
            return "redirect:/password";
        }
        if (!password.equals(confirm)) {
            flash.addFlashAttribute("error", "두 번 입력한 비밀번호가 다릅니다.");
            return "redirect:/password";
        }
        if (encoder.matches(password, user.getPasswordHash())) {
            flash.addFlashAttribute("error", "지금 쓰는 비밀번호와 같습니다.");
            return "redirect:/password";
        }

        user.setPasswordHash(encoder.encode(password));
        user.setMustChange(false);
        // 주기 계산의 기준을 지금으로 옮긴다. 이걸 빼먹으면 바꿔도 계속
        // 만료 상태라 변경 화면에서 나올 수 없다.
        user.setPasswordChangedAt(java.time.Instant.now());
        users.save(user);
        // 비밀번호 자체는 절대 기록하지 않는다. 바꿨다는 사실만 남긴다.
        audit.record(AuditEvent.PASSWORD_CHANGED, user.getUsername(), "");

        flash.addFlashAttribute("message", "비밀번호를 바꿨습니다.");
        return "redirect:/";
    }
}
