package kr.sbomsight.web;

import kr.sbomsight.domain.AppUser;
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

    public AuthController(AppUserRepository users, PasswordEncoder encoder) {
        this.users = users;
        this.encoder = encoder;
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
        users.findByUsername(principal.getName())
             .ifPresent(user -> model.addAttribute("mustChange", user.isMustChange()));
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
        users.save(user);

        flash.addFlashAttribute("message", "비밀번호를 바꿨습니다.");
        return "redirect:/";
    }
}
