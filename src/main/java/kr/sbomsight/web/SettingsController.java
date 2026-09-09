package kr.sbomsight.web;

import kr.sbomsight.config.SbomSightProperties;
import kr.sbomsight.domain.Role;
import kr.sbomsight.service.AccountService;
import kr.sbomsight.service.GrypeRunner;
import kr.sbomsight.service.SettingsService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.security.Principal;

/** 설정 — 계정, 접근 IP, 도구 상태. 관리자만 들어온다. */
@Controller
@RequestMapping("/settings")
@PreAuthorize("hasRole('ADMIN')")
public class SettingsController {

    private final AccountService accounts;
    private final SettingsService settings;
    private final GrypeRunner grype;
    private final SbomSightProperties properties;

    public SettingsController(AccountService accounts, SettingsService settings,
                              GrypeRunner grype, SbomSightProperties properties) {
        this.accounts = accounts;
        this.settings = settings;
        this.grype = grype;
        this.properties = properties;
    }

    @GetMapping
    public String index(HttpServletRequest request, Model model) {
        model.addAttribute("users", accounts.list());
        model.addAttribute("roles", Role.values());
        model.addAttribute("allowedIps", settings.allowedIpsText());
        model.addAttribute("unrestricted", settings.allowlist().isEmpty());
        model.addAttribute("clientIp", request.getRemoteAddr());
        model.addAttribute("grypePath", properties.grypePath());
        // grype 을 실제로 불러 본다. "설치되어 있다"는 말보다 판이 찍히는 것이 낫다.
        model.addAttribute("grype", grype.status());
        return "settings";
    }

    // --- 계정 -------------------------------------------------------------

    @PostMapping("/users")
    public String createUser(@RequestParam String username, @RequestParam String password,
                             @RequestParam Role role,
                             @RequestParam(required = false) String displayName,
                             RedirectAttributes flash) {
        try {
            accounts.create(username, password, role, displayName);
            flash.addFlashAttribute("message", username + " 계정을 만들었습니다.");
        } catch (AccountService.AccountException e) {
            flash.addFlashAttribute("error", e.getMessage());
        }
        return "redirect:/settings";
    }

    @PostMapping("/users/{username}/role")
    public String changeRole(@PathVariable String username, @RequestParam Role role,
                             Principal principal, RedirectAttributes flash) {
        try {
            accounts.changeRole(username, role, principal.getName());
            flash.addFlashAttribute("message", username + " 의 권한을 바꿨습니다.");
        } catch (AccountService.AccountException e) {
            flash.addFlashAttribute("error", e.getMessage());
        }
        return "redirect:/settings";
    }

    @PostMapping("/users/{username}/reset")
    public String resetPassword(@PathVariable String username, Principal principal,
                                RedirectAttributes flash) {
        try {
            accounts.resetPassword(username, principal.getName());
            flash.addFlashAttribute("message",
                    username + " 의 비밀번호를 계정 이름과 같게 되돌렸습니다. "
                    + "본인이 로그인해 새 비밀번호를 정해야 합니다.");
        } catch (AccountService.AccountException e) {
            flash.addFlashAttribute("error", e.getMessage());
        }
        return "redirect:/settings";
    }

    @PostMapping("/users/{username}/delete")
    public String deleteUser(@PathVariable String username, Principal principal,
                             RedirectAttributes flash) {
        try {
            accounts.delete(username, principal.getName());
            flash.addFlashAttribute("message", username + " 계정을 지웠습니다.");
        } catch (AccountService.AccountException e) {
            flash.addFlashAttribute("error", e.getMessage());
        }
        return "redirect:/settings";
    }

    // --- 접근 IP ----------------------------------------------------------

    @PostMapping("/ips")
    public String saveIps(@RequestParam(required = false) String allowedIps,
                          HttpServletRequest request, Principal principal,
                          RedirectAttributes flash) {
        settings.saveAllowedIps(allowedIps, request.getRemoteAddr(), principal.getName())
                .ifPresentOrElse(
                        reason -> flash.addFlashAttribute("error", reason),
                        () -> flash.addFlashAttribute("message", "접근 허용 IP 를 저장했습니다."));
        return "redirect:/settings";
    }
}
