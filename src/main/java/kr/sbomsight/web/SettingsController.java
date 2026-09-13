package kr.sbomsight.web;

import kr.sbomsight.config.SbomSightProperties;
import kr.sbomsight.domain.AppUser;
import kr.sbomsight.domain.AuditEvent;
import kr.sbomsight.domain.Role;
import kr.sbomsight.service.AuditService;
import kr.sbomsight.service.LoginAttemptService;
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

/**
 * 설정 — 계정, 접근 IP, 도구 상태, 감사 로그. 관리자만 들어온다.
 *
 * <p>구역은 여기 없다. 자산을 묶는 방식이지 도구의 설정이 아니라
 * 자산 화면의 <b>구역 관리</b> 로 옮겼다 ({@link ZoneController}).
 */
@Controller
@RequestMapping("/settings")
@PreAuthorize("hasRole('ADMIN')")
public class SettingsController {

    private final AccountService accounts;
    private final SettingsService settings;
    private final GrypeRunner grype;
    private final SbomSightProperties properties;
    private final AuditService audit;
    private final LoginAttemptService attempts;

    public SettingsController(AccountService accounts, SettingsService settings,
                              GrypeRunner grype, SbomSightProperties properties,
                              AuditService audit,
                              LoginAttemptService attempts) {
        this.accounts = accounts;
        this.settings = settings;
        this.grype = grype;
        this.properties = properties;
        this.audit = audit;
        this.attempts = attempts;
    }

    @GetMapping
    public String index(@RequestParam(defaultValue = "accounts") String tab,
                        HttpServletRequest request, Model model) {
        // 탭 선택은 주소에 남는다. 자바스크립트로 감췄다 보였다 하면
        // 새로고침했을 때 첫 탭으로 돌아가고, 링크로 남길 수도 없다.
        model.addAttribute("tab", tab);
        model.addAttribute("users", accounts.list().stream()
                .map(u -> new UserRow(u, attempts.isLocked(u), attempts.minutesRemaining(u)))
                .toList());
        model.addAttribute("lockoutEnabled", properties.lockoutEnabled());
        model.addAttribute("maxLoginFailures", properties.maxLoginFailures());
        model.addAttribute("lockMinutes", properties.lockMinutes());
        model.addAttribute("passwordMaxAgeDays", properties.passwordMaxAgeDays());
        model.addAttribute("roles", Role.values());
        model.addAttribute("allowedIps", settings.allowedIpsText());
        model.addAttribute("unrestricted", settings.allowlist().isEmpty());
        model.addAttribute("clientIp", request.getRemoteAddr());
        model.addAttribute("grypePath", properties.grypePath());
        // grype 을 실제로 불러 본다. "설치되어 있다"는 말보다 판이 찍히는 것이 낫다.
        model.addAttribute("grype", grype.status());
        return "settings";
    }

    /** 계정 한 줄 — 계정과 잠금 상태. */
    public record UserRow(AppUser user, boolean locked, long minutesRemaining) {

        /** 자동 해제를 쓰면 남은 시간을, 안 쓰면 빈 문자열을. */
        public String remainingText() {
            return minutesRemaining < 0 ? "" : minutesRemaining + "분 남음";
        }
    }

    // --- 계정 -------------------------------------------------------------

    @PostMapping("/users")
    public String createUser(@RequestParam String username, @RequestParam String password,
                             @RequestParam Role role,
                             @RequestParam(required = false) String displayName,
                             RedirectAttributes flash) {
        try {
            accounts.create(username, password, role, displayName);
            audit.record(AuditEvent.USER_CREATED, username, "권한 " + role.label());
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
            audit.record(AuditEvent.USER_ROLE_CHANGED, username, "권한 " + role.label());
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
            audit.record(AuditEvent.USER_PASSWORD_RESET, username, "");
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
            audit.record(AuditEvent.USER_DELETED, username, "");
            flash.addFlashAttribute("message", username + " 계정을 지웠습니다.");
        } catch (AccountService.AccountException e) {
            flash.addFlashAttribute("error", e.getMessage());
        }
        return "redirect:/settings";
    }

    @PostMapping("/users/{username}/unlock")
    public String unlockUser(@PathVariable String username, RedirectAttributes flash) {
        attempts.unlock(username);
        flash.addFlashAttribute("message", username + " 의 잠금을 풀었습니다.");
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
                        () -> {
                            audit.record(AuditEvent.IP_ALLOWLIST_CHANGED, "",
                                         settings.allowedIpsText());
                            flash.addFlashAttribute("message", "접근 허용 IP 를 저장했습니다.");
                        });
        return "redirect:/settings";
    }

}
