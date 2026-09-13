package kr.sbomsight.web;

import kr.sbomsight.config.SbomSightProperties;
import kr.sbomsight.domain.AppUser;
import kr.sbomsight.domain.AuditEvent;
import kr.sbomsight.domain.Role;
import kr.sbomsight.service.AuditService;
import kr.sbomsight.service.LoginAttemptService;
import kr.sbomsight.domain.Zone;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.service.ZoneService;
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
    private final ZoneService zones;
    private final AssetRepository assets;
    private final AuditService audit;
    private final LoginAttemptService attempts;

    public SettingsController(AccountService accounts, SettingsService settings,
                              GrypeRunner grype, SbomSightProperties properties,
                              ZoneService zones, AssetRepository assets, AuditService audit,
                              LoginAttemptService attempts) {
        this.accounts = accounts;
        this.settings = settings;
        this.grype = grype;
        this.properties = properties;
        this.zones = zones;
        this.assets = assets;
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

        // 구역마다 자산이 몇 대인지 함께 준다. 비어 있어야 지울 수 있다는
        // 규칙이 화면에서 바로 읽혀야 한다.
        model.addAttribute("zones", zones.all().stream()
                .map(z -> new ZoneRow(z, assets.countByZoneId(z.getId())))
                .toList());
        return "settings";
    }

    /** 계정 한 줄 — 계정과 잠금 상태. */
    public record UserRow(AppUser user, boolean locked, long minutesRemaining) {

        /** 자동 해제를 쓰면 남은 시간을, 안 쓰면 빈 문자열을. */
        public String remainingText() {
            return minutesRemaining < 0 ? "" : minutesRemaining + "분 남음";
        }
    }

    /** 구역 한 줄 — 구역과 그 안의 자산 수. */
    public record ZoneRow(Zone zone, long assetCount) {

        /** 비어 있고 미분류가 아닐 때만 지울 수 있다. */
        public boolean deletable() {
            return assetCount == 0 && !zone.isUnassigned();
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

    // --- 구역 -------------------------------------------------------------

    @PostMapping("/zones")
    public String createZone(@RequestParam String name,
                             @RequestParam(required = false) String color,
                             @RequestParam(required = false) String note,
                             RedirectAttributes flash) {
        return zoneAction(flash, () -> {
            Zone zone = zones.create(name, color, note);
            audit.record(AuditEvent.ZONE_CREATED, zone.getName(), "");
            return zone.getName() + " 구역을 만들었습니다.";
        });
    }

    @PostMapping("/zones/{id}/rename")
    public String renameZone(@PathVariable Long id, @RequestParam String name,
                             RedirectAttributes flash) {
        return zoneAction(flash, () -> {
            String before = zones.require(id).getName();
            zones.rename(id, name);
            audit.record(AuditEvent.ZONE_RENAMED, name, before + " → " + name);
            return "구역 이름을 바꿨습니다.";
        });
    }

    @PostMapping("/zones/{id}/color")
    public String recolorZone(@PathVariable Long id, @RequestParam String color,
                              RedirectAttributes flash) {
        return zoneAction(flash, () -> {
            zones.recolor(id, color);
            audit.record(AuditEvent.ZONE_RECOLORED, zones.require(id).getName(), color);
            return "구역 색을 바꿨습니다.";
        });
    }

    @PostMapping("/zones/{id}/delete")
    public String deleteZone(@PathVariable Long id, RedirectAttributes flash) {
        return zoneAction(flash, () -> {
            // 지우기 전에 이름을 읽어 둔다 — 지운 뒤에는 남지 않는다.
            String name = zones.require(id).getName();
            zones.delete(id);
            audit.record(AuditEvent.ZONE_DELETED, name, "");
            return name + " 구역을 지웠습니다.";
        });
    }

    /**
     * 구역 작업의 공통 처리.
     *
     * <p>{@link ZoneService} 는 규칙을 어기면 {@link IllegalArgumentException}
     * 을 던진다 — 자산이 남은 구역을 지우려 했다든지. 그 사유를 그대로 화면에
     * 띄운다. 500 으로 터뜨리면 무엇이 잘못됐는지 알 수 없다.
     */
    private String zoneAction(RedirectAttributes flash, java.util.function.Supplier<String> work) {
        try {
            flash.addFlashAttribute("message", work.get());
        } catch (IllegalArgumentException e) {
            flash.addFlashAttribute("error", e.getMessage());
        }
        return "redirect:/settings";
    }
}
