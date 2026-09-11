package kr.sbomsight.web;

import kr.sbomsight.config.SbomSightProperties;
import kr.sbomsight.domain.Role;
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

    public SettingsController(AccountService accounts, SettingsService settings,
                              GrypeRunner grype, SbomSightProperties properties,
                              ZoneService zones, AssetRepository assets) {
        this.accounts = accounts;
        this.settings = settings;
        this.grype = grype;
        this.properties = properties;
        this.zones = zones;
        this.assets = assets;
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

        // 구역마다 자산이 몇 대인지 함께 준다. 비어 있어야 지울 수 있다는
        // 규칙이 화면에서 바로 읽혀야 한다.
        model.addAttribute("zones", zones.all().stream()
                .map(z -> new ZoneRow(z, assets.countByZoneId(z.getId())))
                .toList());
        return "settings";
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

    // --- 구역 -------------------------------------------------------------

    @PostMapping("/zones")
    public String createZone(@RequestParam String name,
                             @RequestParam(required = false) String color,
                             @RequestParam(required = false) String note,
                             RedirectAttributes flash) {
        return zoneAction(flash, () -> {
            Zone zone = zones.create(name, color, note);
            return zone.getName() + " 구역을 만들었습니다.";
        });
    }

    @PostMapping("/zones/{id}/rename")
    public String renameZone(@PathVariable Long id, @RequestParam String name,
                             RedirectAttributes flash) {
        return zoneAction(flash, () -> {
            zones.rename(id, name);
            return "구역 이름을 바꿨습니다.";
        });
    }

    @PostMapping("/zones/{id}/color")
    public String recolorZone(@PathVariable Long id, @RequestParam String color,
                              RedirectAttributes flash) {
        return zoneAction(flash, () -> {
            zones.recolor(id, color);
            return "구역 색을 바꿨습니다.";
        });
    }

    @PostMapping("/zones/{id}/delete")
    public String deleteZone(@PathVariable Long id, RedirectAttributes flash) {
        return zoneAction(flash, () -> {
            zones.delete(id);
            return "구역을 지웠습니다.";
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
