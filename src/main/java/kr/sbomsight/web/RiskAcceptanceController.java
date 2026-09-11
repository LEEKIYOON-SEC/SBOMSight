package kr.sbomsight.web;

import kr.sbomsight.domain.Asset;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.service.RiskAcceptanceService;
import kr.sbomsight.service.ZoneService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.security.Principal;
import java.time.LocalDate;

import static org.springframework.http.HttpStatus.NOT_FOUND;

/**
 * 위험 수용 — 고칠 수 없는 건을 "이런 이유로 그대로 둔다" 고 적어 두는 곳.
 *
 * <p>등록·철회는 관리자만 한다. 수용은 결재의 결과를 적는 일이고, 조회
 * 권한으로 남의 결재를 적을 수는 없다.
 */
@Controller
@RequestMapping("/acceptances")
public class RiskAcceptanceController {

    private final RiskAcceptanceService acceptances;
    private final AssetRepository assets;
    private final ZoneService zones;

    public RiskAcceptanceController(RiskAcceptanceService acceptances, AssetRepository assets,
                                    ZoneService zones) {
        this.acceptances = acceptances;
        this.assets = assets;
        this.zones = zones;
    }

    @GetMapping
    public String index(@RequestParam(defaultValue = "false") boolean includeRevoked,
                        @RequestParam(required = false) Long zone,
                        Model model) {
        model.addAttribute("rows", acceptances.list(includeRevoked, zone));
        model.addAttribute("includeRevoked", includeRevoked);
        model.addAttribute("zones", zones.all());
        model.addAttribute("selectedZone", zone);
        model.addAttribute("overdue", acceptances.reviewOverdue());
        return "acceptances";
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public String accept(@RequestParam Long assetId,
                         @RequestParam String cve,
                         @RequestParam String packageName,
                         @RequestParam String reason,
                         @RequestParam(required = false) String compensating,
                         @RequestParam String approvedBy,
                         @RequestParam String reviewBy,
                         @RequestParam(required = false) String back,
                         Principal principal,
                         RedirectAttributes flash) {
        Asset asset = assets.findWithZone(assetId)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "자산을 찾을 수 없습니다."));
        try {
            acceptances.accept(asset, cve, packageName, reason, compensating, approvedBy,
                               LocalDate.parse(reviewBy), principal.getName());
            flash.addFlashAttribute("message", cve + " 를 수용 기록에 남겼습니다.");
        } catch (IllegalArgumentException | java.time.format.DateTimeParseException e) {
            flash.addFlashAttribute("error", message(e));
        }
        return "redirect:" + safeBack(back, "/acceptances");
    }

    @PostMapping("{id}/revoke")
    @PreAuthorize("hasRole('ADMIN')")
    public String revoke(@PathVariable Long id,
                         @RequestParam(required = false) String note,
                         Principal principal, RedirectAttributes flash) {
        try {
            acceptances.revoke(id, note, principal.getName());
            flash.addFlashAttribute("message", "수용을 철회했습니다.");
        } catch (IllegalArgumentException e) {
            flash.addFlashAttribute("error", e.getMessage());
        }
        return "redirect:/acceptances";
    }

    private String message(Exception e) {
        return e instanceof java.time.format.DateTimeParseException
                ? "다시 볼 날짜를 정해 주세요."
                : e.getMessage();
    }

    /**
     * 돌아갈 곳.
     *
     * <p>받은 값을 그대로 리다이렉트에 쓰면 바깥 주소를 넣어 다른 사이트로
     * 보낼 수 있다. 이 앱 안의 경로만 허용한다.
     */
    private String safeBack(String back, String fallback) {
        if (back == null || back.isBlank()) {
            return fallback;
        }
        String clean = back.trim();
        // "//evil.com" 은 프로토콜 상대 주소라 바깥으로 나간다.
        if (!clean.startsWith("/") || clean.startsWith("//")) {
            return fallback;
        }
        return clean;
    }
}
