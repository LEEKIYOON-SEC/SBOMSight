package kr.sbomsight.web;

import kr.sbomsight.domain.*;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.service.FindingAnalysisService;
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
 * 검토 결과 — 탐지 하나하나에 대한 우리의 결정을 적는 곳.
 *
 * <p><b>앞서 '위험 수용' 화면이었다.</b> 그런데 그것은 다섯 상태 중
 * 하나({@code 해당됨})와 다섯 대응 중 하나({@code 조치 안 함})의 조합일
 * 뿐이었고, 나머지 조합을 적을 자리는 없었다. "이건 우리 환경에 해당 없다"
 * 도, "오탐이다" 도 적을 데가 없어서 그냥 목록에 남아 있었다.
 *
 * <p>적는 것은 관리자만 한다. 조회 권한으로 남의 결정을 적을 수는 없다.
 */
@Controller
@RequestMapping("/analyses")
public class FindingAnalysisController {

    private final FindingAnalysisService analyses;
    private final AssetRepository assets;
    private final ZoneService zones;

    public FindingAnalysisController(FindingAnalysisService analyses, AssetRepository assets,
                                     ZoneService zones) {
        this.analyses = analyses;
        this.assets = assets;
        this.zones = zones;
    }

    @GetMapping
    public String index(@RequestParam(defaultValue = "false") boolean includeDone,
                        @RequestParam(required = false) Long zone,
                        Model model) {
        model.addAttribute("rows", analyses.list(includeDone, zone));
        model.addAttribute("includeDone", includeDone);
        model.addAttribute("zones", zones.all());
        model.addAttribute("selectedZone", zone);
        model.addAttribute("overdue", analyses.reviewOverdue());
        return "analyses";
    }

    /**
     * 적는다. 없으면 만들고 있으면 바꾼다 — 화면에서는 같은 한 가지 일이다.
     *
     * <p>빈 문자열을 {@code null} 로 받는다. 화면의 고르개는 "고르지 않음" 을
     * 빈 값으로 보내는데, 스프링이 그대로 enum 으로 바꾸려 하면 400 이 난다.
     */
    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public String record(@RequestParam Long assetId,
                         @RequestParam String cve,
                         @RequestParam String packageName,
                         @RequestParam(required = false) String state,
                         @RequestParam(required = false) String justification,
                         @RequestParam(required = false) String response,
                         @RequestParam(required = false) String note,
                         @RequestParam(required = false) String otherControl,
                         @RequestParam(required = false) String approvalDoc,
                         @RequestParam(required = false) String reviewBy,
                         @RequestParam(required = false) String back,
                         Principal principal,
                         RedirectAttributes flash) {
        Asset asset = assets.findWithZone(assetId)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "자산을 찾을 수 없습니다."));
        try {
            AnalysisState newState = enumOf(AnalysisState.class, state);
            analyses.record(asset, cve, packageName,
                            newState == null ? AnalysisState.NOT_SET : newState,
                            enumOf(AnalysisJustification.class, justification),
                            enumOf(AnalysisResponse.class, response),
                            note, otherControl, approvalDoc, date(reviewBy),
                            principal.getName());
            flash.addFlashAttribute("message", cve + " 의 검토 결과를 적었습니다.");
        } catch (IllegalArgumentException | java.time.format.DateTimeParseException e) {
            flash.addFlashAttribute("error", message(e));
        }
        return "redirect:" + safeBack(back, "/analyses");
    }

    private <E extends Enum<E>> E enumOf(Class<E> type, String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Enum.valueOf(type, value.trim());
        } catch (IllegalArgumentException e) {
            // 화면이 보낼 수 없는 값이다. 목록에 없는 것을 손으로 넣은 경우라
            // 조용히 무시하지 않고 알린다 — 저장은 됐는데 값만 빠지면 더 나쁘다.
            throw new IllegalArgumentException("고를 수 없는 값입니다: " + value);
        }
    }

    private LocalDate date(String value) {
        return value == null || value.isBlank() ? null : LocalDate.parse(value.trim());
    }

    private String message(Exception e) {
        return e instanceof java.time.format.DateTimeParseException
                ? "재검토일을 정해 주세요."
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
