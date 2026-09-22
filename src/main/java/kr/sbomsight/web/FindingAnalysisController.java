package kr.sbomsight.web;

import kr.sbomsight.domain.*;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.service.FindingAnalysisService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.security.Principal;
import java.time.LocalDate;

import static org.springframework.http.HttpStatus.NOT_FOUND;

/**
 * 검토 결과를 <b>적는</b> 자리.
 *
 * <p>목록은 {@link ActionController}(`/actions?tab=analyses`)로 옮겼다. 여기
 * 남은 것은 취약점 화면에서 건을 보면서 적는 길 하나다 — <b>목록이 아니라
 * 건을 보면서 적는다.</b> 무엇이 해당 없는지는 그 탐지를 봐야 알 수 있다.
 *
 * <p>적는 것은 관리자만 한다. 조회 권한으로 남의 결정을 적을 수는 없다.
 */
@Controller
@RequestMapping("/analyses")
public class FindingAnalysisController {

    private static final org.slf4j.Logger log =
            org.slf4j.LoggerFactory.getLogger(FindingAnalysisController.class);

    private final FindingAnalysisService analyses;
    private final AssetRepository assets;

    public FindingAnalysisController(FindingAnalysisService analyses, AssetRepository assets) {
        this.analyses = analyses;
        this.assets = assets;
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
            AnalysisJustification newJustification =
                    enumOf(AnalysisJustification.class, justification);
            AnalysisResponse newResponse = enumOf(AnalysisResponse.class, response);
            java.time.LocalDate newReviewBy = date(reviewBy);
            try {
                analyses.record(asset, cve, packageName,
                                newState == null ? AnalysisState.NOT_SET : newState,
                                newJustification, newResponse,
                                note, otherControl, approvalDoc, newReviewBy,
                                principal.getName());
            } catch (org.springframework.dao.DataIntegrityViolationException race) {
                // **동시에 두 번 눌렸다.** `record` 는 `없으면 만든다` 인데 그
                // 사이에 다른 요청이 같은 `(자산, CVE, 패키지)` 를 만들 수 있다.
                // DB 의 유일 제약(`ux_analysis_key`)이 막아 데이터는 갈라지지
                // 않지만, 예외가 그대로 올라가면 화면이 500 이 되어 적은 것이
                // 들어갔는지 알 수 없다.
                //
                // 한 번 더 부른다 — 이제 그 줄이 있으므로 `고치는 길` 로 가고,
                // 바뀐 칸만 이력에 남는다. 두 번째도 겹치면 그때는 올린다.
                log.info("검토 결과를 적는 요청이 겹쳤습니다 — 다시 한 번 적습니다: {} · {}",
                         cve, packageName);
                analyses.record(asset, cve, packageName,
                                newState == null ? AnalysisState.NOT_SET : newState,
                                newJustification, newResponse,
                                note, otherControl, approvalDoc, newReviewBy,
                                principal.getName());
            }
            flash.addFlashAttribute("message", cve + " 의 검토 결과를 적었습니다.");
        } catch (IllegalArgumentException | java.time.format.DateTimeParseException e) {
            flash.addFlashAttribute("error", message(e));
        }
        return "redirect:" + safeBack(back, "/actions?tab=analyses");
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
