package kr.sbomsight.web;

import jakarta.servlet.http.HttpServletResponse;
import kr.sbomsight.domain.*;
import kr.sbomsight.repo.RemediationRepository;
import kr.sbomsight.repo.ScanRepository;
import kr.sbomsight.service.CsvWriter;
import kr.sbomsight.service.FindingAnalysisService;
import kr.sbomsight.service.RemediationService;
import kr.sbomsight.service.ZoneService;
import org.springframework.format.annotation.DateTimeFormat;
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
 * 대응 — <b>내린 결정을 모아 보는 자리.</b>
 *
 * <p>탭 둘이다. 앞서는 화면이 둘이었고 기둥에서도 갈라져 있어서, 어느 쪽이
 * 급한지 알려면 두 번 봐야 했다. 둘 다 "이 건을 어떻게 할 것인가" 에 대한
 * 답이므로 한자리에 둔다.
 *
 * <ul>
 *   <li><b>조치</b> — 올리기로 한 것. 기한이 지난 것이 맨 위로.</li>
 *   <li><b>검토 결과</b> — 그 탐지를 어떻게 판단했는가. 재검토일이 지난 것이 맨 위로.</li>
 * </ul>
 *
 * <p><b>여기서 등록하지 않는다.</b> 조치도 검토 결과도 취약점 화면에서 건을
 * 보면서 적는다 — 목록만 보고 "무엇을 조치할지" 고를 수는 없다. 이 화면은
 * 이미 내린 결정이 어떻게 되어 가는지 보는 곳이다.
 */
@Controller
@RequestMapping("/actions")
public class ActionController {

    private final RemediationRepository remediations;
    private final RemediationService service;
    private final FindingAnalysisService analyses;
    private final ScanRepository scans;
    private final ZoneService zones;

    public ActionController(RemediationRepository remediations, RemediationService service,
                            FindingAnalysisService analyses, ScanRepository scans,
                            ZoneService zones) {
        this.remediations = remediations;
        this.service = service;
        this.analyses = analyses;
        this.scans = scans;
        this.zones = zones;
    }

    @GetMapping
    public String index(@RequestParam(defaultValue = "remediations") String tab,
                        @RequestParam(required = false) Long zone,
                        @RequestParam(required = false) RemediationStatus status,
                        @RequestParam(defaultValue = "false") boolean includeDone,
                        Model model) {
        // 탭 숫자는 **거르기 전** 전체를 센다. 거른 뒤 세면 구역을 고르는
        // 순간 탭의 수가 함께 줄어, 다른 탭에 무엇이 있는지 알 수 없게 된다.
        model.addAttribute("remediationCount", service.all().size());
        model.addAttribute("analysisCount", analyses.list(false, null).size());

        model.addAttribute("tab", tab);
        model.addAttribute("zones", zones.all());
        model.addAttribute("selectedZone", zone);
        model.addAttribute("status", status);
        model.addAttribute("statuses", RemediationStatus.values());
        model.addAttribute("includeDone", includeDone);

        if ("analyses".equals(tab)) {
            model.addAttribute("analyses", analyses.list(includeDone, zone));
            model.addAttribute("overdue", analyses.reviewOverdue());
        } else {
            model.addAttribute("remediations", service.list(zone, status));
            model.addAttribute("overdue", remediations.findOverdue(LocalDate.now()));
        }
        return "actions";
    }

    /** 조치 하나 — 상태·담당·기한과 그동안의 발자취. */
    @GetMapping("/{id}")
    public String detail(@PathVariable Long id, Model model) {
        Remediation remediation = remediation(id);
        model.addAttribute("remediation", remediation);
        model.addAttribute("statuses", RemediationStatus.values());

        // 최신 검사에서 이 패키지가 아직 몇 건인가. **상태를 자동으로 바꾸지는
        // 않는다** — 대상이 바뀌어 사라진 것인지 정말 올린 것인지 우리가
        // 판단할 수 없다. 숫자만 보여 주고 판단은 담당자가 한다.
        Scan latest = scans.findFirstByAssetIdAndStatusOrderByCreatedAtDesc(
                remediation.getAsset().getId(), ScanStatus.DONE).orElse(null);
        model.addAttribute("latest", latest);
        model.addAttribute("remaining",
                latest == null ? -1L
                        : service.remainingCounts(remediation.getAsset().getId(), latest)
                                 .getOrDefault(remediation.getId(), 0L));
        return "action-detail";
    }

    @PostMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public String update(@PathVariable Long id,
                         @RequestParam RemediationStatus status,
                         @RequestParam(required = false) String owner,
                         @RequestParam(required = false)
                         @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate dueDate,
                         @RequestParam(required = false) String note,
                         @RequestParam(required = false) String comment,
                         Principal principal, RedirectAttributes flash) {
        Remediation remediation = remediation(id);
        service.update(remediation, status, owner, dueDate, note, principal.getName(), comment);
        flash.addFlashAttribute("message", "조치를 갱신했습니다.");
        return "redirect:/actions/" + id;
    }

    /** 내려받기는 보고 있는 탭의 것이다. 다른 탭의 것이 섞여 나오면 대조를 못 한다. */
    @GetMapping("/export.csv")
    public void export(@RequestParam(defaultValue = "remediations") String tab,
                       @RequestParam(required = false) Long zone,
                       @RequestParam(required = false) RemediationStatus status,
                       @RequestParam(defaultValue = "false") boolean includeDone,
                       HttpServletResponse response) throws java.io.IOException {
        boolean isAnalyses = "analyses".equals(tab);
        response.setContentType("text/csv; charset=UTF-8");
        response.setHeader("Content-Disposition",
                "attachment; filename=\"" + (isAnalyses ? "analyses" : "remediations")
                + "-" + LocalDate.now() + ".csv\"");

        if (isAnalyses) {
            CsvWriter.writeAnalyses(response.getOutputStream(), analyses.list(includeDone, zone));
        } else {
            CsvWriter.writeRemediations(response.getOutputStream(), service.list(zone, status));
        }
    }

    /** 자산과 발자취까지 함께 읽는다 — 화면이 둘 다 쓴다. */
    private Remediation remediation(Long id) {
        return remediations.findDetail(id)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "조치를 찾을 수 없습니다."));
    }
}
