package kr.sbomsight.web;

import kr.sbomsight.domain.*;
import kr.sbomsight.repo.*;
import jakarta.servlet.http.HttpServletResponse;
import kr.sbomsight.service.CsvWriter;
import kr.sbomsight.service.RemediationService;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.security.Principal;
import java.time.LocalDate;
import java.util.List;

import static org.springframework.http.HttpStatus.NOT_FOUND;

/** 조치 등록·수정·이력. */
@Controller
public class RemediationController {

    private final RemediationRepository remediations;
    private final AssetRepository assets;
    private final ScanRepository scans;
    private final RemediationService service;

    public RemediationController(RemediationRepository remediations, AssetRepository assets,
                                 ScanRepository scans, RemediationService service) {
        this.remediations = remediations;
        this.assets = assets;
        this.scans = scans;
        this.service = service;
    }

    /** 전체 조치 목록. 기한이 지난 것이 맨 위로 온다. */
    @GetMapping("/remediations")
    public String list(Model model) {
        List<Remediation> all = service.all();
        model.addAttribute("remediations", all);
        model.addAttribute("overdue", remediations.findOverdue(LocalDate.now()));
        model.addAttribute("statuses", RemediationStatus.values());
        return "remediations";
    }

    /** 취약점 화면에서 패키지 하나를 조치로 올린다. */
    @PostMapping("/scans/{scanId}/remediations")
    @PreAuthorize("hasRole('ADMIN')")
    public String open(@PathVariable Long scanId, @RequestParam String packageName,
                       Principal principal, RedirectAttributes flash) {
        Scan scan = scans.findWithAsset(scanId)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "스캔을 찾을 수 없습니다."));

        Remediation remediation = service.open(scan.getAsset(), scan, packageName,
                                               principal.getName());
        flash.addFlashAttribute("message", packageName + " 조치를 등록했습니다.");
        return "redirect:/remediations/" + remediation.getId();
    }

    @GetMapping("/remediations/export.csv")
    public void export(HttpServletResponse response) throws java.io.IOException {
        response.setContentType("text/csv; charset=UTF-8");
        response.setHeader("Content-Disposition", "attachment; filename=remediations.csv");
        CsvWriter.writeRemediations(response.getOutputStream(), service.all());
    }

    @GetMapping("/remediations/{id}")
    public String detail(@PathVariable Long id, Model model) {
        Remediation remediation = remediation(id);
        model.addAttribute("remediation", remediation);
        model.addAttribute("statuses", RemediationStatus.values());

        // 최신 스캔에서 이 패키지가 아직 몇 건인가. **상태를 자동으로 바꾸지는
        // 않는다** — 대상이 바뀌어 사라진 것인지 정말 패치된 것인지 우리가
        // 판단할 수 없다. 숫자만 보여 주고 판단은 담당자가 한다.
        Scan latest = scans.findFirstByAssetIdAndStatusOrderByCreatedAtDesc(
                remediation.getAsset().getId(), ScanStatus.DONE).orElse(null);
        model.addAttribute("latest", latest);
        model.addAttribute("remaining",
                latest == null ? -1L
                        : service.remainingCounts(remediation.getAsset().getId(), latest)
                                 .getOrDefault(remediation.getId(), 0L));
        return "remediation-detail";
    }

    @PostMapping("/remediations/{id}")
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
        return "redirect:/remediations/" + id;
    }

    /** 자산과 발자취까지 함께 읽는다 — 화면이 둘 다 쓴다. */
    private Remediation remediation(Long id) {
        return remediations.findDetail(id)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "조치를 찾을 수 없습니다."));
    }
}
