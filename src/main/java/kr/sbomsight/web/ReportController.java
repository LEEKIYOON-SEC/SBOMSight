package kr.sbomsight.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import kr.sbomsight.domain.ReportPublication;
import kr.sbomsight.domain.Scan;
import kr.sbomsight.repo.ReportPublicationRepository;
import kr.sbomsight.repo.ScanRepository;
import kr.sbomsight.service.PublicationService;
import kr.sbomsight.service.ReportService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.security.Principal;
import java.util.Map;

import static org.springframework.http.HttpStatus.NOT_FOUND;

/**
 * 자산 한 대의 점검 결과 보고서. grype 이 낸 것만으로 만든다.
 *
 * <p>주소가 {@code /reports/} 아래로 들어왔다 (N7). 앞서
 * {@code /report/{scanId}} 와 {@code /report/zone} 과 {@code /reports} 가
 * 따로 있었는데, 한 영역의 주소가 두 갈래면 기억하지 못한다. 옛 주소를 잇던
 * 다리는 운영 전에 걷었다 — 옛 주소를 적어 둔 설치가 없다.
 *
 * <p><b>열 때마다 지금 데이터로 계산한다 — 초안이다.</b> 결재에 올릴 문서는 발행한다
 * (R11): 그 순간의 문서가 발행본으로 저장되고, 이 화면은 제 발행본을 가리킨다.
 */
@Controller
public class ReportController {

    private final ScanRepository scans;
    private final ReportService reports;
    private final PublicationService publishing;
    private final ReportPublicationRepository publications;
    private final DocumentRenderer documents;

    public ReportController(ScanRepository scans, ReportService reports, PublicationService publishing,
                            ReportPublicationRepository publications, DocumentRenderer documents) {
        this.scans = scans;
        this.reports = reports;
        this.publishing = publishing;
        this.publications = publications;
        this.documents = documents;
    }

    @GetMapping("/reports/scan/{scanId}")
    public String report(@PathVariable Long scanId, Model model) {
        Scan scan = scans.findWithAsset(scanId)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "검사를 찾을 수 없습니다."));
        model.addAttribute("report", reports.build(scan));
        model.addAttribute("publications", publications.findForScan(scanId));
        return "report";
    }

    /**
     * 발행 — 지금 계산한 보고서를 문서로 그려 발행본으로 저장한다. 그 발행본으로 간다.
     *
     * <p>그리는 것은 이 화면의 {@code document} 조각이다(DocumentRenderer) — 발행 정보를
     * 넘기면 문서 정보에 발행 번호 · 발행 시각 · 발행자를 찍고 폼 · 관리자 칸을 뺀다.
     */
    @PostMapping("/reports/scan/{scanId}/publish")
    @PreAuthorize("hasRole('ADMIN')")
    public String publish(@PathVariable Long scanId, Principal principal,
                          HttpServletRequest request, HttpServletResponse response,
                          RedirectAttributes flash) {
        try {
            ReportPublication p = publishing.publishScan(scanId, principal.getName(),
                    (report, head) -> documents.render("report",
                            Map.of("report", report, "publication", head), request, response));
            flash.addFlashAttribute("message", "발행했습니다. 발행 번호 " + p.getNumber());
            return "redirect:/reports/publications/" + p.getId();
        } catch (PublicationService.PublicationException e) {
            flash.addFlashAttribute("error", "발행하지 못했습니다: " + e.getMessage());
            return scans.existsById(scanId) ? "redirect:/reports/scan/" + scanId : "redirect:/reports";
        }
    }
}
