package kr.sbomsight.web;

import kr.sbomsight.domain.PublicationKind;
import kr.sbomsight.domain.ReportPublication;
import kr.sbomsight.repo.ReportPublicationRepository;
import kr.sbomsight.repo.ScanRepository;
import kr.sbomsight.repo.ZoneRepository;
import kr.sbomsight.service.Paging;
import kr.sbomsight.service.PublicationService;
import kr.sbomsight.service.VulnQuery;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.security.Principal;

import static org.springframework.http.HttpStatus.NOT_FOUND;

/**
 * 발행본 — 목록과 보기, 결재 문서 번호(R11, V20).
 *
 * <p>발행본은 <b>저장한 문서 그대로</b> 보인다. 다시 계산하지 않는다. 머리에 발행 번호 ·
 * 결재 문서 번호 · 발행본 해시를 두고, 볼 때마다 해시를 다시 대조한다 — 맞지 않으면
 * 문서를 보이지 않는다.
 *
 * <p>보기는 두 권한 모두, 결재 문서 번호는 관리자만. 발행본을 지우는 길은 없다.
 */
@Controller
public class PublicationController {

    private final PublicationService publishing;
    private final ReportPublicationRepository publications;
    private final ScanRepository scans;
    private final ZoneRepository zones;

    public PublicationController(PublicationService publishing, ReportPublicationRepository publications,
                                 ScanRepository scans, ZoneRepository zones) {
        this.publishing = publishing;
        this.publications = publications;
        this.scans = scans;
        this.zones = zones;
    }

    @GetMapping("/reports/publications")
    public String list(@RequestParam(defaultValue = "0") int page,
                       @RequestParam(required = false) Integer size,
                       @RequestParam(required = false) Integer jump,
                       Model model) {
        VulnQuery.Links links = new VulnQuery.Links("/reports/publications", null).size(size);
        String jumped = Paging.jump(links, jump);
        if (jumped != null) {
            return jumped;
        }
        var rows = publications.findRows(Paging.request(page, size));
        // 범위를 넘은 쪽 번호는 마지막 쪽으로 — 다른 목록과 같다(Paging.slice).
        if (rows.getNumber() > 0 && rows.getContent().isEmpty() && rows.getTotalPages() > 0) {
            rows = publications.findRows(Paging.request(rows.getTotalPages() - 1, size));
        }
        model.addAttribute("rows", rows);
        model.addAttribute("links", links);
        return "publications";
    }

    @GetMapping("/reports/publications/{id}")
    public String view(@PathVariable Long id, Model model) {
        PublicationService.Viewed viewed = publishing.view(id)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "발행본을 찾을 수 없습니다."));
        ReportPublication p = viewed.publication();
        model.addAttribute("p", p);
        model.addAttribute("verified", viewed.verified());
        model.addAttribute("target", PublicationService.target(p));
        model.addAttribute("liveLink", liveLink(p));
        return "publication";
    }

    /**
     * 같은 대상의 <b>지금 보고서(초안)</b> 주소 — 대상이 지워졌으면 {@code null}. 발행본과
     * 지금 데이터를 견줘 볼 때 쓴다.
     */
    private String liveLink(ReportPublication p) {
        if (p.getKind() == PublicationKind.SCAN) {
            return p.getScanId() != null && scans.existsById(p.getScanId())
                    ? "/reports/scan/" + p.getScanId() : null;
        }
        if (p.getZoneId() != null && !zones.existsById(p.getZoneId())) {
            return null;
        }
        return new VulnQuery.Links("/reports/zone", null).with("zone", p.getZoneId())
                .with("from", p.getPeriodFrom()).with("to", p.getPeriodTo()).here();
    }

    /** 결재 문서 번호 — 발행한 뒤에 적는다. 바꾼 것은 이력과 감사 로그에 남는다. */
    @PostMapping("/reports/publications/{id}/approval-doc")
    @PreAuthorize("hasRole('ADMIN')")
    public String approvalDoc(@PathVariable Long id, @RequestParam(required = false) String approvalDoc,
                              Principal principal, RedirectAttributes flash) {
        try {
            if (publishing.changeApprovalDoc(id, approvalDoc, principal.getName())) {
                flash.addFlashAttribute("message", "결재 문서 번호를 저장했습니다.");
            }
        } catch (PublicationService.PublicationException e) {
            flash.addFlashAttribute("error", e.getMessage());
        }
        return "redirect:/reports/publications/" + id;
    }
}
