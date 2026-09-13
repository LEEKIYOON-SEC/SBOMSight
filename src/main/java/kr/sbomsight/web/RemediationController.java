package kr.sbomsight.web;

import kr.sbomsight.domain.Remediation;
import kr.sbomsight.domain.Scan;
import kr.sbomsight.repo.ScanRepository;
import kr.sbomsight.service.RemediationService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.security.Principal;

import static org.springframework.http.HttpStatus.NOT_FOUND;

/**
 * 조치를 <b>여는</b> 자리.
 *
 * <p>목록과 상세는 {@link ActionController}(`/actions`)로 옮겼다. 여기 남은
 * 것은 검사 화면에서 패키지 하나를 집어 조치로 올리는 길 하나다 —
 * <b>등록은 목록이 아니라 건을 보면서 한다.</b> 목록만 보고 "무엇을 조치할지"
 * 고를 수는 없다.
 */
@Controller
public class RemediationController {

    private final ScanRepository scans;
    private final RemediationService service;

    public RemediationController(ScanRepository scans, RemediationService service) {
        this.scans = scans;
        this.service = service;
    }

    @PostMapping("/scans/{scanId}/remediations")
    @PreAuthorize("hasRole('ADMIN')")
    public String open(@PathVariable Long scanId, @RequestParam String packageName,
                       Principal principal, RedirectAttributes flash) {
        Scan scan = scans.findWithAsset(scanId)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "검사를 찾을 수 없습니다."));

        Remediation remediation = service.open(scan.getAsset(), scan, packageName,
                                               principal.getName());
        flash.addFlashAttribute("message", packageName + " 조치를 등록했습니다.");
        return "redirect:/actions/" + remediation.getId();
    }
}
