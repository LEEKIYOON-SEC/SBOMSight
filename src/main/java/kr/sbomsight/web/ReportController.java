package kr.sbomsight.web;

import kr.sbomsight.domain.Scan;
import kr.sbomsight.repo.ScanRepository;
import kr.sbomsight.service.ReportService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.server.ResponseStatusException;

import static org.springframework.http.HttpStatus.NOT_FOUND;

/**
 * 자산 한 대의 점검 결과 보고서. grype 이 낸 것만으로 만든다.
 *
 * <p>주소가 {@code /reports/} 아래로 들어왔다 (N7). 앞서
 * {@code /report/{scanId}} 와 {@code /report/zone} 과 {@code /reports} 가
 * 따로 있었는데, 한 영역의 주소가 두 갈래면 기억하지 못한다. 옛 주소는
 * {@link LegacyRedirectController} 가 영구히 받는다.
 */
@Controller
public class ReportController {

    private final ScanRepository scans;
    private final ReportService reports;

    public ReportController(ScanRepository scans, ReportService reports) {
        this.scans = scans;
        this.reports = reports;
    }

    @GetMapping("/reports/scan/{scanId}")
    public String report(@PathVariable Long scanId, Model model) {
        Scan scan = scans.findWithAsset(scanId)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "검사를 찾을 수 없습니다."));
        model.addAttribute("report", reports.build(scan));
        return "report";
    }
}
