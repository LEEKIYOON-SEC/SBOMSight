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

/** 기승전결 보고서. AI 는 쓰지 않는다 — grype 데이터만으로 만든다. */
@Controller
public class ReportController {

    private final ScanRepository scans;
    private final ReportService reports;

    public ReportController(ScanRepository scans, ReportService reports) {
        this.scans = scans;
        this.reports = reports;
    }

    @GetMapping("/report/{scanId}")
    public String report(@PathVariable Long scanId, Model model) {
        Scan scan = scans.findWithAsset(scanId)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "스캔을 찾을 수 없습니다."));
        model.addAttribute("report", reports.build(scan));
        return "report";
    }
}
