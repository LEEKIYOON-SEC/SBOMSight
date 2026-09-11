package kr.sbomsight.web;

import jakarta.servlet.http.HttpServletResponse;
import kr.sbomsight.domain.AuditEvent;
import kr.sbomsight.domain.AuditLog;
import kr.sbomsight.repo.AuditLogRepository;
import kr.sbomsight.service.CsvWriter;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.List;

/**
 * 감사 로그 조회.
 *
 * <p>관리자만 본다. 로그 자체가 "누가 언제 어디서" 를 담고 있어서, 조회 권한을
 * 넓히면 그것이 곧 접속 현황 공개가 된다.
 */
@Controller
@RequestMapping("/audit")
@PreAuthorize("hasRole('ADMIN')")
public class AuditController {

    private static final int PAGE_SIZE = 100;
    private static final ZoneId SEOUL = ZoneId.of("Asia/Seoul");

    private final AuditLogRepository logs;

    public AuditController(AuditLogRepository logs) {
        this.logs = logs;
    }

    @GetMapping
    public String index(@RequestParam(required = false) String actor,
                        @RequestParam(required = false) AuditEvent action,
                        @RequestParam(required = false) String from,
                        @RequestParam(required = false) String to,
                        @RequestParam(required = false) String q,
                        @RequestParam(defaultValue = "0") int page,
                        Model model) {
        Page<AuditLog> result = logs.search(blankToNull(actor), action,
                                            startOf(from), endOf(to), blankToNull(q),
                                            PageRequest.of(Math.max(page, 0), PAGE_SIZE));

        model.addAttribute("page", result);
        model.addAttribute("events", AuditEvent.values());
        model.addAttribute("actor", actor);
        model.addAttribute("action", action);
        model.addAttribute("from", from);
        model.addAttribute("to", to);
        model.addAttribute("q", q);
        return "audit";
    }

    /** 내려받기. 화면의 필터가 그대로 적용된다. */
    @GetMapping("export.csv")
    public void export(@RequestParam(required = false) String actor,
                       @RequestParam(required = false) AuditEvent action,
                       @RequestParam(required = false) String from,
                       @RequestParam(required = false) String to,
                       @RequestParam(required = false) String q,
                       HttpServletResponse response) throws IOException {
        List<AuditLog> rows = logs.export(blankToNull(actor), action,
                                          startOf(from), endOf(to), blankToNull(q));

        response.setContentType("text/csv; charset=UTF-8");
        response.setHeader("Content-Disposition",
                "attachment; filename=\"audit-" + LocalDate.now(SEOUL) + ".csv\"");
        CsvWriter.writeAuditLog(response.getOutputStream(), rows);
    }

    /** 그 날 00:00(한국 시간)부터. */
    private Instant startOf(String date) {
        String clean = blankToNull(date);
        return clean == null ? null : LocalDate.parse(clean).atStartOfDay(SEOUL).toInstant();
    }

    /**
     * 그 날 <b>다음 날</b> 00:00 까지.
     *
     * <p>"~까지" 를 그 날 00:00 으로 잡으면 지정한 날 하루가 통째로 빠진다.
     * 기간으로 걸러 본 결과가 조용히 하루 적으면 그 수를 믿을 수 없다.
     */
    private Instant endOf(String date) {
        String clean = blankToNull(date);
        return clean == null ? null : LocalDate.parse(clean).plusDays(1).atStartOfDay(SEOUL).toInstant();
    }

    private String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
