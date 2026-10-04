package kr.sbomsight.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import kr.sbomsight.domain.ReportPublication;
import kr.sbomsight.repo.ReportPublicationRepository;
import kr.sbomsight.service.PublicationService;
import kr.sbomsight.service.VulnQuery;
import kr.sbomsight.service.ZoneReportService;
import kr.sbomsight.service.ZoneService;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.security.Principal;
import java.time.Instant;
import java.time.LocalDate;
import java.util.Map;

/**
 * 구역 · 기간 보고서 — "9월 DMZ 현황".
 *
 * <p>기간을 안 주면 <b>이번 달</b>이다. 월 단위가 이 도구가 실제로 쓰이는
 * 주기이고, 매달 같은 화면을 열어 같은 두 칸을 채우게 하지 않는다.
 *
 * <p>주소가 {@code /reports/} 아래로 들어왔다 (N7).
 *
 * <p><b>열 때마다 지금 데이터로 계산한다 — 초안이다.</b> 결재에 올릴 문서는 발행한다(R11).
 */
@Controller
public class ZoneReportController {

    private final ZoneReportService reports;
    private final ZoneService zoneService;
    private final PublicationService publishing;
    private final ReportPublicationRepository publications;
    private final DocumentRenderer documents;

    public ZoneReportController(ZoneReportService reports, ZoneService zoneService,
                                PublicationService publishing, ReportPublicationRepository publications,
                                DocumentRenderer documents) {
        this.reports = reports;
        this.zoneService = zoneService;
        this.publishing = publishing;
        this.publications = publications;
        this.documents = documents;
    }

    /**
     * 보고서의 기간 — 안 주면 이번 달 1일부터 오늘까지. 거꾸로 넣었으면 바로잡는다.
     * 보는 것과 발행하는 것이 같은 규칙이어야 화면에 보던 기간 그대로 발행된다.
     *
     * @param swapped 시작일이 종료일보다 늦어 두 날짜를 바꿨는가
     */
    record Period(LocalDate from, LocalDate to, boolean swapped) {

        static Period of(LocalDate from, LocalDate to, LocalDate today) {
            LocalDate start = from != null ? from : today.withDayOfMonth(1);
            LocalDate end = to != null ? to : today;
            // 거꾸로 넣었으면 바로잡고 알린다. 말없이 빈 보고서를 내면 "이 구역은
            // 깨끗하다" 로 읽힌다.
            return end.isBefore(start) ? new Period(end, start, true) : new Period(start, end, false);
        }
    }

    @GetMapping("/reports/zone")
    public String zoneReport(
            @RequestParam(required = false) Long zone,
            @RequestParam(required = false)
            @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate from,
            @RequestParam(required = false)
            @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate to,
            Model model) {

        LocalDate today = LocalDate.now();
        Period period = Period.of(from, to, today);
        LocalDate start = period.from();
        LocalDate end = period.to();

        model.addAttribute("report", reports.build(zone, start, end));
        model.addAttribute("zones", zoneService.all());
        model.addAttribute("selectedZone", zone);
        model.addAttribute("from", start);
        model.addAttribute("to", end);
        // 초안의 `출력 시각` — 이 화면을 그린 시각. 앞서 오늘 날짜(`today`)를 넘겨 `작성일`
        // 로 찍었다 — 결재 문서를 쓴 날처럼 읽혔다(R11).
        //
        // 기간 넷은 날짜로 넘기지 않는다 — 화면은 아래에서 만드는
        // `thisMonthLink` 같은 **주소**를 쓴다. 날짜와 주소를 둘 다 넘기면
        // 기간을 고칠 때 한쪽만 고치는 날이 온다.
        model.addAttribute("printedAt", Instant.now());
        // 같은 구역 · 같은 기간을 발행한 것.
        model.addAttribute("publications", publications.findForZone(zone, start, end));

        // 기간 단추의 주소를 자바에서 만든다. `@{/reports/zone(zone=${zone}, …)}`
        // 는 값이 없어도 이름을 적어서, 구역을 안 고른 전체 범위에서 `zone=`
        // 이 빈 값으로 붙었다 — 그 주소가 결재 문서에 붙는다(N12).
        VulnQuery.Links links = new VulnQuery.Links("/reports/zone", null)
                .with("zone", zone);
        model.addAttribute("thisMonthLink",
                links.copy().with("from", today.withDayOfMonth(1)).with("to", today).here());
        model.addAttribute("lastMonthLink",
                links.copy().with("from", today.minusMonths(1).withDayOfMonth(1))
                      .with("to", today.withDayOfMonth(1).minusDays(1)).here());
        model.addAttribute("quarterLink",
                links.copy().with("from", today.minusMonths(2).withDayOfMonth(1))
                      .with("to", today).here());
        if (period.swapped()) {
            model.addAttribute("message", "시작일이 종료일보다 늦어 두 날짜를 바꿨습니다.");
        }
        return "zone-report";
    }

    /**
     * 발행 — 보던 구역 · 기간 그대로 지금 계산해 발행본으로 저장한다. 그 발행본으로 간다.
     */
    @PostMapping("/reports/zone/publish")
    @PreAuthorize("hasRole('ADMIN')")
    public String publish(
            @RequestParam(required = false) Long zone,
            @RequestParam(required = false)
            @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate from,
            @RequestParam(required = false)
            @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate to,
            Principal principal, HttpServletRequest request, HttpServletResponse response,
            RedirectAttributes flash) {
        Period period = Period.of(from, to, LocalDate.now());
        try {
            ReportPublication p = publishing.publishZone(zone, period.from(), period.to(),
                    principal.getName(),
                    (report, head) -> documents.render("zone-report",
                            Map.of("report", report, "publication", head), request, response));
            flash.addFlashAttribute("message", "발행했습니다. 발행 번호 " + p.getNumber());
            return "redirect:/reports/publications/" + p.getId();
        } catch (PublicationService.PublicationException e) {
            flash.addFlashAttribute("error", "발행하지 못했습니다: " + e.getMessage());
            return "redirect:" + new VulnQuery.Links("/reports/zone", null).with("zone", zone)
                    .with("from", period.from()).with("to", period.to()).here();
        }
    }
}
