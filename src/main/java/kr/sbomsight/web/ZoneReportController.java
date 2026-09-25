package kr.sbomsight.web;

import kr.sbomsight.service.VulnQuery;
import kr.sbomsight.service.ZoneReportService;
import kr.sbomsight.service.ZoneService;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.time.LocalDate;

/**
 * 구역 · 기간 보고서 — "9월 DMZ 현황".
 *
 * <p>기간을 안 주면 <b>이번 달</b>이다. 월 단위가 이 도구가 실제로 쓰이는
 * 주기이고, 매달 같은 화면을 열어 같은 두 칸을 채우게 하지 않는다.
 *
 * <p>주소가 {@code /reports/} 아래로 들어왔다 (N7).
 */
@Controller
public class ZoneReportController {

    private final ZoneReportService reports;
    private final ZoneService zoneService;

    public ZoneReportController(ZoneReportService reports, ZoneService zoneService) {
        this.reports = reports;
        this.zoneService = zoneService;
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
        LocalDate start = from != null ? from : today.withDayOfMonth(1);
        LocalDate end = to != null ? to : today;

        // 거꾸로 넣었으면 바로잡고 알린다. 말없이 빈 보고서를 내면 "이 구역은
        // 깨끗하다" 로 읽힌다.
        boolean swapped = end.isBefore(start);
        if (swapped) {
            LocalDate t = start;
            start = end;
            end = t;
        }

        model.addAttribute("report", reports.build(zone, start, end));
        model.addAttribute("zones", zoneService.all());
        model.addAttribute("selectedZone", zone);
        model.addAttribute("from", start);
        model.addAttribute("to", end);
        // 기간 넷은 날짜로 넘기지 않는다 — 화면은 아래에서 만드는
        // `thisMonthLink` 같은 **주소**를 쓴다. 날짜와 주소를 둘 다 넘기면
        // 기간을 고칠 때 한쪽만 고치는 날이 온다.
        model.addAttribute("today", today);

        // 기간 단추의 주소를 자바에서 만든다. `@{/reports/zone(zone=${zone}, …)}`
        // 는 값이 없어도 이름을 적어서, 구역을 안 고른 전체 범위에서 `zone=`
        // 이 빈 값으로 붙었다 — 그 주소가 결재 문서에 붙는다(N12).
        VulnQuery.Links period = new VulnQuery.Links("/reports/zone", null)
                .with("zone", zone);
        model.addAttribute("thisMonthLink",
                period.copy().with("from", today.withDayOfMonth(1)).with("to", today).here());
        model.addAttribute("lastMonthLink",
                period.copy().with("from", today.minusMonths(1).withDayOfMonth(1))
                      .with("to", today.withDayOfMonth(1).minusDays(1)).here());
        model.addAttribute("quarterLink",
                period.copy().with("from", today.minusMonths(2).withDayOfMonth(1))
                      .with("to", today).here());
        if (swapped) {
            model.addAttribute("message", "시작일이 종료일보다 늦어 두 날짜를 바꿨습니다.");
        }
        return "zone-report";
    }
}
