package kr.sbomsight.web;

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
 */
@Controller
public class ZoneReportController {

    private final ZoneReportService reports;
    private final ZoneService zoneService;

    public ZoneReportController(ZoneReportService reports, ZoneService zoneService) {
        this.reports = reports;
        this.zoneService = zoneService;
    }

    @GetMapping("/report/zone")
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
        model.addAttribute("thisMonth", today.withDayOfMonth(1));
        model.addAttribute("lastMonthFrom", today.minusMonths(1).withDayOfMonth(1));
        model.addAttribute("lastMonthTo", today.withDayOfMonth(1).minusDays(1));
        model.addAttribute("quarterFrom", today.minusMonths(2).withDayOfMonth(1));
        model.addAttribute("today", today);
        if (swapped) {
            model.addAttribute("message", "시작일이 종료일보다 늦어 두 날짜를 바꿨습니다.");
        }
        return "zone-report";
    }
}
