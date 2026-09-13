package kr.sbomsight.web;

import kr.sbomsight.domain.Asset;
import kr.sbomsight.domain.Scan;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.ScanRepository;
import kr.sbomsight.service.ZoneService;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.time.LocalDate;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 보고서 고르기 — 무엇을 뽑을지 여기서 고른다.
 *
 * <p>앞서 기둥의 <b>보고서</b> 가 곧바로 구역 보고서로 갔다. 자산 한 대짜리
 * 보고서는 자산 상세까지 들어가야 있었고, 두 가지가 한 이름 아래 있다는 것을
 * 화면 어디에서도 알 수 없었다.
 *
 * <p>이 화면은 <b>뽑는 자리</b>다. 보고서 자체는
 * {@code /reports/scan/{scanId}} 와 {@code /reports/zone} 이 그린다.
 *
 * <p>검사가 없는 자산도 목록에 남긴다. 빠지면 "안 본 것" 과 "문제가 없는 것"
 * 을 구분할 수 없다 — 이 도구에서 반복해 지키는 규칙이다.
 */
@Controller
public class ReportsController {

    private final ScanRepository scans;
    private final AssetRepository assets;
    private final ZoneService zoneService;

    public ReportsController(ScanRepository scans, AssetRepository assets, ZoneService zoneService) {
        this.scans = scans;
        this.assets = assets;
        this.zoneService = zoneService;
    }

    @GetMapping("/reports")
    @Transactional(readOnly = true)
    public String reports(Model model) {
        List<Scan> latest = scans.findLatestDonePerAssetWithAsset();

        Set<Long> scanned = latest.stream()
                .map(s -> s.getAsset().getId())
                .collect(Collectors.toSet());
        List<Asset> neverScanned = assets.findLiveWithZone().stream()
                .filter(a -> !scanned.contains(a.getId()))
                .toList();

        LocalDate today = LocalDate.now();

        model.addAttribute("latest", latest);
        model.addAttribute("neverScanned", neverScanned);
        model.addAttribute("zones", zoneService.all());
        model.addAttribute("today", today);
        model.addAttribute("thisMonth", today.withDayOfMonth(1));
        model.addAttribute("lastMonthFrom", today.minusMonths(1).withDayOfMonth(1));
        model.addAttribute("lastMonthTo", today.withDayOfMonth(1).minusDays(1));
        model.addAttribute("quarterFrom", today.minusMonths(2).withDayOfMonth(1));
        return "reports";
    }
}
