package kr.sbomsight.web;

import kr.sbomsight.domain.Asset;
import kr.sbomsight.domain.Scan;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.ScanRepository;
import kr.sbomsight.service.Paging;
import kr.sbomsight.service.VulnQuery;
import kr.sbomsight.service.ZoneService;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

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

    /**
     * 목록 한 줄 — 자산 하나.
     *
     * <p>검사된 자산과 <b>한 번도 검사되지 않은 자산</b>을 한 목록에 담는다.
     * 앞서는 표 하나에 반복을 두 벌 두었는데, 쪽으로 나누려면 두 목록이
     * 한 줄씩 번갈아 세어져야 한다. 검사가 없는 자산을 빼지는 않는다 —
     * 빠지면 "안 본 것" 과 "문제가 없는 것" 을 구분할 수 없다.
     *
     * @param scan 완료된 검사가 없으면 {@code null}
     */
    public record ReportRow(Asset asset, Scan scan) {

        public boolean scanned() {
            return scan != null;
        }
    }

    @GetMapping("/reports")
    @Transactional(readOnly = true)
    public String reports(@RequestParam(defaultValue = "0") int page,
                          @RequestParam(required = false) Integer size,
                          @RequestParam(required = false) Integer jump,
                          Model model) {
        VulnQuery.Links links = new VulnQuery.Links("/reports", null).size(size);
        String jumped = Paging.jump(links, jump);
        if (jumped != null) {
            return jumped;
        }

        List<Scan> latest = scans.findLatestDonePerAssetWithAsset();

        Set<Long> scanned = latest.stream()
                .map(s -> s.getAsset().getId())
                .collect(Collectors.toSet());
        List<Asset> neverScanned = assets.findLiveWithZone().stream()
                .filter(a -> !scanned.contains(a.getId()))
                .toList();

        // 검사된 것이 먼저, 안 된 것이 뒤. 순서를 섞으면 첫 쪽에서 무엇을
        // 뽑을 수 있는지 한눈에 안 들어온다.
        List<ReportRow> rows = new java.util.ArrayList<>(
                latest.stream().map(s -> new ReportRow(s.getAsset(), s)).toList());
        neverScanned.forEach(a -> rows.add(new ReportRow(a, null)));

        LocalDate today = LocalDate.now();

        model.addAttribute("links", links);
        // 화면은 `rows` 하나만 본다. `latest`·`neverScanned` 는 그것을
        // 만드는 재료라 여기서 끝난다.
        model.addAttribute("rows", Paging.slice(rows, page, size));
        model.addAttribute("zones", zoneService.all());
        model.addAttribute("today", today);
        model.addAttribute("thisMonth", today.withDayOfMonth(1));
        model.addAttribute("lastMonthFrom", today.minusMonths(1).withDayOfMonth(1));
        model.addAttribute("lastMonthTo", today.withDayOfMonth(1).minusDays(1));
        model.addAttribute("quarterFrom", today.minusMonths(2).withDayOfMonth(1));
        return "reports";
    }
}
