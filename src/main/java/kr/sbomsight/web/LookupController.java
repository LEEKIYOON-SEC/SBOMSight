package kr.sbomsight.web;

import jakarta.servlet.http.HttpServletResponse;
import kr.sbomsight.domain.Finding;
import kr.sbomsight.repo.FindingRepository;
import kr.sbomsight.service.CsvWriter;
import kr.sbomsight.service.ZoneService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;
import java.time.LocalDate;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 전사 조회 — "이 취약점이 어느 서버에 있나".
 *
 * <p>보안팀이 긴급 상황에서 가장 먼저 하는 일이다. 지금까지는 자산을 하나씩
 * 열어 봐야 답이 나왔다.
 *
 * <p><b>각 자산의 최신 완료 스캔만 본다.</b> 이력 전체를 훑으면 이미 조치가
 * 끝난 옛 스캔이 섞여 나와 "아직 있다" 고 말하게 된다 — 그 답을 믿고 서버에
 * 들어가면 없다.
 */
@Controller
@RequestMapping("/lookup")
public class LookupController {

    private static final int PAGE_SIZE = 200;

    private final FindingRepository findings;
    private final ZoneService zones;

    public LookupController(FindingRepository findings, ZoneService zones) {
        this.findings = findings;
        this.zones = zones;
    }

    @GetMapping
    public String index(@RequestParam(required = false) String q,
                        @RequestParam(required = false) Long zone,
                        @RequestParam(required = false) String severity,
                        @RequestParam(required = false) Boolean fixable,
                        @RequestParam(defaultValue = "0") int page,
                        Model model) {
        String term = blankToNull(q);

        model.addAttribute("q", q);
        model.addAttribute("zones", zones.all());
        model.addAttribute("selectedZone", zone);
        model.addAttribute("severity", severity);
        model.addAttribute("fixable", fixable);

        // 검색어가 없으면 아무것도 찾지 않는다. 전체를 쏟아 내면 그 화면은
        // 조회가 아니라 그냥 큰 표다.
        if (term == null) {
            model.addAttribute("searched", false);
            return "lookup";
        }

        Page<Finding> result = findings.lookup(term, zone, blankToNull(severity), fixable,
                                               PageRequest.of(Math.max(page, 0), PAGE_SIZE));

        model.addAttribute("searched", true);
        model.addAttribute("page", result);
        model.addAttribute("byZone", countByZone(result.getContent()));
        model.addAttribute("assetCount", result.getContent().stream()
                .map(f -> f.getScan().getAsset().getId()).distinct().count());
        return "lookup";
    }

    @GetMapping("export.csv")
    public void export(@RequestParam String q,
                       @RequestParam(required = false) Long zone,
                       @RequestParam(required = false) String severity,
                       @RequestParam(required = false) Boolean fixable,
                       HttpServletResponse response) throws IOException {
        // 내려받기는 한 페이지가 아니라 걸린 것 전부다. 화면에 200건만 보이는데
        // 파일도 200건이면 그 파일로 대조를 할 수 없다.
        List<Finding> rows = findings.lookup(q, zone, blankToNull(severity), fixable,
                                             PageRequest.of(0, 100_000)).getContent();

        response.setContentType("text/csv; charset=UTF-8");
        response.setHeader("Content-Disposition",
                "attachment; filename=\"lookup-" + LocalDate.now() + ".csv\"");
        CsvWriter.writeLookup(response.getOutputStream(), rows);
    }

    /**
     * 구역별 몇 대인가.
     *
     * <p>이 한 줄이 "어디까지 번졌나" 에 답한다. DMZ 에 두 대면 성격이
     * 다르고, 개발망에만 있으면 또 다르다.
     */
    private Map<String, Long> countByZone(List<Finding> rows) {
        Map<String, java.util.Set<Long>> assetsPerZone = new LinkedHashMap<>();
        for (Finding f : rows) {
            var asset = f.getScan().getAsset();
            assetsPerZone.computeIfAbsent(asset.getZone().getName(), k -> new java.util.HashSet<>())
                         .add(asset.getId());
        }
        Map<String, Long> counts = new LinkedHashMap<>();
        assetsPerZone.forEach((name, ids) -> counts.put(name, (long) ids.size()));
        return counts;
    }

    private String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
