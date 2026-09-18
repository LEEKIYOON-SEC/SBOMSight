package kr.sbomsight.web;

import jakarta.servlet.http.HttpServletResponse;
import kr.sbomsight.domain.Finding;
import kr.sbomsight.repo.FindingRepository;
import kr.sbomsight.service.CsvWriter;
import kr.sbomsight.service.VulnQuery;
import kr.sbomsight.service.ZoneService;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.time.LocalDate;
import java.util.List;

import static org.springframework.http.HttpStatus.NOT_FOUND;

/**
 * 취약점 — 한 화면.
 *
 * <p><b>왜 합치는가.</b> 앞서는 같은 질의를 두 화면이 나눠 가지고 있었다.
 * 전사 조회는 <b>검색어를 넣어야만</b> 답했고, {@code /scans/{id}} 는 검사
 * 하나만 봤다. 그래서 "우리 전체에 심각이 몇 건인가" 를 물을 자리가 없었다.
 *
 * <pre>
 *   /vulns              전체 — 각 자산의 최신 완료 검사
 *   /vulns?zone=3       한 구역
 *   /vulns?scan=12      검사 하나 (검사 이력의 '열기')
 * </pre>
 *
 * <p><b>한 자산짜리 범위는 여기 없다.</b> {@code ?asset=} 은 자산 상세의
 * 취약점 탭으로 넘긴다 — 한 자산 이야기는 그 자산 안에서 끝난다.
 *
 * <p>묶어 보는 방식은 셋이다. 같은 데이터를 다르게 세는 것이지 다른 화면이 아니다.
 *
 * <ul>
 *   <li><b>항목별</b> — 탐지 한 건이 한 줄. 손에 잡히는 단위.</li>
 *   <li><b>CVE별</b> — "이 취약점이 몇 대에 있나". 긴급 상황의 첫 질문.</li>
 *   <li><b>패키지별</b> — "무엇을 올리면 몇 건이 사라지나". 실무자가 실제로
 *       실행하는 단위.</li>
 * </ul>
 */
@Controller
@RequestMapping("/vulns")
public class VulnController {

    private final FindingRepository findings;
    private final ZoneService zones;
    private final VulnQuery query;

    public VulnController(FindingRepository findings, ZoneService zones, VulnQuery query) {
        this.findings = findings;
        this.zones = zones;
        this.query = query;
    }

    @GetMapping
    public String index(@RequestParam(required = false) Long zone,
                        @RequestParam(required = false) Long scan,
                        @RequestParam(required = false) Long asset,
                        @RequestParam(defaultValue = "item") String group,
                        @RequestParam(required = false) String q,
                        @RequestParam(required = false) String severity,
                        @RequestParam(required = false) Boolean fixable,
                        @RequestParam(required = false) Boolean kev,
                        @RequestParam(defaultValue = "0") int page,
                        @RequestParam(required = false) Integer size,
                        @RequestParam(required = false) Integer jump,
                        @RequestParam(defaultValue = "severity") String sort,
                        @RequestParam(defaultValue = "desc") String dir,
                        Model model) {
        // 한 자산 이야기는 그 자산 안에서 끝난다.
        if (asset != null) {
            return "redirect:/assets/" + asset + "?tab=vulns";
        }

        // 화면 안의 모든 링크는 여기서 나온다. 고르지 않은 것과 **기본값은
        // 주소에 안 붙는다** — `sort=severity&dir=desc&size=100` 은 고른 것이
        // 아니라 아직 아무것도 고르지 않은 상태다.
        VulnQuery.Links links = new VulnQuery.Links("/vulns", null)
                .with("zone", zone).with("scan", scan).with("group", group)
                .with("q", q).with("severity", severity)
                .with("fixable", fixable).with("kev", kev)
                .with("size", VulnQuery.sizeOf(size) == VulnQuery.PAGE_SIZE
                              ? null : VulnQuery.sizeOf(size))
                .with("sort", "severity".equals(sort) ? null : sort)
                .with("dir", "desc".equals(dir) ? null : dir);

        // 페이지 이동. **사람이 적는 값은 1부터**이고 주소의 `page` 는 0부터
        // 센다(스프링의 셈). 같은 이름으로 받으면 한 칸 어긋난 페이지로 가므로
        // 다른 이름으로 받아 여기서 환산하고, 주소에는 남기지 않는다 —
        // 남기면 거르개를 바꿀 때마다 따라다니며 엉뚱한 페이지로 튄다.
        if (jump != null && jump > 0) {
            return "redirect:" + links.page(jump - 1);
        }

        VulnQuery.Scope scope = scan != null ? query.ofScan(scan) : query.ofZone(zone);
        model.addAttribute("scope", scope);
        model.addAttribute("zones", zones.all());
        model.addAttribute("selectedZone", zone);
        model.addAttribute("selectedScan", scan);
        model.addAttribute("group", group);
        model.addAttribute("q", q);
        model.addAttribute("severity", severity);
        model.addAttribute("fixable", fixable);
        model.addAttribute("kev", kev);
        model.addAttribute("sort", sort);
        model.addAttribute("dir", dir);
        model.addAttribute("links", links);

        query.fill(model, scope, group, q, severity, fixable, kev, page, size, sort, dir);
        return "vulns";
    }

    /** CVE 하나 — 어디에 있고 무엇이 걸려 있나. 앞서는 CVE 를 눌러도 갈 곳이 없었다. */
    @GetMapping("/{cve}")
    public String detail(@PathVariable String cve,
                         @RequestParam(required = false) Long zone,
                         Model model) {
        VulnQuery.Scope scope = query.ofZone(zone);
        List<Finding> rows = scope.scanIds().isEmpty()
                ? List.of() : findings.findByCveIn(scope.scanIds(), cve);
        if (rows.isEmpty()) {
            throw new ResponseStatusException(NOT_FOUND, cve + " 로 걸리는 탐지가 없습니다.");
        }

        model.addAttribute("cve", cve);
        model.addAttribute("rows", rows);
        // 대표로 한 건을 쓴다 — CVSS·벡터·심각도는 취약점의 속성이라 같다.
        model.addAttribute("first", rows.get(0));
        model.addAttribute("spread", findings.zoneSpread(scope.scanIds(), cve));
        model.addAttribute("assetCount",
                rows.stream().map(f -> f.getScan().getAsset().getId()).distinct().count());
        return "vuln-detail";
    }

    @GetMapping("/export.csv")
    public void export(@RequestParam(required = false) Long zone,
                       @RequestParam(required = false) Long scan,
                       @RequestParam(required = false) String q,
                       @RequestParam(required = false) String severity,
                       @RequestParam(required = false) Boolean fixable,
                       @RequestParam(required = false) Boolean kev,
                       HttpServletResponse response) throws IOException {
        VulnQuery.Scope scope = scan != null ? query.ofScan(scan) : query.ofZone(zone);
        // 내려받기는 한 페이지가 아니라 걸린 것 전부다. 화면에 100건만 보이는데
        // 파일도 100건이면 그 파일로 대조를 할 수 없다.
        List<Finding> rows = scope.scanIds().isEmpty() ? List.of()
                // 파일은 언제나 심각한 것부터다. 화면의 정렬 방향을 따라가지
                // 않는다 — 내려받은 파일이 어떤 순서였는지 나중에 알 수 없으면
                // 두 파일을 나란히 놓고 대조할 수 없다.
                : findings.findInBySeverity(scope.scanIds(), blank(q), blank(severity),
                                            fixable, kev, false, PageRequest.of(0, 100_000))
                          .getContent();

        response.setContentType("text/csv; charset=UTF-8");
        response.setHeader("Content-Disposition",
                "attachment; filename=\"vulns-" + LocalDate.now() + ".csv\"");
        CsvWriter.writeLookup(response.getOutputStream(), rows);
    }

    private String blank(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
