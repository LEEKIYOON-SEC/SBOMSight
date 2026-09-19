package kr.sbomsight.web;

import jakarta.servlet.http.HttpServletResponse;
import kr.sbomsight.repo.ComponentRepository;
import kr.sbomsight.service.CsvWriter;
import kr.sbomsight.service.PackageService;
import kr.sbomsight.service.VulnQuery;
import kr.sbomsight.service.ZoneService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.List;

/**
 * 패키지 — 무엇이 어디에 몇 버전으로 깔려 있나.
 *
 * <p>취약점 화면은 grype 이 매치를 낸 것만 답한다. 이 화면은 <b>SBOM 이 담아
 * 온 것 전부</b>를 답한다 — 취약점이 하나도 없는 패키지도 여기 있다.
 *
 * <p><b>빈 것과 안 본 것을 구분해서 말한다.</b> V13 은 이미 쌓인 SBOM 을
 * 되읽지 않으므로, 다시 검사하기 전에는 인벤토리가 비어 있다. 그 상태를
 * "패키지가 없습니다" 라고 말하면 거짓이다.
 */
@Controller
public class PackageController {

    private static final ZoneId SEOUL = ZoneId.of("Asia/Seoul");

    private final PackageService packages;
    private final ComponentRepository components;
    private final ZoneService zoneService;

    public PackageController(PackageService packages, ComponentRepository components,
                             ZoneService zoneService) {
        this.packages = packages;
        this.components = components;
        this.zoneService = zoneService;
    }

    /**
     * 거르개는 <b>고르개</b>라 빈 값(`전체`)이 온다 — 그래서 {@code boolean}
     * 이 아니라 {@code Boolean} 으로 받는다. 원시형으로 받으면 빈 문자열이
     * 오는 순간 400 이 되고, 사람은 `전체` 를 골랐을 뿐인데 화면이 죽는다.
     *
     * <p><b>{@code name} 을 못 박는다.</b> 이름을 안 적으면 스프링이 자바
     * 매개변수 이름을 그대로 주소의 이름으로 쓴다 — 여기서 이름을 바꾸는
     * 순간 {@code ?mixed=true} 가 아무 데도 안 붙고, 거르개가 조용히 꺼진다.
     * 시험이 잡았다.
     */
    @GetMapping("/packages")
    public String list(@RequestParam(required = false) Long zone,
                       @RequestParam(required = false) String type,
                       @RequestParam(required = false) String q,
                       @RequestParam(name = "vulnerable", required = false) Boolean vulnerableParam,
                       @RequestParam(name = "mixed", required = false) Boolean mixedParam,
                       @RequestParam(required = false) String open,
                       Model model) {
        boolean vulnerable = Boolean.TRUE.equals(vulnerableParam);
        boolean mixed = Boolean.TRUE.equals(mixedParam);

        PackageService.Listing listing = packages.list(zone, type, q, vulnerable, mixed);

        model.addAttribute("listing", listing);
        model.addAttribute("zones", zoneService.all());
        model.addAttribute("selectedZone", zone);
        model.addAttribute("type", type);
        model.addAttribute("q", q);
        model.addAttribute("vulnerable", vulnerable);
        model.addAttribute("mixed", mixed);

        // 화면 안의 링크를 자바에서 만든다. 타임리프의 `@{/packages(zone=…)}`
        // 는 값이 없어도 이름을 적어서, 아무것도 고르지 않은 화면의 링크가
        // `?zone=&type=&q=&vulnerable=false&mixed=false` 가 된다. 동작은
        // 하지만 그 주소가 결재 문서에 붙고 옆자리에 전달된다.
        //
        // 거짓말이 되는 자리도 있다 — `vulnerable=false` 는 안 고른 것이
        // 아니라 **끄기로 골랐다**고 읽힌다.
        model.addAttribute("links", filters(new VulnQuery.Links("/packages", null),
                                            zone, type, q, vulnerable, mixed));
        model.addAttribute("csv", filters(new VulnQuery.Links("/packages/export.csv", null),
                                          zone, type, q, vulnerable, mixed));
        // 그 패키지의 취약점으로 — 구역은 이어 간다.
        model.addAttribute("vulnLinks", new VulnQuery.Links("/vulns", null).with("zone", zone));

        // 펼친 줄. 주소에 남는다 — 새로고침하면 접히는 화면은 공유할 수 없다.
        model.addAttribute("open", open);
        if (open != null && !open.isBlank()) {
            model.addAttribute("openRows", packages.assetsOf(open, zone));
        }

        // 인벤토리 자체가 비어 있는가. "거르개에 걸리는 것이 없다" 와
        // "아직 아무 자산도 다시 검사하지 않았다" 는 다른 말이다.
        model.addAttribute("inventoryEmpty", components.count() == 0);
        return "packages";
    }

    /** 지금 고른 거르개를 링크에 얹는다. 켠 것만 적는다 — 끈 것은 안 적는다. */
    private static VulnQuery.Links filters(VulnQuery.Links links, Long zone, String type,
                                           String q, boolean vulnerable, boolean mixed) {
        return links.with("zone", zone)
                    .with("type", type)
                    .with("q", q)
                    .with("vulnerable", vulnerable ? "true" : null)
                    .with("mixed", mixed ? "true" : null);
    }

    /**
     * CSV 내려받기 — 결재와 공유는 엑셀로 돈다.
     *
     * <p><b>화면의 200개 상한을 따르지 않는다.</b> 화면은 앞 200개만 싣지만,
     * 잘린 파일은 그것이 잘렸다는 사실을 들고 다니지 않는다 — 거른 것 전부를
     * 낸다. 거르개는 그대로 따른다: 보고 있던 것과 다른 파일이 떨어지면
     * 어느 쪽이 맞는지 물어볼 자리가 없다.
     */
    @GetMapping("/packages/export.csv")
    public void export(@RequestParam(required = false) Long zone,
                       @RequestParam(required = false) String type,
                       @RequestParam(required = false) String q,
                       @RequestParam(name = "vulnerable", required = false) Boolean vulnerableParam,
                       @RequestParam(name = "mixed", required = false) Boolean mixedParam,
                       HttpServletResponse response) throws IOException {
        // 화면과 같은 거르개를 그대로 받는다 — 빈 값(`전체`)이 오므로 Boolean.
        List<PackageService.ExportRow> rows = packages.export(
                zone, type, q, Boolean.TRUE.equals(vulnerableParam),
                Boolean.TRUE.equals(mixedParam));

        response.setContentType("text/csv; charset=UTF-8");
        response.setHeader("Content-Disposition",
                "attachment; filename=\"packages-" + LocalDate.now(SEOUL) + ".csv\"");
        CsvWriter.writePackages(response.getOutputStream(), rows);
    }
}
