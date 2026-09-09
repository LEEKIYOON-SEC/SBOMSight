package kr.sbomsight.web;

import jakarta.validation.Valid;
import kr.sbomsight.domain.*;
import kr.sbomsight.repo.*;
import kr.sbomsight.service.ScanService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;

import static org.springframework.http.HttpStatus.NOT_FOUND;

/** 자산 목록·상세, SBOM 업로드, 취약점 목록. */
@Controller
@RequestMapping("/")
public class AssetController {

    private static final Logger log = LoggerFactory.getLogger(AssetController.class);

    private final AssetRepository assets;
    private final ScanRepository scans;
    private final FindingRepository findings;
    private final RemediationRepository remediations;
    private final ScanService scanService;

    public AssetController(AssetRepository assets, ScanRepository scans, FindingRepository findings,
                           RemediationRepository remediations, ScanService scanService) {
        this.assets = assets;
        this.scans = scans;
        this.findings = findings;
        this.remediations = remediations;
        this.scanService = scanService;
    }

    /** 자산 목록. 한 화면에서 "어느 서버부터 볼 것인가"에 답해야 한다. */
    @GetMapping
    public String index(Model model) {
        List<Asset> list = assets.findByArchivedAtIsNullOrderByGroupNameAscNameAsc();

        // 자산마다 질의하면 자산 수만큼 왕복한다. 한 번에 가져와 맞춘다.
        Map<Long, Scan> latest = scans.findLatestDonePerAsset().stream()
                .collect(Collectors.toMap(s -> s.getAsset().getId(), s -> s, (a, b) -> a));

        List<AssetRow> rows = list.stream().map(asset -> {
            Scan scan = latest.get(asset.getId());
            Map<String, Long> severity = scan == null ? Map.of() : severityMap(scan.getId());
            long open = remediations.countByAssetIdAndStatusIn(
                    asset.getId(), List.of(RemediationStatus.OPEN, RemediationStatus.IN_PROGRESS));
            return new AssetRow(asset, scan, severity, open);
        }).toList();

        model.addAttribute("rows", rows);
        model.addAttribute("newAsset", new Asset());
        model.addAttribute("overdue", remediations.findOverdue(java.time.LocalDate.now()));
        return "assets";
    }

    @PostMapping("assets")
    @PreAuthorize("hasRole('ADMIN')")
    public String create(@Valid @ModelAttribute("newAsset") Asset asset,
                         BindingResult binding, RedirectAttributes flash) {
        if (assets.existsByName(asset.getName())) {
            binding.rejectValue("name", "duplicate", "같은 이름의 자산이 이미 있습니다.");
        }
        if (binding.hasErrors()) {
            flash.addFlashAttribute("error", binding.getAllErrors().get(0).getDefaultMessage());
            return "redirect:/";
        }
        assets.save(asset);
        flash.addFlashAttribute("message", asset.getName() + " 자산을 등록했습니다.");
        return "redirect:/assets/" + asset.getId();
    }

    /** 자산 상세 — 스캔 이력과 조치가 한 화면에 있다. */
    @GetMapping("assets/{id}")
    public String detail(@PathVariable Long id, Model model) {
        Asset asset = asset(id);
        List<Scan> history = scans.findByAssetIdOrderByCreatedAtDesc(id);
        Scan latest = history.stream()
                .filter(s -> s.getStatus() == ScanStatus.DONE)
                .findFirst().orElse(null);

        model.addAttribute("asset", asset);
        model.addAttribute("history", history);
        model.addAttribute("latest", latest);
        model.addAttribute("severity", latest == null ? Map.of() : severityMap(latest.getId()));
        model.addAttribute("remediations",
                remediations.findByAssetIdOrderByStatusAscPackageNameAsc(id));
        return "asset-detail";
    }

    /** SBOM 업로드. 저장까지만 하고 grype 은 뒤에서 돌린다. */
    @PostMapping("assets/{id}/sbom")
    @PreAuthorize("hasRole('ADMIN')")
    public String upload(@PathVariable Long id, @RequestParam("file") MultipartFile file,
                         Principal principal, RedirectAttributes flash) {
        Asset asset = asset(id);
        if (file.isEmpty()) {
            flash.addFlashAttribute("error", "파일을 선택하세요.");
            return "redirect:/assets/" + id;
        }
        try {
            Scan scan = scanService.submit(asset, file, principal.getName());
            scanService.runAsync(scan.getId());
            flash.addFlashAttribute("message",
                    "SBOM 을 올렸습니다. grype 검사가 진행 중이며, 끝나면 이력에 나타납니다.");
        } catch (Exception e) {
            log.error("업로드 실패 asset={}", id, e);
            flash.addFlashAttribute("error", "업로드하지 못했습니다: " + e.getMessage());
        }
        return "redirect:/assets/" + id;
    }

    /** 취약점 목록. 정렬·필터·페이징은 전부 SQL 에서 끝난다. */
    @GetMapping("scans/{scanId}")
    public String scan(@PathVariable Long scanId,
                       @RequestParam(required = false) String severity,
                       @RequestParam(required = false) Boolean fixable,
                       @RequestParam(required = false) Boolean kev,
                       @RequestParam(required = false) String q,
                       @RequestParam(defaultValue = "0") int page,
                       @RequestParam(defaultValue = "cvss") String sort,
                       Model model) {
        Scan scan = scans.findById(scanId)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "스캔을 찾을 수 없습니다."));

        Page<Finding> result = findings.search(scanId, blankToNull(severity), fixable, kev,
                                               blankToNull(q), PageRequest.of(page, 100, order(sort)));

        model.addAttribute("scan", scan);
        model.addAttribute("page", result);
        model.addAttribute("severity", severity);
        model.addAttribute("fixable", fixable);
        model.addAttribute("kev", kev);
        model.addAttribute("q", q);
        model.addAttribute("sort", sort);
        model.addAttribute("severityCounts", severityMap(scanId));
        return "scan";
    }

    /**
     * 정렬 기준.
     *
     * <p>어느 축으로 정렬하든 <b>값이 없는 건은 항상 뒤로</b> 보낸다. CVSS 가
     * 없는 건을 0 점으로 줄 세우면 "안전하다"는, 아무도 내리지 않은 판정이 된다.
     */
    private Sort order(String sort) {
        return switch (sort) {
            case "epss" -> Sort.by(Sort.Order.desc("epss").nullsLast(),
                                   Sort.Order.desc("cvssScore").nullsLast());
            case "package" -> Sort.by(Sort.Order.asc("packageName"), Sort.Order.asc("cve"));
            case "cve" -> Sort.by(Sort.Order.asc("cve"));
            default -> Sort.by(Sort.Order.desc("cvssScore").nullsLast(),
                               Sort.Order.asc("packageName"));
        };
    }

    private Map<String, Long> severityMap(Long scanId) {
        Map<String, Long> counts = new LinkedHashMap<>();
        findings.countBySeverity(scanId)
                .forEach(row -> counts.put(row.getSeverity() == null ? "" : row.getSeverity(),
                                           row.getTotal()));
        return counts;
    }

    private Asset asset(Long id) {
        return assets.findById(id)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "자산을 찾을 수 없습니다."));
    }

    private String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    /** 목록 한 줄에 필요한 것 — 자산, 마지막 스캔, 심각도 분포, 열린 조치 수. */
    public record AssetRow(Asset asset, Scan latest, Map<String, Long> severity, long openRemediations) {

        public long severityCount(String key) {
            return severity.getOrDefault(key, 0L);
        }

        public boolean hasScan() {
            return latest != null;
        }
    }
}
