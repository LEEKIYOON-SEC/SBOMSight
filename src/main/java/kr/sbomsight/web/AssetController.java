package kr.sbomsight.web;

import jakarta.validation.Valid;
import kr.sbomsight.domain.*;
import kr.sbomsight.repo.*;
import jakarta.servlet.http.HttpServletResponse;
import kr.sbomsight.service.AssetService;
import kr.sbomsight.service.CsvWriter;
import kr.sbomsight.service.ScanService;
import kr.sbomsight.service.ZoneService;
import kr.sbomsight.service.AuditService;
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
    private final AssetService assetService;
    private final ZoneService zoneService;
    private final AuditService audit;

    public AssetController(AssetRepository assets, ScanRepository scans, FindingRepository findings,
                           RemediationRepository remediations, ScanService scanService,
                           AssetService assetService, ZoneService zoneService, AuditService audit) {
        this.assets = assets;
        this.scans = scans;
        this.findings = findings;
        this.remediations = remediations;
        this.scanService = scanService;
        this.assetService = assetService;
        this.zoneService = zoneService;
        this.audit = audit;
    }

    /** 자산 목록. 구역별로 묶어 "어느 구역의 어느 서버부터 볼 것인가"에 답한다. */
    @GetMapping
    public String index(@RequestParam(required = false) Long zone, Model model) {
        List<Asset> list = assets.findLiveWithZone();

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

        // 구역 순서는 구역 목록이 정한다. 자산이 한 대도 없는 구역도 보여
        // 준다 — 없는 것처럼 보이면 "왜 안 보이지" 부터 물어야 한다.
        List<ZoneGroup> groups = zoneService.all().stream()
                .filter(z -> zone == null || z.getId().equals(zone))
                .map(z -> new ZoneGroup(z, rows.stream()
                        .filter(r -> r.asset().getZone().getId().equals(z.getId()))
                        .toList()))
                .toList();

        model.addAttribute("groups", groups);
        model.addAttribute("zones", zoneService.all());
        model.addAttribute("selectedZone", zone);
        model.addAttribute("assetCount", rows.size());
        model.addAttribute("newAsset", new Asset());
        model.addAttribute("overdue", remediations.findOverdue(java.time.LocalDate.now()));
        return "assets";
    }

    @PostMapping("assets")
    @PreAuthorize("hasRole('ADMIN')")
    public String create(@Valid @ModelAttribute("newAsset") Asset asset,
                         BindingResult binding,
                         @RequestParam(required = false) Long zoneId,
                         RedirectAttributes flash) {
        if (assets.existsByName(asset.getName())) {
            binding.rejectValue("name", "duplicate", "같은 이름의 자산이 이미 있습니다.");
        }
        if (binding.hasErrors()) {
            flash.addFlashAttribute("error", binding.getAllErrors().get(0).getDefaultMessage());
            return "redirect:/";
        }
        // 구역을 고르지 않았으면 미분류로. 어디에도 속하지 않는 자산은 만들지 않는다.
        asset.setZone(zoneId == null ? zoneService.unassigned() : zoneService.require(zoneId));
        assets.save(asset);
        audit.record(AuditEvent.ASSET_CREATED, asset.getName(),
                     "구역 " + asset.getZone().getName());
        flash.addFlashAttribute("message", asset.getName() + " 자산을 등록했습니다.");
        return "redirect:/assets/" + asset.getId();
    }

    /** 자산을 다른 구역으로 옮긴다. */
    @PostMapping("assets/{id}/zone")
    @PreAuthorize("hasRole('ADMIN')")
    public String moveZone(@PathVariable Long id, @RequestParam Long zoneId,
                           RedirectAttributes flash) {
        Asset asset = asset(id);
        Zone target = zoneService.require(zoneId);
        String before = asset.getZone().getName();
        asset.setZone(target);
        assets.save(asset);
        audit.record(AuditEvent.ASSET_ZONE_CHANGED, asset.getName(),
                     before + " → " + target.getName());
        flash.addFlashAttribute("message", asset.getName() + " 을 " + target.getName() + " 으로 옮겼습니다.");
        return "redirect:/assets/" + id;
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
        model.addAttribute("zones", zoneService.all());
        model.addAttribute("history", history);
        model.addAttribute("latest", latest);
        model.addAttribute("severity", latest == null ? Map.of() : severityMap(latest.getId()));
        model.addAttribute("remediations",
                remediations.findByAssetIdOrderByStatusAscPackageNameAsc(id));
        // 지우면 무엇이 함께 사라지는지 확인 문구에 그대로 쓴다.
        model.addAttribute("impact", assetService.impactOf(asset));
        return "asset-detail";
    }

    /**
     * 자산을 지운다. <b>스캔·탐지·조치와 보관 파일까지 함께 사라진다.</b>
     *
     * <p>화면에서 무엇이 지워지는지 숫자로 보여 주고 확인을 받는다. "정말
     * 지울까요?" 만으로는 그 안에 스캔 이력이 얼마나 쌓여 있었는지 모른다.
     */
    @PostMapping("assets/{id}/delete")
    @PreAuthorize("hasRole('ADMIN')")
    public String delete(@PathVariable Long id, @RequestParam String confirm,
                         Principal principal, RedirectAttributes flash) {
        Asset asset = asset(id);
        if (!asset.getName().equals(confirm)) {
            flash.addFlashAttribute("error",
                    "확인란에 자산 이름(" + asset.getName() + ")을 정확히 입력해야 지워집니다.");
            return "redirect:/assets/" + id;
        }
        String name = asset.getName();
        String zoneName = asset.getZone().getName();
        AssetService.Impact impact = assetService.delete(asset, principal.getName());
        audit.record(AuditEvent.ASSET_DELETED, name,
                     "구역 " + zoneName + " · 스캔 " + impact.scanCount()
                     + "건 · 탐지 " + impact.findingCount()
                     + "건 · 조치 " + impact.remediationCount() + "건 함께 삭제");
        flash.addFlashAttribute("message",
                asset.getName() + " 자산을 지웠습니다 — 스캔 " + impact.scanCount() + "건 · 탐지 "
                + impact.findingCount() + "건 · 조치 " + impact.remediationCount()
                + "건과 보관된 SBOM·검사 결과가 함께 삭제되었습니다.");
        return "redirect:/";
    }

    /** 보관된 SBOM 을 갱신된 grype DB 로 다시 돌린다. */
    @PostMapping("scans/{scanId}/rescan")
    @PreAuthorize("hasRole('ADMIN')")
    public String rescan(@PathVariable Long scanId, Principal principal,
                         RedirectAttributes flash) {
        Scan source = scans.findWithAsset(scanId)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "스캔을 찾을 수 없습니다."));
        Long assetId = source.getAsset().getId();
        try {
            Scan copy = scanService.rescan(source, principal.getName());
            audit.record(AuditEvent.SCAN_RESCANNED, source.getAsset().getName(),
                         source.getSbomFilename() + " (원본 스캔 " + scanId + ")");
            scanService.runAsync(copy.getId());
            flash.addFlashAttribute("message",
                    "같은 SBOM 을 다시 검사합니다. 끝나면 아래 이력에 새 줄로 나타납니다.");
        } catch (Exception e) {
            log.error("재검사 실패 scan={}", scanId, e);
            flash.addFlashAttribute("error", "다시 검사하지 못했습니다: " + e.getMessage());
        }
        return "redirect:/assets/" + assetId;
    }

    @PostMapping("scans/{scanId}/delete")
    @PreAuthorize("hasRole('ADMIN')")
    public String deleteScan(@PathVariable Long scanId, RedirectAttributes flash) {
        Scan scan = scans.findWithAsset(scanId)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "스캔을 찾을 수 없습니다."));
        Long assetId = scan.getAsset().getId();
        String detail = scan.getSbomFilename() + " · 탐지 " + scan.getFindingCount() + "건";
        String assetName = scan.getAsset().getName();
        scanService.delete(scan);
        audit.record(AuditEvent.SCAN_DELETED, assetName, detail);
        flash.addFlashAttribute("message", "스캔을 지웠습니다. 보관된 파일도 함께 삭제되었습니다.");
        return "redirect:/assets/" + assetId;
    }

    /**
     * 지금 화면의 필터가 그대로 적용된 결과를 CSV 로.
     *
     * <p>화면에서 걸러 놓고 내려받으면 전체가 나오는 것이 가장 흔한 불만이다.
     * 같은 조건을 같은 질의에 넘긴다.
     */
    @GetMapping("scans/{scanId}/export.csv")
    public void exportFindings(@PathVariable Long scanId,
                               @RequestParam(required = false) String severity,
                               @RequestParam(required = false) Boolean fixable,
                               @RequestParam(required = false) Boolean kev,
                               @RequestParam(required = false) String q,
                               @RequestParam(defaultValue = "cvss") String sort,
                               HttpServletResponse response) throws java.io.IOException {
        Scan scan = scans.findWithAsset(scanId)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "스캔을 찾을 수 없습니다."));

        // 내려받기는 화면과 달리 전부 담는다. 5만 건이면 파일이 크지만, 잘린
        // 파일로 결재를 올리는 것보다 낫다.
        List<Finding> all = findings.search(scanId, blankToNull(severity), fixable, kev,
                                            blankToNull(q),
                                            PageRequest.of(0, 200_000, order(sort))).getContent();

        String name = scan.getAsset().getName() + "-"
                + scan.getCreatedAt().atZone(java.time.ZoneId.systemDefault())
                      .format(java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd-HHmm"))
                + ".csv";
        response.setContentType("text/csv; charset=UTF-8");
        response.setHeader("Content-Disposition",
                "attachment; filename*=UTF-8''" + java.net.URLEncoder.encode(
                        name, java.nio.charset.StandardCharsets.UTF_8));
        CsvWriter.writeFindings(response.getOutputStream(), all);
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
            audit.record(AuditEvent.SBOM_UPLOADED, asset.getName(),
                         file.getOriginalFilename() + " · " + file.getSize() + "바이트");
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
        Scan scan = scans.findWithAsset(scanId)
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
        // 구역을 함께 가져온다. open-in-view 가 꺼져 있어 화면에서 asset.zone
        // 을 읽는 순간 세션이 없으면 LazyInitializationException 이 난다.
        return assets.findWithZone(id)
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

    /** 구역 하나와 그 안의 자산들. 머리줄에 쓸 합계를 함께 낸다. */
    public record ZoneGroup(Zone zone, List<AssetRow> rows) {

        public int serverCount() {
            return rows.size();
        }

        public long findingCount() {
            return rows.stream().filter(AssetRow::hasScan)
                       .mapToLong(r -> r.latest().getFindingCount()).sum();
        }

        public long severityCount(String key) {
            return rows.stream().mapToLong(r -> r.severityCount(key)).sum();
        }

        public long openRemediations() {
            return rows.stream().mapToLong(AssetRow::openRemediations).sum();
        }

        public boolean isEmpty() {
            return rows.isEmpty();
        }
    }
}
