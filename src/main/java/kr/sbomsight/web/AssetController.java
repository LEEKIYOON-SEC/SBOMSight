package kr.sbomsight.web;

import jakarta.validation.Valid;
import kr.sbomsight.domain.*;
import kr.sbomsight.repo.*;
import jakarta.servlet.http.HttpServletResponse;
import kr.sbomsight.service.AssetService;
import kr.sbomsight.service.SbomStorage;
import kr.sbomsight.service.PackageService;
import kr.sbomsight.service.Paging;
import kr.sbomsight.service.VulnQuery;
import kr.sbomsight.service.ScanService;
import kr.sbomsight.service.ZoneService;
import kr.sbomsight.service.AuditService;
import kr.sbomsight.service.FindingAnalysisService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
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
    private final FindingAnalysisService analyses;
    private final SbomStorage storage;
    private final VulnQuery vulns;
    private final ComponentRepository components;
    private final PackageService packages;

    public AssetController(AssetRepository assets, ScanRepository scans, FindingRepository findings,
                           RemediationRepository remediations, ScanService scanService,
                           AssetService assetService, ZoneService zoneService, AuditService audit,
                           FindingAnalysisService analyses, SbomStorage storage,
                           VulnQuery vulns, ComponentRepository components,
                           PackageService packages) {
        this.assets = assets;
        this.scans = scans;
        this.findings = findings;
        this.remediations = remediations;
        this.scanService = scanService;
        this.assetService = assetService;
        this.zoneService = zoneService;
        this.audit = audit;
        this.analyses = analyses;
        this.storage = storage;
        this.vulns = vulns;
        this.components = components;
        this.packages = packages;
    }

    /** 마지막 검사가 이보다 오래되면 "오래됐다" 고 센다. */
    private static final int STALE_DAYS = 30;

    /**
     * 자산 상세의 탭 이름. <b>화면(`asset-detail.html`)의 `th:if` 와 같아야 한다.</b>
     *
     * <p>여기 없는 값이 오면 개요로 되돌린다 — 그러지 않으면 탭 줄만 있고
     * 본문이 빈 화면이 200 으로 뜬다.
     */
    private static final java.util.Set<String> TABS =
            java.util.Set.of("overview", "vulns", "packages", "history", "actions");

    /**
     * 자산 목록.
     *
     * <p>맨 위 한 줄이 "지금 무엇이 급한가" 에 답하고, 그 숫자를 누르면 그
     * 조건이 걸린 화면으로 간다. 카드 벽을 세우지 않는다 — 매일 보는 사람에게
     * 숫자 상자 여섯 개는 한 번 보고 지나치는 장식이 된다.
     *
     * @param zone     구역 거르개. 기둥에 있던 구역 목록이 여기로 내려왔다.
     * @param filter   {@code noscan} 검사 없는 것 · {@code stale} 오래된 것
     * @param view     {@code table} 표 · {@code zones} 구역 카드
     * @param archived 운영 종료한 자산도 함께 보는가
     */
    @GetMapping
    public String index(@RequestParam(required = false) Long zone,
                        @RequestParam(required = false) String filter,
                        @RequestParam(defaultValue = "table") String view,
                        @RequestParam(defaultValue = "name") String sort,
                        @RequestParam(defaultValue = "asc") String dir,
                        @RequestParam(defaultValue = "false") boolean archived,
                        @RequestParam(defaultValue = "0") int page,
                        @RequestParam(required = false) Integer size,
                        @RequestParam(required = false) Integer jump,
                        Model model) {
        List<Asset> list = archived ? assets.findAllWithZone() : assets.findLiveWithZone();

        // 자산마다 질의하면 자산 수만큼 왕복한다. 한 번에 가져와 맞춘다.
        Map<Long, Scan> latest = scans.findLatestDonePerAsset().stream()
                .collect(Collectors.toMap(s -> s.getAsset().getId(), s -> s, (a, b) -> a));

        // 실제 악용(KEV)은 최신 검사들에서 한 번에 센다 — 자산마다 물으면
        // 자산 수만큼 왕복한다. 심각도와 다른 축이라 따로 센다: 심각도가
        // `보통` 인데 실제로 악용되고 있는 건이 `심각` 100건보다 급하다.
        List<Long> latestIds = latest.values().stream().map(Scan::getId).toList();
        Map<Long, Long> kev = latestIds.isEmpty() ? Map.of()
                : findings.countKevPerAsset(latestIds).stream()
                          .collect(Collectors.toMap(FindingRepository.AssetCount::getAssetId,
                                                    FindingRepository.AssetCount::getTotal));

        // 심각도 분포와 열린 조치 수도 한 번씩에 센다. 앞서 자산마다 둘을 따로
        // 물었다 — 요약 줄이 거르기 전 전체를 세므로 쪽에 안 보이는 자산까지,
        // 자산 스무 대를 더하면 질의가 서른아홉 번 늘었다(AssetListQueryTest).
        Map<Long, Map<String, Long>> severities = new HashMap<>();
        if (!latestIds.isEmpty()) {
            findings.countBySeverityPerAsset(latestIds)
                    .forEach(row -> severities.computeIfAbsent(row.getAssetId(), id -> new LinkedHashMap<>())
                                              .put(row.getSeverity() == null ? "" : row.getSeverity(),
                                                   row.getTotal()));
        }
        Map<Long, Long> open = remediations
                .countPerAsset(List.of(RemediationStatus.OPEN, RemediationStatus.IN_PROGRESS)).stream()
                .collect(Collectors.toMap(FindingRepository.AssetCount::getAssetId,
                                          FindingRepository.AssetCount::getTotal));

        List<AssetRow> all = list.stream().map(asset -> {
            Scan scan = latest.get(asset.getId());
            Map<String, Long> severity = scan == null ? Map.of()
                    : severities.getOrDefault(asset.getId(), Map.of());
            return new AssetRow(asset, scan, severity, open.getOrDefault(asset.getId(), 0L),
                                kev.getOrDefault(asset.getId(), 0L));
        }).toList();

        // 요약 줄은 **거르기 전** 전체를 센다. 거른 뒤 세면 "검사 안 한 자산 3"
        // 을 눌렀을 때 숫자가 3 에서 다른 값으로 바뀐다.
        model.addAttribute("summary", summarize(all, archived));
        // 기한 지난 조치 · 재검토일 지난 검토 결과를 누르면 가는 곳. 운영 종료
        // 포함을 이어 간다 — 켠 채로 센 숫자를 끈 목록으로 보내면 누른 숫자와
        // 뜬 건수가 다르다.
        model.addAttribute("overdueActionsHref", new VulnQuery.Links("/actions", null)
                .with("archived", archived ? "true" : null).here());
        model.addAttribute("overdueReviewsHref", new VulnQuery.Links("/actions", "tab=analyses")
                .with("archived", archived ? "true" : null).here());

        // **구역 칩도 거르개다.** 앞서 이 줄 목록은 구역을 보지 않았고, 구역을
        // 좁히는 일은 화면을 그리는 `groups` 에서만 했다. 세는 자리가 없을
        // 때는 티가 안 났는데, 건수 줄을 붙이자 구역을 고른 화면 머리에
        // `18대` 가 적히고 표에는 두 줄만 남았다 — 어느 쪽이 맞는지 물어볼
        // 자리가 없다. 세는 것과 그리는 것을 같은 목록에서 낸다.
        List<AssetRow> rows = all.stream()
                .filter(r -> matches(r, filter))
                .filter(r -> zone == null || r.asset().getZone().getId().equals(zone))
                .sorted(comparator(sort, dir))
                .toList();

        // 쪽은 **줄 단위**로 나눈다. 구역 단위로 나누면 자산 3천 대짜리
        // 구역이 한 쪽에 통째로 들어가 아무것도 해결되지 않는다.
        //
        // **구역 카드 보기는 자르지 않는다.** 카드 한 장이 곧 구역 하나의
        // 요약이라 구역 수만큼이고, 자르면 자산이 뒷쪽에 있는 구역의 카드가
        // 통째로 사라진다.
        boolean cards = "zones".equals(view);
        Page<AssetRow> slice = Paging.slice(rows, page, size);
        List<AssetRow> onScreen = cards ? rows : slice.getContent();
        Set<Long> shownIds = onScreen.stream()
                .map(r -> r.asset().getId()).collect(Collectors.toSet());

        // 구역 순서는 구역 목록이 정한다. 자산이 한 대도 없는 구역도 보여
        // 준다 — 없는 것처럼 보이면 "왜 안 보이지" 부터 물어야 한다.
        // 다만 그것은 **첫 쪽에서만** 말한다: 쪽마다 되풀이하면 목록이 아니라
        // 구역 목록이 된다.
        List<ZoneGroup> groups = zoneService.all().stream()
                .filter(z -> zone == null || z.getId().equals(zone))
                .map(z -> {
                    List<AssetRow> inZone = rows.stream()
                            .filter(r -> r.asset().getZone().getId().equals(z.getId()))
                            .toList();
                    return new ZoneGroup(z, inZone, inZone.stream()
                            .filter(r -> shownIds.contains(r.asset().getId()))
                            .toList());
                })
                .filter(g -> g.onThisPage() || (g.isEmpty() && (cards || slice.getNumber() == 0)))
                .toList();

        model.addAttribute("groups", groups);
        model.addAttribute("rowPage", slice);
        model.addAttribute("zones", zoneService.all());
        model.addAttribute("zoneCounts", all.stream().collect(Collectors.groupingBy(
                r -> r.asset().getZone().getId(), Collectors.counting())));
        model.addAttribute("selectedZone", zone);
        model.addAttribute("assetCount", rows.size());
        model.addAttribute("totalCount", all.size());
        model.addAttribute("filter", filter);
        model.addAttribute("view", view);

        // 화면 안의 링크를 자바에서 만든다. 타임리프의 `@{/(zone=${zone}, …)}`
        // 는 값이 없어도 이름을 적어서, 아무것도 고르지 않은 목록의 링크가
        // `/?zone=&filter=&view=table&sort=name&dir=asc&archived=false` 가 된다.
        // 동작은 하지만 그 주소가 결재 문서에 붙고 옆자리에 전달된다.
        //
        // **기본값은 적지 않는다.** `archived=false` 는 안 고른 것이 아니라
        // "운영 종료한 것은 빼기로 골랐다" 고 읽힌다.
        VulnQuery.Links links = new VulnQuery.Links("/", null)
                .with("zone", zone)
                .with("filter", filter)
                .with("view", "zones".equals(view) ? "zones" : null)
                .with("sort", "name".equals(sort) ? null : sort)
                .with("dir", "asc".equals(dir) ? null : dir)
                .with("archived", archived ? "true" : null)
                .size(size);
        String jumped = Paging.jump(links, jump);
        if (jumped != null) {
            return jumped;
        }
        model.addAttribute("links", links);
        model.addAttribute("sort", sort);
        model.addAttribute("dir", dir);
        model.addAttribute("archived", archived);
        model.addAttribute("newAsset", new Asset());
        return "assets";
    }

    /**
     * 요약 줄에 들어가는 숫자. 0 인 것은 화면이 그리지 않는다.
     *
     * <p>{@code kev}(실제 악용)를 앞에 둔다 — <b>확인된 사실</b>이고 심각도와
     * 다른 축이다. {@code critical}·{@code high} 는 grype 이 준 단계를 그대로
     * 센다(다시 나누지 않는다).
     */
    public record Summary(long noScan, long stale, long actionOverdue, long reviewOverdue,
                          long kev, long critical, long high, long noFix) {
    }

    /**
     * @param rows     목록에 오를 자산 전부(거르기 전)
     * @param archived 운영 종료 자산 포함 — 조치 기한 · 재검토일도 같은 범위로 센다
     */
    private Summary summarize(List<AssetRow> rows, boolean archived) {
        java.time.Instant cut = java.time.Instant.now()
                .minus(STALE_DAYS, java.time.temporal.ChronoUnit.DAYS);
        long noScan = rows.stream().filter(r -> !r.hasScan()).count();
        long stale = rows.stream()
                .filter(r -> r.hasScan() && r.latest().getCreatedAt().isBefore(cut)).count();
        long critical = rows.stream().mapToLong(r -> r.severityCount("critical")).sum();
        long high = rows.stream().mapToLong(r -> r.severityCount("high")).sum();
        long kev = rows.stream().mapToLong(AssetRow::kevCount).sum();

        // 수정 버전이 없는 탐지. 최신 완료 검사들만 한 번에 센다 — 자산마다
        // 물으면 자산 수만큼 왕복한다.
        List<Long> scanIds = rows.stream().filter(AssetRow::hasScan)
                .map(r -> r.latest().getId()).toList();
        long noFix = scanIds.isEmpty() ? 0 : findings.countByFixStateIn(scanIds).stream()
                .filter(c -> "wont-fix".equals(c.getFixState()) || "not-fixed".equals(c.getFixState()))
                .mapToLong(FindingRepository.FixStateCount::getTotal).sum();

        // **조치 기한과 재검토일을 따로 센다.** 앞서 둘을 합쳐 `기한 지난 조치`
        // 로 찍었는데, 누르면 가는 조치 탭에는 재검토일 지난 것이 없다 — 띄운
        // 앱에서 `1 기한 지난 조치` 를 눌렀더니 기한 지난 조치가 0건이었다.
        // 둘의 합은 기둥의 `대응` 배지와 같다(그 배지는 두 탭을 함께 센다).
        //
        // **목록과 같은 자산만 센다.** 앞서 운영 종료한 자산의 것까지 세어,
        // 목록에서 사라진 자산의 건이 이 줄에 남았다(RetiredAssetActionsTest).
        long actionOverdue = remediations.countOverdue(java.time.LocalDate.now(), archived);
        long reviewOverdue = analyses.reviewOverdue(archived).size();
        return new Summary(noScan, stale, actionOverdue, reviewOverdue, kev, critical, high, noFix);
    }

    private boolean matches(AssetRow row, String filter) {
        if (filter == null || filter.isBlank()) {
            return true;
        }
        java.time.Instant cut = java.time.Instant.now()
                .minus(STALE_DAYS, java.time.temporal.ChronoUnit.DAYS);
        return switch (filter) {
            case "noscan" -> !row.hasScan();
            case "stale" -> row.hasScan() && row.latest().getCreatedAt().isBefore(cut);
            default -> true;
        };
    }

    /**
     * 표 머리를 눌러 정렬한다.
     *
     * <p><b>검사가 없는 자산은 방향과 무관하게 언제나 뒤로.</b> 탐지 0건으로
     * 놓고 줄 세우면 "안전하다" 는, 아무도 확인하지 않은 판정이 된다.
     */
    private Comparator<AssetRow> comparator(String sort, String dir) {
        Comparator<AssetRow> base = switch (sort) {
            case "scanned" -> Comparator.comparing(
                    r -> r.hasScan() ? r.latest().getCreatedAt() : null,
                    Comparator.nullsLast(Comparator.naturalOrder()));
            case "findings" -> Comparator.comparingLong(
                    (AssetRow r) -> r.hasScan() ? r.latest().getFindingCount() : -1).reversed();
            case "critical" -> Comparator.comparingLong(
                    (AssetRow r) -> r.severityCount("critical")).reversed();
            default -> Comparator.comparing(r -> r.asset().getName(), String.CASE_INSENSITIVE_ORDER);
        };
        Comparator<AssetRow> ordered = "desc".equals(dir) ? base.reversed() : base;
        // 검사 없는 것은 뒤로 몰아 둔다 — 뒤집어도 따라 올라오지 않는다.
        return Comparator.comparing((AssetRow r) -> !r.hasScan()).thenComparing(ordered);
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
        flash.addFlashAttribute("message", asset.getName() + " 자산을 " + target.getName() + " 구역으로 옮겼습니다.");
        return "redirect:/assets/" + id;
    }

    /**
     * 자산 상세.
     *
     * <p>앞서는 SBOM 올리기·검사 이력·조치·자산 삭제가 한 화면에 세로로 이어
     * 붙어 있어 아래가 화면 밖으로 밀렸다. 탭으로 가른다.
     *
     * <p>탭 선택은 <b>주소에 남는다</b>({@code ?tab=}). 자바스크립트로 감췄다
     * 보였다 하면 새로고침했을 때 첫 탭으로 돌아가고 링크로 남길 수도 없다.
     */
    @GetMapping("assets/{id}")
    public String detail(@PathVariable Long id,
                         @RequestParam(defaultValue = "overview") String tab,
                         @RequestParam(defaultValue = "item") String group,
                         @RequestParam(required = false) String q,
                         @RequestParam(name = "severity", required = false) String severityFilter,
                         @RequestParam(required = false) Boolean fixable,
                         @RequestParam(required = false) Boolean kev,
                         @RequestParam(defaultValue = "false") boolean includeDone,
                         @RequestParam(defaultValue = "0") int page,
                         @RequestParam(required = false) Integer size,
                         @RequestParam(required = false) Integer jump,
                         @RequestParam(defaultValue = "severity") String sort,
                         @RequestParam(defaultValue = "desc") String dir,
                         Model model) {
        // 모르는 탭 이름은 개요로 되돌린다. 화면은 `th:if` 로 갈라져 있어서,
        // 아무 것에도 맞지 않는 값이 오면 **탭 줄만 있고 본문이 빈 화면**이
        // 뜬다 — 200 이라 시험도 통과한다. `?tab=scans` 로 실제 그랬다
        // (이력 탭의 이름은 `history` 다).
        tab = TABS.contains(tab) ? tab : "overview";

        // 페이지 이동. 사람이 적는 값은 1부터, 주소의 `page` 는 0부터 센다.
        // 자산 상세와 `/vulns` 가 같은 표·같은 쪽 넘김을 쓰므로 여기도 같다.
        String jumped = "vulns".equals(tab) || "packages".equals(tab) || "history".equals(tab)
                ? Paging.jump(tabLinks(id, tab, group, q, severityFilter, fixable, kev,
                                       includeDone, size, sort, dir), jump)
                : null;
        if (jumped != null) {
            return jumped;
        }
        model.addAttribute("tab", tab);
        Asset asset = asset(id);
        List<Scan> history = scans.findByAssetIdOrderByCreatedAtDesc(id);
        Scan latest = history.stream()
                .filter(s -> s.getStatus() == ScanStatus.DONE)
                .findFirst().orElse(null);

        // 아직 도는 중인 검사. 있으면 화면이 진행 카드를 띄우고 물어본다.
        Scan running = history.stream().filter(Scan::isInFlight).findFirst().orElse(null);

        // 가장 최근 검사가 실패했는가. 진행 표시는 실패를 잠깐 띄운 뒤 화면을
        // 새로 그리며 사라진다 — 개요가 말하지 않으면 실패는 검사 이력 탭에만
        // 남고, 머리의 `마지막 검사` 는 그 전 완료 검사를 가리킨 채다. 그 뒤에
        // 검사가 완료되면(다시 검사 포함) 알릴 것이 없어진다.
        Scan newest = history.isEmpty() ? null : history.get(0);
        model.addAttribute("lastFailed",
                newest != null && newest.getStatus() == ScanStatus.FAILED ? newest : null);

        model.addAttribute("asset", asset);
        model.addAttribute("zones", zoneService.all());
        model.addAttribute("history", history);
        model.addAttribute("historyPage", Paging.slice(history, page, size));
        model.addAttribute("latest", latest);
        model.addAttribute("running", running);
        // 이력의 '이전 대비' — 바로 앞 완료 검사와 견준 탐지 수 변화.
        model.addAttribute("delta", deltas(history));
        // 다시 검사한 줄이 가리키는 원본. **번호가 아니라 시각을 찍기 위한
        // 것이다** — `원본 1` 은 내부 번호라 사람이 아는 값이 아니다.
        model.addAttribute("origins", history.stream()
                .collect(Collectors.toMap(Scan::getId, s -> s, (a, b) -> a)));
        model.addAttribute("severity", latest == null ? Map.of() : severityMap(latest.getId()));
        // 취약점 탭의 숫자는 **그 탭이 처음 열었을 때 보여 주는 줄 수**다 —
        // 해당 없음 · 오탐은 기본에서 빠진다. 탐지 건수(개요 · 이력 · 자산
        // 목록)와 다를 수 있고, 그 차이는 탭 안의 `해당 없음·오탐 포함 (n건)` 이
        // 말한다.
        model.addAttribute("vulnTabCount", latest == null ? 0
                : findings.countByScanId(latest.getId()) - findings.countReviewedOut(
                        List.of(latest.getId()), null, null, null, null, null));
        model.addAttribute("remediations",
                remediations.findByAssetIdOrderByStatusAscPackageNameAsc(id));
        // 이 자산에 대해 내린 결정 둘을 한 탭에서 본다. 검토 결과를 대응
        // 화면에서만 볼 수 있으면 "이 서버 것만" 을 물을 자리가 없다.
        model.addAttribute("assetAnalyses", analyses.forAsset(id));
        // 지우면 무엇이 함께 사라지는지 확인 문구에 그대로 쓴다.
        model.addAttribute("impact", assetService.impactOf(asset));

        // 취약점 탭. 전체 취약점 화면과 **같은 서비스·같은 조각**을 쓴다 —
        // 각자 자기 질의를 부르게 두면 한쪽만 고치는 날이 오고, 그때부터
        // 같은 데이터가 화면마다 다르게 보인다.
        if ("vulns".equals(tab) && latest != null) {
            // **자산 하나에서는 항목별 하나뿐이다.** CVE별은 자산 수가 언제나
            // 1 이라 뜻이 없고 패키지별도 `영향 자산 1대` 만 늘어놓는다.
            // 화면에서 단추를 뗐으니 주소로 들어와도 같은 곳을 보여 준다 —
            // 안 그러면 손으로 적은 `?group=cve` 가 빈 화면이 된다.
            group = "item";
            // `scope` 는 넘기지 않는다 — 전체 취약점 화면은 머리에
            // `scope.label()` 을 찍지만 자산 상세는 자기 제목을 따로 그린다.
            // `ofScan` 을 두 번 부르던 것도 한 번으로 줄인다.
            vulns.fill(model, vulns.ofScan(latest.getId()), group, q, severityFilter,
                       fixable, kev, includeDone, page, size, sort, dir);
            model.addAttribute("links", tabLinks(id, tab, group, q, severityFilter, fixable,
                                                 kev, includeDone, size, sort, dir));
            model.addAttribute("group", group);
            model.addAttribute("q", q);
            model.addAttribute("fixable", fixable);
            model.addAttribute("kev", kev);
            model.addAttribute("sort", sort);
            model.addAttribute("dir", dir);
            model.addAttribute("severityFilter", severityFilter);
        }

        // 패키지 탭. 그 자산에 깔린 것 전부 — 취약점이 없는 것도 있다.
        // **빈 것과 안 본 것을 구분해서 말한다**: V13 은 이미 쌓인 SBOM 을
        // 되읽지 않으므로, 다시 검사하기 전에는 인벤토리가 비어 있다.
        model.addAttribute("packageCount", components.countCurrentByAssetId(id));
        if ("packages".equals(tab)) {
            // **한 쪽씩 읽는다.** 앞서는 그 자산에 깔린 것을 전부 한 번에
            // 읽어 한 화면에 그렸다 — 4천 줄짜리 서버에서 표가 끝나지 않았다.
            model.addAttribute("assetPackages", packages.ofAsset(id, q, page, size));
            model.addAttribute("q", q);
        }
        if ("packages".equals(tab) || "history".equals(tab)) {
            model.addAttribute("links", tabLinks(id, tab, group, q, severityFilter, fixable,
                                                 kev, includeDone, size, sort, dir));
        }
        return "asset-detail";
    }

    /**
     * 쪽을 넘기는 탭의 링크 — <b>취약점 · 패키지 · 검사 이력.</b>
     *
     * <p>탭은 언제나 {@code tab=} 를 달고 다닌다. 나머지는 고른 것만 붙고
     * <b>기본값은 적지 않는다</b> — {@code sort=severity&dir=desc&size=100} 은
     * 고른 것이 아니라 아직 아무것도 고르지 않은 상태다.
     *
     * <p>한 벌로 둔다. 쪽 이동이 되돌릴 주소와 화면이 그리는 주소가 갈리면,
     * 거르개를 하나 더할 때 한쪽만 고치는 날이 온다.
     */
    private VulnQuery.Links tabLinks(Long id, String tab, String group, String q,
                                     String severity, Boolean fixable, Boolean kev,
                                     boolean includeDone, Integer size, String sort,
                                     String dir) {
        // 취약점 탭 말고도 쪽을 넘기는 탭이 있다(패키지 · 검사 이력). 그 탭들은
        // 취약점 탭의 거르개를 달고 다니지 않는다 — 붙여 두면 패키지 탭 주소에
        // `severity=Critical` 이 따라다니며 아무 일도 안 하고 남는다.
        VulnQuery.Links links = new VulnQuery.Links("/assets/" + id, "tab=" + tab)
                .with("q", q)
                .size(size);
        if (!"vulns".equals(tab)) {
            return links;
        }
        return links.with("group", group)
                .with("severity", severity)
                .with("fixable", fixable).with("kev", kev)
                .with("includeDone", includeDone ? "true" : null)
                .with("sort", "severity".equals(sort) ? null : sort)
                .with("dir", "desc".equals(dir) ? null : dir);
    }

    /**
     * 이력의 "이전 대비" — 바로 앞 <b>완료</b> 검사와 견준 탐지 수 차이.
     *
     * <p>실패한 검사는 건너뛴다. 실패는 0건이 아니라 "모른다" 이고, 그것을
     * 0 으로 놓고 빼면 다음 검사가 폭증한 것처럼 보인다.
     *
     * <p>앞선 완료 검사가 없는 첫 검사는 목록에 넣지 않는다 — 화면이 그 줄에
     * 아무것도 그리지 않는다. 0 을 찍으면 "변화 없음" 으로 읽힌다.
     */
    private Map<Long, Integer> deltas(List<Scan> history) {
        Map<Long, Integer> out = new LinkedHashMap<>();
        Scan previous = null;
        // history 는 최신순이므로 뒤에서부터 훑어 시간 순으로 견준다.
        for (int i = history.size() - 1; i >= 0; i--) {
            Scan scan = history.get(i);
            if (scan.getStatus() != ScanStatus.DONE) {
                continue;
            }
            if (previous != null) {
                out.put(scan.getId(), scan.getFindingCount() - previous.getFindingCount());
            }
            previous = scan;
        }
        return out;
    }

    /**
     * 운영 종료 — 목록과 <b>현황 숫자</b>에서 빼되 이력은 남긴다.
     *
     * <p><b>화면 말을 `보관` 에서 `운영 종료` 로 바꿨다.</b> `보관` 은 목적을
     * 말하지 않았고, 이 저장소에서 같은 말이 SBOM 원본을 gzip 으로 쥐고 있는
     * 것도 가리키고 있었다 — 한 말이 두 가지를 가리키면 둘 다 흐려진다.
     * 저장하는 열 이름({@code archived_at})은 그대로다: 데이터 이관이 없다.
     *
     * <p>주기적으로 SBOM 을 올리는 것으로 이 자리를 대신할 수 없다. 폐기한
     * 서버는 <b>그냥 SBOM 이 안 올라온다</b> — 그러면 마지막 검사가 영원히
     * "최신" 으로 남아 전사 심각 건수에 계속 더해지고 `30일 넘은 자산` 에도
     * 계속 뜬다. 지우는 것과도 다르다: 지우면 검사 이력과 보고서 근거가 함께
     * 사라지고, 점검에서 "작년 그 서버 기록" 을 물으면 답할 것이 없어진다.
     */
    @PostMapping("assets/{id}/archive")
    @PreAuthorize("hasRole('ADMIN')")
    public String archive(@PathVariable Long id, RedirectAttributes flash) {
        Asset asset = asset(id);
        asset.setArchivedAt(java.time.Instant.now());
        assets.save(asset);
        audit.record(AuditEvent.ASSET_ARCHIVED, asset.getName(), "");
        flash.addFlashAttribute("message",
                asset.getName() + " 자산을 운영 종료로 처리했습니다. 목록과 현황 숫자에서 빠집니다.");
        return "redirect:/assets/" + id;
    }

    @PostMapping("assets/{id}/unarchive")
    @PreAuthorize("hasRole('ADMIN')")
    public String unarchive(@PathVariable Long id, RedirectAttributes flash) {
        Asset asset = asset(id);
        asset.setArchivedAt(null);
        assets.save(asset);
        audit.record(AuditEvent.ASSET_UNARCHIVED, asset.getName(), "");
        flash.addFlashAttribute("message", asset.getName() + " 자산을 운영 재개로 되돌렸습니다.");
        return "redirect:/assets/" + id;
    }

    /**
     * 보관해 둔 SBOM 원본을 내려받는다.
     *
     * <p>올린 파일을 gzip 으로 쥐고만 있고 꺼내 볼 길이 없었다. 검사 결과가
     * 이상할 때 "그 SBOM 에 실제로 뭐가 들어 있었나" 를 확인할 방법이 없으면
     * grype 의 판정을 대조할 수도 없다.
     */
    @GetMapping("scans/{scanId}/sbom")
    public void downloadSbom(@PathVariable Long scanId, HttpServletResponse response)
            throws java.io.IOException {
        Scan scan = scans.findById(scanId)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "검사를 찾을 수 없습니다."));
        if (scan.getSbomPath() == null || scan.getSbomPath().isBlank()) {
            throw new ResponseStatusException(NOT_FOUND, "보관된 SBOM 이 없습니다.");
        }
        java.nio.file.Path stored = java.nio.file.Path.of(scan.getSbomPath());
        if (!java.nio.file.Files.exists(stored)) {
            throw new ResponseStatusException(NOT_FOUND, "보관된 SBOM 파일이 사라졌습니다.");
        }

        String name = scan.getSbomFilename() == null || scan.getSbomFilename().isBlank()
                ? "sbom-" + scanId + ".json" : scan.getSbomFilename();
        response.setContentType("application/json; charset=UTF-8");
        // 파일 이름에 한글·공백이 섞일 수 있다. RFC 5987 로 함께 준다.
        response.setHeader("Content-Disposition", "attachment; filename=\"sbom-" + scanId
                + ".json\"; filename*=UTF-8''"
                + java.net.URLEncoder.encode(name, java.nio.charset.StandardCharsets.UTF_8));
        try (java.io.InputStream in = storage.openGzip(stored)) {
            in.transferTo(response.getOutputStream());
        }
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
        // **검토 결과 건수를 빼지 않는다.** 누르기 전 확인 상자는 이것을
        // 세어 보여 주는데, 감사 로그와 완료 안내에는 빠져 있었다 — 지운
        // 기록이 실제보다 적게 남는다는 뜻이고, 점검에서 답이 어긋난다.
        String counted = "검사 " + impact.scanCount() + "건 · 탐지 " + impact.findingCount()
                         + "건 · 조치 " + impact.remediationCount()
                         + "건 · 검토 결과 " + impact.analysisCount() + "건";
        audit.record(AuditEvent.ASSET_DELETED, name,
                     "구역 " + zoneName + " · " + counted + " 함께 삭제");
        flash.addFlashAttribute("message",
                name + " 자산을 지웠습니다 — " + counted
                + ", 보관된 SBOM · 검사 결과 파일까지 함께 삭제했습니다.");
        return "redirect:/";
    }

    /**
     * 보관된 SBOM 을 갱신된 grype DB 로 다시 돌린다. 실패한 검사도 된다 — SBOM 은
     * 올린 순간 보관된다(ScanService.rescan).
     */
    @PostMapping("scans/{scanId}/rescan")
    @PreAuthorize("hasRole('ADMIN')")
    public String rescan(@PathVariable Long scanId, Principal principal,
                         RedirectAttributes flash) {
        Scan source = scans.findWithAsset(scanId)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "검사를 찾을 수 없습니다."));
        Long assetId = source.getAsset().getId();
        try {
            Scan copy = scanService.rescan(source, principal.getName());
            audit.record(AuditEvent.SCAN_RESCANNED, source.getAsset().getName(),
                         source.getSbomFilename() + " (원본 검사 " + scanId + ")");
            scanService.runAsync(copy.getId());
            // 돌아가는 곳은 개요 탭이다(진행 표시가 거기 뜬다) — 이력은 그 아래가
            // 아니라 옆 탭이다.
            flash.addFlashAttribute("message",
                    "같은 SBOM 을 다시 검사합니다. 끝나면 검사 이력에 새 줄로 나타납니다.");
        } catch (ScanService.UnsupportedSbomException e) {
            // 고장이 아니라 보관된 파일이 받는 형식이 아니다(예전에 받은 XML).
            // 업로드와 같이 오류 로그에 스택을 남기지 않는다.
            flash.addFlashAttribute("error", "다시 검사하지 못했습니다: " + e.getMessage());
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
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "검사를 찾을 수 없습니다."));
        Long assetId = scan.getAsset().getId();
        String detail = scan.getSbomFilename() + " · 탐지 " + scan.getFindingCount() + "건";
        String assetName = scan.getAsset().getName();
        scanService.delete(scan);
        audit.record(AuditEvent.SCAN_DELETED, assetName, detail);
        flash.addFlashAttribute("message", "검사를 지웠습니다. 보관된 파일도 함께 삭제되었습니다.");
        return "redirect:/assets/" + assetId;
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
                    "SBOM 업로드 완료. grype 검사가 진행 중이며, 끝나면 검사 이력에 나타납니다.");
        } catch (ScanService.UnsupportedSbomException e) {
            // 고장이 아니라 고른 파일이 다른 것이다. 오류 로그에 스택을 남기지 않는다.
            flash.addFlashAttribute("error", "업로드하지 못했습니다: " + e.getMessage());
        } catch (Exception e) {
            log.error("업로드 실패 asset={}", id, e);
            flash.addFlashAttribute("error", "업로드하지 못했습니다: " + e.getMessage());
        }
        return "redirect:/assets/" + id;
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

    /**
     * 목록 한 줄에 필요한 것 — 자산, 마지막 스캔, 심각도 분포, 열린 조치 수,
     * 실제 악용 건수.
     */
    public record AssetRow(Asset asset, Scan latest, Map<String, Long> severity,
                           long openRemediations, long kevCount) {

        public long severityCount(String key) {
            return severity.getOrDefault(key, 0L);
        }

        public boolean hasScan() {
            return latest != null;
        }
    }

    /** 구역 하나와 그 안의 자산들. 머리줄에 쓸 합계를 함께 낸다. */
    /**
     * 구역 한 덩이.
     *
     * @param rows  <b>구역 전체</b>(거른 뒤). 머리줄의 수가 이것을 센다 —
     *              쪽에 실린 것만 세면 `DMZ 5대` 가 쪽을 넘길 때마다 달라진다
     * @param shown 이 쪽에 실리는 줄. 표가 그리는 것은 이것뿐이다
     */
    public record ZoneGroup(Zone zone, List<AssetRow> rows, List<AssetRow> shown) {

        /** 이 쪽에 그릴 줄이 있는가. 없으면 머리줄도 그리지 않는다. */
        public boolean onThisPage() {
            return !shown.isEmpty();
        }

        /** 구역 전체가 이 쪽에 다 실렸는가. 아니면 머리가 `이 쪽 N대` 를 적는다. */
        public boolean partial() {
            return shown.size() != rows.size();
        }

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

        /** 이 구역의 실제 악용(KEV) 건수. 구역 머리줄의 첫 숫자다. */
        public long kevCount() {
            return rows.stream().mapToLong(AssetRow::kevCount).sum();
        }

        public boolean isEmpty() {
            return rows.isEmpty();
        }

        /**
         * 아직 한 번도 검사하지 않은 자산 수.
         *
         * <p>탐지 0건과 "아직 안 봤다" 는 완전히 다른 이야기다. 카드에 0 만
         * 떠 있으면 깨끗한 구역으로 읽힌다.
         */
        public long unscannedCount() {
            return rows.stream().filter(r -> !r.hasScan()).count();
        }

        /** 이 구역에서 가장 오래된 마지막 검사. 없으면 {@code null}. */
        public java.time.Instant oldestScan() {
            return rows.stream().filter(AssetRow::hasScan)
                       .map(r -> r.latest().getCreatedAt())
                       .min(java.time.Instant::compareTo).orElse(null);
        }
    }
}
