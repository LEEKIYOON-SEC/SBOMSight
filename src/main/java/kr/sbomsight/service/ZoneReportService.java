package kr.sbomsight.service;

import kr.sbomsight.domain.AnalysisState;
import kr.sbomsight.domain.Asset;
import kr.sbomsight.domain.CvssVector;
import kr.sbomsight.domain.Remediation;
import kr.sbomsight.domain.FindingAnalysis;
import kr.sbomsight.domain.Scan;
import kr.sbomsight.domain.Severity;
import kr.sbomsight.domain.Zone;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.FindingRepository;
import kr.sbomsight.repo.FindingRepository.ZonePackageGroup;
import kr.sbomsight.repo.RemediationRepository;
import kr.sbomsight.repo.ScanRepository;
import kr.sbomsight.repo.ZoneRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * 구역 · 기간 보고서 — "9월 DMZ 현황".
 *
 * <p>자산 한 대짜리 보고서를 서른 장 묶어 놓은 것이 아니다. 구역으로 볼 때만
 * 나오는 값이 있다: <b>openssl 을 올리면 12대에서 47건이 사라진다.</b> 자산을
 * 하나씩 열어 보면 "여기 3건, 저기 5건" 으로 흩어져 그 판단이 서지 않는다.
 *
 * <p>구성은 자산 보고서와 같은 번호 매긴 장이되, 1장이 다르다.
 * <b>기간 안에 검사되지 않은 자산을 먼저 밝힌다.</b> 서른 대 중 열 대만
 * 검사하고 "탐지 1,200건" 이라고 쓰면 그것은 구역의 현황이 아니라 열 대의
 * 현황이다. 보고서를 받는 사람은 그 차이를 알 수 없다.
 *
 * <p>{@link ReportService} 와 마찬가지로 grype 의 판정을 다시 계산하지 않는다.
 * 여기서 하는 일은 세고 묶고 줄 세우는 것뿐이다.
 */
@Service
public class ZoneReportService {

    /**
     * 날짜는 사용자의 벽시계 기준으로 받고 저장은 UTC 다. 서버의 지역 시간대로
     * 경계를 잡는다 — 한국 시간 9월 1일 00:00 은 UTC 8월 31일 15:00 이고,
     * 그것을 맞추지 않으면 9월 보고서에 8월 말 검사가 끼거나 9월 1일 아침
     * 검사가 빠진다.
     */
    private static final ZoneId WALL_CLOCK = ZoneId.systemDefault();

    private final AssetRepository assets;
    private final ZoneRepository zones;
    private final ScanRepository scans;
    private final FindingRepository findings;
    private final RemediationRepository remediations;
    private final FindingAnalysisService analyses;

    public ZoneReportService(AssetRepository assets, ZoneRepository zones, ScanRepository scans,
                             FindingRepository findings, RemediationRepository remediations,
                             FindingAnalysisService analyses) {
        this.assets = assets;
        this.zones = zones;
        this.scans = scans;
        this.findings = findings;
        this.remediations = remediations;
        this.analyses = analyses;
    }

    /**
     * @param zoneId {@code null} 이면 전체 구역
     * @param from   시작일 (포함)
     * @param to     종료일 (포함) — 안에서 다음 날 00:00 미만으로 바꾼다
     */
    @Transactional(readOnly = true)
    public ZoneReport build(Long zoneId, LocalDate from, LocalDate to) {
        Instant start = from.atStartOfDay(WALL_CLOCK).toInstant();
        // 종료일을 포함하려면 다음 날 0시 미만으로 잡는다. 23:59:59 로 끊으면
        // 그 1초 사이에 끝난 검사가 사라진다.
        Instant end = to.plusDays(1).atStartOfDay(WALL_CLOCK).toInstant();

        Zone zone = zoneId == null ? null : zones.findById(zoneId).orElse(null);
        List<Asset> inScope = assets.findLiveWithZone().stream()
                .filter(a -> zoneId == null || a.getZone().getId().equals(zoneId))
                .toList();

        List<Scan> current = scans.findLatestDonePerAssetBetween(zoneId, start, end);
        List<Scan> baseline = scans.findLatestDonePerAssetBefore(zoneId, start);
        long scanRuns = scans.countDoneBetween(zoneId, start, end);

        Set<Long> scannedIds = current.stream().map(s -> s.getAsset().getId())
                                      .collect(java.util.stream.Collectors.toSet());
        List<Asset> notScanned = inScope.stream()
                .filter(a -> !scannedIds.contains(a.getId()))
                .toList();

        Scope scope = scope(zone, from, to, inScope, current, notScanned, scanRuns);
        // **2·3장은 탐지 전부, 4·5장(과 그것을 잇는 6장의 건수)은 목록이다.**
        // 목록은 검토 결과가 해당 없음 · 오탐인 건을 뺀다 — 취약점 화면 · 자산
        // 보고서와 같은 규칙. 뺀 건수는 1장이 말한다.
        Exposure exposure = exposure(current, true);
        Aggregate aggregate = aggregate(current, exposure, inScope, notScanned);
        Judgement judgement = judgement(current, baseline, exposure(current, false));
        Action action = action(zoneId, inScope, judgement, start, end, scanIds(current));

        return new ZoneReport(scope, aggregate, judgement, action);
    }

    // --- 1장: 점검 범위 -----------------------------------------------------

    private Scope scope(Zone zone, LocalDate from, LocalDate to, List<Asset> inScope,
                        List<Scan> current, List<Asset> notScanned, long scanRuns) {
        long totalFindings = current.stream().mapToLong(Scan::getFindingCount).sum();

        // 기간 동안 grype 이 바뀌었으면 증감의 일부는 서버가 아니라 도구가
        // 움직인 것이다. 판이 둘 이상이면 그 사실을 보고서에 적는다.
        Set<String> grypeVersions = new TreeSet<>();
        Set<LocalDate> dbDates = new TreeSet<>();
        for (Scan s : current) {
            if (s.getGrypeVersion() != null && !s.getGrypeVersion().isBlank()) {
                grypeVersions.add(s.getGrypeVersion());
            }
            if (s.getGrypeDbBuilt() != null) {
                dbDates.add(LocalDate.ofInstant(s.getGrypeDbBuilt(), WALL_CLOCK));
            }
        }

        Instant oldest = current.stream().map(Scan::getCreatedAt)
                                .min(Comparator.naturalOrder()).orElse(null);
        Instant newest = current.stream().map(Scan::getCreatedAt)
                                .max(Comparator.naturalOrder()).orElse(null);

        return new Scope(zone, from, to, inScope.size(), current.size(), notScanned,
                         scanRuns, totalFindings, List.copyOf(grypeVersions),
                         List.copyOf(dbDates), oldest, newest);
    }

    // --- 노출면 --------------------------------------------------------------

    /**
     * grype 이 준 CVSS 벡터를 풀어 <b>어떻게 닿을 수 있는 건인지</b> 센다.
     *
     * <p>읽지 못한 벡터는 세지 않고 따로 센다. "아니오" 로 밀어 넣으면
     * 아무도 확인하지 않은 판정이 보고서에 실린다.
     */
    private Exposure exposure(List<Scan> current, boolean includeReviewed) {
        if (current.isEmpty()) {
            return new Exposure(0, 0, 0, 0, Map.of(), Map.of());
        }
        long reachable = 0, reachableFixable = 0, scopeChanged = 0, unreadable = 0;
        Map<String, Long> byPackage = new HashMap<>();
        Map<Long, Long> byAsset = new HashMap<>();

        for (FindingRepository.ZoneExposureRow row
                : findings.exposureRowsIn(scanIds(current), includeReviewed)) {
            Optional<CvssVector> parsed = CvssVector.parse(row.getVector());
            if (parsed.isEmpty()) {
                unreadable++;
                continue;
            }
            CvssVector v = parsed.get();
            if (v.scopeChanged()) {
                scopeChanged++;
            }
            if (v.directlyReachable()) {
                reachable++;
                if ("fixed".equalsIgnoreCase(row.getFixState())) {
                    reachableFixable++;
                }
                byPackage.merge(row.getPackageName(), 1L, Long::sum);
                byAsset.merge(row.getAssetId(), 1L, Long::sum);
            }
        }
        return new Exposure(reachable, reachableFixable, scopeChanged, unreadable, byPackage, byAsset);
    }

    // --- 2·3장: 점검 결과 요약과 자산별 현황 --------------------------------

    private Aggregate aggregate(List<Scan> current, Exposure exposure,
                                List<Asset> inScope, List<Asset> notScanned) {
        Map<String, Long> severity = new LinkedHashMap<>();
        // 순서는 Severity 한곳에 있다. 여기 다시 적으면 곧 갈라진다.
        for (String key : Severity.KEYS) {
            severity.put(key, 0L);
        }
        Map<String, Long> fixState = new LinkedHashMap<>();
        Map<Long, Map<String, Long>> perAsset = new HashMap<>();

        if (!current.isEmpty()) {
            List<Long> ids = scanIds(current);
            findings.countBySeverityIn(ids)
                    .forEach(r -> severity.merge(key(r.getSeverity()), r.getTotal(), Long::sum));
            findings.countByFixStateIn(ids)
                    .forEach(r -> fixState.merge(key(r.getFixState()), r.getTotal(), Long::sum));
            findings.countBySeverityPerAsset(ids)
                    .forEach(r -> perAsset.computeIfAbsent(r.getAssetId(), k -> new HashMap<>())
                                          .merge(key(r.getSeverity()), r.getTotal(), Long::sum));
        }

        long total = severity.values().stream().mapToLong(Long::longValue).sum();
        long fixable = fixState.getOrDefault("fixed", 0L);
        long noFix = fixState.getOrDefault("wont-fix", 0L) + fixState.getOrDefault("not-fixed", 0L);
        long unknownFix = total - fixable - noFix;

        // 자산 표. 검사된 자산이 먼저(심각·높음이 많은 순), 검사되지 않은
        // 자산이 뒤에 붙는다. 빼지 않는다 — 목록에서 사라지면 안 본 것과
        // 문제가 없는 것을 구분할 수 없다.
        Map<Long, Scan> scanByAsset = new HashMap<>();
        current.forEach(s -> scanByAsset.put(s.getAsset().getId(), s));

        List<AssetRow> rows = new ArrayList<>();
        for (Scan s : current) {
            Map<String, Long> sev = perAsset.getOrDefault(s.getAsset().getId(), Map.of());
            rows.add(new AssetRow(s.getAsset(), s,
                                  sev.getOrDefault("critical", 0L),
                                  sev.getOrDefault("high", 0L),
                                  exposure.reachableInAsset(s.getAsset().getId())));
        }
        rows.sort(Comparator.comparingLong(AssetRow::critical).reversed()
                            .thenComparing(Comparator.comparingLong(AssetRow::high).reversed())
                            .thenComparing(Comparator.comparingLong(AssetRow::reachable).reversed())
                            .thenComparing(r -> r.asset().getName()));
        for (Asset a : notScanned) {
            rows.add(new AssetRow(a, null, 0, 0, 0));
        }

        return new Aggregate(severity, fixState, total, fixable, noFix, unknownFix, rows, exposure,
                             reviewCounts(current, inScope));
    }

    /**
     * <b>2.4 — 우리가 몇 건을 봤는가.</b>
     *
     * <p>2.1~2.3 은 전부 grype 의 축이다. 이 도구가 하는 일은 그 목록을
     * 검토하고 조치를 추적하는 것인데, 그 축이 요약에 한 줄도 없었다.
     *
     * <p>자산 보고서와 <b>같은 규칙</b>으로 맞춘다
     * ({@link FindingAnalysisService#stateOf}) — 두 보고서가 같은 건을
     * 다르게 세면 둘 중 하나는 틀린 것이다.
     */
    private Map<AnalysisState, Long> reviewCounts(List<Scan> current, List<Asset> inScope) {
        Map<AnalysisState, Long> counts = FindingAnalysisService.emptyStateCounts();
        if (current.isEmpty()) {
            return counts;
        }
        // 자산으로 한 번 갈라 둔다. 구역은 자산이 섞여 있어서 (CVE, 패키지명)
        // 으로만 맞추면 web-01 의 검토 결과가 api-01 의 탐지에 붙는다.
        //
        // **미리 갈라 둔다.** 탐지 줄마다 전체 지도를 훑으면 자산 다섯에
        // 탐지 이백이면 훑기가 천 번이다 — 구역이 커질수록 보고서가 느려진다.
        Map<Long, Map<String, FindingAnalysis>> byAsset = new HashMap<>();
        analyses.byAssetKey(inScope.stream().map(Asset::getId).toList())
                .forEach((key, value) -> byAsset
                        .computeIfAbsent(value.getAsset().getId(), id -> new HashMap<>())
                        .put(value.key(), value));

        for (FindingRepository.AssetFindingKey row : findings.findKeysIn(scanIds(current))) {
            Map<String, FindingAnalysis> forThisAsset =
                    byAsset.getOrDefault(row.getAssetId(), Map.of());
            counts.merge(FindingAnalysisService.stateOf(forThisAsset, row.getCve(),
                                                        row.getRelatedCve(), row.getPackageName()),
                         1L, Long::sum);
        }
        return counts;
    }

    // --- 4·5·7장: 조치 대상 · 수정 버전 없는 항목 · 기간 시작 대비 ----------

    private Judgement judgement(List<Scan> current, List<Scan> baseline, Exposure exposure) {
        List<ZonePackageAction> actions = List.of();
        List<ZonePackageAction> blocked = List.of();

        if (!current.isEmpty()) {
            // 필터는 걸지 않는다 — 기간 안의 것을 전부 센다(넷 다 null). 다만
            // 목록이므로 해당 없음 · 오탐은 뺀다.
            List<ZonePackageGroup> groups =
                    findings.groupByPackageIn(scanIds(current), null, null, null, null, false);
            actions = groups.stream()
                    .filter(g -> g.getFixable() > 0)
                    .map(g -> new ZonePackageAction(g, exposure.reachableIn(g.getPackageName())))
                    .sorted(BY_URGENCY)
                    .toList();
            blocked = groups.stream()
                    .filter(g -> g.getFixable() == 0)
                    .map(g -> new ZonePackageAction(g, exposure.reachableIn(g.getPackageName())))
                    .sorted(BY_URGENCY)
                    .toList();
        }

        return new Judgement(actions, blocked, movement(current, baseline), exposure);
    }

    /**
     * 먼저 손댈 것부터.
     *
     * <p>바로 닿는 건 수 → 실제 악용 → 걸린 자산 수 → 최고 CVSS → 건수.
     * 자산 수가 들어가는 것이 자산 보고서와 다른 점이다 — 같은 조건이면
     * 열두 대에 걸린 패키지를 한 대짜리보다 먼저 올린다.
     *
     * <p>이것은 표시 순서를 정하는 일이지 grype 의 판정을 바꾸는 것이 아니다.
     * 건수도 심각도도 수정 상태도 grype 이 준 그대로다.
     */
    private static final Comparator<ZonePackageAction> BY_URGENCY =
            Comparator.comparingLong(ZonePackageAction::reachableCount).reversed()
                      .thenComparing(Comparator.comparingLong(ZonePackageAction::kevCount).reversed())
                      .thenComparing(Comparator.comparingLong(ZonePackageAction::assetCount).reversed())
                      .thenComparing(ZonePackageAction::maxCvss,
                                     Comparator.nullsLast(Comparator.reverseOrder()))
                      .thenComparing(Comparator.comparingLong(ZonePackageAction::total).reversed())
                      .thenComparing(ZonePackageAction::packageName);

    /**
     * 기간 시작 직전 대비 신규 · 해소 · 유지.
     *
     * <p>대조 축은 {@code (자산, CVE, 패키지명)} 이다. 버전을 넣으면 패치한
     * 건이 "해소 1건 + 신규 1건" 으로 갈라져 보이고, 자산을 빼면 A 서버에서
     * 고치고 B 서버에서 생긴 것이 상쇄되어 둘 다 없던 일이 된다.
     *
     * <p><b>기준선이 없는 자산은 대조에서 뺀다.</b> 기간 중에 처음 등록한
     * 서버의 탐지를 전부 "신규" 로 세면 증감이 부풀려진다 — 새로 본 것이지
     * 새로 생긴 것이 아니다. 몇 대를 뺐는지는 보고서에 적는다.
     */
    private Movement movement(List<Scan> current, List<Scan> baseline) {
        Set<Long> baselineAssets = baseline.stream().map(s -> s.getAsset().getId())
                                           .collect(java.util.stream.Collectors.toSet());
        List<Scan> comparable = current.stream()
                .filter(s -> baselineAssets.contains(s.getAsset().getId()))
                .toList();

        if (comparable.isEmpty()) {
            return new Movement(0, 0, 0, 0, current.size(), baseline.isEmpty() ? null : latest(baseline));
        }

        Set<Long> comparableAssets = comparable.stream().map(s -> s.getAsset().getId())
                                               .collect(java.util.stream.Collectors.toSet());
        List<Scan> baselineComparable = baseline.stream()
                .filter(s -> comparableAssets.contains(s.getAsset().getId()))
                .toList();

        Set<String> now = keys(comparable);
        Set<String> before = keys(baselineComparable);

        long added = now.stream().filter(k -> !before.contains(k)).count();
        long resolved = before.stream().filter(k -> !now.contains(k)).count();
        long kept = now.stream().filter(before::contains).count();

        return new Movement(added, resolved, kept, comparable.size(),
                            current.size() - comparable.size(), latest(baselineComparable));
    }

    private Set<String> keys(List<Scan> forScans) {
        if (forScans.isEmpty()) {
            return Set.of();
        }
        Set<String> out = new HashSet<>();
        for (FindingRepository.AssetFindingKey k : findings.findKeysIn(scanIds(forScans))) {
            out.add(k.getAssetId() + "|" + k.getCve() + "|" + k.getPackageName());
        }
        return out;
    }

    private Instant latest(List<Scan> list) {
        return list.stream().map(Scan::getCreatedAt).max(Comparator.naturalOrder()).orElse(null);
    }

    // --- 6장: 조치 진행 현황 ------------------------------------------------

    private Action action(Long zoneId, List<Asset> inScope, Judgement judgement,
                          Instant start, Instant end, List<Long> scanIds) {
        Set<Long> scope = inScope.stream().map(Asset::getId)
                                 .collect(java.util.stream.Collectors.toSet());
        List<Remediation> all = remediations.findByZone(zoneId).stream()
                .filter(r -> scope.contains(r.getAsset().getId()))
                .toList();

        long open = all.stream().filter(r -> !r.getStatus().isClosed()).count();
        long overdue = all.stream().filter(Remediation::isOverdue).count();
        long openedInPeriod = all.stream()
                .filter(r -> !r.getCreatedAt().isBefore(start) && r.getCreatedAt().isBefore(end))
                .count();
        long closedInPeriod = all.stream()
                .filter(r -> r.getClosedAt() != null
                             && !r.getClosedAt().isBefore(start) && r.getClosedAt().isBefore(end))
                .count();

        // 검토가 끝난 것(해당 없음·오탐)도 가져온다 — 목록에서는 빠지지만
        // "왜 그대로 두는가" 에는 그것도 답이다.
        List<FindingAnalysis> explained = analyses.list(true, zoneId).stream()
                .filter(a -> scope.contains(a.getAsset().getId()))
                .toList();

        List<Remediation> overdueRows = all.stream()
                .filter(Remediation::isOverdue)
                .sorted(Comparator.comparing(Remediation::getDueDate))
                .toList();

        // **단위를 잇는다.** 조치는 (자산, 패키지)로 등록되고 탐지는 건이다.
        // "등록된 조치 3개" 만 적으면 읽는 사람은 그 3 이 138건 중 얼마인지
        // 알 수 없다 — 결재로 올라가는 문서에서 가장 먼저 의심받는 자리다.
        Set<String> tracked = all.stream()
                .filter(r -> !r.getStatus().isClosed())
                .map(r -> r.getAsset().getId() + "|" + r.getPackageName())
                .collect(java.util.stream.Collectors.toSet());
        long trackedFindings = 0, untrackedFindings = 0;
        // 4장의 `해소 건수` 와 같은 축이다 — 해당 없음 · 오탐은 넣지 않는다.
        for (FindingRepository.AssetPackageCount row
                : findings.countPerAssetPackage(scanIds, false)) {
            if (row.getFixable() == 0) {
                continue;   // 올려서 해소되는 것이 없는 패키지는 조치 대상이 아니다
            }
            if (tracked.contains(row.getAssetId() + "|" + row.getPackageName())) {
                trackedFindings += row.getFixable();
            } else {
                untrackedFindings += row.getFixable();
            }
        }

        Map<String, Set<Long>> answeredAssets = new HashMap<>();
        Map<String, Reviewed> reviewed = reviewByPackage(inScope, scanIds, answeredAssets);
        return new Action(all.size(), open, overdue, openedInPeriod, closedInPeriod,
                          overdueRows, explained, judgement.blocked(),
                          trackedFindings, untrackedFindings, reviewed, answeredAssets);
    }

    /**
     * 패키지마다 <b>몇 건에 답이 있나</b> — 구역 전체에서.
     *
     * <p>3장(검토 결과 분포)과 <b>같은 걸음으로 센다.</b> 자산으로 한 번
     * 갈라 맞춘다 — 구역은 자산이 섞여 있어서 {@code (CVE, 패키지명)} 으로만
     * 맞추면 web-01 의 검토 결과가 api-01 의 탐지에 붙는다.
     */
    private Map<String, Reviewed> reviewByPackage(List<Asset> inScope, List<Long> scanIds,
                                                 Map<String, Set<Long>> answeredAssets) {
        Map<Long, Map<String, FindingAnalysis>> byAsset = new HashMap<>();
        analyses.byAssetKey(inScope.stream().map(Asset::getId).toList())
                .forEach((key, value) -> byAsset
                        .computeIfAbsent(value.getAsset().getId(), id -> new HashMap<>())
                        .put(value.key(), value));

        Map<String, long[]> counts = new LinkedHashMap<>();
        for (FindingRepository.AssetFindingKey row : findings.findKeysIn(scanIds)) {
            AnalysisState state = FindingAnalysisService.stateOf(
                    byAsset.getOrDefault(row.getAssetId(), Map.of()),
                    row.getCve(), row.getRelatedCve(), row.getPackageName());
            // 5장은 목록이다 — 해당 없음 · 오탐으로 빠진 건은 세지 않는다.
            if (!state.isOpen()) {
                continue;
            }
            long[] cell = counts.computeIfAbsent(row.getPackageName(), name -> new long[2]);
            cell[1]++;
            if (state != AnalysisState.NOT_SET) {
                cell[0]++;
                answeredAssets.computeIfAbsent(row.getPackageName(), name -> new HashSet<>())
                              .add(row.getAssetId());
            }
        }
        Map<String, Reviewed> out = new LinkedHashMap<>();
        counts.forEach((name, cell) -> out.put(name, new Reviewed(cell[0], cell[1])));
        return out;
    }

    // -----------------------------------------------------------------------

    private List<Long> scanIds(List<Scan> list) {
        return list.stream().map(Scan::getId).toList();
    }

    private String key(String value) {
        return value == null || value.isBlank() ? "unknown" : value.toLowerCase();
    }

    // -----------------------------------------------------------------------
    // 화면에 넘기는 모양
    // -----------------------------------------------------------------------

    public record ZoneReport(Scope scope, Aggregate aggregate, Judgement judgement, Action action) {
    }

    /**
     * 1장 — 점검 범위.
     *
     * @param notScanned 기간 안에 검사되지 않은 자산. <b>이 목록이 이 장의 핵심이다.</b>
     */
    public record Scope(Zone zone, LocalDate from, LocalDate to,
                        int assetsInScope, int assetsScanned, List<Asset> notScanned,
                        long scanRuns, long totalFindings,
                        List<String> grypeVersions, List<LocalDate> dbDates,
                        Instant oldestScan, Instant newestScan) {

        public String zoneName() {
            return zone == null ? "전체" : zone.getName();
        }

        /** 전 구역을 한 장에 볼 때는 자산마다 어느 구역인지가 있어야 읽힌다. */
        public boolean wholeSite() {
            return zone == null;
        }

        /** 몇 %를 실제로 보았는가. 이 값이 낮으면 아래 숫자는 구역의 현황이 아니다. */
        public int coveragePercent() {
            return assetsInScope == 0 ? 0 : (int) Math.round(assetsScanned * 100.0 / assetsInScope);
        }

        public boolean fullyCovered() {
            return assetsInScope > 0 && notScanned.isEmpty();
        }

        public boolean nothingScanned() {
            return assetsScanned == 0;
        }

        /**
         * 기간 동안 grype 이 바뀌었는가.
         *
         * <p>바뀌었다면 증감의 일부는 서버가 아니라 도구가 움직인 것이다.
         * 새 판이 규칙을 더 가지면 같은 서버에서도 탐지가 는다.
         */
        public boolean toolChanged() {
            return grypeVersions.size() > 1 || dbDates.size() > 1;
        }
    }

    /** 어떻게 닿을 수 있는가 — grype 이 준 CVSS 벡터를 풀어 센 것. */
    public record Exposure(long reachable, long reachableFixable, long scopeChanged,
                           long unreadable, Map<String, Long> reachableByPackage,
                           Map<Long, Long> reachableByAsset) {

        public long reachableIn(String packageName) {
            return reachableByPackage.getOrDefault(packageName, 0L);
        }

        public long reachableInAsset(Long assetId) {
            return reachableByAsset.getOrDefault(assetId, 0L);
        }

        /** 바로 닿는데 수정본이 없는 것. 가장 곤란한 자리다. */
        public long reachableWithoutFix() {
            return reachable - reachableFixable;
        }
    }

    /** 2·3장 — 점검 결과 요약과 자산별 현황. */
    public record Aggregate(Map<String, Long> severity, Map<String, Long> fixState,
                            long total, long fixable, long noFix, long unknownFix,
                            List<AssetRow> rows, Exposure exposure,
                            Map<AnalysisState, Long> review) {

        public long severityOf(String key) {
            return severity.getOrDefault(key, 0L);
        }

        /** 2.4 한 줄. */
        public long reviewOf(AnalysisState state) {
            return review.getOrDefault(state, 0L);
        }

        /** 아직 아무도 보지 않은 건. */
        public long notReviewed() {
            return reviewOf(AnalysisState.NOT_SET);
        }

        /** 해당 없음 · 오탐 — 4·5장 목록에서 뺀 건수. 1장이 말한다. */
        public long excludedFromLists() {
            return reviewOf(AnalysisState.NOT_AFFECTED) + reviewOf(AnalysisState.FALSE_POSITIVE);
        }

        /**
         * 비중(%). 표에 건수와 나란히 놓는다.
         *
         * <p>전체가 0 이면 <b>0% 가 아니라 값이 없다.</b> 0으로 적으면 "0%"
         * 라는, 세어 본 적 없는 숫자가 표에 앉는다.
         */
        public String share(long count) {
            return total <= 0 ? "—" : String.format("%.1f%%", count * 100.0 / total);
        }

        public long urgent() {
            return severityOf("critical") + severityOf("high");
        }

        /** 심각·높음을 한 건이라도 가진 자산 수. "몇 대가 문제인가" 에 답한다. */
        public long assetsWithUrgent() {
            return rows.stream().filter(r -> r.scanned() && r.critical() + r.high() > 0).count();
        }
    }

    /** 자산 한 줄. {@code scan} 이 {@code null} 이면 기간 안에 검사되지 않은 자산이다. */
    public record AssetRow(Asset asset, Scan scan, long critical, long high, long reachable) {

        public boolean scanned() {
            return scan != null;
        }

        public long findingCount() {
            return scan == null ? 0 : scan.getFindingCount();
        }
    }

    /** 4·5·7장 — 조치 대상 · 수정 버전 없는 항목 · 기간 시작 대비. */
    public record Judgement(List<ZonePackageAction> actions, List<ZonePackageAction> blocked,
                            Movement movement, Exposure exposure) {

        /** 상위 다섯 패키지가 덮는 건수 — "몇 개만 손대면 되는가". */
        public long topFiveCoverage() {
            return actions.stream().limit(5).mapToLong(ZonePackageAction::fixableCount).sum();
        }

        /**
         * 4장 표의 해소 건수 합계.
         *
         * <p>앞서 이 자리에 {@link #topFiveCoverage()} 를 넣었다. 패키지가 다섯
         * 개 이하일 때는 같은 값이라 띄워 놓고도 못 봤는데, 여섯 개부터는
         * <b>합계 줄이 위 칸들의 합이 아니다.</b> 표에서 그것보다 나쁜 것이 없다.
         */
        public long resolvableFindings() {
            return actions.stream().mapToLong(ZonePackageAction::fixableCount).sum();
        }

        /** 4장 표가 덮는 '원격 접근' 건수 합계. */
        public long resolvableReach() {
            return actions.stream().mapToLong(ZonePackageAction::reachableCount).sum();
        }

        public long reachablePackages() {
            return actions.stream().filter(a -> a.reachableCount() > 0).count();
        }

        /** 두 대 이상에 공통으로 걸린 패키지 — 한 번 판단해 여러 대에 적용할 수 있는 것. */
        public List<ZonePackageAction> shared() {
            return actions.stream().filter(a -> a.assetCount() > 1).toList();
        }
    }

    /**
     * 패키지 하나에 대한 구역 단위 조치 후보.
     *
     * @param assetCount   몇 대에 걸려 있는가 — 구역 보고서에만 있는 값
     * @param versionCount 자산마다 설치된 판이 몇 가지인가
     * @param targetCount  grype 이 제시한 수정 버전이 몇 가지인가
     */
    public record ZonePackageAction(String packageName, String packageType,
                                    String anyVersion, long versionCount,
                                    String targetVersion, long targetCount,
                                    long total, long fixableCount, long assetCount,
                                    long kevCount, long criticalCount, long highCount,
                                    BigDecimal maxCvss, BigDecimal maxEpss, long reachableCount) {

        ZonePackageAction(ZonePackageGroup g, long reachableCount) {
            this(g.getPackageName(), g.getPackageType(), g.getAnyVersion(), g.getVersionCount(),
                 g.getTargetVersion() == null ? "" : g.getTargetVersion(), g.getTargetCount(),
                 g.getTotal(), g.getFixable(), g.getAssetCount(), g.getKevCount(),
                 g.getCriticalCount(), g.getHighCount(), g.getMaxCvss(), g.getMaxEpss(),
                 reachableCount);
        }

        /** 설치된 판이 하나뿐일 때만 버전을 적는다. 섞여 있으면 "N종" 이다. */
        public boolean oneVersion() {
            return versionCount == 1;
        }

        /**
         * 목표 버전을 단정할 수 있는가.
         *
         * <p>자산마다 배포판이 다르면 grype 이 주는 수정 버전도 다르다. 그중
         * 하나를 골라 "이걸로 올리세요" 라고 쓰면 나머지 자산에 대해 <b>틀린
         * 지시</b>가 된다. 여러 가지면 단정하지 않고 자산별 보고서로 보낸다.
         */
        public boolean oneTarget() {
            return targetCount == 1 && targetVersion != null && !targetVersion.isBlank();
        }

        public boolean hasReachable() {
            return reachableCount > 0;
        }
    }

    /**
     * 기간 시작 직전 대비 증감.
     *
     * @param assetsCompared     기준선이 있어 실제로 대조한 자산 수
     * @param assetsWithoutBase  기간 중 처음 검사되어 대조에서 뺀 자산 수
     */
    public record Movement(long added, long resolved, long kept,
                           long assetsCompared, long assetsWithoutBase, Instant baselineAt) {

        public boolean comparable() {
            return assetsCompared > 0;
        }

        /** 줄었는가 늘었는가. 보고서 첫 줄에 쓰는 값이다. */
        public long net() {
            return added - resolved;
        }
    }

    /** 6장 — 조치 진행 현황. */
    /**
     * 6장 — 조치 진행 현황.
     *
     * <p><b>단위가 둘이다.</b> {@code total}·{@code open} 은 <b>조치</b> 수
     * ((자산, 패키지)로 등록된다)이고, {@code trackedFindings} ·
     * {@code untrackedFindings} 는 그것이 덮는 <b>건</b> 수다. 둘을 함께
     * 적지 않으면 "등록된 조치 3개" 가 138건 중 얼마인지 말해 주지 않는다.
     */
    public record Action(long total, long open, long overdue,
                         long openedInPeriod, long closedInPeriod,
                         List<Remediation> overdueRows, List<FindingAnalysis> explained,
                         List<ZonePackageAction> residual,
                         long trackedFindings, long untrackedFindings,
                         Map<String, Reviewed> reviewed, Map<String, Set<Long>> answeredAssets) {

        /**
         * 이 패키지의 <b>모든 건</b>에 답이 있는가.
         *
         * <p>앞서 {@code explained} 에 그 이름이 한 번이라도 있으면 참이었다.
         * 자산 수는 {@link #explainedAssets} 가 이미 가려 주고 있었지만, 한
         * 자산 안에서 <b>탐지 열 건 중 한 건만</b> 적어 둔 것은 여전히 전부
         * 설명된 것으로 세어졌다.
         */
        public boolean isExplained(String packageName) {
            Reviewed r = reviewed.get(packageName);
            return r != null && r.all();
        }

        /** 그 패키지의 검토 진행 — 표의 `검토 결과` 칸이 이것을 그린다. */
        public Reviewed reviewedIn(String packageName) {
            return reviewed.get(packageName);
        }

        /**
         * 그 패키지에 검토 결과가 적힌 <b>자산이 몇 대인가.</b>
         *
         * <p>구역 보고서에서 {@link #isExplained(String)} 하나로 "검토함" 이라고
         * 쓰면, 열두 대에 걸린 패키지를 한 대에서만 검토해 놓고도 전부 검토한
         * 것처럼 읽힌다. 걸린 자산 수와 나란히 놓아야 그 차이가 보인다.
         */
        public long explainedAssets(String packageName) {
            // 그 줄에 실린 탐지(해당 없음 · 오탐을 뺀 것) 가운데 답이 있는 자산만
            // 센다. 앞서는 그 구역의 검토 결과 전부에서 셌다 — 목록에서 빠진
            // 해당 없음과 이미 사라진 탐지의 검토까지 들어가, `1대` 짜리 줄에
            // `2대 검토` 가 붙을 수 있었다.
            return answeredAssets.getOrDefault(packageName, Set.of()).size();
        }

        public long reviewOverdue() {
            return explained.stream().filter(FindingAnalysis::isReviewOverdue).count();
        }

        /** 5장 표의 건수 합계. */
        public long residualFindings() {
            return residual.stream().mapToLong(ZonePackageAction::total).sum();
        }

        /** 손댈 수 없는데 <b>답이 없는 건이 남은</b> 패키지 — 설명이 빈 자리다. */
        public long unexplained() {
            return residual.stream().filter(r -> !isExplained(r.packageName())).count();
        }
    }
}
