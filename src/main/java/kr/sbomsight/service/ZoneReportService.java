package kr.sbomsight.service;

import kr.sbomsight.domain.Asset;
import kr.sbomsight.domain.CvssVector;
import kr.sbomsight.domain.Remediation;
import kr.sbomsight.domain.RiskAcceptance;
import kr.sbomsight.domain.Scan;
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
 * <p>구성은 자산 보고서와 같은 기 · 승 · 전 · 결이되, 기(起)가 다르다.
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
    private final RiskAcceptanceService acceptances;

    public ZoneReportService(AssetRepository assets, ZoneRepository zones, ScanRepository scans,
                             FindingRepository findings, RemediationRepository remediations,
                             RiskAcceptanceService acceptances) {
        this.assets = assets;
        this.zones = zones;
        this.scans = scans;
        this.findings = findings;
        this.remediations = remediations;
        this.acceptances = acceptances;
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
        Exposure exposure = exposure(current);
        Aggregate aggregate = aggregate(current, exposure, inScope, notScanned);
        Judgement judgement = judgement(current, baseline, exposure);
        Action action = action(zoneId, inScope, judgement, start, end);

        return new ZoneReport(scope, aggregate, judgement, action);
    }

    // --- 기(起): 무엇을, 언제, 얼마나 보았는가 ------------------------------

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
    private Exposure exposure(List<Scan> current) {
        if (current.isEmpty()) {
            return new Exposure(0, 0, 0, 0, Map.of(), Map.of());
        }
        long reachable = 0, reachableFixable = 0, scopeChanged = 0, unreadable = 0;
        Map<String, Long> byPackage = new HashMap<>();
        Map<Long, Long> byAsset = new HashMap<>();

        for (FindingRepository.ZoneExposureRow row : findings.exposureRowsIn(scanIds(current))) {
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

    // --- 승(承): 그 안이 어떻게 생겼는가 ------------------------------------

    private Aggregate aggregate(List<Scan> current, Exposure exposure,
                                List<Asset> inScope, List<Asset> notScanned) {
        Map<String, Long> severity = new LinkedHashMap<>();
        for (String key : List.of("critical", "high", "medium", "low", "negligible", "unknown")) {
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

        return new Aggregate(severity, fixState, total, fixable, noFix, unknownFix, rows, exposure);
    }

    // --- 전(轉): 그래서 무엇을 해야 하는가 ----------------------------------

    private Judgement judgement(List<Scan> current, List<Scan> baseline, Exposure exposure) {
        List<ZonePackageAction> actions = List.of();
        List<ZonePackageAction> blocked = List.of();

        if (!current.isEmpty()) {
            List<ZonePackageGroup> groups = findings.groupByPackageIn(scanIds(current));
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

    // --- 결(結): 무엇을 언제까지 누가 하는가 --------------------------------

    private Action action(Long zoneId, List<Asset> inScope, Judgement judgement,
                          Instant start, Instant end) {
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

        List<RiskAcceptance> accepted = acceptances.list(false, zoneId).stream()
                .filter(a -> scope.contains(a.getAsset().getId()))
                .toList();

        List<Remediation> overdueRows = all.stream()
                .filter(Remediation::isOverdue)
                .sorted(Comparator.comparing(Remediation::getDueDate))
                .toList();

        return new Action(all.size(), open, overdue, openedInPeriod, closedInPeriod,
                          overdueRows, accepted, judgement.blocked());
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
     * 기 — 무엇을, 언제, 얼마나 보았는가.
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

    /** 승 — 그 안이 어떻게 생겼는가. */
    public record Aggregate(Map<String, Long> severity, Map<String, Long> fixState,
                            long total, long fixable, long noFix, long unknownFix,
                            List<AssetRow> rows, Exposure exposure) {

        public long severityOf(String key) {
            return severity.getOrDefault(key, 0L);
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

    /** 전 — 그래서 무엇을 해야 하는가. */
    public record Judgement(List<ZonePackageAction> actions, List<ZonePackageAction> blocked,
                            Movement movement, Exposure exposure) {

        /** 상위 다섯 패키지가 덮는 건수 — "몇 개만 손대면 되는가". */
        public long topFiveCoverage() {
            return actions.stream().limit(5).mapToLong(ZonePackageAction::fixableCount).sum();
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

    /** 결 — 무엇을 언제까지 누가 하는가. */
    public record Action(long total, long open, long overdue,
                         long openedInPeriod, long closedInPeriod,
                         List<Remediation> overdueRows, List<RiskAcceptance> accepted,
                         List<ZonePackageAction> residual) {

        public boolean isAccepted(String packageName) {
            return accepted.stream().anyMatch(a -> a.getPackageName().equals(packageName));
        }

        public long acceptanceReviewOverdue() {
            return accepted.stream().filter(RiskAcceptance::isReviewOverdue).count();
        }

        /** 손댈 수 없는데 수용 기록도 없는 패키지 — 설명이 비어 있는 자리다. */
        public long unexplained() {
            return residual.stream().filter(r -> !isAccepted(r.packageName())).count();
        }
    }
}
