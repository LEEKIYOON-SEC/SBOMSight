package kr.sbomsight.service;

import kr.sbomsight.domain.*;
import kr.sbomsight.repo.FindingRepository;
import kr.sbomsight.repo.FindingRepository.PackageGroup;
import kr.sbomsight.repo.RemediationRepository;
import kr.sbomsight.repo.ScanRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 보고서 — 기 · 승 · 전 · 결.
 *
 * <p>AI 는 쓰지 않는다. <b>grype 이 준 데이터만으로</b> 네 장을 만든다.
 *
 * <pre>
 *   기(起) 현황   무엇을, 언제, 무엇으로 봤는가
 *                 자산 · SBOM · grype 판과 DB 기준일 · 총 탐지
 *   승(承) 분석   그 안이 어떻게 생겼는가
 *                 심각도 분포 · 수정 가능 여부 · 실제 악용 · 매칭 근거
 *   전(轉) 판단   그래서 무엇이 문제인가
 *                 조치 하나로 몇 건이 사라지는가 · 손댈 수 없는 것은 무엇인가
 *                 · 지난번 대비 무엇이 늘고 줄었는가
 *   결(結) 조치   무엇을 언제까지 누가 하는가
 *                 조치 목록 · 잔여 위험
 * </pre>
 *
 * <p>"CVE 187건"은 손댈 곳을 알려 주지 않는다. 실무자가 실행하는 단위는 패키지
 * 업데이트이므로 전(轉)과 결(結)은 패키지로 묶어 낸다.
 */
@Service
public class ReportService {

    private final FindingRepository findings;
    private final ScanRepository scans;
    private final RemediationRepository remediations;

    public ReportService(FindingRepository findings, ScanRepository scans,
                         RemediationRepository remediations) {
        this.findings = findings;
        this.scans = scans;
        this.remediations = remediations;
    }

    @Transactional(readOnly = true)
    public Report build(Scan scan) {
        Exposure exposure = exposure(scan);
        Chapter1 ch1 = chapter1(scan);
        Chapter2 ch2 = chapter2(scan, exposure);
        Chapter3 ch3 = chapter3(scan, exposure);
        Chapter4 ch4 = chapter4(scan, ch3);
        return new Report(scan, ch1, ch2, ch3, ch4);
    }

    // --- 노출면 --------------------------------------------------------------

    /**
     * grype 이 준 CVSS 벡터를 풀어 <b>어떻게 닿을 수 있는 건인지</b>를 센다.
     *
     * <p>지금까지 이 값은 {@code cvss_vector} 열에 저장만 되고 화면·보고서
     * 어디에도 쓰이지 않았다. 실제 98건짜리 스캔에서 96건이 벡터를 가지고
     * 있었고, 그중 78건이 <i>원격 · 인증 불필요 · 사용자 개입 불필요</i>였다.
     * "심각 21건"보다 이 수가 대응 순서를 훨씬 잘 정해 준다.
     *
     * <p>벡터를 읽을 수 없는 건은 <b>세지 않고 따로 센다.</b> 아니오로 밀어
     * 넣으면 "원격에서 닿지 않습니다" 라는, 아무도 확인하지 않은 판정이 된다.
     */
    private Exposure exposure(Scan scan) {
        long reachable = 0, reachableFixable = 0, scopeChanged = 0, unreadable = 0;
        Map<String, Long> reachableByPackage = new HashMap<>();

        for (FindingRepository.ExposureRow row : findings.exposureRows(scan.getId())) {
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
                reachableByPackage.merge(row.getPackageName(), 1L, Long::sum);
            }
        }

        return new Exposure(reachable, reachableFixable, scopeChanged, unreadable, reachableByPackage);
    }

    // --- 기(起): 무엇을, 언제, 무엇으로 봤는가 ------------------------------

    private Chapter1 chapter1(Scan scan) {
        return new Chapter1(
                scan.getAsset(),
                scan.getSbomFilename(),
                scan.getComponentCount(),
                scan.getFindingCount(),
                scan.getGrypeVersion(),
                scan.getGrypeDbBuilt(),
                scan.getDistroName(),
                scan.getDistroVersion(),
                scan.getMatchCount(),
                scan.getMergedCount(),
                scan.getDroppedCount(),
                scan.accountsBalance());
    }

    // --- 승(承): 그 안이 어떻게 생겼는가 ------------------------------------

    private Chapter2 chapter2(Scan scan, Exposure exposure) {
        Map<String, Long> severity = new LinkedHashMap<>();
        for (String key : List.of("critical", "high", "medium", "low", "negligible", "unknown")) {
            severity.put(key, 0L);
        }
        findings.countBySeverity(scan.getId())
                .forEach(row -> severity.merge(key(row.getSeverity()), row.getTotal(), Long::sum));

        Map<String, Long> fixState = new LinkedHashMap<>();
        findings.countByFixState(scan.getId())
                .forEach(row -> fixState.merge(key(row.getFixState()), row.getTotal(), Long::sum));

        long fixable = fixState.getOrDefault("fixed", 0L);
        long noFix = fixState.getOrDefault("wont-fix", 0L) + fixState.getOrDefault("not-fixed", 0L);
        long unknownFix = scan.getFindingCount() - fixable - noFix;

        List<PackageGroup> groups = findings.groupByPackage(scan.getId());
        long kev = groups.stream().mapToLong(PackageGroup::getKevCount).sum();
        // grype 이 KEV 를 확인했는지 자체를 모를 수 있다(옛 판은 주지 않는다).
        boolean kevKnown = groups.stream().anyMatch(g -> g.getKevCount() > 0)
                || hasAnyKevFlag(scan);

        return new Chapter2(severity, fixState, fixable, noFix, unknownFix,
                            groups.size(), kev, kevKnown, exposure);
    }

    private boolean hasAnyKevFlag(Scan scan) {
        // 한 건이라도 kev 가 true/false 로 채워져 있으면 grype 이 확인한 것이다.
        return findings.search(scan.getId(), null, null, Boolean.FALSE, null,
                               org.springframework.data.domain.PageRequest.of(0, 1))
                       .getTotalElements() > 0;
    }

    // --- 전(轉): 그래서 무엇이 문제인가 --------------------------------------

    private Chapter3 chapter3(Scan scan, Exposure exposure) {
        List<PackageGroup> groups = findings.groupByPackage(scan.getId());

        // 조치 하나로 몇 건이 사라지는가. 이것이 보고서의 핵심 표다.
        //
        // 순서는 '밖에서 바로 닿는 건이 몇 개 딸려 있는가'를 먼저 본다. 같은
        // CVSS 라도 인증이 필요한 건과 아닌 건은 먼저 할 일이 다르다. 이것은
        // 표시 순서를 정하는 일이지 grype 의 판정을 바꾸는 것이 아니다 —
        // 건수도 심각도도 수정 상태도 grype 이 준 그대로다.
        List<PackageAction> actions = groups.stream()
                .filter(g -> g.getFixable() > 0)
                .map(g -> new PackageAction(g, exposure.reachableIn(g.getPackageName())))
                .sorted(BY_URGENCY)
                .toList();

        // 손댈 수 없는 것. 지우거나 감추지 않고 따로 세워 둔다 — 조치가 아니라
        // 다른 통제(접근 제한·모니터링)가 필요한 자리다.
        List<PackageAction> blocked = groups.stream()
                .filter(g -> g.getFixable() == 0)
                .map(g -> new PackageAction(g, exposure.reachableIn(g.getPackageName())))
                .sorted(BY_URGENCY)
                .toList();

        Diff diff = diff(scan);
        return new Chapter3(actions, blocked, diff, exposure);
    }

    /**
     * 먼저 손댈 것부터.
     *
     * <p>바로 닿는 건 수 → 실제 악용 확인 → 최고 CVSS → 건수. 앞의 것이 같을
     * 때만 뒤를 본다.
     */
    private static final Comparator<PackageAction> BY_URGENCY =
            Comparator.comparingLong(PackageAction::reachableCount).reversed()
                      .thenComparing(Comparator.comparingLong(PackageAction::kevCount).reversed())
                      .thenComparing(PackageAction::maxCvss,
                                     Comparator.nullsLast(Comparator.reverseOrder()))
                      .thenComparing(Comparator.comparingLong(PackageAction::total).reversed())
                      .thenComparing(PackageAction::packageName);

    /**
     * 지난 스캔 대비 신규 · 해소 · 유지.
     *
     * <p>{@code (CVE, 패키지명)} 으로 대조한다. 버전을 넣으면 패치했을 때 키가
     * 바뀌어 "해소 1건 + 신규 1건"으로 갈라져 화면이 거짓말을 한다.
     */
    private Diff diff(Scan scan) {
        Optional<Scan> previous = scans.findByAssetIdOrderByCreatedAtDesc(scan.getAsset().getId())
                .stream()
                .filter(s -> s.getStatus() == ScanStatus.DONE)
                .filter(s -> s.getCreatedAt().isBefore(scan.getCreatedAt()))
                .findFirst();

        if (previous.isEmpty()) {
            return new Diff(null, 0, 0, 0);
        }

        Set<String> now = new HashSet<>(findings.findCvePackagePairs(scan.getId()));
        Set<String> before = new HashSet<>(findings.findCvePackagePairs(previous.get().getId()));

        long added = now.stream().filter(k -> !before.contains(k)).count();
        long resolved = before.stream().filter(k -> !now.contains(k)).count();
        long kept = now.stream().filter(before::contains).count();
        return new Diff(previous.get(), added, resolved, kept);
    }

    // --- 결(結): 무엇을 언제까지 누가 하는가 --------------------------------

    private Chapter4 chapter4(Scan scan, Chapter3 ch3) {
        Map<String, Remediation> byPackage = remediations
                .findByAssetIdOrderByStatusAscPackageNameAsc(scan.getAsset().getId()).stream()
                .collect(Collectors.toMap(Remediation::getPackageName, r -> r, (a, b) -> a));

        List<ActionRow> rows = ch3.actions().stream()
                .map(action -> new ActionRow(action, byPackage.get(action.packageName())))
                .toList();

        long tracked = rows.stream().filter(r -> r.remediation() != null).count();
        long overdue = rows.stream()
                .filter(r -> r.remediation() != null && r.remediation().isOverdue()).count();

        return new Chapter4(rows, tracked, rows.size() - tracked, overdue, ch3.blocked());
    }

    private String key(String value) {
        return value == null || value.isBlank() ? "unknown" : value.toLowerCase();
    }

    // -----------------------------------------------------------------------
    // 화면에 넘기는 모양
    // -----------------------------------------------------------------------

    public record Report(Scan scan, Chapter1 status, Chapter2 analysis,
                         Chapter3 judgement, Chapter4 action) {
    }

    /** 기 — 무엇을, 언제, 무엇으로 봤는가. */
    public record Chapter1(Asset asset, String sbomFilename, int componentCount, int findingCount,
                           String grypeVersion, java.time.Instant grypeDbBuilt,
                           String distroName, String distroVersion,
                           int matchCount, int mergedCount, int droppedCount, boolean balanced) {

        /** 회계에 설명할 것이 있는가 — 없으면 이 문단 자체를 싣지 않는다. */
        public boolean hasAccountingNote() {
            return mergedCount > 0 || droppedCount > 0 || !balanced;
        }
    }

    /**
     * 어떻게 닿을 수 있는 건인가 — grype 이 준 CVSS 벡터를 풀어 센 것.
     *
     * @param reachable        원격 · 인증 불필요 · 사용자 개입 불필요 (AV:N/PR:N/UI:N)
     * @param reachableFixable 그중 패키지를 올리면 사라지는 것
     * @param scopeChanged     권한 경계를 넘는 것 (S:C)
     * @param unreadable       벡터가 없거나 3.x 가 아니어서 <b>판단하지 못한</b> 것.
     *                         0 이 아니라 판단 불가다 — 아니오로 세지 않는다.
     */
    public record Exposure(long reachable, long reachableFixable, long scopeChanged,
                           long unreadable, Map<String, Long> reachableByPackage) {

        public long reachableIn(String packageName) {
            return reachableByPackage.getOrDefault(packageName, 0L);
        }

        /** 바로 닿는데 수정본이 없는 것. 가장 곤란한 자리다. */
        public long reachableWithoutFix() {
            return reachable - reachableFixable;
        }

        /** 한 건도 읽지 못했으면 이 문단을 싣지 않는다 — 0건이라고 말하면 거짓이다. */
        public boolean measured() {
            return reachable > 0 || reachableFixable > 0 || scopeChanged > 0
                    || unreadable == 0;
        }
    }

    /** 승 — 그 안이 어떻게 생겼는가. */
    public record Chapter2(Map<String, Long> severity, Map<String, Long> fixState,
                           long fixable, long noFix, long unknownFix,
                           int packageCount, long kevCount, boolean kevKnown,
                           Exposure exposure) {

        public long severityOf(String key) {
            return severity.getOrDefault(key, 0L);
        }

        /** 심각·높음 합. 먼저 봐야 하는 숫자다. */
        public long urgent() {
            return severityOf("critical") + severityOf("high");
        }
    }

    /** 전 — 그래서 무엇이 문제인가. */
    public record Chapter3(List<PackageAction> actions, List<PackageAction> blocked,
                           Diff diff, Exposure exposure) {

        /** 조치로 없앨 수 있는 건수 합계. */
        public long resolvableFindings() {
            return actions.stream().mapToLong(PackageAction::fixableCount).sum();
        }

        /** 몇 개만 손대면 되는가 — 상위 다섯 패키지가 덮는 건수. */
        public long topFiveCoverage() {
            return actions.stream().limit(5).mapToLong(PackageAction::fixableCount).sum();
        }

        /** 상위 다섯 패키지가 덮는 '바로 닿는' 건수. */
        public long topFiveReach() {
            return actions.stream().limit(5).mapToLong(PackageAction::reachableCount).sum();
        }

        /** 바로 닿는 건을 하나라도 품은 패키지 수 — 먼저 손댈 대상의 크기다. */
        public long reachablePackages() {
            return actions.stream().filter(a -> a.reachableCount() > 0).count();
        }
    }

    /** 결 — 무엇을 언제까지 누가 하는가. */
    public record Chapter4(List<ActionRow> rows, long tracked, long untracked, long overdue,
                           List<PackageAction> residual) {
    }

    /** 패키지 하나에 대한 조치 후보. */
    public record PackageAction(String packageName, String packageType, String currentVersion,
                                String targetVersion, long total, long fixableCount,
                                long kevCount, long criticalCount, long highCount,
                                BigDecimal maxCvss, BigDecimal maxEpss, long reachableCount) {

        PackageAction(PackageGroup group, long reachableCount) {
            this(group.getPackageName(), group.getPackageType(), group.getPackageVersion(),
                 group.getTargetVersion() == null ? "" : group.getTargetVersion(),
                 group.getTotal(), group.getFixable(), group.getKevCount(),
                 group.getCriticalCount(), group.getHighCount(),
                 group.getMaxCvss(), group.getMaxEpss(), reachableCount);
        }

        public boolean hasTarget() {
            return targetVersion != null && !targetVersion.isBlank();
        }

        public boolean hasReachable() {
            return reachableCount > 0;
        }
    }

    /** 조치 표 한 줄 — 후보와, 실제로 등록된 조치가 있으면 그것. */
    public record ActionRow(PackageAction action, Remediation remediation) {

        public boolean isTracked() {
            return remediation != null;
        }
    }

    /** 지난 스캔 대비. */
    public record Diff(Scan previous, long added, long resolved, long kept) {

        public boolean hasPrevious() {
            return previous != null;
        }
    }
}
