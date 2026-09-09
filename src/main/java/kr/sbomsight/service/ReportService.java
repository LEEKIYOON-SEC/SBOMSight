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
        Chapter1 ch1 = chapter1(scan);
        Chapter2 ch2 = chapter2(scan);
        Chapter3 ch3 = chapter3(scan);
        Chapter4 ch4 = chapter4(scan, ch3);
        return new Report(scan, ch1, ch2, ch3, ch4);
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

    private Chapter2 chapter2(Scan scan) {
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
                            groups.size(), kev, kevKnown);
    }

    private boolean hasAnyKevFlag(Scan scan) {
        // 한 건이라도 kev 가 true/false 로 채워져 있으면 grype 이 확인한 것이다.
        return findings.search(scan.getId(), null, null, Boolean.FALSE, null,
                               org.springframework.data.domain.PageRequest.of(0, 1))
                       .getTotalElements() > 0;
    }

    // --- 전(轉): 그래서 무엇이 문제인가 --------------------------------------

    private Chapter3 chapter3(Scan scan) {
        List<PackageGroup> groups = findings.groupByPackage(scan.getId());

        // 조치 하나로 몇 건이 사라지는가. 이것이 보고서의 핵심 표다.
        List<PackageAction> actions = groups.stream()
                .filter(g -> g.getFixable() > 0)
                .map(g -> new PackageAction(g, true))
                .toList();

        // 손댈 수 없는 것. 지우거나 감추지 않고 따로 세워 둔다 — 조치가 아니라
        // 다른 통제(접근 제한·모니터링)가 필요한 자리다.
        List<PackageAction> blocked = groups.stream()
                .filter(g -> g.getFixable() == 0)
                .map(g -> new PackageAction(g, false))
                .toList();

        Diff diff = diff(scan);
        return new Chapter3(actions, blocked, diff);
    }

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

    /** 승 — 그 안이 어떻게 생겼는가. */
    public record Chapter2(Map<String, Long> severity, Map<String, Long> fixState,
                           long fixable, long noFix, long unknownFix,
                           int packageCount, long kevCount, boolean kevKnown) {

        public long severityOf(String key) {
            return severity.getOrDefault(key, 0L);
        }

        /** 심각·높음 합. 먼저 봐야 하는 숫자다. */
        public long urgent() {
            return severityOf("critical") + severityOf("high");
        }
    }

    /** 전 — 그래서 무엇이 문제인가. */
    public record Chapter3(List<PackageAction> actions, List<PackageAction> blocked, Diff diff) {

        /** 조치로 없앨 수 있는 건수 합계. */
        public long resolvableFindings() {
            return actions.stream().mapToLong(PackageAction::fixableCount).sum();
        }

        /** 몇 개만 손대면 되는가 — 상위 다섯 패키지가 덮는 건수. */
        public long topFiveCoverage() {
            return actions.stream().limit(5).mapToLong(PackageAction::fixableCount).sum();
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
                                BigDecimal maxCvss, BigDecimal maxEpss) {

        PackageAction(PackageGroup group, boolean fixable) {
            this(group.getPackageName(), group.getPackageType(), group.getPackageVersion(),
                 group.getTargetVersion() == null ? "" : group.getTargetVersion(),
                 group.getTotal(), group.getFixable(), group.getKevCount(),
                 group.getCriticalCount(), group.getHighCount(),
                 group.getMaxCvss(), group.getMaxEpss());
        }

        public boolean hasTarget() {
            return targetVersion != null && !targetVersion.isBlank();
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
