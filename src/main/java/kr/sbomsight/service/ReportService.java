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
 * 점검 결과 보고서.
 *
 * <p><b>기승전결을 폐기했다.</b> 앞서 네 장에 각각 서술형 문단을 얹어
 * "…해 187건을 탐지했습니다", "…사라집니다" 로 풀어썼다. 읽는 사람은 결재를
 * 올리는 실무자인데, 그 문장들은 표에 이미 있는 숫자를 한 번 더 말할 뿐이었고
 * <b>누가 봐도 사람이 쓴 문서가 아니었다.</b>
 *
 * <p>점검 결과 보고서의 모양으로 바꾼다 — <b>문서 정보 + 번호 붙은 장, 내용은
 * 표.</b> 서술형 문단을 두지 않는다. 설명이 필요한 약어는 표 아래 각주 한 줄로
 * 단다.
 *
 * <pre>
 *   문서 정보   점검 대상 · 점검 일시 · 점검 도구 · SBOM · 작성일
 *   1. 점검 개요        패키지 · 탐지 · 고유 취약점 · 영향 패키지 · 제외
 *   2. 점검 결과 요약   심각도별 · 수정 가능 여부 · 접근 경로
 *   3. 조치 대상        패키지를 올리면 해소되는 것
 *   4. 수정 버전 없는 항목
 *   5. 조치 진행 현황
 *   6. 이전 검사 대비
 * </pre>
 *
 * <p>AI 는 쓰지 않는다. <b>grype 이 준 데이터만으로</b> 만든다.
 *
 * <p>"취약점 187건"은 손댈 곳을 알려 주지 않는다. 실무자가 실행하는 단위는
 * 패키지 업데이트이므로 3장과 5장은 패키지로 묶어 낸다.
 */
@Service
public class ReportService {

    private final FindingRepository findings;
    private final ScanRepository scans;
    private final RemediationRepository remediations;
    private final FindingAnalysisService analyses;

    public ReportService(FindingRepository findings, ScanRepository scans,
                         RemediationRepository remediations,
                         FindingAnalysisService analyses) {
        this.findings = findings;
        this.scans = scans;
        this.remediations = remediations;
        this.analyses = analyses;
    }

    @Transactional(readOnly = true)
    public Report build(Scan scan) {
        Exposure exposure = exposure(scan);
        Overview overview = overview(scan);
        Summary summary = summary(scan, exposure);
        Targets targets = targets(scan, exposure);
        Progress progress = progress(scan, targets);
        return new Report(scan, overview, summary, targets, progress,
                          java.time.Instant.now());
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

    // --- 1장: 점검 개요 ------------------------------------------------------

    private Overview overview(Scan scan) {
        return new Overview(
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
                scan.accountsBalance(),
                distinctVulnerabilities(scan),
                findings.groupByPackage(scan.getId()).size(),
                excludedByAnalysis(scan));
    }

    /** 고유 취약점 수 — 같은 CVE 가 여러 패키지에 걸리면 한 가지로 센다. 1장은 탐지 전부를 센다. */
    private long distinctVulnerabilities(Scan scan) {
        return findings.groupByCveIn(List.of(scan.getId()), null, null, null, null, true).size();
    }

    /**
     * <b>검토를 마쳐 목록에서 빠지는 건수.</b>
     *
     * <p>보고서는 이 수를 반드시 찍는다. 검토 결과로 목록에서 빠진 건이 있는데
     * 그 사실을 안 적으면, 숫자가 조용히 줄어든 보고서가 된다 — 점검에서
     * 문제가 되는 것이 정확히 그것이다. <b>탐지 건수 자체는 줄지 않는다.</b>
     *
     * <p>적어 둔 번호가 grype 의 주 식별자일 수도, 함께 온 CVE 번호일 수도
     * 있다. 둘 다 본다 — 한쪽만 보면 적어 둔 것이 보고서에서 사라진다.
     */
    private long excludedByAnalysis(Scan scan) {
        Set<String> done = analyses.forAsset(scan.getAsset().getId()).stream()
                .filter(a -> !a.isOpen())
                .map(FindingAnalysis::key)
                .collect(Collectors.toSet());
        if (done.isEmpty()) {
            return 0;
        }
        return findings.findKeyRows(scan.getId()).stream()
                .filter(row -> done.contains(row.getCve() + "|" + row.getPackageName())
                            || (row.getRelatedCve() != null && !row.getRelatedCve().isBlank()
                                && done.contains(row.getRelatedCve() + "|" + row.getPackageName())))
                .count();
    }

    // --- 2장: 점검 결과 요약 -------------------------------------------------

    private Summary summary(Scan scan, Exposure exposure) {
        Map<String, Long> severity = new LinkedHashMap<>();
        // 순서는 Severity 한곳에 있다. 여기 다시 적으면 곧 갈라진다.
        for (String key : Severity.KEYS) {
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

        return new Summary(severity, fixState, fixable, noFix, unknownFix,
                           groups.size(), kev, kevKnown, exposure, scan.getFindingCount(),
                           reviewCounts(scan));
    }

    /**
     * <b>2.4 — 우리가 몇 건을 봤는가.</b>
     *
     * <p>2.1~2.3 은 전부 grype 의 축(심각도 · 수정 가능 여부 · 접근 경로)이다.
     * 이 도구가 하는 일은 그 목록을 <b>검토하고 조치를 추적하는 것</b>인데,
     * 그 축이 보고서 요약에 한 줄도 없었다 — "48건 중 몇 건을 봤나" 에 답할
     * 자리가 없었다.
     *
     * <p><b>`미검토` 와 `검토 중` 을 가른다.</b> 앞서 4장 각주의
     * `검토 결과 없음` 은 기록이 아예 없는 것만 셌다. `검토 중` 으로 열어 두고
     * 반년 방치한 건이 "설명됨" 으로 집계됐다 — 아무도 손대지 않은 것과
     * 보고 있는 것은 다른 상태다.
     *
     * <p>맞추는 규칙은 {@link FindingAnalysisService#stateOf}에 한 곳으로
     * 둔다. 1장의 `제외` 집계와 같은 규칙이어야 두 수가 어긋나지 않는다.
     */
    private Map<AnalysisState, Long> reviewCounts(Scan scan) {
        Map<String, FindingAnalysis> byKey = analyses.byKey(scan.getAsset().getId());
        Map<AnalysisState, Long> counts = FindingAnalysisService.emptyStateCounts();
        for (FindingRepository.FindingKey row : findings.findKeyRows(scan.getId())) {
            AnalysisState state = FindingAnalysisService.stateOf(
                    byKey, row.getCve(), row.getRelatedCve(), row.getPackageName());
            counts.merge(state, 1L, Long::sum);
        }
        return counts;
    }

    private boolean hasAnyKevFlag(Scan scan) {
        // 한 건이라도 kev 가 true/false 로 채워져 있으면 grype 이 확인한 것이다.
        return findings.search(scan.getId(), null, null, Boolean.FALSE, null,
                               org.springframework.data.domain.PageRequest.of(0, 1))
                       .getTotalElements() > 0;
    }

    // --- 3·4장: 조치 대상과 수정 버전 없는 항목 -------------------------------

    private Targets targets(Scan scan, Exposure exposure) {
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
        // 4장은 '손댈 수 없는 것' 에 우리가 적어 둔 검토 결과를 붙여 낸다.
        //
        // **패키지 하나에 검토 결과가 여럿 달린다** — 검토는 (자산, CVE,
        // 패키지)에 하나씩이고 이 표는 패키지로 한 줄이다. 그중 하나를 골라
        // 붙이는 것은 그 줄의 `근거` 를 채우기 위한 것이고, <b>그 패키지가
        // 검토됐는지는 건 수로 센다</b>(`reviewByPackage`).
        Map<String, FindingAnalysis> byPackage = analyses.forAsset(scan.getAsset().getId())
                .stream()
                .collect(Collectors.toMap(FindingAnalysis::getPackageName, a -> a, (a, b) -> a));
        Map<String, Reviewed> reviewed = reviewByPackage(scan);
        List<NoFixRow> noFixRows = blocked.stream()
                .map(b -> new NoFixRow(b, byPackage.get(b.packageName()),
                                       reviewed.getOrDefault(b.packageName(),
                                                             new Reviewed(0, b.total()))))
                .toList();
        return new Targets(actions, blocked, noFixRows, diff, exposure);
    }

    /**
     * 패키지마다 <b>몇 건에 답이 있나.</b>
     *
     * <p>2.4 와 <b>같은 걸음으로 센다</b> — 같은 탐지 목록을 훑고 같은
     * {@link FindingAnalysisService#stateOf} 로 맞춘다. 규칙이 갈리면 한 보고서
     * 안에서 2.4 의 `미검토 30건` 과 4장의 `해당 없음` 이 서로를 부정한다.
     */
    private Map<String, Reviewed> reviewByPackage(Scan scan) {
        Map<String, FindingAnalysis> byKey = analyses.byKey(scan.getAsset().getId());
        Map<String, long[]> counts = new LinkedHashMap<>();
        for (FindingRepository.FindingKey row : findings.findKeyRows(scan.getId())) {
            long[] cell = counts.computeIfAbsent(row.getPackageName(), name -> new long[2]);
            cell[1]++;
            if (FindingAnalysisService.stateOf(byKey, row.getCve(), row.getRelatedCve(),
                                               row.getPackageName()) != AnalysisState.NOT_SET) {
                cell[0]++;
            }
        }
        Map<String, Reviewed> out = new LinkedHashMap<>();
        counts.forEach((name, cell) -> out.put(name, new Reviewed(cell[0], cell[1])));
        return out;
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

    // --- 5장: 조치 진행 현황 -------------------------------------------------

    private Progress progress(Scan scan, Targets targets) {
        // 4장이 센 것을 그대로 쓴다 — 5장의 `검토 결과 없음` 과 4장의 표가
        // 다른 규칙으로 세면 같은 패키지를 두 장이 다르게 말한다.
        Map<String, Reviewed> reviewed = targets.noFixRows().stream()
                .collect(Collectors.toMap(r -> r.action().packageName(), NoFixRow::reviewed,
                                          (a, b) -> a, LinkedHashMap::new));
        Map<String, Remediation> byPackage = remediations
                .findByAssetIdOrderByStatusAscPackageNameAsc(scan.getAsset().getId()).stream()
                .collect(Collectors.toMap(Remediation::getPackageName, r -> r, (a, b) -> a));

        List<ActionRow> rows = targets.fixTargets().stream()
                .map(action -> new ActionRow(action, byPackage.get(action.packageName())))
                .toList();

        long tracked = rows.stream().filter(r -> r.remediation() != null).count();
        long overdue = rows.stream()
                .filter(r -> r.remediation() != null && r.remediation().isOverdue()).count();

        // 고칠 수 없는 건에 "왜 그대로 두는가" 가 적혀 있는지. 점검에서
        // 반드시 묻는 것이고, 답이 없으면 방치로 읽힌다.
        //
        // 검토가 끝난 것(해당 없음·오탐)도 가져온다 — 목록에서는 빠지지만
        // "왜 그대로 두는가" 에는 그것도 답이다.
        List<FindingAnalysis> explained =
                analyses.list(true, null).stream()
                        .filter(a -> a.getAsset().getId().equals(scan.getAsset().getId()))
                        .toList();

        return new Progress(rows, tracked, rows.size() - tracked, overdue,
                            targets.blocked(), explained, reviewed);
    }

    private String key(String value) {
        return value == null || value.isBlank() ? "unknown" : value.toLowerCase();
    }

    // -----------------------------------------------------------------------
    // 화면에 넘기는 모양
    // -----------------------------------------------------------------------

    public record Report(Scan scan, Overview overview, Summary summary,
                         Targets targets, Progress progress, java.time.Instant printedAt) {
    }

    /** 1장 — 점검 개요. */
    public record Overview(Asset asset, String sbomFilename, int componentCount, int findingCount,
                           String grypeVersion, java.time.Instant grypeDbBuilt,
                           String distroName, String distroVersion,
                           int matchCount, int mergedCount, int droppedCount, boolean balanced,
                           long distinctVulnerabilities, int affectedPackages,
                           long excludedByAnalysis) {

        /** 회계에 설명할 것이 있는가 — 없으면 그 줄 자체를 싣지 않는다. */
        public boolean hasAccountingNote() {
            return mergedCount > 0 || droppedCount > 0 || !balanced;
        }
    }

    /**
     * 어떻게 닿을 수 있는 건인가 — grype 이 준 CVSS 벡터를 풀어 센 것.
     *
     * @param reachable        원격 · 인증 불필요 · 사용자 개입 불필요 (AV:N/PR:N/UI:N)
     * @param reachableFixable 그중 패키지를 올리면 사라지는 것
     * @param scopeChanged     영향 범위 변경 (S:C) — 취약한 것 <b>밖</b>의 자원까지
     *                         영향이 미치는 것. 권한 상승과는 다른 축이다
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

    /** 2장 — 점검 결과 요약. */
    public record Summary(Map<String, Long> severity, Map<String, Long> fixState,
                          long fixable, long noFix, long unknownFix,
                          int packageCount, long kevCount, boolean kevKnown,
                          Exposure exposure, int total,
                          Map<AnalysisState, Long> review) {

        public long severityOf(String key) {
            return severity.getOrDefault(key, 0L);
        }

        /** 2.4 한 줄. */
        public long reviewOf(AnalysisState state) {
            return review.getOrDefault(state, 0L);
        }

        /** 아직 아무도 보지 않은 건. 2.4 에서 가장 먼저 읽히는 수다. */
        public long notReviewed() {
            return reviewOf(AnalysisState.NOT_SET);
        }

        /** 누군가 손댄 건 — 미검토가 아닌 것 전부. */
        public long reviewed() {
            return total - notReviewed();
        }

        /** 심각·높음 합. 먼저 봐야 하는 숫자다. */
        public long urgent() {
            return severityOf("critical") + severityOf("high");
        }

        /**
         * 비중(%). 표에 건수와 나란히 놓는다.
         *
         * <p>전체가 0 이면 <b>0% 가 아니라 값이 없다.</b> 0으로 적으면 "0%"
         * 라는, 세어 본 적 없는 숫자가 표에 앉는다.
         */
        public String share(long count) {
            return total <= 0 ? "—"
                    : String.format("%.1f%%", count * 100.0 / total);
        }
    }

    /** 3·4장 — 조치 대상과 수정 버전 없는 항목. */
    public record Targets(List<PackageAction> fixTargets, List<PackageAction> blocked,
                          List<NoFixRow> noFixRows, Diff diff, Exposure exposure) {

        /** 조치로 없앨 수 있는 건수 합계. 3장 표의 합계 줄이다. */
        public long resolvableFindings() {
            return fixTargets.stream().mapToLong(PackageAction::fixableCount).sum();
        }

        /** 3장 표가 덮는 '원격 접근' 건수 합계. */
        public long resolvableReach() {
            return fixTargets.stream().mapToLong(PackageAction::reachableCount).sum();
        }

        /** 4장 표의 건수 합계. */
        public long blockedFindings() {
            return blocked.stream().mapToLong(PackageAction::total).sum();
        }
    }

    /**
     * 4장 한 줄 — 손댈 수 없는 패키지와, 우리가 적어 둔 검토 결과.
     *
     * <p>검토 결과가 없으면 {@code analysis} 가 {@code null} 이다. <b>비어
     * 있다는 것을 그대로 보여 준다</b> — 점검에서 "이건 왜 안 고쳤냐" 를
     * 묻는 자리가 여기다.
     *
     * <p><b>{@code analysis} 가 있다는 것이 "이 패키지를 검토했다" 는 뜻은
     * 아니다.</b> 검토는 {@code (자산, CVE, 패키지)} 하나에 하나씩 달리고 이
     * 줄은 패키지 하나다. {@code reviewed} 가 그 묶음의 <b>몇 건에 답이
     * 있는지</b>를 센다 — 그것 없이 앞의 {@code null} 검사만으로 `해당 없음`
     * 을 찍고 있었고, 세 건 중 한 건만 적어 둔 패키지가 전부 설명된 것으로
     * 읽혔다.
     */
    public record NoFixRow(PackageAction action, FindingAnalysis analysis, Reviewed reviewed) {

        /** 그 줄에 붙일 근거가 있는가 — 검토가 <b>끝났는가와는 다르다.</b> */
        public boolean hasAnalysis() {
            return analysis != null;
        }
    }

    /**
     * 5장 — 조치 진행 현황.
     *
     * <p><b>단위가 둘이다.</b> {@code tracked}/{@code untracked} 는
     * <b>패키지</b> 수이고({@link Remediation} 이 (자산, 패키지)로 등록된다),
     * {@code trackedFindings}/{@code untrackedFindings} 는 그것이 덮는
     * <b>건</b> 수다. 보고서가 "미등록 15개" 라고만 쓰면 읽는 사람은 그 15 가
     * 48건 중 얼마인지 알 수 없다 — <b>단위가 말없이 바뀌는 자리</b>이고,
     * 결재로 올라가는 문서에서 그것이 가장 먼저 의심받는다. 늘 함께 적는다.
     */
    public record Progress(List<ActionRow> rows, long tracked, long untracked, long overdue,
                           List<PackageAction> residual, List<FindingAnalysis> explained,
                           Map<String, Reviewed> reviewed) {

        /** 등록된 조치가 덮는 건수. 3장의 `해소 건수` 와 같은 축이다. */
        public long trackedFindings() {
            return rows.stream().filter(ActionRow::isTracked)
                       .mapToLong(r -> r.action().fixableCount()).sum();
        }

        /** 아직 아무도 맡지 않은 건수. */
        public long untrackedFindings() {
            return rows.stream().filter(r -> !r.isTracked())
                       .mapToLong(r -> r.action().fixableCount()).sum();
        }

        /**
         * 이 패키지의 <b>모든 건</b>에 답이 있는가.
         *
         * <p>앞서 {@code explained} 에 그 패키지 이름이 한 번이라도 있으면
         * 참이었다. 그러면 세 건 중 한 건만 적어 둔 패키지가 설명된 것으로
         * 세어지고, 아래 {@code unexplained()} 가 보고서에 찍는 수가 실제보다
         * 작아진다 — <b>실제보다 안전해 보이는 숫자</b>다.
         */
        public boolean isExplained(String packageName) {
            Reviewed r = reviewed.get(packageName);
            return r != null && r.all();
        }

        /** 재검토일이 지난 검토 결과. 기한이 있어야 방치와 구분된다. */
        public long reviewOverdue() {
            return explained.stream().filter(FindingAnalysis::isReviewOverdue).count();
        }

        /** 손댈 수 없는데 <b>답이 없는 건이 남은</b> 패키지 — 설명이 빈 자리다. */
        public long unexplained() {
            return residual.stream().filter(r -> !isExplained(r.packageName())).count();
        }
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
