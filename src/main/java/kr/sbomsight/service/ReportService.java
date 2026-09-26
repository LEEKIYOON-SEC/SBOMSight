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
 *   6. 이전 검사 대비   + 최근 검사 추이(완료 검사 여섯 번까지)
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
        // **1·2장은 탐지 전부, 3·4장(과 그것을 잇는 5장)은 목록이다.** 목록은
        // 검토 결과가 해당 없음 · 오탐인 건을 뺀다 — 취약점 화면과 같은 규칙
        // (FindingRepository 의 includeReviewed). 뺀 건수는 1장이 말한다.
        // 앞서 1장은 "목록에서 제외" 라고 적으면서 어느 장도 빼지 않았다.
        Map<AnalysisState, Long> review = reviewCounts(scan);
        Exposure exposure = exposure(scan, true);
        Overview overview = overview(scan, review);
        Summary summary = summary(scan, exposure, review);
        Targets targets = targets(scan, exposure(scan, false));
        Progress progress = progress(scan, targets);
        // 부록 — 실제 악용 · 심각과 그 설명 첫 문장(Appendix). 목록이다: 해당
        // 없음 · 오탐은 3 · 4장처럼 뺀다.
        List<Appendix.Row> appendix = Appendix.of(findings.findUrgentIn(List.of(scan.getId()), false));
        return new Report(scan, overview, summary, targets, progress, trend(scan), appendix,
                          java.time.Instant.now());
    }

    /** 6장 아래 표에 싣는 완료 검사 수 — 이 검사까지. */
    private static final int TREND = 6;

    /**
     * <b>최근 검사 추이</b> — 이 검사까지 완료 검사 여섯 번, 오래된 것부터.
     *
     * <p>6장은 바로 앞 검사 하나와만 댄다. 그것만으로는 줄고 있는지 늘고 있는지
     * 알 수 없다 — 한 번 줄었다가 다시 느는 것이 보이지 않는다. 검사 결과가 낸
     * 수를 그대로 늘어놓는다(다시 세지 않는다). 같은 SBOM 을 새 DB 로 다시 검사한
     * 것은 화면이 표시한다 — 자산이 아니라 취약점 DB 가 움직인 것이다.
     *
     * <p>앞 검사는 6장 위 표({@link #diff})와 <b>같은 규칙</b>으로 고른다 — 이
     * 검사보다 먼저 끝난 완료 검사. 그래야 이 표의 끝에서 둘째 줄이 위 표의
     * `이전 검사` 와 같은 검사다. 실패한 검사는 넣지 않는다 — 0건이 아니라 모르는 것이다.
     *
     * <p>앞 검사가 없으면 비운다 — 한 줄짜리 추이는 없다.
     */
    private List<TrendRow> trend(Scan scan) {
        List<Scan> recent = new ArrayList<>(scans.findByAssetIdOrderByCreatedAtDesc(scan.getAsset().getId())
                .stream()
                .filter(s -> s.getStatus() == ScanStatus.DONE)
                .filter(s -> s.getCreatedAt().isBefore(scan.getCreatedAt()))
                .limit(TREND - 1)
                .toList());
        if (recent.isEmpty()) {
            return List.of();
        }
        Collections.reverse(recent);    // 오래된 것부터
        recent.add(scan);
        Map<Long, Map<String, Long>> bySeverity = new HashMap<>();
        findings.countBySeverityPerScan(recent.stream().map(Scan::getId).toList())
                .forEach(r -> bySeverity.computeIfAbsent(r.getScanId(), id -> new HashMap<>())
                                        .merge(key(r.getSeverity()), r.getTotal(), Long::sum));
        List<TrendRow> rows = new ArrayList<>();
        for (Scan s : recent) {
            Map<String, Long> sev = bySeverity.getOrDefault(s.getId(), Map.of());
            rows.add(new TrendRow(s, sev.getOrDefault("critical", 0L), sev.getOrDefault("high", 0L),
                                  s.getId().equals(scan.getId())));
        }
        return rows;
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
    private Exposure exposure(Scan scan, boolean includeReviewed) {
        long reachable = 0, reachableFixable = 0, scopeChanged = 0, unreadable = 0;
        Map<String, Long> reachableByPackage = new HashMap<>();

        for (FindingRepository.ExposureRow row
                : findings.exposureRows(scan.getId(), includeReviewed)) {
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

    private Overview overview(Scan scan, Map<AnalysisState, Long> review) {
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
                findings.groupByPackage(scan.getId(), true).size(),
                review.get(AnalysisState.NOT_AFFECTED) + review.get(AnalysisState.FALSE_POSITIVE));
    }

    /** 고유 취약점 수 — 같은 CVE 가 여러 패키지에 걸리면 한 가지로 센다. 1장은 탐지 전부를 센다. */
    private long distinctVulnerabilities(Scan scan) {
        return findings.groupByCveIn(List.of(scan.getId()), null, null, null, null, true).size();
    }

    // --- 2장: 점검 결과 요약 -------------------------------------------------

    private Summary summary(Scan scan, Exposure exposure, Map<AnalysisState, Long> review) {
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

        List<PackageGroup> groups = findings.groupByPackage(scan.getId(), true);
        long kev = groups.stream().mapToLong(PackageGroup::getKevCount).sum();
        // grype 이 KEV 를 확인했는지 자체를 모를 수 있다(옛 판은 주지 않는다).
        boolean kevKnown = groups.stream().anyMatch(g -> g.getKevCount() > 0)
                || hasAnyKevFlag(scan);

        return new Summary(severity, fixState, fixable, noFix, unknownFix,
                           groups.size(), kev, kevKnown, exposure, scan.getFindingCount(),
                           review);
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
        // 목록이다 — 해당 없음 · 오탐은 뺀다. `원격 접근` 도 같은 규칙으로 센
        // 노출면(exposure)을 받는다. 한 줄 안에서 `해소 건수` 는 뺐는데
        // `원격 접근` 은 넣으면 두 칸이 서로 다른 건을 센다.
        List<PackageGroup> groups = findings.groupByPackage(scan.getId(), false);

        // 수정 버전은 하나로 고르지 않는다 — 그 줄에 실린 탐지(해당 없음 ·
        // 오탐을 뺀 것)의 수정 버전 전부(FixVersions). 묶음 키와 같은
        // (이름, 버전, 유형)으로 모은다.
        Map<String, List<String>> fixes = findings
                .fixVersionsIn(List.of(scan.getId()), null, false).stream()
                .collect(Collectors.groupingBy(
                        r -> groupKey(r.getPackageName(), r.getPackageVersion(), r.getPackageType()),
                        Collectors.collectingAndThen(
                                Collectors.mapping(FindingRepository.FixVersionRow::getFixedVersion,
                                                   Collectors.toList()),
                                FixVersions::collect)));

        // 조치 하나로 몇 건이 사라지는가. 이것이 보고서의 핵심 표다.
        //
        // 순서는 '밖에서 바로 닿는 건이 몇 개 딸려 있는가'를 먼저 본다. 같은
        // CVSS 라도 인증이 필요한 건과 아닌 건은 먼저 할 일이 다르다. 이것은
        // 표시 순서를 정하는 일이지 grype 의 판정을 바꾸는 것이 아니다 —
        // 건수도 심각도도 수정 상태도 grype 이 준 그대로다.
        List<PackageAction> actions = groups.stream()
                .filter(g -> g.getFixable() > 0)
                .map(g -> new PackageAction(g, exposure.reachableIn(g.getPackageName()),
                                            fixes.getOrDefault(groupKey(g.getPackageName(),
                                                    g.getPackageVersion(), g.getPackageType()),
                                                    List.of())))
                .sorted(BY_URGENCY)
                .toList();

        // 손댈 수 없는 것. 지우거나 감추지 않고 따로 세워 둔다 — 조치가 아니라
        // 다른 통제(접근 제한·모니터링)가 필요한 자리다.
        List<PackageAction> blocked = groups.stream()
                .filter(g -> g.getFixable() == 0)
                .map(g -> new PackageAction(g, exposure.reachableIn(g.getPackageName()), List.of()))
                .sorted(BY_URGENCY)
                .toList();

        Diff diff = diff(scan);
        // 4장은 '손댈 수 없는 것' 에 우리가 적어 둔 검토 결과를 붙여 낸다.
        //
        // **패키지 하나에 검토 결과가 여럿 달린다** — 검토는 (자산, CVE,
        // 패키지)에 하나씩이고 이 표는 패키지로 한 줄이다. 앞서 그중 **아무
        // 한 건**을 골라 상태 · 근거 · 재검토일을 찍었다(띄운 앱에서 nginx
        // 네 건이 `오탐 · — · —` — 위험 수용과 그 재검토일이 사라졌다). 이제
        // 그 줄에 실린 탐지들의 것을 **모은다**(reviewSummaries).
        Map<String, NoFixReview> reviews = reviewSummaries(scan);
        List<NoFixRow> noFixRows = blocked.stream()
                .map(b -> {
                    NoFixReview r = reviews.get(b.packageName());
                    return r == null
                            ? new NoFixRow(b, new Reviewed(0, b.total()), Map.of(), null)
                            : new NoFixRow(b, r.reviewed(), r.responses(), r.earliestReview());
                })
                .toList();
        return new Targets(actions, blocked, noFixRows, diff, exposure);
    }

    /** 묶음 질의의 키 — 이름 · 버전 · 유형. 셋 중 하나라도 null 이면 빈 값으로 친다. */
    private static String groupKey(String name, String version, String type) {
        return Objects.toString(name, "") + '\u0000' + Objects.toString(version, "")
                + '\u0000' + Objects.toString(type, "");
    }

    /**
     * 패키지마다 <b>몇 건에 답이 있나 · 대응 방안은 무엇 무엇인가 · 가장 먼저
     * 오는 재검토일은 언제인가.</b>
     *
     * <p>2.4 와 <b>같은 걸음으로 센다</b> — 같은 탐지 목록을 훑고 같은
     * {@link FindingAnalysisService#analysisOf} 로 맞춘다. 규칙이 갈리면 한
     * 보고서 안에서 2.4 의 `미검토 30건` 과 4장이 서로를 부정한다.
     */
    private Map<String, NoFixReview> reviewSummaries(Scan scan) {
        Map<String, FindingAnalysis> byKey = analyses.byKey(scan.getAsset().getId());
        Map<String, long[]> counts = new LinkedHashMap<>();
        Map<String, Map<AnalysisResponse, Long>> responses = new HashMap<>();
        Map<String, java.time.LocalDate> earliest = new HashMap<>();
        for (FindingRepository.FindingKey row : findings.findKeyRows(scan.getId())) {
            FindingAnalysis found = FindingAnalysisService.analysisOf(
                    byKey, row.getCve(), row.getRelatedCve(), row.getPackageName());
            AnalysisState state = found == null ? AnalysisState.NOT_SET : found.getState();
            // 4장은 목록이다 — 해당 없음 · 오탐으로 빠진 건은 그 줄의 `건수` 에도
            // `답 있는 건` 에도 넣지 않는다. 넣으면 `1 / 4건` 의 4 가 표의 건수(1)와
            // 다르다.
            if (!state.isOpen()) {
                continue;
            }
            String name = row.getPackageName();
            long[] cell = counts.computeIfAbsent(name, n -> new long[2]);
            cell[1]++;
            if (state == AnalysisState.NOT_SET) {
                continue;
            }
            cell[0]++;
            if (found.getResponse() != null) {
                responses.computeIfAbsent(name, n -> new java.util.EnumMap<>(AnalysisResponse.class))
                         .merge(found.getResponse(), 1L, Long::sum);
            }
            if (found.getReviewBy() != null) {
                earliest.merge(name, found.getReviewBy(),
                               (a, b) -> a.isBefore(b) ? a : b);
            }
        }
        Map<String, NoFixReview> out = new LinkedHashMap<>();
        counts.forEach((name, cell) -> out.put(name, new NoFixReview(
                new Reviewed(cell[0], cell[1]),
                responses.getOrDefault(name, Map.of()),
                earliest.get(name))));
        return out;
    }

    /** 4장 한 줄에 붙는 검토 결과의 모음. */
    private record NoFixReview(Reviewed reviewed, Map<AnalysisResponse, Long> responses,
                               java.time.LocalDate earliestReview) {
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
        List<Remediation> registered = remediations
                .findByAssetIdOrderByStatusAscPackageNameAsc(scan.getAsset().getId());
        Map<String, Remediation> byPackage = registered.stream()
                .collect(Collectors.toMap(Remediation::getPackageName, r -> r, (a, b) -> a));

        List<ActionRow> rows = targets.fixTargets().stream()
                .map(action -> new ActionRow(action, byPackage.get(action.packageName())))
                .toList();

        // 5장 아래 표. 3장 순서로 조치가 달린 줄을 싣고, 그 뒤에 **이 검사에
        // 해소 건수가 없는데 아직 대기 · 진행인 조치**를 붙인다 — 올려서
        // 탐지가 사라졌는데 완료로 넘기지 않은 것이다. 앞서는 3장에 없는
        // 조치를 5장이 아예 모르고 있어서, 조치 화면의 대기 · 진행 수와
        // 보고서의 수가 달랐다. 완료로 닫혔고 남은 것도 없는 조치는 싣지 않는다.
        Set<String> targeted = rows.stream().map(r -> r.action().packageName())
                                   .collect(Collectors.toSet());
        List<TrackedRow> tracking = new ArrayList<>();
        rows.stream().filter(ActionRow::isTracked)
            .forEach(r -> tracking.add(new TrackedRow(r.remediation(), r.action().fixableCount())));
        registered.stream()
                  .filter(r -> !r.getStatus().isClosed() && !targeted.contains(r.getPackageName()))
                  .forEach(r -> tracking.add(new TrackedRow(r, 0)));

        // 고칠 수 없는 건에 "왜 그대로 두는가" 가 적혀 있는지. 점검에서
        // 반드시 묻는 것이고, 답이 없으면 방치로 읽힌다.
        //
        // 검토가 끝난 것(해당 없음·오탐)도 가져온다 — 목록에서는 빠지지만
        // "왜 그대로 두는가" 에는 그것도 답이다.
        // 운영 종료한 자산의 것도 넣는다 — 그 자산의 제 보고서다.
        List<FindingAnalysis> explained =
                analyses.list(true, null, true).stream()
                        .filter(a -> a.getAsset().getId().equals(scan.getAsset().getId()))
                        .toList();

        return new Progress(rows, List.copyOf(tracking), targets.blocked(), explained, reviewed);
    }

    private String key(String value) {
        return value == null || value.isBlank() ? "unknown" : value.toLowerCase();
    }

    // -----------------------------------------------------------------------
    // 화면에 넘기는 모양
    // -----------------------------------------------------------------------

    /**
     * @param trend    6장 아래 표 — 최근 완료 검사(오래된 것부터). 하나뿐이면 비어 있다
     * @param appendix 부록 — 실제 악용 · 심각 취약점(한 줄 = 취약점 하나)
     */
    public record Report(Scan scan, Overview overview, Summary summary,
                         Targets targets, Progress progress, List<TrendRow> trend,
                         List<Appendix.Row> appendix, java.time.Instant printedAt) {
    }

    /**
     * 추이 한 줄 — 검사 하나와 그 검사의 심각 · 높음 건수.
     *
     * @param current 이 보고서의 검사인가
     */
    public record TrendRow(Scan scan, long critical, long high, boolean current) {
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
     * 4장 한 줄 — 손댈 수 없는 패키지와, 그 줄에 실린 탐지들의 검토 결과.
     *
     * <p>적어 둔 것이 없으면 <b>비어 있다는 것을 그대로 보여 준다</b> — 점검에서
     * "이건 왜 안 고쳤냐" 를 묻는 자리가 여기다.
     *
     * <p><b>한 건을 골라 그 줄을 말하지 않는다.</b> 검토는 {@code (자산, CVE,
     * 패키지)} 하나에 하나씩 달리고 이 줄은 패키지 하나다. {@code reviewed} 가
     * 몇 건에 답이 있는지, {@code responses} 가 대응 방안별로 몇 건인지,
     * {@code earliestReview} 가 가장 먼저 오는 재검토일을 말한다.
     *
     * @param responses      대응 방안 → 건수. 비어 있으면 아직 정한 대응이 없다
     * @param earliestReview 그 줄의 재검토일 가운데 가장 이른 날. 없으면 {@code null}
     */
    public record NoFixRow(PackageAction action, Reviewed reviewed,
                           Map<AnalysisResponse, Long> responses,
                           java.time.LocalDate earliestReview) {

        /** 재검토일이 이미 지났는가. */
        public boolean reviewOverdue() {
            return earliestReview != null && earliestReview.isBefore(java.time.LocalDate.now());
        }

        /** `조치 불가 2 · 위험 수용 1` — 없으면 빈 문자열. */
        public String responseLine() {
            return responses.entrySet().stream()
                    .map(e -> e.getKey().label() + " " + e.getValue())
                    .collect(Collectors.joining(" · "));
        }
    }

    /**
     * 5장 — 조치 진행 현황.
     *
     * <p><b>세 갈래로 가른다</b> — 대기 · 진행 / 완료 · 탐지 남음 / 미등록.
     * 조치를 완료로 바꿨는데 이 검사에 그 패키지의 해소 건수가 남아 있으면,
     * 앞서 이 장은 `등록` 에, 구역 보고서 6장은 `미등록` 에 넣었다 — 같은
     * 자산 하나를 두고 두 보고서의 수가 달랐다(띄운 앱에서 374 와 406).
     * 완료했는데 남은 것은 둘 다 아니다. 구역 보고서가 같은 갈래로 센다
     * ({@code RemediationProgressTest}).
     *
     * <p><b>단위가 둘이다.</b> {@code …Packages()} 는 <b>패키지</b> 수이고
     * ({@link Remediation} 이 (자산, 패키지)로 등록된다), {@code …Findings()}
     * 는 그것이 덮는 <b>건</b> 수다. 보고서가 "미등록 15개" 라고만 쓰면 읽는
     * 사람은 그 15 가 48건 중 얼마인지 알 수 없다 — <b>단위가 말없이 바뀌는
     * 자리</b>이고, 결재로 올라가는 문서에서 그것이 가장 먼저 의심받는다.
     * 늘 함께 적는다. 세 갈래의 건수를 더하면 3장 합계다.
     *
     * @param rows     3장의 줄 — 조치 대상 패키지와, 등록된 조치가 있으면 그것
     * @param tracking 5장 아래 표의 줄 — 대기 · 진행인 조치 전부와 완료 · 탐지 남음
     */
    public record Progress(List<ActionRow> rows, List<TrackedRow> tracking,
                           List<PackageAction> residual, List<FindingAnalysis> explained,
                           Map<String, Reviewed> reviewed) {

        /** 5장 아래 표의 줄 수. 0 이면 표를 그리지 않는다. */
        public long tracked() {
            return tracking.size();
        }

        /** 대기 · 진행 — 그 상태인 조치 전부. 이 검사에 해소 건수가 없는 것도 든다. */
        public long openPackages() {
            return tracking.stream().filter(r -> !r.isDoneRemaining()).count();
        }

        /** 대기 · 진행인 조치가 덮는 건수. 3장의 `해소 건수` 와 같은 축이다. */
        public long openFindings() {
            return tracking.stream().filter(r -> !r.isDoneRemaining())
                           .mapToLong(TrackedRow::fixableCount).sum();
        }

        /** 완료 · 탐지 남음 — 조치 상태는 완료인데 이 검사에 해소 건수가 남은 패키지. */
        public long doneRemainingPackages() {
            return tracking.stream().filter(TrackedRow::isDoneRemaining).count();
        }

        public long doneRemainingFindings() {
            return tracking.stream().filter(TrackedRow::isDoneRemaining)
                           .mapToLong(TrackedRow::fixableCount).sum();
        }

        /** 미등록 — 조치 대상인데 아무도 맡지 않은 패키지. */
        public long untracked() {
            return rows.stream().filter(r -> !r.isTracked()).count();
        }

        /** 아직 아무도 맡지 않은 건수. */
        public long untrackedFindings() {
            return rows.stream().filter(r -> !r.isTracked())
                       .mapToLong(r -> r.action().fixableCount()).sum();
        }

        /** 기한이 지난 조치. 닫힌 조치는 지났다고 하지 않는다. */
        public long overdue() {
            return tracking.stream().filter(r -> r.remediation().isOverdue()).count();
        }

        /** 조치 대상도, 대기 · 진행인 조치도 없다 — 장에 `해당 없음` 한 줄. */
        public boolean isEmpty() {
            return rows.isEmpty() && tracking.isEmpty();
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

    /**
     * 패키지 하나에 대한 조치 후보.
     *
     * @param fixVersions 그 줄에 실린 탐지의 수정 버전 전부 — 하나로 고르지 않는다
     *                    ({@link FixVersions}). 4장의 줄은 늘 비어 있다
     */
    public record PackageAction(String packageName, String packageType, String currentVersion,
                                List<String> fixVersions, long total, long fixableCount,
                                long kevCount, long criticalCount, long highCount,
                                BigDecimal maxCvss, BigDecimal maxEpss, long reachableCount) {

        PackageAction(PackageGroup group, long reachableCount, List<String> fixVersions) {
            this(group.getPackageName(), group.getPackageType(), group.getPackageVersion(),
                 fixVersions, group.getTotal(), group.getFixable(), group.getKevCount(),
                 group.getCriticalCount(), group.getHighCount(),
                 group.getMaxCvss(), group.getMaxEpss(), reachableCount);
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

        /**
         * 완료 · 탐지 남음. 3장의 줄은 전부 해소 건수가 있는 패키지라, 닫힌
         * 조치가 여기 붙어 있으면 곧 그 뜻이다.
         */
        public boolean isDoneRemaining() {
            return remediation != null && remediation.getStatus().isClosed();
        }
    }

    /** 5장 아래 표 한 줄 — 조치와, 이 검사에서 그 조치가 덮는 해소 건수. */
    public record TrackedRow(Remediation remediation, long fixableCount) {

        /** 닫혔는데 이 표에 있으면 해소 건수가 남은 것이다 — 남은 것이 없으면 싣지 않는다. */
        public boolean isDoneRemaining() {
            return remediation.getStatus().isClosed();
        }
    }

    /** 지난 스캔 대비. */
    public record Diff(Scan previous, long added, long resolved, long kept) {

        public boolean hasPrevious() {
            return previous != null;
        }
    }
}
