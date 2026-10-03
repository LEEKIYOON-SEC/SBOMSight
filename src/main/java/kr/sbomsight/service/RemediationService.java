package kr.sbomsight.service;

import kr.sbomsight.domain.*;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.FindingRepository;
import kr.sbomsight.repo.RemediationRepository;
import kr.sbomsight.repo.RemediationTargetRepository;
import kr.sbomsight.repo.ScanRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * 조치 관리.
 *
 * <p>조치는 자산 + 패키지에 붙는다. grype 결과는 스캔마다 새로 쌓이지만 조치는 그것을
 * 가로질러야 한다 — "openssl 을 3.0.7 로 올린다"는 다음 스캔에서도 같은 일이고, 스캔이
 * 바뀌었다고 처음부터 다시 적을 이유가 없다.
 *
 * <p><b>회차</b>(D5): 열린 조치는 (자산, 패키지)에 하나다. 닫힌 조치만 있는 패키지에
 * 등록하면 새 조치를 연다 — 조치 회차가 늘고 이전 조치를 가리킨다. 그 (자산, 패키지)의
 * <b>지금 조치</b>는 최신 회차다({@link #byAssetPackage}). 다시 열기는 잘못 닫은 것을
 * 바로잡을 때만 — 최신 회차만 다시 연다.
 */
@Service
public class RemediationService {

    private final RemediationRepository remediations;
    private final RemediationTargetRepository targets;
    private final FindingRepository findings;
    private final ScanRepository scans;
    private final AssetRepository assets;
    private final FindingAnalysisService analyses;

    public RemediationService(RemediationRepository remediations, RemediationTargetRepository targets,
                              FindingRepository findings, ScanRepository scans,
                              AssetRepository assets, FindingAnalysisService analyses) {
        this.remediations = remediations;
        this.targets = targets;
        this.findings = findings;
        this.scans = scans;
        this.assets = assets;
        this.analyses = analyses;
    }

    /**
     * 연 결과 — <b>새로 만들었는지 함께 알려 준다.</b>
     *
     * <p>부르는 쪽이 감사 로그에 남기는데, 이미 있던 것을 돌려받은 경우까지
     * `등록` 으로 남기면 단추를 두 번 누른 것이 등록 두 번으로 보인다.
     */
    public record Opened(Remediation remediation, boolean created) {
    }

    /**
     * 조치를 연다 — 열린 것이 있으면 그것, 닫힌 것만 있으면 다음 회차, 없으면 첫 회차.
     *
     * <p><b>자산 행을 맨 먼저 잠근다.</b> "열린 조치가 있는가" 를 보고 만드는 사이에 다른
     * 요청이 끼어들 수 있다 — 같은 패키지의 검토 여러 줄이 모두 `조치 등록` 을 달고 있어
     * 두 번 눌리는 것이 보통이다. 앞서는 DB 의 유일 제약이 막았는데 회차가 생기며 그
     * 제약을 풀었다(V19). 뒤 요청은 잠금에서 기다렸다가 앞 요청이 연 조치를 받는다.
     *
     * <p>잠근 <b>뒤에</b> 읽는다. MariaDB · MySQL(REPEATABLE READ)은 트랜잭션의 첫 읽기
     * 때 스냅숏을 잡는다 — 잠그기 전에 읽으면 앞 요청이 커밋한 조치를 못 본다.
     */
    @Transactional
    public Opened open(Asset asset, Scan scan, String packageName, String actor) {
        assets.lockById(asset.getId());
        Optional<Remediation> latest = remediations.findLatest(asset.getId(), packageName);
        if (latest.isPresent() && !latest.get().getStatus().isClosed()) {
            return new Opened(latest.get(), false);
        }
        return new Opened(create(asset, scan, packageName, actor, latest.orElse(null)), true);
    }

    private Remediation create(Asset asset, Scan scan, String packageName, String actor,
                               Remediation previous) {
        Remediation remediation = new Remediation(asset, packageName, actor);
        if (previous != null) {
            remediation.followUp(previous);
        }

        // 만들 당시의 현재 버전과 목표 버전을 스냅샷으로 남긴다. 나중에
        // "그때 무엇을 근거로 정했나" 를 되짚기 위한 것이고, 판정에는 쓰지 않는다.
        //
        // 현재 버전도 하나로 고르지 않는다 — 등록 당시 건수(openedCount)와 같은
        // 건의 설치 버전 전부. 앞서는 CVSS 가 가장 높은 건의 것 하나라, 같은
        // 패키지가 두 벌 깔린 자산에서 한 벌이 조치 어디에도 없었다(V16).
        List<Finding> current = findings
                .findByScanIdAndPackageNameOrderByCvssScoreDesc(scan.getId(), packageName);
        remediation.setFromVersions(current.stream().map(Finding::getPackageVersion).toList());
        // 목표는 하나로 고르지 않는다 — 수정 버전 전부(FixVersions). 앞서는
        // CVSS 가 가장 높은 건의 것 하나를 적었다(curl deb10u4 — 그리로 올려도
        // 10건이 남는다). 보고서 3장과 같은 건(해당 없음 · 오탐 제외)에서 모은다.
        remediation.setToVersions(findings
                .fixVersionsIn(List.of(scan.getId()), packageName, false).stream()
                .map(FindingRepository.FixVersionRow::getFixedVersion)
                .toList());
        remediation.setOpenedScanId(scan.getId());
        remediation.setOpenedCount(current.size());
        remediation.moveTo(RemediationStatus.OPEN, actor, "조치 등록");
        Remediation saved = remediations.save(remediation);
        // 조치 대상 — 등록 당시 건수와 같은 건(R9). 완료 뒤 남은 탐지가 덜 된 것인지
        // 새 것인지를 이것으로 가른다({@link #afterDone}).
        targets.saveAll(RemediationTarget.of(saved, current));
        return saved;
    }

    /**
     * 조치를 지운다 — <b>이력까지 함께.</b>
     *
     * <p>왜 지울 수 있어야 하는가. 보고서의 `조치 등록` 은 단추 한 번이고
     * 확인 창도 없다. 잘못 누른 줄이 담당도 기한도 없이 목록에 남으면,
     * `미등록 15개` 가 `14개` 로 줄어 <b>보고서의 수가 틀어진다.</b>
     * 되돌릴 수 없는 등록은 등록이 아니라 사고다.
     *
     * <p><b>다음 회차가 이은 조치는 지우지 않는다</b> — 그 회차의 이전 조치가 사라져
     * 회차가 끊긴다. 잘못 등록한 것은 최신 회차다.
     *
     * <p>지운 사실은 부르는 쪽이 감사 로그에 남긴다. 여기서 남기지 않는
     * 것은 이 서비스가 요청 맥락(누가·어디서)을 모르기 때문이다.
     */
    @Transactional
    public void delete(Remediation remediation) {
        Optional<Remediation> next = remediations.findFirstByPreviousId(remediation.getId());
        if (next.isPresent()) {
            throw new IllegalArgumentException(next.get().getRoundNo()
                    + "회차가 이은 조치라 지울 수 없습니다 — 회차가 끊깁니다.");
        }
        remediations.delete(remediation);
    }

    /**
     * 상태 · 담당 · 기한 · 설명을 고친다. 바뀐 것마다 발자취에 남는다 — 상태는 상태 줄,
     * 나머지는 칸 줄(R8). 변경 사유는 같은 저장의 줄마다 붙는다.
     *
     * <p><b>다시 열기는 최신 회차만.</b> 닫힌 조치를 대기 · 진행으로 되돌리는 것은 잘못
     * 닫은 것을 바로잡을 때다(D5). 다음 회차가 이미 이었으면 그 조치를 다시 열지 않는다
     * — 열면 같은 (자산, 패키지)에 열린 조치가 둘이 된다. 자산을 잠그고 본다({@link #open}
     * 과 같은 잠금 — 그 사이에 다음 회차가 열리지 않게).
     */
    @Transactional
    public void update(Remediation remediation, RemediationStatus status, String owner,
                       LocalDate dueDate, String note, String actor, String comment) {
        if (remediation.getStatus().isClosed() && !status.isClosed()) {
            assets.lockById(remediation.getAsset().getId());
            remediations.findFirstByPreviousId(remediation.getId()).ifPresent(next -> {
                throw new IllegalArgumentException(next.getRoundNo() + "회차가 이은 조치라 다시 열 수 없습니다 — "
                        + next.getRoundNo() + "회차에서 이어서 합니다.");
            });
        }
        if (remediation.getStatus() != status) {
            remediation.moveTo(status, actor, comment);
        }
        remediation.edit(owner, dueDate, note, actor, comment);
        remediation.setUpdatedBy(actor);
        remediations.save(remediation);
    }

    /**
     * 최신 스캔에 비추어 조치가 실제로 해소됐는지 본다.
     *
     * <p><b>상태를 자동으로 바꾸지는 않는다.</b> 화면에 "최신 스캔에서 이 패키지의
     * 탐지가 0건"이라고 알려 줄 뿐이고, 완료로 넘기는 것은 사람이 한다 — 스캔
     * 대상이 바뀌어 사라진 것인지 정말 패치된 것인지는 우리가 판단할 수 없다.
     */
    @Transactional(readOnly = true)
    public Map<Long, Long> remainingCounts(Long assetId, Scan latest) {
        List<Remediation> list = remediations.findByAssetIdOrderByStatusAscPackageNameAsc(assetId);
        if (latest == null) {
            return list.stream().collect(Collectors.toMap(Remediation::getId, r -> -1L));
        }
        // 탐지 수다 — 해당 없음 · 오탐도 센다(검토는 탐지를 없애지 않는다).
        Map<String, Long> byPackage = findings.groupByPackage(latest.getId(), true).stream()
                .collect(Collectors.toMap(FindingRepository.PackageGroup::getPackageName,
                                          FindingRepository.PackageGroup::getTotal,
                                          Long::sum));
        return list.stream().collect(Collectors.toMap(
                Remediation::getId,
                r -> byPackage.getOrDefault(r.getPackageName(), 0L),
                (a, b) -> a));
    }

    /**
     * <b>완료 뒤</b> — 완료로 닫았는데 자산의 <b>지금 검사</b>에 그 패키지의 해소 건수가
     * 남은 조치를 세 갈래로 가른다({@link AfterDone}). 조치 id → 갈래와 남은 건수. 남은
     * 것이 없거나, 닫히지 않았거나, 다음 회차가 이은 조치는 빠진다.
     *
     * <p>보고서 5장 · 구역 보고서 6장과 <b>같은 규칙</b>이다({@link #afterDone(Collection, Map)}
     * 를 함께 쓴다). 상태를 바꾸지 않는다 — 보여 줄 뿐이다({@link #remainingCounts} 와
     * 같은 이유).
     */
    @Transactional(readOnly = true)
    public Map<Long, AfterDone> afterDone(Collection<Remediation> list) {
        List<Remediation> closed = latestClosed(list);
        if (closed.isEmpty()) {
            return Map.of();
        }
        Set<Long> assetIds = closed.stream().map(r -> r.getAsset().getId()).collect(Collectors.toSet());
        Map<Long, Scan> current = scans.findLatestDonePerAsset().stream()
                .filter(s -> assetIds.contains(s.getAsset().getId()))
                .collect(Collectors.toMap(s -> s.getAsset().getId(), Function.identity(), (a, b) -> a));
        return judge(closed, current);
    }

    /**
     * 위와 같은 규칙을 <b>주어진 검사</b>에 비춘다 — 보고서는 그 보고서가 보는 검사
     * (자산 보고서는 그 검사, 구역 보고서는 자산마다 기간 중 최신 검사)로 말한다.
     *
     * @param scanPerAsset 자산 id → 비출 검사. 없는 자산의 조치는 빠진다
     */
    @Transactional(readOnly = true)
    public Map<Long, AfterDone> afterDone(Collection<Remediation> list, Map<Long, Scan> scanPerAsset) {
        List<Remediation> closed = latestClosed(list);
        return closed.isEmpty() ? Map.of() : judge(closed, scanPerAsset);
    }

    /** 닫힌 것 가운데 지난 회차가 아닌 것 — 다음 회차가 이은 조치는 그 회차가 말한다. */
    private List<Remediation> latestClosed(Collection<Remediation> list) {
        List<Remediation> closed = list.stream().filter(r -> r.getStatus().isClosed()).toList();
        if (closed.isEmpty()) {
            return closed;
        }
        Set<Long> succeeded = new HashSet<>(
                remediations.findPreviousIdsIn(closed.stream().map(Remediation::getId).toList()));
        return closed.stream().filter(r -> !succeeded.contains(r.getId())).toList();
    }

    /**
     * 갈래를 정한다 — 검증 대기 › 탐지 남음 › 신규 탐지({@link AfterDone}).
     *
     * <ul>
     *   <li>남은 해소 건 = 그 검사의 그 패키지에서 수정 버전이 있는 탐지, 해당 없음 · 오탐은
     *       뺀다 — 보고서 3 · 5장의 `해소 건수` 와 같은 축. 해당 없음 · 오탐은 자바의 같은
     *       규칙(FindingAnalysisService.analysisOf)으로 뺀다.</li>
     *   <li>검증 대기 — 그 검사의 SBOM 생성 시각이 조치 완료보다 앞.</li>
     *   <li>탐지 남음 — 남은 것 가운데 조치 대상(번호 둘 중 하나라도 같은 것)이 있다. 대상을
     *       모르는 옛 조치(등록 당시 건수는 있는데 대상이 없다 — 등록한 검사가 지워짐)도
     *       여기 — 새 것인지 가를 근거가 없다.</li>
     *   <li>신규 탐지 — 남은 것이 모두 조치 대상이 아니다. 등록할 때 그 패키지에 탐지가
     *       없던 조치(등록 당시 건수 0)도 여기 — 대상이 없다고 알려져 있다.</li>
     * </ul>
     *
     * <p>시각은 마이크로초까지만 견준다 — DB 칸(DATETIME(6))이 거기까지다.
     */
    private Map<Long, AfterDone> judge(List<Remediation> closed, Map<Long, Scan> scanPerAsset) {
        List<Long> scanIds = closed.stream()
                .map(r -> scanPerAsset.get(r.getAsset().getId()))
                .filter(Objects::nonNull).map(Scan::getId).distinct().toList();
        if (scanIds.isEmpty()) {
            return Map.of();
        }
        Set<Long> assetIds = closed.stream().map(r -> r.getAsset().getId()).collect(Collectors.toSet());
        Map<String, FindingAnalysis> byAssetKey = analyses.byAssetKey(assetIds);

        // (자산|패키지) → 남은 해소 건의 번호 짝들
        Map<String, List<FindingRepository.AssetFindingKey>> left = new HashMap<>();
        for (FindingRepository.AssetFindingKey k : findings.findFixableKeysIn(scanIds)) {
            FindingAnalysis found = FindingAnalysisService.analysisOf(
                    byAssetKey, k.getAssetId(), k.getCve(), k.getRelatedCve(), k.getPackageName());
            if (found != null && !found.getState().isOpen()) {
                continue;   // 해당 없음 · 오탐 — 목록에서 빠진 건
            }
            left.computeIfAbsent(k.getAssetId() + "|" + k.getPackageName(), x -> new ArrayList<>()).add(k);
        }

        Map<Long, Set<String>> targetIds = new HashMap<>();
        for (RemediationTargetRepository.TargetKey t
                : targets.findKeys(closed.stream().map(Remediation::getId).toList())) {
            Set<String> ids = targetIds.computeIfAbsent(t.getRemediationId(), x -> new HashSet<>());
            ids.add(t.getCve());
            if (t.getRelatedCve() != null && !t.getRelatedCve().isBlank()) {
                ids.add(t.getRelatedCve());
            }
        }

        Map<Long, AfterDone> out = new HashMap<>();
        for (Remediation r : closed) {
            Scan scan = scanPerAsset.get(r.getAsset().getId());
            List<FindingRepository.AssetFindingKey> rest =
                    left.getOrDefault(r.getAsset().getId() + "|" + r.getPackageName(), List.of());
            if (scan == null || rest.isEmpty()) {
                continue;
            }
            AfterDone.Kind kind;
            if (r.getClosedAt() != null && micros(scan.getSbomCreatedAt()).isBefore(micros(r.getClosedAt()))) {
                kind = AfterDone.Kind.PENDING;
            } else {
                Set<String> ids = targetIds.getOrDefault(r.getId(), Set.of());
                // 조치 대상이 비었으면 둘로 갈린다 — 조치 상세의 `등록 당시 탐지 없음` ·
                // `확인되지 않음` 과 같은 기준(등록 당시 건수). 탐지가 없을 때 등록했으면
                // 남은 것은 모두 대상이 아니다. 등록한 검사가 지워져 모르면 가를 근거가 없다.
                boolean targetLeft = ids.isEmpty()
                        ? r.getOpenedCount() > 0
                        : rest.stream().anyMatch(f -> ids.contains(f.getCve())
                                || (f.getRelatedCve() != null && !f.getRelatedCve().isBlank()
                                    && ids.contains(f.getRelatedCve())));
                kind = targetLeft ? AfterDone.Kind.REMAINING : AfterDone.Kind.NEW_FINDINGS;
            }
            out.put(r.getId(), new AfterDone(kind, rest.size()));
        }
        return out;
    }

    private static Instant micros(Instant at) {
        return at.truncatedTo(ChronoUnit.MICROS);
    }

    /** 대응 화면의 탭 숫자 — 거르기 전 전체. 운영 종료한 자산의 것은 켰을 때만. */
    @Transactional(readOnly = true)
    public List<Remediation> all(boolean includeArchived) {
        return remediations.findAllWithAsset(List.of(RemediationStatus.values()), includeArchived);
    }

    /**
     * 대응 화면의 조치 탭 — 구역으로 좁힐 수 있고 기한 지난 것이 위로 온다.
     *
     * @param includeArchived 운영 종료한 자산의 조치도 넣는가 ({@code 운영 종료 자산 포함})
     */
    @Transactional(readOnly = true)
    public List<Remediation> list(Long zoneId, RemediationStatus status, boolean includeArchived) {
        List<RemediationStatus> statuses =
                status == null ? List.of(RemediationStatus.values()) : List.of(status);
        return remediations.findForList(zoneId, statuses, LocalDate.now(), includeArchived);
    }

    /**
     * 여러 자산치를 {@code (자산id, 패키지명)} 키로 — 그 (자산, 패키지)의 <b>지금 조치</b>
     * (최신 회차).
     *
     * <p>목록이 줄마다 `조치 등록`/`조치 보기` 중 무엇을 그릴지 정하는 데
     * 쓴다. 키에 <b>자산 id 를 넣는다</b> — 구역·전체 범위는 자산이 섞여
     * 있어서 패키지명으로만 맞추면 web-01 의 조치가 api-01 행에 붙는다.
     */
    @Transactional(readOnly = true)
    public Map<String, Remediation> byAssetPackage(Collection<Long> assetIds) {
        return assetIds.isEmpty() ? Map.of()
                : latestPerPackage(remediations.findByAssets(assetIds));
    }

    /**
     * {@code (자산id|패키지명)} → 최신 회차. 보고서도 이것으로 고른다 — 지난 회차는 다음
     * 회차가 이어받았으므로 지금 그 패키지를 말하지 않는다.
     */
    public static Map<String, Remediation> latestPerPackage(Collection<Remediation> list) {
        return list.stream().collect(Collectors.toMap(
                r -> r.getAsset().getId() + "|" + r.getPackageName(), Function.identity(),
                (a, b) -> later(a, b) ? a : b));
    }

    /** a 가 b 보다 늦은 회차인가 — 회차, 같으면 번호. */
    private static boolean later(Remediation a, Remediation b) {
        if (a.getRoundNo() != b.getRoundNo()) {
            return a.getRoundNo() > b.getRoundNo();
        }
        return a.getId() > b.getId();
    }

    // --- 조치 상세 ---------------------------------------------------------------

    /**
     * 조치 대상 — 등록 당시의 탐지. 등록한 검사를 모르는 옛 조치는 비어 있다.
     *
     * <p><b>화면에 찍는 번호 순</b>이다(함께 온 CVE 가 있으면 그것). 표가 그 번호를 크게
     * 쓰므로 주 식별자(GHSA) 순으로 실으면 읽는 순서가 어긋난다.
     */
    @Transactional(readOnly = true)
    public List<RemediationTarget> targets(Remediation remediation) {
        return targets.findByRemediation(remediation.getId()).stream()
                .sorted(Comparator.comparing(RemediationTarget::getDisplayId)
                        .thenComparing(RemediationTarget::getPackageVersion)
                        .thenComparing(RemediationTarget::getId))
                .toList();
    }

    /**
     * 그 검사의 그 패키지 탐지가 가진 번호들(주 식별자 · 함께 온 CVE) — 조치 대상이 지금도
     * 있는지 맞대는 데 쓴다. 해당 없음 · 오탐도 든다(검토는 탐지를 없애지 않는다).
     */
    @Transactional(readOnly = true)
    public Set<String> idsIn(Scan scan, String packageName) {
        if (scan == null) {
            return Set.of();
        }
        Set<String> ids = new HashSet<>();
        for (Finding f : findings.findByScanIdAndPackageNameOrderByCvssScoreDesc(scan.getId(), packageName)) {
            ids.add(f.getCve());
            if (f.getRelatedCve() != null && !f.getRelatedCve().isBlank()) {
                ids.add(f.getRelatedCve());
            }
        }
        return ids;
    }

    /** 이전 조치 — 바로 앞 회차. */
    @Transactional(readOnly = true)
    public Optional<Remediation> previous(Remediation remediation) {
        return remediation.getPreviousId() == null ? Optional.empty()
                : remediations.findById(remediation.getPreviousId());
    }

    /** 그 (자산, 패키지)의 최신 회차 — 이 조치가 지난 회차일 때 화면이 그리로 잇는다. */
    @Transactional(readOnly = true)
    public Optional<Remediation> latestOf(Remediation remediation) {
        return remediations.findLatest(remediation.getAsset().getId(), remediation.getPackageName())
                           .filter(latest -> !latest.getId().equals(remediation.getId()));
    }
}
