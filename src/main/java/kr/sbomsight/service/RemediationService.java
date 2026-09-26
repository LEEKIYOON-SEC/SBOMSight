package kr.sbomsight.service;

import kr.sbomsight.domain.*;
import kr.sbomsight.repo.FindingRepository;
import kr.sbomsight.repo.RemediationRepository;
import kr.sbomsight.repo.ScanRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * 조치 관리.
 *
 * <p>조치는 자산 + 패키지에 하나씩 붙는다. grype 결과는 스캔마다 새로 쌓이지만
 * 조치는 그것을 가로질러야 한다 — "openssl 을 3.0.7 로 올린다"는 다음 스캔에서도
 * 같은 일이고, 스캔이 바뀌었다고 처음부터 다시 적을 이유가 없다.
 */
@Service
public class RemediationService {

    private final RemediationRepository remediations;
    private final FindingRepository findings;
    private final ScanRepository scans;

    public RemediationService(RemediationRepository remediations, FindingRepository findings,
                              ScanRepository scans) {
        this.remediations = remediations;
        this.findings = findings;
        this.scans = scans;
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
     * 조치를 만들거나, 이미 있으면 그것을 돌려준다.
     *
     * <p>같은 패키지에 조치를 두 개 만들 수 있게 두면 담당이 갈리고 이력이
     * 쪼개진다. 하나만 열어 두고, 닫힌 것을 다시 열 때도 같은 줄을 쓴다.
     */
    @Transactional
    public Opened open(Asset asset, Scan scan, String packageName, String actor) {
        return remediations.findByAssetIdAndPackageName(asset.getId(), packageName)
                .map(existing -> new Opened(existing, false))
                .orElseGet(() -> new Opened(create(asset, scan, packageName, actor), true));
    }

    /**
     * 동시에 두 번 눌린 뒤 <b>먼저 들어간 것을 읽어 온다.</b>
     *
     * <p>{@link #open} 은 `없으면 만든다` 인데 그 사이에 다른 요청이 같은
     * {@code (자산, 패키지)} 를 만들 수 있다. 그때 DB 의 유일 제약
     * ({@code uk_remediation_open})이 막는다 — <b>데이터는 갈라지지
     * 않는다.</b> 다만 그 예외가 그대로 올라가면 화면이 500 이 되고, 누른
     * 사람은 조치가 열렸는지 아닌지 알 수 없다.
     *
     * <p><b>왜 {@code open} 안에서 못 잡는가.</b> 제약 위반은 flush 때 나고
     * 그 시점에 트랜잭션은 이미 되돌리기로 표시된다 — 같은 트랜잭션에서
     * 다시 읽을 수 없다. 부르는 쪽이 새 트랜잭션으로 읽어야 한다.
     */
    @Transactional(readOnly = true)
    public Opened rejoin(Long assetId, String packageName) {
        return remediations.findByAssetIdAndPackageName(assetId, packageName)
                .map(existing -> new Opened(existing, false))
                .orElseThrow(() -> new IllegalStateException(
                        "조치를 열지 못했고 먼저 열린 것도 없습니다: " + packageName));
    }

    private Remediation create(Asset asset, Scan scan, String packageName, String actor) {
        Remediation remediation = new Remediation(asset, packageName, actor);

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
        return remediations.save(remediation);
    }

    /**
     * 조치를 지운다 — <b>이력까지 함께.</b>
     *
     * <p>왜 지울 수 있어야 하는가. 보고서의 `조치 등록` 은 단추 한 번이고
     * 확인 창도 없다. 잘못 누른 줄이 담당도 기한도 없이 목록에 남으면,
     * `미등록 15개` 가 `14개` 로 줄어 <b>보고서의 수가 틀어진다.</b>
     * 되돌릴 수 없는 등록은 등록이 아니라 사고다.
     *
     * <p>지운 사실은 부르는 쪽이 감사 로그에 남긴다. 여기서 남기지 않는
     * 것은 이 서비스가 요청 맥락(누가·어디서)을 모르기 때문이다.
     */
    @Transactional
    public void delete(Remediation remediation) {
        remediations.delete(remediation);
    }

    @Transactional
    public void update(Remediation remediation, RemediationStatus status, String owner,
                       LocalDate dueDate, String note, String actor, String comment) {
        remediation.setOwner(owner);
        remediation.setDueDate(dueDate);
        remediation.setNote(note);
        if (remediation.getStatus() != status) {
            remediation.moveTo(status, actor, comment);
        } else {
            remediation.setUpdatedBy(actor);
        }
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
     * <b>완료 · 탐지 남음</b> — 완료로 닫았는데 자산의 최신 완료 검사에 그
     * 패키지의 해소 건수가 남은 조치. 조치 id → 남은 해소 건수. 없으면 빠진다.
     *
     * <p>보고서 5장 · 구역 보고서 6장과 <b>같은 규칙</b>이다(같은 질의): 해소
     * 건수는 수정 버전이 있는 탐지를 세고, 검토 결과가 해당 없음 · 오탐인 건은
     * 뺀다. 앞서 보고서는 이 갈래를 따로 셌는데 조치 화면은 그냥 `완료` 로
     * 적고 줄을 흐리게 그렸다 — 보고서가 "탐지 남음" 이라고 한 조치가 조치
     * 화면에서는 끝난 일로 보였다.
     *
     * <p>상태를 바꾸지 않는다 — 보여 줄 뿐이다({@link #remainingCounts} 와 같은 이유).
     */
    @Transactional(readOnly = true)
    public Map<Long, Long> doneRemaining(Collection<Remediation> list) {
        List<Remediation> closed = list.stream().filter(r -> r.getStatus().isClosed()).toList();
        if (closed.isEmpty()) {
            return Map.of();
        }
        Set<Long> assetIds = closed.stream().map(r -> r.getAsset().getId())
                                   .collect(Collectors.toSet());
        List<Long> latest = scans.findLatestDonePerAsset().stream()
                .filter(s -> assetIds.contains(s.getAsset().getId()))
                .map(Scan::getId)
                .toList();
        if (latest.isEmpty()) {
            return Map.of();
        }
        Map<String, Long> fixable = findings.countPerAssetPackage(latest, false).stream()
                .collect(Collectors.toMap(c -> c.getAssetId() + "|" + c.getPackageName(),
                                          FindingRepository.AssetPackageCount::getFixable,
                                          Long::sum));
        Map<Long, Long> out = new HashMap<>();
        for (Remediation r : closed) {
            long left = fixable.getOrDefault(r.getAsset().getId() + "|" + r.getPackageName(), 0L);
            if (left > 0) {
                out.put(r.getId(), left);
            }
        }
        return out;
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
     * 여러 자산치를 {@code (자산id, 패키지명)} 키로.
     *
     * <p>목록이 줄마다 `조치 등록`/`조치 보기` 중 무엇을 그릴지 정하는 데
     * 쓴다. 키에 <b>자산 id 를 넣는다</b> — 구역·전체 범위는 자산이 섞여
     * 있어서 패키지명으로만 맞추면 web-01 의 조치가 api-01 행에 붙는다.
     */
    @Transactional(readOnly = true)
    public Map<String, Remediation> byAssetPackage(Collection<Long> assetIds) {
        return assetIds.isEmpty() ? Map.of()
                : remediations.findByAssets(assetIds).stream()
                              .collect(Collectors.toMap(
                                      r -> r.getAsset().getId() + "|" + r.getPackageName(),
                                      Function.identity(), (a, b) -> a));
    }
}
