package kr.sbomsight.service;

import kr.sbomsight.domain.*;
import kr.sbomsight.repo.FindingRepository;
import kr.sbomsight.repo.RemediationRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.List;
import java.util.Map;
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

    public RemediationService(RemediationRepository remediations, FindingRepository findings) {
        this.remediations = remediations;
        this.findings = findings;
    }

    /**
     * 조치를 만들거나, 이미 있으면 그것을 돌려준다.
     *
     * <p>같은 패키지에 조치를 두 개 만들 수 있게 두면 담당이 갈리고 이력이
     * 쪼개진다. 하나만 열어 두고, 닫힌 것을 다시 열 때도 같은 줄을 쓴다.
     */
    @Transactional
    public Remediation open(Asset asset, Scan scan, String packageName, String actor) {
        return remediations.findByAssetIdAndPackageName(asset.getId(), packageName)
                .orElseGet(() -> create(asset, scan, packageName, actor));
    }

    private Remediation create(Asset asset, Scan scan, String packageName, String actor) {
        Remediation remediation = new Remediation(asset, packageName, actor);

        // 만들 당시의 현재 버전과 목표 버전을 스냅샷으로 남긴다. 나중에
        // "그때 무엇을 근거로 정했나" 를 되짚기 위한 것이고, 판정에는 쓰지 않는다.
        List<Finding> current = findings
                .findByScanIdAndPackageNameOrderByCvssScoreDesc(scan.getId(), packageName);
        if (!current.isEmpty()) {
            remediation.setFromVersion(current.get(0).getPackageVersion());
            current.stream()
                   .filter(Finding::isFixAvailable)
                   .map(Finding::getFixedVersion)
                   .findFirst()
                   .ifPresent(remediation::setToVersion);
        }
        remediation.setOpenedScanId(scan.getId());
        remediation.setOpenedCount(current.size());
        remediation.moveTo(RemediationStatus.OPEN, actor, "조치 등록");
        return remediations.save(remediation);
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
        Map<String, Long> byPackage = findings.groupByPackage(latest.getId()).stream()
                .collect(Collectors.toMap(FindingRepository.PackageGroup::getPackageName,
                                          FindingRepository.PackageGroup::getTotal,
                                          Long::sum));
        return list.stream().collect(Collectors.toMap(
                Remediation::getId,
                r -> byPackage.getOrDefault(r.getPackageName(), 0L),
                (a, b) -> a));
    }

    @Transactional(readOnly = true)
    public List<Remediation> all() {
        return remediations.findAllWithAsset(List.of(RemediationStatus.values()));
    }

    @Transactional(readOnly = true)
    public Map<Long, Remediation> byPackage(Long assetId) {
        return remediations.findByAssetIdOrderByStatusAscPackageNameAsc(assetId).stream()
                .collect(Collectors.toMap(Remediation::getId, Function.identity()));
    }
}
