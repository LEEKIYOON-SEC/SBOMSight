package kr.sbomsight.service;

import kr.sbomsight.domain.Asset;
import kr.sbomsight.domain.Scan;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.RemediationRepository;
import kr.sbomsight.repo.ScanRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/** 자산 삭제 — DB 행과 <b>보관 파일을 함께</b> 지운다. */
@Service
public class AssetService {

    private static final Logger log = LoggerFactory.getLogger(AssetService.class);

    private final AssetRepository assets;
    private final ScanRepository scans;
    private final RemediationRepository remediations;
    private final SbomStorage storage;

    public AssetService(AssetRepository assets, ScanRepository scans,
                        RemediationRepository remediations, SbomStorage storage) {
        this.assets = assets;
        this.scans = scans;
        this.remediations = remediations;
        this.storage = storage;
    }

    /** 삭제하면 무엇이 함께 사라지는지 — 확인 화면에서 그대로 보여 준다. */
    public record Impact(long scanCount, long findingCount, long remediationCount) {
    }

    @Transactional(readOnly = true)
    public Impact impactOf(Asset asset) {
        List<Scan> list = scans.findByAssetIdOrderByCreatedAtDesc(asset.getId());
        long findings = list.stream().mapToLong(Scan::getFindingCount).sum();
        long rems = remediations.findByAssetIdOrderByStatusAscPackageNameAsc(asset.getId()).size();
        return new Impact(list.size(), findings, rems);
    }

    /**
     * 자산과 그 안의 모든 것을 지운다.
     *
     * <p><b>디스크에 보관한 SBOM 과 grype 원본도 함께 지운다.</b> DB 행만 지우면
     * 용량은 그대로이고, 그 파일 안에는 그 서버에 설치된 패키지 목록이 통째로
     * 들어 있다 — 자산을 지웠는데 가장 민감한 것이 남는 셈이다.
     */
    @Transactional
    public Impact delete(Asset asset, String actor) {
        Impact impact = impactOf(asset);
        Long assetId = asset.getId();

        // 파일 경로에 스캔 번호가 필요하므로 지우기 전에 목록을 받아 둔다.
        List<Long> scanIds = scans.findByAssetIdOrderByCreatedAtDesc(assetId).stream()
                .map(Scan::getId).toList();

        // findings 와 remediations 는 FK ON DELETE CASCADE 로 따라간다.
        scans.deleteAllByIdInBatch(scanIds);
        assets.delete(asset);

        scanIds.forEach(scanId -> storage.deleteScanDir(assetId, scanId));

        log.info("자산을 지웠습니다: {} — 스캔 {}건 · 탐지 {}건 · 조치 {}건 ({})",
                 asset.getName(), impact.scanCount(), impact.findingCount(),
                 impact.remediationCount(), actor);
        return impact;
    }
}
