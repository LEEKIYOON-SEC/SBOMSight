package kr.sbomsight.service;

import kr.sbomsight.domain.Scan;
import kr.sbomsight.repo.ComponentRepository;
import kr.sbomsight.repo.ScanRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

/**
 * 기동할 때 — <b>패키지 목록이 최신 검사의 것인지</b> 맞춘다.
 *
 * <p>패키지 목록은 자산마다 최신 검사 것만 둔다(ComponentInventoryService). 최신 검사를
 * 고르는 규칙이 바뀌면(V17 — 검사 시각에서 SBOM 생성 시각으로) 옛 규칙으로 최신이던
 * 검사의 목록이 남은 자산이 생긴다. 옛 SBOM 을 다시 검사한 줄이 최신이던 자산이 그렇다 —
 * 취약점 화면은 새 규칙의 최신 검사를, 패키지 화면은 옛 것을 말하게 된다(1단계에서
 * 막은 어긋남이 다시 생긴다).
 *
 * <p>그런 자산만 찾아 최신 검사의 보관 SBOM 에서 다시 담고(restoreCurrent), 남은 옛
 * 행은 버린다(dropStale). <b>목록이 아예 없던 자산은 건드리지 않는다</b> — V13 전에
 * 검사한 자산은 다음 검사 때 찬다(V13). 어긋난 자산이 없으면 질의 둘로 끝난다.
 *
 * <p>{@code BootstrapService} 와 따로 둔다 — 그쪽은 한 트랜잭션으로 돌아, 다시 담기가
 * 자산마다 제 트랜잭션으로 끝나지 않는다.
 */
@Component
public class InventoryReconciler implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(InventoryReconciler.class);

    private final ScanRepository scans;
    private final ComponentRepository components;
    private final ComponentInventoryService inventory;

    public InventoryReconciler(ScanRepository scans, ComponentRepository components,
                               ComponentInventoryService inventory) {
        this.scans = scans;
        this.components = components;
        this.inventory = inventory;
    }

    @Override
    public void run(ApplicationArguments args) {
        int fixed = reconcile();
        if (fixed > 0) {
            log.info("패키지 목록이 최신 검사의 것이 아니던 자산 {}대를 맞췄습니다", fixed);
        }
    }

    /** @return 맞춘 자산 수 */
    public int reconcile() {
        Map<Long, Long> latest = scans.findLatestDonePerAsset().stream()
                .collect(Collectors.toMap(s -> s.getAsset().getId(), Scan::getId, (a, b) -> a));
        Set<Long> off = new TreeSet<>();
        for (ComponentRepository.Holder h : components.findFinishedScansHoldingRows()) {
            if (!Objects.equals(latest.get(h.getAssetId()), h.getScanId())) {
                off.add(h.getAssetId());
            }
        }
        for (Long assetId : off) {
            ComponentInventoryService.Restored restored = inventory.restoreCurrent(assetId);
            int dropped = inventory.dropStale(assetId);
            if (restored.failed()) {
                log.warn("자산 {} 의 패키지 목록을 최신 검사에서 다시 담지 못했습니다({}). "
                         + "최신 검사가 아닌 검사의 행 {}개를 버렸습니다 — 다음 검사 때 찹니다",
                         assetId, restored.problem(), dropped);
            } else {
                log.info("자산 {} 의 패키지 목록을 최신 검사(검사 {}) 것으로 맞췄습니다 — 다시 담음 {}행 · 버림 {}행",
                         assetId, latest.get(assetId), restored.rows(), dropped);
            }
        }
        return off.size();
    }
}
