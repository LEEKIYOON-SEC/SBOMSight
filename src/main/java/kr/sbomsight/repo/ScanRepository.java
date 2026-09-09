package kr.sbomsight.repo;

import kr.sbomsight.domain.Scan;
import kr.sbomsight.domain.ScanStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface ScanRepository extends JpaRepository<Scan, Long> {

    List<Scan> findByAssetIdOrderByCreatedAtDesc(Long assetId);

    /** 자산의 가장 최근 완료 스캔. 목록과 보고서가 기준으로 삼는 것. */
    Optional<Scan> findFirstByAssetIdAndStatusOrderByCreatedAtDesc(Long assetId, ScanStatus status);

    List<Scan> findByStatusIn(List<ScanStatus> statuses);

    /**
     * 자산별 최근 완료 스캔을 한 번에.
     *
     * <p>자산마다 질의를 돌리면 자산 수만큼 왕복한다. 목록 화면 한 장에 그러면
     * 서른 대에 서른 번이다.
     */
    @Query("""
           SELECT s FROM Scan s
           WHERE s.status = 'DONE'
             AND s.createdAt = (SELECT MAX(x.createdAt) FROM Scan x
                                WHERE x.asset.id = s.asset.id AND x.status = 'DONE')
           """)
    List<Scan> findLatestDonePerAsset();

    long countByAssetId(Long assetId);
}
