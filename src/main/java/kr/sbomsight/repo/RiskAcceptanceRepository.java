package kr.sbomsight.repo;

import kr.sbomsight.domain.RiskAcceptance;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

public interface RiskAcceptanceRepository extends JpaRepository<RiskAcceptance, Long> {

    /** 살아 있는 수용 하나. 철회된 것은 찾지 않는다 — 같은 건을 다시 수용할 수 있어야 한다. */
    @Query("""
           SELECT r FROM RiskAcceptance r
           WHERE r.asset.id = :assetId AND r.cve = :cve AND r.packageName = :packageName
             AND r.revokedAt IS NULL
           """)
    Optional<RiskAcceptance> findActive(@Param("assetId") Long assetId,
                                        @Param("cve") String cve,
                                        @Param("packageName") String packageName);

    /** 한 자산의 살아 있는 수용. 보고서와 취약점 화면이 이것으로 표시를 붙인다. */
    @Query("""
           SELECT r FROM RiskAcceptance r
           WHERE r.asset.id = :assetId AND r.revokedAt IS NULL
           ORDER BY r.reviewBy ASC, r.packageName ASC
           """)
    List<RiskAcceptance> findActiveByAsset(@Param("assetId") Long assetId);

    /**
     * 전체 목록. 철회된 것까지 포함할 수 있다.
     *
     * <p>철회된 것을 지우지 않는 이유: 누가 언제 왜 거뒀는지도 점검 대상이다.
     */
    @Query("""
           SELECT r FROM RiskAcceptance r JOIN FETCH r.asset a JOIN FETCH a.zone
           WHERE (:includeRevoked = TRUE OR r.revokedAt IS NULL)
             AND (:zoneId IS NULL OR a.zone.id = :zoneId)
           ORDER BY r.revokedAt ASC, r.reviewBy ASC, a.name ASC
           """)
    List<RiskAcceptance> findAllWithAsset(@Param("includeRevoked") boolean includeRevoked,
                                          @Param("zoneId") Long zoneId);

    /** 재검토일이 지난 것. 자산 목록 머리에 기한 지난 조치와 나란히 세운다. */
    @Query("""
           SELECT r FROM RiskAcceptance r JOIN FETCH r.asset a JOIN FETCH a.zone
           WHERE r.revokedAt IS NULL AND r.reviewBy < :today
           ORDER BY r.reviewBy ASC
           """)
    List<RiskAcceptance> findReviewOverdue(@Param("today") LocalDate today);

    long countByAssetIdAndRevokedAtIsNull(Long assetId);

    /** 사이드바 숫자 — 재검토일이 지난 수용. 수용은 기한이 있어야 방치와 구분된다. */
    @Query("""
           SELECT COUNT(r) FROM RiskAcceptance r
           WHERE r.revokedAt IS NULL AND r.reviewBy < :today
           """)
    long countReviewOverdue(@Param("today") LocalDate today);
}
