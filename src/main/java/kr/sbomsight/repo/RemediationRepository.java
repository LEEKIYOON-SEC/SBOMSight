package kr.sbomsight.repo;

import kr.sbomsight.domain.Remediation;
import kr.sbomsight.domain.RemediationStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

/**
 * 조치 조회.
 *
 * <p>화면에서 {@code r.asset.name} 을 쓰는 질의는 전부 {@code JOIN FETCH} 로
 * 자산을 함께 읽는다. {@code open-in-view} 를 꺼 두었으므로 화면을 그릴 때는
 * 이미 세션이 닫혀 있고, 여기서 안 읽어 오면 그 자리에서 터진다. 열어 두는
 * 쪽으로 도망가면 표 한 장에 질의가 줄 수만큼 더 나간다.
 */
public interface RemediationRepository extends JpaRepository<Remediation, Long> {

    Optional<Remediation> findByAssetIdAndPackageName(Long assetId, String packageName);

    List<Remediation> findByAssetIdOrderByStatusAscPackageNameAsc(Long assetId);

    /** 상세 화면 — 자산과 발자취까지 한 번에. */
    @Query("""
           SELECT DISTINCT r FROM Remediation r
           JOIN FETCH r.asset
           LEFT JOIN FETCH r.events
           WHERE r.id = :id
           """)
    Optional<Remediation> findDetail(@Param("id") Long id);

    @Query("""
           SELECT r FROM Remediation r JOIN FETCH r.asset
           WHERE r.status IN :statuses
           ORDER BY r.dueDate ASC, r.asset.name ASC, r.packageName ASC
           """)
    List<Remediation> findAllWithAsset(@Param("statuses") List<RemediationStatus> statuses);

    /**
     * 대응 화면의 조치 탭.
     *
     * <p><b>기한이 지난 것이 맨 위로 온다.</b> 앞서는 {@code dueDate ASC} 로만
     * 줄 세웠는데, 그러면 기한을 아직 안 정한 것(NULL)이 MySQL 에서 맨 앞에
     * 온다 — 가장 급한 자리에 가장 안 급한 것이 앉는다.
     *
     * <p>순서: 기한 지난 것 → 아직 열린 것 → 닫힌 것. 닫힌 것을 아예 빼지는
     * 않는다. "저건 어떻게 됐더라" 를 물을 자리가 여기 말고 없다.
     *
     * <p>구역을 {@code JOIN FETCH} 로 함께 끌어온다. 화면이 구역 이름을 찍고
     * {@code open-in-view} 가 꺼져 있다.
     */
    @Query("""
           SELECT r FROM Remediation r JOIN FETCH r.asset a JOIN FETCH a.zone z
           WHERE r.status IN :statuses
             AND (:zoneId IS NULL OR z.id = :zoneId)
           ORDER BY CASE WHEN r.status IN ('DONE', 'ACCEPTED') THEN 2
                         WHEN r.dueDate < :today THEN 0
                         ELSE 1 END,
                    r.dueDate ASC NULLS LAST, a.name ASC, r.packageName ASC
           """)
    List<Remediation> findForList(@Param("zoneId") Long zoneId,
                                  @Param("statuses") List<RemediationStatus> statuses,
                                  @Param("today") LocalDate today);

    /** 기한이 지난 채 아직 안 닫힌 것. 첫 화면에서 먼저 보여야 하는 값이다. */
    @Query("""
           SELECT r FROM Remediation r JOIN FETCH r.asset
           WHERE r.dueDate < :today AND r.status IN ('OPEN', 'IN_PROGRESS')
           ORDER BY r.dueDate ASC
           """)
    List<Remediation> findOverdue(@Param("today") LocalDate today);

    long countByAssetIdAndStatusIn(Long assetId, List<RemediationStatus> statuses);

    /** 사이드바 숫자 — 아직 안 닫힌 조치. */
    long countByStatusIn(List<RemediationStatus> statuses);

    /** 사이드바 숫자 — 기한이 지난 채 안 닫힌 것. 붉게 띄우는 근거다. */
    @Query("""
           SELECT COUNT(r) FROM Remediation r
           WHERE r.dueDate < :today AND r.status IN ('OPEN', 'IN_PROGRESS')
           """)
    long countOverdue(@Param("today") LocalDate today);


    /** 구역 보고서용 — 한 구역(또는 전체)의 조치 전부. 닫힌 것도 함께 센다. */
    @Query("""
           SELECT r FROM Remediation r JOIN FETCH r.asset a JOIN FETCH a.zone z
           WHERE a.archivedAt IS NULL
             AND (:zoneId IS NULL OR z.id = :zoneId)
           ORDER BY a.name ASC, r.packageName ASC
           """)
    List<Remediation> findByZone(@Param("zoneId") Long zoneId);
}
