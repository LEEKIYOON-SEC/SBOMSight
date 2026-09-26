package kr.sbomsight.repo;

import kr.sbomsight.domain.AnalysisState;
import kr.sbomsight.domain.FindingAnalysis;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDate;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

/**
 * 검토 결과 조회.
 *
 * <p>목록 한 장에 수백 건이 뜨는데 건마다 물으면 그만큼 왕복한다. 자산
 * 하나치를 한 번에 가져와 키로 맞춘다.
 */
public interface FindingAnalysisRepository extends JpaRepository<FindingAnalysis, Long> {

    @Query("""
           SELECT f FROM FindingAnalysis f
           WHERE f.asset.id = :assetId AND f.cve = :cve AND f.packageName = :packageName
           """)
    Optional<FindingAnalysis> findOne(@Param("assetId") Long assetId,
                                      @Param("cve") String cve,
                                      @Param("packageName") String packageName);

    /** 한 자산치 전부. 취약점 목록이 행마다 표시를 붙이는 데 쓴다. */
    @Query("SELECT f FROM FindingAnalysis f WHERE f.asset.id = :assetId")
    List<FindingAnalysis> findByAsset(@Param("assetId") Long assetId);

    /** 여러 자산치 한 번에 — 구역·전체 범위의 목록이 쓴다. */
    @Query("""
           SELECT f FROM FindingAnalysis f
           WHERE f.asset.id IN :assetIds
           """)
    List<FindingAnalysis> findByAssets(@Param("assetIds") Collection<Long> assetIds);

    /**
     * 목록 화면.
     *
     * <p>{@code 검토 끝난 것도 보기} 를 끄면 볼 일이 끝난 상태(해당 없음·오탐)가
     * 빠진다. 사람이 켜고 끄는 감추기 칸은 두지 않는다 — 상태가 정한다.
     *
     * <p>아무도 손대지 않은 행({@code 미검토} 이고 대응도 없는 것)은 목록에
     * 내지 않는다. 탐지 전체가 그대로 쏟아지는 것이라 목록이 되지 못한다 —
     * 그 목록은 취약점 화면이다.
     *
     * <p><b>재검토일이 지난 것이 맨 위로 온다.</b> 표 어딘가에 섞여 있으면
     * 지났다는 사실 자체를 못 보고 지나간다.
     *
     * <p>운영 종료한 자산의 것은 {@code includeArchived} 일 때만 — 조치와 같은
     * 규칙이다(RemediationRepository 머리 주석).
     *
     * <p><b>끝이 줄 하나를 가리킨다</b> — 자산 이름은 유일하고, 검토 결과는
     * (자산, CVE, 패키지) 에 하나다. 앞서 CVE 에서 멈춰, 같은 자산의 같은 CVE
     * 가 패키지 둘에 걸리면 요청마다 순서가 달라질 수 있었다. 화면은 요청마다
     * 이 목록을 읽어 쪽을 자르므로 쪽 경계에서 줄이 빠지거나 겹친다(ListOrderTest).
     */
    @Query("""
           SELECT f FROM FindingAnalysis f JOIN FETCH f.asset a JOIN FETCH a.zone z
           WHERE NOT (f.state = kr.sbomsight.domain.AnalysisState.NOT_SET AND f.response IS NULL)
             AND (:includeDone = TRUE OR f.state IN :openStates)
             AND (:zoneId IS NULL OR z.id = :zoneId)
             AND (:includeArchived = TRUE OR a.archivedAt IS NULL)
           ORDER BY CASE WHEN f.reviewBy IS NOT NULL AND f.reviewBy < :today THEN 0
                         WHEN f.state IN :openStates THEN 1
                         ELSE 2 END,
                    f.reviewBy ASC NULLS LAST, a.name ASC, f.cve ASC, f.packageName ASC
           """)
    List<FindingAnalysis> findForList(@Param("includeDone") boolean includeDone,
                                      @Param("openStates") Collection<AnalysisState> openStates,
                                      @Param("zoneId") Long zoneId,
                                      @Param("today") LocalDate today,
                                      @Param("includeArchived") boolean includeArchived);

    /** 재검토일이 지난 것. 자산 목록 머리와 기둥의 숫자에 조치 기한과 나란히 선다. */
    @Query("""
           SELECT f FROM FindingAnalysis f JOIN FETCH f.asset a JOIN FETCH a.zone
           WHERE f.reviewBy IS NOT NULL AND f.reviewBy < :today
             AND (:includeArchived = TRUE OR a.archivedAt IS NULL)
           ORDER BY f.reviewBy ASC
           """)
    List<FindingAnalysis> findReviewOverdue(@Param("today") LocalDate today,
                                            @Param("includeArchived") boolean includeArchived);

    @Query("""
           SELECT COUNT(f) FROM FindingAnalysis f
           WHERE f.reviewBy IS NOT NULL AND f.reviewBy < :today
             AND (:includeArchived = TRUE OR f.asset.archivedAt IS NULL)
           """)
    long countReviewOverdue(@Param("today") LocalDate today,
                            @Param("includeArchived") boolean includeArchived);

    /** 이 자산에 검토 결과가 몇 건 달려 있나. 자산을 지울 때 무엇이 함께 사라지는지 알린다. */
    @Query("""
           SELECT COUNT(f) FROM FindingAnalysis f
           WHERE f.asset.id = :assetId
             AND NOT (f.state = kr.sbomsight.domain.AnalysisState.NOT_SET AND f.response IS NULL)
           """)
    long countByAsset(@Param("assetId") Long assetId);
}
