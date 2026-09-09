package kr.sbomsight.repo;

import kr.sbomsight.domain.Finding;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

/**
 * 탐지 조회.
 *
 * <p>집계는 전부 SQL 로 한다. 서버 한 대가 5만 건을 내는데 그것을 자바 객체로
 * 되살려 세면 화면 한 장에 몇 초가 걸린다. 화면에 필요한 것은 100건과 몇 개의
 * 합계뿐이다.
 */
public interface FindingRepository extends JpaRepository<Finding, Long> {

    /**
     * 목록 한 페이지. 정렬·필터를 SQL 에서 끝낸다.
     *
     * <p>{@code cvssScore} 가 NULL 인 건은 <b>방향과 무관하게 항상 뒤로</b> 보낸다.
     * 값이 없는 것을 0 점으로 줄 세우면 "위험하지 않다"는 없는 판정이 된다.
     */
    @Query("""
           SELECT f FROM Finding f
           WHERE f.scan.id = :scanId
             AND (:severity IS NULL OR LOWER(f.severity) = LOWER(:severity))
             AND (:fixable IS NULL
                  OR (:fixable = TRUE  AND f.fixState = 'fixed')
                  OR (:fixable = FALSE AND f.fixState <> 'fixed'))
             AND (:kev IS NULL OR f.kev = :kev)
             AND (:q IS NULL OR LOWER(f.packageName) LIKE LOWER(CONCAT('%', :q, '%'))
                             OR LOWER(f.cve) LIKE LOWER(CONCAT('%', :q, '%')))
           """)
    Page<Finding> search(@Param("scanId") Long scanId,
                         @Param("severity") String severity,
                         @Param("fixable") Boolean fixable,
                         @Param("kev") Boolean kev,
                         @Param("q") String q,
                         Pageable pageable);

    long countByScanId(Long scanId);

    /** 심각도 분포. 보고서 1장(현황)이 이 값으로 시작한다. */
    @Query("""
           SELECT LOWER(f.severity) AS severity, COUNT(f) AS total
           FROM Finding f WHERE f.scan.id = :scanId
           GROUP BY LOWER(f.severity)
           """)
    List<SeverityCount> countBySeverity(@Param("scanId") Long scanId);

    /** 수정 상태 분포 — 조치로 없앨 수 있는 것과 그럴 수 없는 것을 가른다. */
    @Query("""
           SELECT LOWER(f.fixState) AS fixState, COUNT(f) AS total
           FROM Finding f WHERE f.scan.id = :scanId
           GROUP BY LOWER(f.fixState)
           """)
    List<FixStateCount> countByFixState(@Param("scanId") Long scanId);

    /**
     * 패키지별 묶음 — <b>보고서의 핵심.</b>
     *
     * <p>"CVE 187건"은 손댈 곳을 알려 주지 않지만 "openssl 을 3.0.7 로 올리면
     * 12건이 사라진다"는 그대로 작업 지시가 된다. 실무자가 실행하는 단위는
     * 패키지 업데이트이므로 조치 목록은 여기서 나온다.
     */
    @Query("""
           SELECT f.packageName        AS packageName,
                  f.packageVersion     AS packageVersion,
                  f.packageType        AS packageType,
                  COUNT(f)             AS total,
                  SUM(CASE WHEN f.fixState = 'fixed' THEN 1 ELSE 0 END)      AS fixable,
                  SUM(CASE WHEN f.kev = TRUE THEN 1 ELSE 0 END)              AS kevCount,
                  SUM(CASE WHEN LOWER(f.severity) = 'critical' THEN 1 ELSE 0 END) AS criticalCount,
                  SUM(CASE WHEN LOWER(f.severity) = 'high' THEN 1 ELSE 0 END)     AS highCount,
                  MAX(f.cvssScore)     AS maxCvss,
                  MAX(f.epss)          AS maxEpss,
                  MAX(f.fixedVersion)  AS targetVersion
           FROM Finding f
           WHERE f.scan.id = :scanId
           GROUP BY f.packageName, f.packageVersion, f.packageType
           ORDER BY SUM(CASE WHEN f.kev = TRUE THEN 1 ELSE 0 END) DESC,
                    MAX(f.cvssScore) DESC,
                    COUNT(f) DESC
           """)
    List<PackageGroup> groupByPackage(@Param("scanId") Long scanId);

    /** 이력 대조용. 버전이 바뀌면 키도 바뀌므로 (CVE, 패키지명) 으로 본다. */
    @Query("SELECT CONCAT(f.cve, '|', f.packageName) FROM Finding f WHERE f.scan.id = :scanId")
    List<String> findCvePackagePairs(@Param("scanId") Long scanId);

    List<Finding> findByScanIdAndPackageNameOrderByCvssScoreDesc(Long scanId, String packageName);

    void deleteByScanId(Long scanId);

    interface SeverityCount {
        String getSeverity();

        long getTotal();
    }

    interface FixStateCount {
        String getFixState();

        long getTotal();
    }

    interface PackageGroup {
        String getPackageName();

        String getPackageVersion();

        String getPackageType();

        long getTotal();

        long getFixable();

        long getKevCount();

        long getCriticalCount();

        long getHighCount();

        java.math.BigDecimal getMaxCvss();

        java.math.BigDecimal getMaxEpss();

        String getTargetVersion();
    }
}
