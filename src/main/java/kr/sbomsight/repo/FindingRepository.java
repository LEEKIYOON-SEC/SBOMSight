package kr.sbomsight.repo;

import kr.sbomsight.domain.Finding;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Collection;
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
                             OR LOWER(f.cve) LIKE LOWER(CONCAT('%', :q, '%'))
                             OR LOWER(f.relatedCve) LIKE LOWER(CONCAT('%', :q, '%')))
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

    /**
     * 노출면 집계용 원재료.
     *
     * <p>벡터 해석을 SQL 로 흉내 내지 않는다({@code LIKE '%AV:N%'}). 그렇게 하면
     * {@link kr.sbomsight.domain.CvssVector} 와 규칙이 두 벌이 되고, 둘이
     * 갈라지는 순간 화면과 보고서가 서로 다른 수를 말한다. 필요한 네 칸만
     * 꺼내 와서 해석은 한 곳에서 한다.
     */
    @Query("""
           SELECT f.cvssVector      AS vector,
                  f.fixState        AS fixState,
                  LOWER(f.severity) AS severity,
                  f.packageName     AS packageName
           FROM Finding f WHERE f.scan.id = :scanId
           """)
    List<ExposureRow> exposureRows(@Param("scanId") Long scanId);

    // --- 통합 취약점 화면 (/vulns) -----------------------------------------
    //
    // 전사 조회의 질의(lookup)가 여기 있었다. "각 자산의 최신 완료 검사만
    // 본다" 는 조건이 질의 안에 박혀 있어서, 검사 하나만 보는 화면은 그
    // 질의를 쓸 수 없었고 따로 한 벌을 더 들고 있었다. 지금은 <b>범위를
    // 스캔 id 목록으로 받는다</b> — 무엇이 범위인지는 VulnQuery 가 정하고,
    // 여기는 그 목록 안에서만 센다. 질의가 한 벌로 줄었다.

    /**
     * 범위 안의 탐지 한 페이지.
     *
     * <p>범위를 <b>스캔 id 목록으로 받는다.</b> 검사 하나든, 한 구역의 최신
     * 검사들이든, 전체든 부르는 쪽이 정해서 넘긴다 — 질의를 세 벌 두지 않는다.
     *
     * <p><b>검색어는 있어도 되고 없어도 된다.</b> 앞서 전사 조회는 검색어가
     * 없으면 아무것도 보여 주지 않았는데, 그러면 "우리 전체에 심각이 몇 건인가"
     * 를 물을 수가 없다.
     *
     * <p>자산·구역을 {@code JOIN FETCH} 로 함께 끌어온다. {@code open-in-view}
     * 가 꺼져 있어 화면에서 {@code f.scan.asset.zone.name} 을 읽는 순간 세션이
     * 없으면 터진다.
     */
    @Query(value = """
           SELECT f FROM Finding f
             JOIN FETCH f.scan s JOIN FETCH s.asset a JOIN FETCH a.zone
           WHERE s.id IN :scanIds
             AND (:severity IS NULL OR LOWER(f.severity) = LOWER(:severity))
             AND (:fixable IS NULL
                  OR (:fixable = TRUE  AND f.fixState = 'fixed')
                  OR (:fixable = FALSE AND f.fixState <> 'fixed'))
             AND (:kev IS NULL OR f.kev = :kev)
             AND (:q IS NULL OR LOWER(f.packageName) LIKE LOWER(CONCAT('%', :q, '%'))
                             OR LOWER(f.cve)        LIKE LOWER(CONCAT('%', :q, '%'))
                             OR LOWER(f.relatedCve) LIKE LOWER(CONCAT('%', :q, '%')))
           """,
           countQuery = """
           SELECT COUNT(f) FROM Finding f JOIN f.scan s
           WHERE s.id IN :scanIds
             AND (:severity IS NULL OR LOWER(f.severity) = LOWER(:severity))
             AND (:fixable IS NULL
                  OR (:fixable = TRUE  AND f.fixState = 'fixed')
                  OR (:fixable = FALSE AND f.fixState <> 'fixed'))
             AND (:kev IS NULL OR f.kev = :kev)
             AND (:q IS NULL OR LOWER(f.packageName) LIKE LOWER(CONCAT('%', :q, '%'))
                             OR LOWER(f.cve)        LIKE LOWER(CONCAT('%', :q, '%'))
                             OR LOWER(f.relatedCve) LIKE LOWER(CONCAT('%', :q, '%')))
           """)
    Page<Finding> findIn(@Param("scanIds") Collection<Long> scanIds,
                         @Param("q") String q,
                         @Param("severity") String severity,
                         @Param("fixable") Boolean fixable,
                         @Param("kev") Boolean kev,
                         Pageable pageable);

    /**
     * 심각도 순으로 정렬한 같은 목록.
     *
     * <p>왜 질의를 따로 두는가 — 심각도는 <b>글자</b>다. {@code Critical} 이
     * {@code High} 보다 앞이라는 것은 알파벳 순서가 아니라 우리가 아는 뜻이고,
     * 그 순서는 {@code ORDER BY CASE} 로만 낼 수 있다. Pageable 의 Sort 로는
     * 표현되지 않으므로 질의에 박아 둔다.
     *
     * <p>순위를 열로 저장해 두는 방법도 있지만, 그러면 grype 이 준 단계를
     * 우리가 한 번 더 옮겨 적는 자리가 생긴다. 옮겨 적는 자리는 틀어진다.
     *
     * <p><b>방향을 질의 안에서 뒤집는다</b>({@code :asc}). 오름차순용 질의를
     * 한 벌 더 두면 {@code WHERE} 절이 두 곳에 있게 되고, 거르개를 하나
     * 고칠 때 한쪽만 고치는 날이 온다 — 그때부터 같은 목록이 정렬 방향에
     * 따라 다른 건수를 낸다.
     *
     * <p><b>심각도를 모르는 건은 방향과 무관하게 언제나 뒤로</b>(순위 9).
     * 오름차순에서 앞으로 올리면 "가장 안 위험한 것" 자리에 서게 되는데,
     * 그것은 아무도 내리지 않은 판정이다. CVSS 가 없는 건도 같다.
     */
    @Query(value = """
           SELECT f FROM Finding f
             JOIN FETCH f.scan s JOIN FETCH s.asset a JOIN FETCH a.zone
           WHERE s.id IN :scanIds
             AND (:severity IS NULL OR LOWER(f.severity) = LOWER(:severity))
             AND (:fixable IS NULL
                  OR (:fixable = TRUE  AND f.fixState = 'fixed')
                  OR (:fixable = FALSE AND f.fixState <> 'fixed'))
             AND (:kev IS NULL OR f.kev = :kev)
             AND (:q IS NULL OR LOWER(f.packageName) LIKE LOWER(CONCAT('%', :q, '%'))
                             OR LOWER(f.cve)        LIKE LOWER(CONCAT('%', :q, '%'))
                             OR LOWER(f.relatedCve) LIKE LOWER(CONCAT('%', :q, '%')))
           ORDER BY CASE WHEN :asc = TRUE
                           THEN CASE LOWER(f.severity)
                                  WHEN 'low'      THEN 0 WHEN 'medium'   THEN 1
                                  WHEN 'high'     THEN 2 WHEN 'critical' THEN 3 ELSE 9 END
                           ELSE CASE LOWER(f.severity)
                                  WHEN 'critical' THEN 0 WHEN 'high'     THEN 1
                                  WHEN 'medium'   THEN 2 WHEN 'low'      THEN 3 ELSE 9 END
                         END,
                    CASE WHEN :asc = TRUE THEN f.cvssScore ELSE -f.cvssScore END ASC NULLS LAST,
                    f.packageName ASC, f.cve ASC
           """,
           countQuery = """
           SELECT COUNT(f) FROM Finding f JOIN f.scan s
           WHERE s.id IN :scanIds
             AND (:severity IS NULL OR LOWER(f.severity) = LOWER(:severity))
             AND (:fixable IS NULL
                  OR (:fixable = TRUE  AND f.fixState = 'fixed')
                  OR (:fixable = FALSE AND f.fixState <> 'fixed'))
             AND (:kev IS NULL OR f.kev = :kev)
             AND (:q IS NULL OR LOWER(f.packageName) LIKE LOWER(CONCAT('%', :q, '%'))
                             OR LOWER(f.cve)        LIKE LOWER(CONCAT('%', :q, '%'))
                             OR LOWER(f.relatedCve) LIKE LOWER(CONCAT('%', :q, '%')))
           """)
    Page<Finding> findInBySeverity(@Param("scanIds") Collection<Long> scanIds,
                                   @Param("q") String q,
                                   @Param("severity") String severity,
                                   @Param("fixable") Boolean fixable,
                                   @Param("kev") Boolean kev,
                                   @Param("asc") boolean asc,
                                   Pageable pageable);

    /**
     * CVE 로 묶어 본다 — "이 취약점이 몇 대에 있나".
     *
     * <p>긴급 상황에서 가장 먼저 묻는 것이다. 항목별 목록은 같은 CVE 가 자산
     * 수만큼 반복되어 그 답을 세기 어렵다.
     *
     * <p>심각도를 묶음 키에 넣는다. grype 은 취약점 하나에 심각도 하나를
     * 주므로 보통 갈리지 않지만, 갈리면 <b>갈린 채로 보여 준다</b> — 하나로
     * 합치려면 어느 쪽을 버릴지 우리가 정해야 하고 그건 grype 의 판정을
     * 바꾸는 일이다.
     *
     * <p><b>묶는 축은 화면에 찍는 번호와 같아야 한다.</b> 항목별 목록은
     * {@link kr.sbomsight.domain.Finding#getDisplayId()} 를 찍는데(있으면
     * CVE 번호, 없으면 grype 의 식별자), 여기서 {@code f.cve} 로만 묶으면 같은
     * 취약점이 한 화면에서는 {@code CVE-2021-44228}, 다른 화면에서는
     * {@code GHSA-jfh8-c2jp-5v3q} 로 보인다. 결재와 보고는 CVE 번호로 도는데
     * 목록마다 번호가 달라지면 대조가 안 된다. 같은 식을 쓴다.
     */
    @Query("""
           SELECT CASE WHEN f.relatedCve <> '' THEN f.relatedCve ELSE f.cve END AS cve,
                  f.severity AS severity,
                  MAX(f.cvssScore) AS maxCvss, MAX(f.epss) AS maxEpss,
                  COUNT(f) AS total,
                  COUNT(DISTINCT f.scan.asset.id) AS assetCount,
                  COUNT(DISTINCT f.packageName) AS packageCount,
                  MIN(f.packageName) AS anyPackage,
                  SUM(CASE WHEN f.fixState = 'fixed' THEN 1 ELSE 0 END) AS fixable,
                  SUM(CASE WHEN f.kev = TRUE THEN 1 ELSE 0 END) AS kevCount
           FROM Finding f
           WHERE f.scan.id IN :scanIds
             AND (:severity IS NULL OR LOWER(f.severity) = LOWER(:severity))
             AND (:fixable IS NULL
                  OR (:fixable = TRUE  AND f.fixState = 'fixed')
                  OR (:fixable = FALSE AND f.fixState <> 'fixed'))
             AND (:kev IS NULL OR f.kev = :kev)
             AND (:q IS NULL OR LOWER(f.packageName) LIKE LOWER(CONCAT('%', :q, '%'))
                             OR LOWER(f.cve)        LIKE LOWER(CONCAT('%', :q, '%'))
                             OR LOWER(f.relatedCve) LIKE LOWER(CONCAT('%', :q, '%')))
           GROUP BY CASE WHEN f.relatedCve <> '' THEN f.relatedCve ELSE f.cve END,
                    f.severity
           ORDER BY CASE LOWER(f.severity)
                      WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                      WHEN 'medium'   THEN 2 WHEN 'low'  THEN 3 ELSE 4 END,
                    MAX(f.cvssScore) DESC,
                    CASE WHEN f.relatedCve <> '' THEN f.relatedCve ELSE f.cve END ASC
           """)
    List<CveGroup> groupByCveIn(@Param("scanIds") Collection<Long> scanIds,
                                @Param("q") String q,
                                @Param("severity") String severity,
                                @Param("fixable") Boolean fixable,
                                @Param("kev") Boolean kev);

    /** CVE 상세 — 이 CVE 가 걸린 자산 전부. */
    @Query("""
           SELECT f FROM Finding f
             JOIN FETCH f.scan s JOIN FETCH s.asset a JOIN FETCH a.zone
           WHERE s.id IN :scanIds AND (f.cve = :cve OR f.relatedCve = :cve)
           ORDER BY a.name ASC, f.packageName ASC
           """)
    List<Finding> findByCveIn(@Param("scanIds") Collection<Long> scanIds,
                              @Param("cve") String cve);

    /** 구역 분포 — "어디까지 번졌나". 자산 수를 구역 이름별로 센다. */
    @Query("""
           SELECT z.name AS zoneName, COUNT(DISTINCT a.id) AS assetCount
           FROM Finding f JOIN f.scan s JOIN s.asset a JOIN a.zone z
           WHERE s.id IN :scanIds AND (f.cve = :cve OR f.relatedCve = :cve)
           GROUP BY z.name ORDER BY z.name
           """)
    List<ZoneSpread> zoneSpread(@Param("scanIds") Collection<Long> scanIds,
                                @Param("cve") String cve);

    interface CveGroup {
        String getCve();

        String getSeverity();

        java.math.BigDecimal getMaxCvss();

        java.math.BigDecimal getMaxEpss();

        long getTotal();

        /** 이 CVE 가 걸린 자산 수. CVE별 보기의 핵심 숫자다. */
        long getAssetCount();

        long getPackageCount();

        String getAnyPackage();

        long getFixable();

        long getKevCount();
    }

    interface ZoneSpread {
        String getZoneName();

        long getAssetCount();
    }

    /**
     * 이 검사의 식별자·패키지 짝 — 검토 결과와 맞대 보는 데 쓴다.
     *
     * <p>{@code relatedCve} 까지 함께 준다. grype 이 GHSA 를 주 식별자로 낸
     * 건은 사람이 적을 때 CVE 번호를 쓰므로, 둘 중 어느 쪽으로 적혔든 찾아야
     * 한다 — 한쪽만 보면 적어 둔 검토 결과가 보고서에서 사라진다.
     */
    @Query("""
           SELECT f.cve AS cve, f.relatedCve AS relatedCve, f.packageName AS packageName
           FROM Finding f WHERE f.scan.id = :scanId
           """)
    List<FindingKey> findKeyRows(@Param("scanId") Long scanId);

    interface FindingKey {
        String getCve();

        String getRelatedCve();

        String getPackageName();
    }

    /** 이력 대조용. 버전이 바뀌면 키도 바뀌므로 (CVE, 패키지명) 으로 본다. */
    @Query("SELECT CONCAT(f.cve, '|', f.packageName) FROM Finding f WHERE f.scan.id = :scanId")
    List<String> findCvePackagePairs(@Param("scanId") Long scanId);

    List<Finding> findByScanIdAndPackageNameOrderByCvssScoreDesc(Long scanId, String packageName);

    void deleteByScanId(Long scanId);

    // --- 구역·기간 보고서: 여러 스캔을 한 번에 --------------------------------
    //
    // 자산마다 질의를 돌리면 서른 대에 백스무 번 왕복한다. 보고서 한 장에
    // 그럴 이유가 없다. 빈 목록으로 부르면 안 된다 — 부르는 쪽에서 막는다.

    @Query("""
           SELECT LOWER(f.severity) AS severity, COUNT(f) AS total
           FROM Finding f WHERE f.scan.id IN :scanIds
           GROUP BY LOWER(f.severity)
           """)
    List<SeverityCount> countBySeverityIn(@Param("scanIds") Collection<Long> scanIds);

    @Query("""
           SELECT LOWER(f.fixState) AS fixState, COUNT(f) AS total
           FROM Finding f WHERE f.scan.id IN :scanIds
           GROUP BY LOWER(f.fixState)
           """)
    List<FixStateCount> countByFixStateIn(@Param("scanIds") Collection<Long> scanIds);

    /** 노출면 원재료. 자산 id 가 붙어 있어 구역 합계와 자산별 수를 한 번에 낸다. */
    @Query("""
           SELECT f.cvssVector      AS vector,
                  f.fixState        AS fixState,
                  LOWER(f.severity) AS severity,
                  f.packageName     AS packageName,
                  s.asset.id        AS assetId
           FROM Finding f JOIN f.scan s WHERE s.id IN :scanIds
           """)
    List<ZoneExposureRow> exposureRowsIn(@Param("scanIds") Collection<Long> scanIds);

    /**
     * 자산별 <b>실제 악용</b>(KEV) 건수.
     *
     * <p>목록의 요약 줄과 구역 머리줄이 쓴다. 심각도 분포와 따로 세는 이유 —
     * 실제 악용은 심각도와 다른 축이다. 심각도가 `보통` 인데 실제로 악용되고
     * 있는 건이 있고, 그 건이 `심각` 100건보다 급하다.
     *
     * <p>{@code kev} 는 grype 이 준 값이다. 없으면 NULL 이고 그것은 "아니다"
     * 가 아니라 "모른다" 다 — {@code = TRUE} 로만 센다.
     */
    @Query("""
           SELECT s.asset.id AS assetId, COUNT(f) AS total
           FROM Finding f JOIN f.scan s
           WHERE s.id IN :scanIds AND f.kev = TRUE
           GROUP BY s.asset.id
           """)
    List<AssetCount> countKevPerAsset(@Param("scanIds") Collection<Long> scanIds);

    interface AssetCount {
        Long getAssetId();

        long getTotal();
    }

    /** 자산별 심각도 분포 — 구역 보고서의 자산 표. */
    @Query("""
           SELECT s.asset.id AS assetId, LOWER(f.severity) AS severity, COUNT(f) AS total
           FROM Finding f JOIN f.scan s WHERE s.id IN :scanIds
           GROUP BY s.asset.id, LOWER(f.severity)
           """)
    List<AssetSeverityCount> countBySeverityPerAsset(@Param("scanIds") Collection<Long> scanIds);

    /**
     * 구역 전체를 패키지로 묶는다 — <b>구역 보고서의 핵심 표.</b>
     *
     * <p>"openssl 을 올리면 12대에서 47건이 사라진다" 는 그대로 작업 지시가
     * 된다. 자산 하나짜리 보고서에는 없는 값(몇 대에 걸쳐 있는가)이 여기서
     * 나오고, 그것이 구역 단위로 보는 이유다.
     *
     * <p>버전은 묶음 축에서 뺀다 — 같은 openssl 이라도 자산마다 판이 다르다.
     * 대신 몇 가지 판이 섞여 있는지를 세어, 하나가 아니면 화면에서 목표
     * 버전을 단정하지 않는다.
     */
    @Query("""
           SELECT f.packageName    AS packageName,
                  f.packageType    AS packageType,
                  COUNT(f)         AS total,
                  COUNT(DISTINCT s.asset.id)     AS assetCount,
                  COUNT(DISTINCT f.packageVersion) AS versionCount,
                  MIN(f.packageVersion)          AS anyVersion,
                  SUM(CASE WHEN f.fixState = 'fixed' THEN 1 ELSE 0 END)          AS fixable,
                  SUM(CASE WHEN f.kev = TRUE THEN 1 ELSE 0 END)                  AS kevCount,
                  SUM(CASE WHEN LOWER(f.severity) = 'critical' THEN 1 ELSE 0 END) AS criticalCount,
                  SUM(CASE WHEN LOWER(f.severity) = 'high' THEN 1 ELSE 0 END)     AS highCount,
                  MAX(f.cvssScore)               AS maxCvss,
                  MAX(f.epss)                    AS maxEpss,
                  MAX(f.fixedVersion)            AS targetVersion,
                  COUNT(DISTINCT f.fixedVersion) AS targetCount
           FROM Finding f JOIN f.scan s
           WHERE s.id IN :scanIds
           GROUP BY f.packageName, f.packageType
           """)
    List<ZonePackageGroup> groupByPackageIn(@Param("scanIds") Collection<Long> scanIds);

    /**
     * 증감 대조용 키. {@code (자산, CVE, 패키지명)} 세 축이다.
     *
     * <p>문자열로 이어 붙여 돌려주지 않는다 — {@code CAST(id AS string)} 은
     * DB 마다 다르게 굴고, 시험은 H2 로 도는데 운영은 MariaDB 나 MySQL 이다.
     * 이어 붙이는 일은 자바에서 한다.
     */
    @Query("""
           SELECT s.asset.id AS assetId, f.cve AS cve, f.packageName AS packageName
           FROM Finding f JOIN f.scan s WHERE s.id IN :scanIds
           """)
    List<AssetFindingKey> findKeysIn(@Param("scanIds") Collection<Long> scanIds);

    /** 노출면 계산에 쓰는 네 칸. */
    interface ExposureRow {
        String getVector();

        String getFixState();

        String getSeverity();

        String getPackageName();
    }

    /**
     * 패키지 인벤토리의 <b>버전별 심각도</b> — {@code /packages} 의 버전 분포.
     *
     * <p>{@code (이름, 버전)} 마다 심각도별 건수를 낸다. 이것으로 <b>취약한
     * 버전과 안전한 버전을 눈으로 가른다</b> — 같은 패키지 안에 둘이 섞여
     * 있으면 "이미 올린 자산이 있는데 안 올린 자산이 남았다" 는 뜻이고,
     * 그것이 이 화면에서 가장 중요한 신호다.
     *
     * <p>목록에 뜬 이름만 물어 본다. 전부 가져오면 자산 백 대 × 12만 개에서
     * 수백만 행이 된다.
     */
    @Query("""
           SELECT f.packageName AS packageName, f.packageVersion AS packageVersion,
                  LOWER(f.severity) AS severity, COUNT(f) AS total
           FROM Finding f
           WHERE f.scan.id IN :scanIds AND f.packageName IN :names
           GROUP BY f.packageName, f.packageVersion, LOWER(f.severity)
           """)
    List<PackageVersionSeverity> severityByPackageVersion(
            @Param("scanIds") Collection<Long> scanIds, @Param("names") Collection<String> names);

    /**
     * 위와 같은 것을 <b>이름 목록 없이</b>. CSV 내보내기가 쓴다.
     *
     * <p>화면은 앞 200개만 싣지만 내보내기는 거른 것 전부를 낸다 — 200개에서
     * 잘린 파일이 결재 문서에 붙으면 그 수를 아무도 의심하지 않는다. 이름을
     * 수천 개 넘기면 {@code IN} 절이 그만큼 길어지므로 여기서는 조건을 뺀다.
     * 탐지 건수만큼이라 인벤토리 전체보다 훨씬 작다.
     */
    @Query("""
           SELECT f.packageName AS packageName, f.packageVersion AS packageVersion,
                  LOWER(f.severity) AS severity, COUNT(f) AS total
           FROM Finding f
           WHERE f.scan.id IN :scanIds
           GROUP BY f.packageName, f.packageVersion, LOWER(f.severity)
           """)
    List<PackageVersionSeverity> severityByPackageVersion(
            @Param("scanIds") Collection<Long> scanIds);

    interface PackageVersionSeverity {
        String getPackageName();

        String getPackageVersion();

        String getSeverity();

        long getTotal();
    }

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

    /** 노출면 원재료에 자산 id 를 얹은 것. */
    interface ZoneExposureRow extends ExposureRow {
        Long getAssetId();
    }

    interface AssetSeverityCount {
        Long getAssetId();

        String getSeverity();

        long getTotal();
    }

    interface AssetFindingKey {
        Long getAssetId();

        String getCve();

        String getPackageName();
    }

    /**
     * 구역 전체를 패키지로 묶은 한 줄.
     *
     * <p>{@link PackageGroup} 과 달리 버전이 묶음 축에 없다. 대신 몇 대에
     * 걸쳐 있는지({@code assetCount}), 판이 몇 가지인지({@code versionCount})
     * 가 붙는다.
     */
    interface ZonePackageGroup {
        String getPackageName();

        String getPackageType();

        long getTotal();

        /** 이 패키지가 걸린 자산 수. 구역 보고서에만 있는 값이다. */
        long getAssetCount();

        /** 자산마다 설치된 판이 몇 가지인가. 1 이 아니면 목표 버전을 단정하지 않는다. */
        long getVersionCount();

        String getAnyVersion();

        long getFixable();

        long getKevCount();

        long getCriticalCount();

        long getHighCount();

        java.math.BigDecimal getMaxCvss();

        java.math.BigDecimal getMaxEpss();

        String getTargetVersion();

        /** grype 이 제시한 수정 버전이 몇 가지인가. 1 이 아니면 "자산별 확인" 이다. */
        long getTargetCount();
    }
}
