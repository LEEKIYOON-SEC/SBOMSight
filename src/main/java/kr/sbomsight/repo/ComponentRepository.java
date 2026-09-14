package kr.sbomsight.repo;

import kr.sbomsight.domain.Component;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

/**
 * 설치된 패키지.
 *
 * <p><b>자산마다 최신 검사 것만 들어 있다.</b> 그래서 "지금 깔려 있는 것" 을
 * 물을 때 스캔을 고를 필요가 없다 — 자산으로 묶으면 그것이 곧 현재 상태다.
 */
public interface ComponentRepository extends JpaRepository<Component, Long> {

    /**
     * 새 검사가 읽혔다 — 그 자산의 <b>다른 검사에서 온 행을 지운다.</b>
     *
     * <p>넣기 전에 지우지 않고 넣은 뒤에 지운다. 읽다가 중간에 터지면 이전
     * 인벤토리가 그대로 남아 있어야 한다 — 실패한 검사 때문에 "이 자산에는
     * 패키지가 없다" 가 되면 안 된다.
     */
    @Modifying
    @Query("DELETE FROM Component c WHERE c.asset.id = :assetId AND c.scan.id <> :scanId")
    int deleteOtherScans(@Param("assetId") Long assetId, @Param("scanId") Long scanId);

    @Modifying
    @Query("DELETE FROM Component c WHERE c.scan.id = :scanId")
    int deleteByScanId(@Param("scanId") Long scanId);

    long countByAssetId(Long assetId);

    /** 이 자산에 깔린 것. 자산 상세의 `패키지` 탭. */
    @Query("""
           SELECT c FROM Component c
           WHERE c.asset.id = :assetId
             AND (:q IS NULL OR LOWER(c.name) LIKE LOWER(CONCAT('%', :q, '%')))
           ORDER BY c.name ASC, c.version ASC
           """)
    List<Component> findByAsset(@Param("assetId") Long assetId, @Param("q") String q);

    /**
     * 패키지 이름으로 묶은 한 줄 — {@code /packages} 의 표.
     *
     * <p>유형을 {@code MIN} 으로 집는다. 같은 이름이 두 유형으로 깔린 일은
     * 실제로 드물고, 있으면 버전 분포에서 갈려 보인다.
     */
    @Query("""
           SELECT c.name AS name, MIN(c.type) AS type,
                  COUNT(DISTINCT c.asset.id) AS assetCount,
                  COUNT(DISTINCT c.version) AS versionCount
           FROM Component c
           JOIN c.asset a
           WHERE a.archivedAt IS NULL
             AND (:zoneId IS NULL OR a.zone.id = :zoneId)
             AND (:type IS NULL OR c.type = :type)
             AND (:q IS NULL OR LOWER(c.name) LIKE LOWER(CONCAT('%', :q, '%')))
           GROUP BY c.name
           ORDER BY COUNT(DISTINCT c.asset.id) DESC, c.name ASC
           """)
    List<PackageRow> groupByName(@Param("zoneId") Long zoneId,
                                 @Param("type") String type,
                                 @Param("q") String q);

    interface PackageRow {
        String getName();

        String getType();

        long getAssetCount();

        long getVersionCount();
    }

    /**
     * 버전 분포 — {@code (이름, 버전)} 마다 몇 대인가.
     *
     * <p>목록에 뜬 이름만 물어 본다. 전부 가져오면 12만 개짜리 자산 백 대에서
     * 수백만 행이 된다.
     */
    @Query("""
           SELECT c.name AS name, c.version AS version,
                  COUNT(DISTINCT c.asset.id) AS assetCount
           FROM Component c
           JOIN c.asset a
           WHERE a.archivedAt IS NULL
             AND c.name IN :names
             AND (:zoneId IS NULL OR a.zone.id = :zoneId)
           GROUP BY c.name, c.version
           ORDER BY COUNT(DISTINCT c.asset.id) DESC, c.version ASC
           """)
    List<VersionRow> versionSpread(@Param("names") List<String> names,
                                   @Param("zoneId") Long zoneId);

    interface VersionRow {
        String getName();

        String getVersion();

        long getAssetCount();
    }

    /**
     * 버전 분포 전부 — CSV 내보내기.
     *
     * <p>화면은 앞 200개 이름만 싣는다. 내보내기가 거기서 잘리면 <b>잘린 파일이
     * 결재 문서에 붙는다</b> — 그래서 여기서는 이름으로 자르지 않고 거르개만
     * 건다. 행 수는 {@code (이름, 버전)} 쌍만큼이라 인벤토리 전체보다 작다.
     */
    @Query("""
           SELECT c.name AS name, c.version AS version, MIN(c.type) AS type,
                  COUNT(DISTINCT c.asset.id) AS assetCount
           FROM Component c
           JOIN c.asset a
           WHERE a.archivedAt IS NULL
             AND (:zoneId IS NULL OR a.zone.id = :zoneId)
             AND (:type IS NULL OR c.type = :type)
             AND (:q IS NULL OR LOWER(c.name) LIKE LOWER(CONCAT('%', :q, '%')))
           GROUP BY c.name, c.version
           ORDER BY c.name ASC, c.version ASC
           """)
    List<TypedVersionRow> versionSpreadAll(@Param("zoneId") Long zoneId,
                                           @Param("type") String type,
                                           @Param("q") String q);

    interface TypedVersionRow {
        String getName();

        String getVersion();

        String getType();

        long getAssetCount();
    }

    /** 유형 거르개에 채울 값. SBOM 이 실제로 담아 온 것만 보여 준다. */
    @Query("""
           SELECT DISTINCT c.type FROM Component c JOIN c.asset a
           WHERE a.archivedAt IS NULL AND c.type <> '' ORDER BY c.type ASC
           """)
    List<String> types();

    /** 펼쳤을 때의 자산별 줄. 한 패키지만 물어 본다. */
    @Query("""
           SELECT c FROM Component c
             JOIN FETCH c.asset a
             JOIN FETCH a.zone
             JOIN FETCH c.scan
           WHERE c.name = :name AND a.archivedAt IS NULL
             AND (:zoneId IS NULL OR a.zone.id = :zoneId)
           ORDER BY c.version ASC, a.name ASC
           """)
    List<Component> findByName(@Param("name") String name, @Param("zoneId") Long zoneId);
}
