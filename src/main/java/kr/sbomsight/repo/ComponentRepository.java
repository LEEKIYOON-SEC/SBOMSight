package kr.sbomsight.repo;

import kr.sbomsight.domain.Component;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

/**
 * 설치된 패키지.
 *
 * <p><b>자산마다 최신 완료 검사 것만 남는다.</b> 그래서 "지금 깔려 있는 것" 을
 * 물을 때 스캔을 고를 필요가 없다 — 자산으로 묶으면 그것이 곧 현재 상태다.
 *
 * <p><b>읽는 질의는 전부 완료된 검사의 행만 본다</b>({@code s.status = 'DONE'}).
 * 검사는 SBOM 을 읽으며 담고 grype 은 그 뒤에 몇 분씩 돈다 — 그동안 담긴 행이
 * 보이면 패키지 화면은 새 SBOM 을, 취약점 화면은 이전 검사를 말한다. 이전
 * 검사의 행은 새 검사가 끝나는 순간에 지운다({@code ScanService.run}).
 */
public interface ComponentRepository extends JpaRepository<Component, Long> {

    /**
     * 새 검사가 끝났다 — 그 자산의 <b>다른 검사에서 온 행을 지운다.</b>
     *
     * <p>넣기 전에 지우지 않고, 검사가 끝난 뒤에 지운다. 읽다가든 grype 에서든
     * 중간에 터지면 이전 인벤토리가 그대로 남아 있어야 한다 — 실패한 검사
     * 때문에 "이 자산에는 패키지가 없다" 가 되면 안 된다.
     */
    @Modifying
    @Query("DELETE FROM Component c WHERE c.asset.id = :assetId AND c.scan.id <> :scanId")
    int deleteOtherScans(@Param("assetId") Long assetId, @Param("scanId") Long scanId);

    @Modifying
    @Query("DELETE FROM Component c WHERE c.scan.id = :scanId")
    int deleteByScanId(@Param("scanId") Long scanId);

    /** 담긴 행 전부 — 도는 중이거나 실패한 검사 것까지. 정리가 됐는지 잴 때 쓴다. */
    long countByAssetId(Long assetId);

    /** 이 자산의 지금 인벤토리 — 자산 상세의 `패키지` 탭 숫자. */
    @Query("""
           SELECT COUNT(c) FROM Component c JOIN c.scan s
           WHERE c.asset.id = :assetId AND s.status = 'DONE'
           """)
    long countCurrentByAssetId(@Param("assetId") Long assetId);

    /** 지금 인벤토리가 하나라도 있나 — 패키지 화면이 "아직 안 담겼다" 를 말할지. */
    @Query("SELECT COUNT(c) FROM Component c JOIN c.scan s WHERE s.status = 'DONE'")
    long countCurrent();

    /**
     * 이 자산에 깔린 것. 자산 상세의 `패키지` 탭.
     *
     * <p><b>한 쪽씩 읽는다.</b> 앞서는 전부 한 번에 읽어 한 화면에 그렸다 —
     * 4천 줄짜리 서버에서 표가 끝나지 않았고, 4천 개 엔티티를 되살리느라
     * 그 탭만 눈에 띄게 느렸다.
     */
    @Query("""
           SELECT c FROM Component c JOIN c.scan s
           WHERE c.asset.id = :assetId AND s.status = 'DONE'
             AND (:q IS NULL OR LOWER(c.name) LIKE LOWER(CONCAT('%', :q, '%')))
           ORDER BY c.name ASC, c.version ASC
           """)
    Page<Component> findByAsset(@Param("assetId") Long assetId, @Param("q") String q,
                                Pageable pageable);

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
           JOIN c.scan s
           WHERE a.archivedAt IS NULL AND s.status = 'DONE'
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
           JOIN c.scan s
           WHERE a.archivedAt IS NULL AND s.status = 'DONE'
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
           JOIN c.scan s
           WHERE a.archivedAt IS NULL AND s.status = 'DONE'
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
           SELECT DISTINCT c.type FROM Component c JOIN c.asset a JOIN c.scan s
           WHERE a.archivedAt IS NULL AND s.status = 'DONE' AND c.type <> ''
           ORDER BY c.type ASC
           """)
    List<String> types();

    /** 펼쳤을 때의 자산별 줄. 한 패키지만 물어 본다. */
    @Query("""
           SELECT c FROM Component c
             JOIN FETCH c.asset a
             JOIN FETCH a.zone
             JOIN FETCH c.scan s
           WHERE c.name = :name AND a.archivedAt IS NULL AND s.status = 'DONE'
             AND (:zoneId IS NULL OR a.zone.id = :zoneId)
           ORDER BY c.version ASC, a.name ASC
           """)
    List<Component> findByName(@Param("name") String name, @Param("zoneId") Long zoneId);
}
