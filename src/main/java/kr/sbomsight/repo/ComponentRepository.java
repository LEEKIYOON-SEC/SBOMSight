package kr.sbomsight.repo;

import kr.sbomsight.domain.Component;
import kr.sbomsight.domain.PackageKey;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Collection;
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
     * 새 검사가 그 자산의 지금 검사가 됐다 — <b>끝난 다른 검사에서 온 행을 지운다.</b>
     *
     * <p>넣기 전에 지우지 않고, 검사가 끝난 뒤에 지운다. 읽다가든 grype 에서든
     * 중간에 터지면 이전 인벤토리가 그대로 남아 있어야 한다 — 실패한 검사
     * 때문에 "이 자산에는 패키지가 없다" 가 되면 안 된다.
     *
     * <p><b>아직 도는 검사의 행은 두지 않고 지우지도 않는다.</b> 앞서 다른 검사의
     * 행을 전부 지워, 겹쳐 돌던 검사가 담아 둔 것까지 사라졌다 — 그 검사가 끝나며
     * 다시 이쪽 것을 지워 패키지가 0행이 됐다(ScanOverlapTest). 도는 검사의 행은
     * 그 검사가 끝날 때 기준이 되거나 버려진다(ComponentInventoryService.makeCurrent).
     */
    @Modifying
    @Query("""
           DELETE FROM Component c
           WHERE c.asset.id = :assetId AND c.scan.id <> :scanId
             AND c.scan.id IN (SELECT s.id FROM Scan s
                               WHERE s.asset.id = :assetId AND s.status IN ('DONE', 'FAILED'))
           """)
    int deleteFinishedOtherScans(@Param("assetId") Long assetId, @Param("scanId") Long scanId);

    /** 이 검사에서 온 행 수 — 지금 검사에 패키지 목록이 담겨 있는지 볼 때. */
    long countByScanId(Long scanId);

    /**
     * 패키지 행을 쥐고 있는 <b>끝난</b> 검사 — 자산마다. 최신 검사가 아닌 것이 섞여
     * 있으면 그 자산의 패키지 목록이 최신 검사의 것이 아니다(InventoryReconciler).
     *
     * <p>검사 쪽에서 묻는다 — 검사마다 행이 있는지만 본다(ix_component_scan). 패키지
     * 표를 통째로 훑어 묶으면 12만 개짜리 자산 백 대에서 천만 행이다.
     */
    @Query("""
           SELECT s.asset.id AS assetId, s.id AS scanId FROM Scan s
           WHERE s.status IN ('DONE', 'FAILED')
             AND EXISTS (SELECT c.id FROM Component c WHERE c.scan.id = s.id)
           """)
    List<Holder> findFinishedScansHoldingRows();

    interface Holder {
        Long getAssetId();

        Long getScanId();
    }

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
     *
     * <p><b>끝에 {@code c.id} 를 둔다.</b> 같은 패키지 · 같은 버전이 두 경로에
     * 깔리면 이름과 버전으로는 순서가 정해지지 않는다(유일 키가 없다). 쪽을
     * 나눠 읽으므로 경계에서 줄이 빠지거나 겹친다(ListOrderTest).
     *
     * <p>검색어는 이름과 식별자의 네임스페이스에서 찾는다({@link #keyPattern}).
     */
    default Page<Component> findByAsset(Long assetId, String q, Pageable pageable) {
        return findByAssetMatching(assetId, q, keyPattern(q), pageable);
    }

    @Query("""
           SELECT c FROM Component c JOIN c.scan s
           WHERE c.asset.id = :assetId AND s.status = 'DONE'
             AND (:q IS NULL OR LOWER(c.name) LIKE LOWER(CONCAT('%', :q, '%'))
                  OR LOWER(c.packageKey) LIKE LOWER(CONCAT('pkg:%/%', :qk, '%')) ESCAPE '!')
           ORDER BY c.name ASC, c.version ASC, c.id ASC
           """)
    Page<Component> findByAssetMatching(@Param("assetId") Long assetId, @Param("q") String q,
                                        @Param("qk") String qk, Pageable pageable);

    /**
     * 검색어를 식별자에서 찾는 LIKE 조각 — 식별자와 같은 인코딩({@link PackageKey#searchable})에서
     * LIKE 의 특수 글자({@code % _})를 {@code !} 로 막는다. 식별자에는 퍼센트 인코딩의 {@code %} 가
     * 글자로 들어 있다 — 막지 않으면 {@code %40types} 의 {@code %} 가 아무 글자나 받는다.
     *
     * <p>{@code pkg:%/} 뒤에서 찾는다 — 유형({@code npm} · {@code maven})에 걸려 그 유형 전부가
     * 나오지 않게. 네임스페이스(groupId · scope · 배포판) · 이름 · 남긴 한정자(classifier …)에서 찾는다.
     */
    static String keyPattern(String q) {
        return q == null ? null
                : PackageKey.searchable(q).replace("!", "!!").replace("%", "!%").replace("_", "!_");
    }

    /**
     * 패키지 식별자로 묶은 한 줄 — {@code /packages} 의 표.
     *
     * <p><b>한 줄은 패키지 식별자다</b>(PackageKey · V24) — 탐지 · 검토 결과 · 조치와 같은 키.
     * 앞서 (이름, 유형)이라 groupId 만 다른 두 jackson-databind 가 한 줄로 합쳐져, 버전 분포 ·
     * 취약점 수에 남의 것이 섞였다(그 전에는 이름 하나라 npm 과 pypi 의 {@code semver} 가).
     * 이름 · 유형은 화면에 찍을 값이다 — 같은 식별자를 syft 가 다른 이름으로 적었으면
     * 그중 하나(MIN)다.
     *
     * <p>검색어는 이름과 식별자의 네임스페이스에서 찾는다({@link #keyPattern}) — 앞서 이름만이라
     * groupId({@code org.apache.logging.log4j}) · scope({@code @types})로는 아무것도 나오지 않았다.
     */
    default List<PackageRow> groupByPackage(Long zoneId, String type, String q) {
        return groupByPackageMatching(zoneId, type, q, keyPattern(q));
    }

    @Query("""
           SELECT c.packageKey AS packageKey, MIN(c.name) AS name, MIN(c.type) AS type,
                  COUNT(DISTINCT c.asset.id) AS assetCount,
                  COUNT(DISTINCT c.version) AS versionCount
           FROM Component c
           JOIN c.asset a
           JOIN c.scan s
           WHERE a.archivedAt IS NULL AND s.status = 'DONE'
             AND (:zoneId IS NULL OR a.zone.id = :zoneId)
             AND (:type IS NULL OR c.type = :type)
             AND (:q IS NULL OR LOWER(c.name) LIKE LOWER(CONCAT('%', :q, '%'))
                  OR LOWER(c.packageKey) LIKE LOWER(CONCAT('pkg:%/%', :qk, '%')) ESCAPE '!')
           GROUP BY c.packageKey
           ORDER BY COUNT(DISTINCT c.asset.id) DESC, MIN(c.name) ASC, c.packageKey ASC
           """)
    List<PackageRow> groupByPackageMatching(@Param("zoneId") Long zoneId,
                                            @Param("type") String type,
                                            @Param("q") String q,
                                            @Param("qk") String qk);

    interface PackageRow {
        String getPackageKey();

        String getName();

        String getType();

        long getAssetCount();

        long getVersionCount();
    }

    /**
     * 버전 분포 — {@code (식별자, 버전)} 마다 몇 대인가.
     *
     * <p>목록에 뜬 줄의 식별자만 물어 본다. 전부 가져오면 12만 개짜리 자산 백 대에서
     * 수백만 행이 된다. 앞서 이름으로 물어 유형으로 갈랐는데, 이제 줄의 키 그대로 묻는다 —
     * 같은 이름의 다른 패키지 버전이 그 줄의 버전 분포에 끼지 않는다. 유형을 모르는 줄이 받을
     * 탐지 가운데 다른 줄이 가진 것을 가를 때도 쓴다(PackageService).
     */
    @Query("""
           SELECT c.packageKey AS packageKey, MIN(c.name) AS name, MIN(c.type) AS type,
                  c.version AS version,
                  COUNT(DISTINCT c.asset.id) AS assetCount
           FROM Component c
           JOIN c.asset a
           JOIN c.scan s
           WHERE a.archivedAt IS NULL AND s.status = 'DONE'
             AND c.packageKey IN :keys
             AND (:zoneId IS NULL OR a.zone.id = :zoneId)
           GROUP BY c.packageKey, c.version
           ORDER BY COUNT(DISTINCT c.asset.id) DESC, c.version ASC
           """)
    List<VersionRow> versionSpread(@Param("keys") List<String> keys,
                                   @Param("zoneId") Long zoneId);

    /**
     * <b>유형을 모르는 줄</b>({@code pkg:/이름}) 가운데 이름이 이것인 것 — 그 구역 전체에서. 이름은
     * 대소문자를 가리지 않는다(소문자로 넘긴다). 이름의 대소문자만 다른 유형 없는 줄이 둘 이상이면
     * 아무 줄도 갖지 않은 탐지를 그 가운데 한 줄에만 주려고 쓴다(PackageService) — 화면의 한 쪽이나
     * 거른 줄만 보면 쪽 · 거르개마다 받는 줄이 달라진다.
     */
    @Query("""
           SELECT c.packageKey AS packageKey, MIN(c.name) AS name, MIN(c.type) AS type,
                  c.version AS version,
                  COUNT(DISTINCT c.asset.id) AS assetCount
           FROM Component c
           JOIN c.asset a
           JOIN c.scan s
           WHERE a.archivedAt IS NULL AND s.status = 'DONE'
             AND c.packageKey LIKE 'pkg:/%' AND LOWER(c.name) IN :names
             AND (:zoneId IS NULL OR a.zone.id = :zoneId)
           GROUP BY c.packageKey, c.version
           """)
    List<VersionRow> untypedByName(@Param("names") Collection<String> names,
                                   @Param("zoneId") Long zoneId);

    /** 버전 분포 한 조각 — {@code (식별자, 버전)} 하나. 이름 · 유형은 화면 · CSV 에 찍을 값. */
    interface VersionRow {
        String getPackageKey();

        String getName();

        String getType();

        String getVersion();

        long getAssetCount();
    }

    /**
     * 버전 분포 전부 — CSV 내보내기.
     *
     * <p>화면은 앞 200개 이름만 싣는다. 내보내기가 거기서 잘리면 <b>잘린 파일이
     * 결재 문서에 붙는다</b> — 그래서 여기서는 이름으로 자르지 않고 거르개만
     * 건다. 행 수는 {@code (식별자, 버전)} 만큼이라 인벤토리 전체보다 작다.
     * 앞서 {@code (이름, 버전)} 으로 묶고 유형을 {@code MIN} 으로 집어, 같은 이름 · 버전이
     * 두 유형에 있으면 한 줄로 합쳐졌다. 검색어는 화면({@link #groupByPackage})과 같이 찾는다.
     */
    default List<VersionRow> versionSpreadAll(Long zoneId, String type, String q) {
        return versionSpreadAllMatching(zoneId, type, q, keyPattern(q));
    }

    @Query("""
           SELECT c.packageKey AS packageKey, MIN(c.name) AS name, MIN(c.type) AS type,
                  c.version AS version,
                  COUNT(DISTINCT c.asset.id) AS assetCount
           FROM Component c
           JOIN c.asset a
           JOIN c.scan s
           WHERE a.archivedAt IS NULL AND s.status = 'DONE'
             AND (:zoneId IS NULL OR a.zone.id = :zoneId)
             AND (:type IS NULL OR c.type = :type)
             AND (:q IS NULL OR LOWER(c.name) LIKE LOWER(CONCAT('%', :q, '%'))
                  OR LOWER(c.packageKey) LIKE LOWER(CONCAT('pkg:%/%', :qk, '%')) ESCAPE '!')
           GROUP BY c.packageKey, c.version
           ORDER BY MIN(c.name) ASC, c.packageKey ASC, c.version ASC
           """)
    List<VersionRow> versionSpreadAllMatching(@Param("zoneId") Long zoneId,
                                              @Param("type") String type,
                                              @Param("q") String q,
                                              @Param("qk") String qk);

    /** 유형 거르개에 채울 값. SBOM 이 실제로 담아 온 것만 보여 준다. */
    @Query("""
           SELECT DISTINCT c.type FROM Component c JOIN c.asset a JOIN c.scan s
           WHERE a.archivedAt IS NULL AND s.status = 'DONE' AND c.type <> ''
           ORDER BY c.type ASC
           """)
    List<String> types();

    /** 펼쳤을 때의 자산별 줄 — 패키지 하나(식별자). */
    @Query("""
           SELECT c FROM Component c
             JOIN FETCH c.asset a
             JOIN FETCH a.zone
             JOIN FETCH c.scan s
           WHERE c.packageKey = :packageKey AND a.archivedAt IS NULL AND s.status = 'DONE'
             AND (:zoneId IS NULL OR a.zone.id = :zoneId)
           ORDER BY c.version ASC, a.name ASC, c.id ASC
           """)
    List<Component> findByPackageKey(@Param("packageKey") String packageKey,
                                     @Param("zoneId") Long zoneId);

    /**
     * 식별자가 붙기 전의 주소({@code ?open=이름&openType=유형} · {@code ?open=이름})로 열었을 때 —
     * 적어 둔 주소가 죽지 않게. 유형이 {@code null} 이면 그 이름의 줄 전부다. 화면은 줄마다
     * 제 식별자의 것만 그린다.
     */
    @Query("""
           SELECT c FROM Component c
             JOIN FETCH c.asset a
             JOIN FETCH a.zone
             JOIN FETCH c.scan s
           WHERE c.name = :name AND a.archivedAt IS NULL AND s.status = 'DONE'
             AND (:type IS NULL OR c.type = :type)
             AND (:zoneId IS NULL OR a.zone.id = :zoneId)
           ORDER BY c.version ASC, a.name ASC
           """)
    List<Component> findByNameAndType(@Param("name") String name, @Param("type") String type,
                                      @Param("zoneId") Long zoneId);
}
