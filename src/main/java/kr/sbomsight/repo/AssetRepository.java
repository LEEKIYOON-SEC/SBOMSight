package kr.sbomsight.repo;

import kr.sbomsight.domain.Asset;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface AssetRepository extends JpaRepository<Asset, Long> {

    /**
     * 목록용. 구역 먼저, 그 안에서 이름 순.
     *
     * <p>{@code JOIN FETCH} 로 구역을 함께 끌어온다. {@code open-in-view} 가
     * 꺼져 있어서, 화면에서 {@code asset.zone.name} 을 읽는 순간 세션이 없으면
     * {@code LazyInitializationException} 이 난다. 이 도구에서 세 번 겪은
     * 자리다 — 뷰에서 세션을 다시 여는 것이 아니라 필요한 것을 여기서 가져온다.
     */
    @Query("""
           SELECT a FROM Asset a JOIN FETCH a.zone z
           WHERE a.archivedAt IS NULL
           ORDER BY z.sortOrder ASC, z.name ASC, a.name ASC
           """)
    List<Asset> findLiveWithZone();

    /**
     * 보관한 것까지 전부. 목록에서 <b>보관된 자산도</b> 를 켰을 때 쓴다.
     *
     * <p>보관은 지우는 것과 다르다 — 결과는 남고 목록에서만 빠진다. 그런데
     * 다시 볼 길이 없으면 그건 지운 것이나 마찬가지다.
     */
    @Query("""
           SELECT a FROM Asset a JOIN FETCH a.zone z
           ORDER BY z.sortOrder ASC, z.name ASC, a.name ASC
           """)
    List<Asset> findAllWithZone();

    @Query("SELECT a FROM Asset a JOIN FETCH a.zone WHERE a.id = :id")
    Optional<Asset> findWithZone(@Param("id") Long id);

    /** 구역 하나에 자산이 몇 대 있는가. 비어 있어야 지울 수 있다. */
    long countByZoneId(Long zoneId);

    Optional<Asset> findByName(String name);

    boolean existsByName(String name);
}
