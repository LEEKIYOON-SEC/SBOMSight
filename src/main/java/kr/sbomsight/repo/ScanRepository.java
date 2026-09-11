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

    /**
     * 자산까지 함께 읽는다.
     *
     * <p>{@code open-in-view} 를 꺼 두었기 때문에 화면을 그리는 시점에는 이미
     * 세션이 닫혀 있다. 화면에서 {@code scan.asset.name} 을 쓰려면 여기서
     * 같이 읽어 와야 한다 — 열어 두는 쪽으로 도망가면 화면이 표를 그리는
     * 동안 질의를 수십 번 더 날리게 된다.
     */
    /**
     * 구역까지 함께 끌어온다. 보고서 머리에 자산의 구역이 찍히는데,
     * {@code open-in-view} 가 꺼져 있어 여기서 안 가져오면 그 자리에서
     * {@code LazyInitializationException} 이 난다.
     */
    @Query("SELECT s FROM Scan s JOIN FETCH s.asset a JOIN FETCH a.zone WHERE s.id = :id")
    Optional<Scan> findWithAsset(@Param("id") Long id);

    /** 자산의 가장 최근 완료 스캔. 목록과 보고서가 기준으로 삼는 것. */
    Optional<Scan> findFirstByAssetIdAndStatusOrderByCreatedAtDesc(Long assetId, ScanStatus status);

    List<Scan> findByStatusIn(List<ScanStatus> statuses);

    /**
     * 자산별 최근 완료 스캔을 한 번에.
     *
     * <p>자산마다 질의를 돌리면 자산 수만큼 왕복한다. 목록 화면 한 장에 그러면
     * 서른 대에 서른 번이다.
     *
     * <p><b>자산 하나당 정확히 한 행이 나와야 한다.</b> 앞서는
     * {@code createdAt = MAX(createdAt)} 로 잡았는데, 같은 시각에 완료된
     * 스캔이 둘이면 두 행이 나온다. 목록에서는 둘 중 아무거나 골라 쓰게 되고
     * 조회에서는 같은 자산이 두 번 보인다. 시각이 같으면 id 로 가른다.
     */
    @Query("""
           SELECT s FROM Scan s
           WHERE s.status = 'DONE'
             AND NOT EXISTS (SELECT 1 FROM Scan x
                             WHERE x.asset.id = s.asset.id AND x.status = 'DONE'
                               AND (x.createdAt > s.createdAt
                                    OR (x.createdAt = s.createdAt AND x.id > s.id)))
           """)
    List<Scan> findLatestDonePerAsset();

    long countByAssetId(Long assetId);
}
