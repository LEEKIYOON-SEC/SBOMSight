package kr.sbomsight.repo;

import kr.sbomsight.domain.Scan;
import kr.sbomsight.domain.ScanStage;
import kr.sbomsight.domain.ScanStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

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

    /** {@link #currentOf} 의 질의 — SBOM 생성 시각, 같으면 검사 시각, 그것도 같으면 번호. */
    Optional<Scan> findFirstByAssetIdAndStatusOrderBySbomCreatedAtDescCreatedAtDescIdDesc(
            Long assetId, ScanStatus status);

    /**
     * 자산의 <b>최신 검사</b> — SBOM 생성 시각이 가장 늦은 완료 검사(D1). 패키지 목록 ·
     * 조치 · 검토 결과 · 취약점 화면 · 보고서가 이것으로 고른다.
     *
     * <p><b>검사가 돈 시각이 아니다.</b> 앞서는 가장 나중에 만들어진 완료 검사였다 —
     * 옛 줄에서 `다시 검사` 를 누르면 옛 SBOM 이 최신이 됐고(재현 시험 P4), 예전에 떠 둔
     * SBOM 을 늦게 올려도 그것이 최신이 됐다. 서버의 상태가 거꾸로 돌아간 것처럼 보였다.
     *
     * <p>SBOM 생성 시각이 같으면 — 같은 SBOM 을 다시 검사했으면 — 나중에 돈 쪽이다(새
     * 취약점 DB). 그것도 같으면 번호로 가른다. <b>이 규칙은 아래 질의들과 {@link
     * Scan#BY_SBOM_TIME} 에도 그대로 적혀 있다</b> — 하나를 고치면 셋을 고친다.
     */
    default Optional<Scan> currentOf(Long assetId) {
        return findFirstByAssetIdAndStatusOrderBySbomCreatedAtDescCreatedAtDescIdDesc(
                assetId, ScanStatus.DONE);
    }

    /**
     * 자산의 완료 검사 — <b>최신 검사부터</b>({@link #currentOf} 와 같은 순서). 보고서가
     * "지난 검사 대비" 와 최근 추이를 이 순서로 고른다.
     */
    List<Scan> findByAssetIdAndStatusOrderBySbomCreatedAtDescCreatedAtDescIdDesc(
            Long assetId, ScanStatus status);

    /**
     * 진행 중(대기 · 검사 중)인 검사가 있는가 — <b>같은 자산에 검사 둘을 돌리지
     * 않는다</b>(ScanService). 끝날 때 서로의 패키지 목록을 지운다.
     */
    boolean existsByAssetIdAndStatusIn(Long assetId, java.util.Collection<ScanStatus> statuses);

    List<Scan> findByStatusIn(List<ScanStatus> statuses);

    /**
     * 자산별 최신 검사를 한 번에 — {@link #currentOf} 와 같은 규칙(SBOM 생성 시각 →
     * 검사 시각 → 번호).
     *
     * <p>자산마다 질의를 돌리면 자산 수만큼 왕복한다. 목록 화면 한 장에 그러면
     * 서른 대에 서른 번이다.
     *
     * <p><b>자산 하나당 정확히 한 행이 나와야 한다.</b> 앞서는
     * {@code createdAt = MAX(createdAt)} 로 잡았는데, 같은 시각에 완료된
     * 스캔이 둘이면 두 행이 나온다. 목록에서는 둘 중 아무거나 골라 쓰게 되고
     * 조회에서는 같은 자산이 두 번 보인다. 시각이 같으면 다음 열로 가른다.
     */
    @Query("""
           SELECT s FROM Scan s
           WHERE s.status = 'DONE'
             AND NOT EXISTS (SELECT 1 FROM Scan x
                             WHERE x.asset.id = s.asset.id AND x.status = 'DONE'
                               AND (x.sbomCreatedAt > s.sbomCreatedAt
                                    OR (x.sbomCreatedAt = s.sbomCreatedAt
                                        AND (x.createdAt > s.createdAt
                                             OR (x.createdAt = s.createdAt AND x.id > s.id)))))
           """)
    List<Scan> findLatestDonePerAsset();

    /**
     * 위와 같되 자산 · 구역까지 끌어오고 최근 순으로 준다 — 보고서 고르기 화면용.
     *
     * <p>{@link #findLatestDonePerAsset()} 는 자산의 <b>id</b> 만 쓰는 쪽에서
     * 부르므로 지연 프록시로 충분하다. 여기서는 화면이 자산 이름과 구역
     * 이름을 찍는데 {@code open-in-view} 가 꺼져 있어, 같이 읽어 오지 않으면
     * 그 자리에서 {@code LazyInitializationException} 이 난다.
     *
     * <p>운영 종료한 자산은 뺀다 — 더 뽑을 일이 없는 자산이다.
     */
    @Query("""
           SELECT s FROM Scan s
             JOIN FETCH s.asset a
             JOIN FETCH a.zone z
           WHERE s.status = 'DONE'
             AND a.archivedAt IS NULL
             AND NOT EXISTS (SELECT 1 FROM Scan x
                             WHERE x.asset.id = s.asset.id AND x.status = 'DONE'
                               AND (x.sbomCreatedAt > s.sbomCreatedAt
                                    OR (x.sbomCreatedAt = s.sbomCreatedAt
                                        AND (x.createdAt > s.createdAt
                                             OR (x.createdAt = s.createdAt AND x.id > s.id)))))
           ORDER BY s.createdAt DESC
           """)
    List<Scan> findLatestDonePerAssetWithAsset();

    long countByAssetId(Long assetId);

    /**
     * 진행 단계를 그 자리에서 바꾼다.
     *
     * <p><b>엔티티를 고쳐 저장하지 않고 갱신 질의를 쓰는 이유.</b> 이 값은
     * 검사가 도는 <i>동안</i> 다른 요청(진행 상태를 묻는 화면)에 보여야 한다.
     * 바깥 트랜잭션 안에서 필드를 바꾸면 커밋 전까지 아무에게도 안 보이고,
     * 그러면 단계가 하나씩 뜨는 것이 아니라 끝나는 순간 한꺼번에 뜬다 —
     * 진행 표시가 있으나 마나가 된다.
     *
     * <p>{@code REQUIRES_NEW} 로 제 트랜잭션을 열어 바로 커밋한다.
     */
    @Modifying
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    @Query("UPDATE Scan s SET s.stage = :stage WHERE s.id = :id")
    void updateStage(@Param("id") Long id, @Param("stage") ScanStage stage);

    /**
     * 구역 보고서의 기준 검사 — 자산마다 <b>기간 안에 돈</b> 완료 검사 가운데 최신 검사
     * ({@link #currentOf} 와 같은 규칙).
     *
     * <p>기간 밖의 스캔을 끌어오면 "9월 현황" 에 8월 상태가 섞인다. 반대로
     * 기간 안에 검사가 없는 자산은 <b>여기에 나오지 않는다</b> — 그 자산이
     * 조용히 빠지지 않도록, 부르는 쪽에서 대상 자산 목록과 대조해 빠진 것을
     * 따로 센다.
     *
     * <p>{@code createdAt < :to} 로 끝을 연다. 종료일의 23:59:59 를 쓰면
     * 그 1초 사이의 스캔이 사라진다.
     */
    @Query("""
           SELECT s FROM Scan s
             JOIN FETCH s.asset a
             JOIN FETCH a.zone z
           WHERE s.status = 'DONE'
             AND a.archivedAt IS NULL
             AND s.createdAt >= :from AND s.createdAt < :to
             AND (:zoneId IS NULL OR z.id = :zoneId)
             AND NOT EXISTS (SELECT 1 FROM Scan x
                             WHERE x.asset.id = s.asset.id AND x.status = 'DONE'
                               AND x.createdAt >= :from AND x.createdAt < :to
                               AND (x.sbomCreatedAt > s.sbomCreatedAt
                                    OR (x.sbomCreatedAt = s.sbomCreatedAt
                                        AND (x.createdAt > s.createdAt
                                             OR (x.createdAt = s.createdAt AND x.id > s.id)))))
           """)
    List<Scan> findLatestDonePerAssetBetween(@Param("zoneId") Long zoneId,
                                             @Param("from") java.time.Instant from,
                                             @Param("to") java.time.Instant to);

    /**
     * 기간이 시작되기 <b>직전</b>의 상태 — 증감을 재는 기준선. 기간 전에 돈 완료 검사
     * 가운데 최신 검사({@link #currentOf} 와 같은 규칙).
     *
     * <p>이 스캔이 없는 자산은 기간 중에 처음 들어온 자산이다. 그 자산의
     * 탐지를 전부 "신규" 로 세면 증감이 부풀려진다 — 새로 본 것이지 새로
     * 생긴 것이 아니다. 부르는 쪽에서 대조 대상에서 빼고 그 수를 밝힌다.
     */
    @Query("""
           SELECT s FROM Scan s
             JOIN FETCH s.asset a
             JOIN FETCH a.zone z
           WHERE s.status = 'DONE'
             AND a.archivedAt IS NULL
             AND s.createdAt < :before
             AND (:zoneId IS NULL OR z.id = :zoneId)
             AND NOT EXISTS (SELECT 1 FROM Scan x
                             WHERE x.asset.id = s.asset.id AND x.status = 'DONE'
                               AND x.createdAt < :before
                               AND (x.sbomCreatedAt > s.sbomCreatedAt
                                    OR (x.sbomCreatedAt = s.sbomCreatedAt
                                        AND (x.createdAt > s.createdAt
                                             OR (x.createdAt = s.createdAt AND x.id > s.id)))))
           """)
    List<Scan> findLatestDonePerAssetBefore(@Param("zoneId") Long zoneId,
                                            @Param("before") java.time.Instant before);

    /**
     * 기간 중에 <b>SBOM 을 올린</b> 자산 — 다시 검사가 아닌 완료 검사가 하나라도 있는 것.
     *
     * <p>구역 보고서 1장이 "다시 검사만 한 자산" 을 가를 때 쓴다. 기준 검사 하나로는
     * 모른다 — 기간 안에 옛 SBOM 을 올리고 그것을 다시 검사했으면 기준 검사는 다시 검사다.
     */
    @Query("""
           SELECT DISTINCT a.id FROM Scan s JOIN s.asset a JOIN a.zone z
           WHERE s.status = 'DONE' AND s.rescanOf IS NULL AND a.archivedAt IS NULL
             AND s.createdAt >= :from AND s.createdAt < :to
             AND (:zoneId IS NULL OR z.id = :zoneId)
           """)
    List<Long> findAssetIdsWithUploadBetween(@Param("zoneId") Long zoneId,
                                             @Param("from") java.time.Instant from,
                                             @Param("to") java.time.Instant to);

    /**
     * 기간 중 <b>실패한</b> 검사 — 자산마다 횟수와 마지막 시각.
     *
     * <p>구역 보고서는 자산마다 기간 안의 마지막 <b>완료</b> 검사로 센다. 그 뒤에
     * 검사가 실패했으면 보고서의 수는 실패 전 상태다 — 말하지 않으면 최신으로
     * 읽힌다. 그리고 완료 검사 없이 실패만 있는 자산은 "검사 기록이 없는" 자산이
     * 아니다 — 돌렸는데 실패했다. 둘 다 보고서가 말하려면 이 수가 있어야 한다.
     */
    @Query("""
           SELECT a.id AS assetId, COUNT(s) AS failures, MAX(s.createdAt) AS lastFailedAt
           FROM Scan s JOIN s.asset a JOIN a.zone z
           WHERE s.status = 'FAILED' AND a.archivedAt IS NULL
             AND s.createdAt >= :from AND s.createdAt < :to
             AND (:zoneId IS NULL OR z.id = :zoneId)
           GROUP BY a.id
           """)
    List<FailedCount> countFailedPerAssetBetween(@Param("zoneId") Long zoneId,
                                                 @Param("from") java.time.Instant from,
                                                 @Param("to") java.time.Instant to);

    interface FailedCount {
        Long getAssetId();

        long getFailures();

        java.time.Instant getLastFailedAt();
    }

    /** 기간 중 실제로 돌린 검사 횟수. 자산 수와 다르다 — 한 자산을 여러 번 돌린다. */
    @Query("""
           SELECT COUNT(s) FROM Scan s JOIN s.asset a JOIN a.zone z
           WHERE s.status = 'DONE' AND a.archivedAt IS NULL
             AND s.createdAt >= :from AND s.createdAt < :to
             AND (:zoneId IS NULL OR z.id = :zoneId)
           """)
    long countDoneBetween(@Param("zoneId") Long zoneId,
                          @Param("from") java.time.Instant from,
                          @Param("to") java.time.Instant to);

    /**
     * 발행하는 보고서의 근거가 된 검사가 <b>아직 있는가</b> — 잠그며 읽는다(PublicationService).
     *
     * <p>잠그며 읽어야 지금 커밋된 것을 본다. 보통 읽기는 그 트랜잭션이 처음 읽은 때의
     * 모습을 보여 주어(REPEATABLE READ), 보고서를 계산하는 사이에 지워진 검사가 아직 있는
     * 것으로 보인다. 빈 목록으로 부르지 않는다({@code IN ()} 은 SQL 이 아니다).
     */
    @Query(value = "SELECT id FROM scans WHERE id IN (:ids) FOR UPDATE", nativeQuery = true)
    List<Number> lockExisting(@Param("ids") java.util.Collection<Long> ids);
}
