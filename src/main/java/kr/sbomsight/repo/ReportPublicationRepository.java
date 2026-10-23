package kr.sbomsight.repo;

import kr.sbomsight.domain.PublicationKind;
import kr.sbomsight.domain.ReportPublication;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.time.LocalDate;
import java.util.List;

/**
 * 발행본(V20).
 *
 * <p><b>목록은 문서를 읽지 않는다.</b> 한 줄에 문서(HTML · JSON)가 통째로 들어 있다 —
 * 엔티티로 읽으면 목록 한 쪽에 문서 백 벌을 끌어온다. 목록은 {@link PublicationRow} 로
 * 칸만 읽는다.
 */
public interface ReportPublicationRepository extends JpaRepository<ReportPublication, Long> {

    /** 목록 한 줄의 칸 — 문서는 빼고. */
    String ROW = """
            SELECT p.id AS id, p.kind AS kind, p.pubYear AS pubYear, p.pubSeq AS pubSeq,
                   p.publishedAt AS publishedAt, p.publishedBy AS publishedBy,
                   p.targetName AS targetName, p.scanId AS scanId, p.zoneId AS zoneId,
                   p.periodFrom AS periodFrom, p.periodTo AS periodTo, p.approvalDoc AS approvalDoc
            FROM ReportPublication p
            """;

    /** 그해의 마지막 일련번호. 없으면 {@code null}. */
    @Query("SELECT MAX(p.pubSeq) FROM ReportPublication p WHERE p.pubYear = :year")
    Integer maxSeq(@Param("year") int year);

    /** 발행본 목록 — 최근 것부터. */
    @Query(value = ROW + " ORDER BY p.publishedAt DESC, p.id DESC",
           countQuery = "SELECT COUNT(p) FROM ReportPublication p")
    Page<PublicationRow> findRows(Pageable pageable);

    /** 이 검사의 점검 결과 보고서를 발행한 것 — 지금 보고서가 제 발행본을 가리킨다. */
    @Query(ROW + " WHERE p.kind = 'SCAN' AND p.scanId = :scanId ORDER BY p.publishedAt DESC, p.id DESC")
    List<PublicationRow> findForScan(@Param("scanId") Long scanId);

    /** 같은 구역(전체면 전체) · 같은 기간의 구역 현황 보고서를 발행한 것. */
    @Query(ROW + """
             WHERE p.kind = 'ZONE'
               AND ((:zoneId IS NULL AND p.zoneId IS NULL) OR p.zoneId = :zoneId)
               AND p.periodFrom = :from AND p.periodTo = :to
             ORDER BY p.publishedAt DESC, p.id DESC
            """)
    List<PublicationRow> findForZone(@Param("zoneId") Long zoneId,
                                     @Param("from") LocalDate from, @Param("to") LocalDate to);

    /** 이 검사를 가리키는 발행본의 번호 — 검사를 지우지 못하는 까닭으로 화면에 낸다. */
    @Query("""
           SELECT p.pubYear AS pubYear, p.pubSeq AS pubSeq
           FROM ReportPublication p JOIN p.scanIds s
           WHERE s = :scanId
           ORDER BY p.pubYear, p.pubSeq
           """)
    List<NumberRow> findNumbersReferring(@Param("scanId") Long scanId);

    /**
     * 이 검사들을 가리키는 발행본 — 검사 이력 탭이 그 줄에 `삭제` 대신 발행본을 둔다.
     * 한 검사를 여럿이 가리키면 최근 것이 앞이다.
     */
    @Query("""
           SELECT s AS scanId, p.id AS id, p.pubYear AS pubYear, p.pubSeq AS pubSeq
           FROM ReportPublication p JOIN p.scanIds s
           WHERE s IN :scanIds
           ORDER BY p.publishedAt DESC, p.id DESC
           """)
    List<ScanReference> findReferences(@Param("scanIds") java.util.Collection<Long> scanIds);

    interface ScanReference {
        Long getScanId();

        Long getId();

        int getPubYear();

        int getPubSeq();

        default String getNumber() {
            return ReportPublication.number(getPubYear(), getPubSeq());
        }
    }

    interface NumberRow {
        int getPubYear();

        int getPubSeq();

        default String getNumber() {
            return ReportPublication.number(getPubYear(), getPubSeq());
        }
    }

    interface PublicationRow {
        Long getId();

        PublicationKind getKind();

        int getPubYear();

        int getPubSeq();

        Instant getPublishedAt();

        String getPublishedBy();

        String getTargetName();

        Long getScanId();

        Long getZoneId();

        LocalDate getPeriodFrom();

        LocalDate getPeriodTo();

        String getApprovalDoc();

        default String getNumber() {
            return ReportPublication.number(getPubYear(), getPubSeq());
        }
    }
}
