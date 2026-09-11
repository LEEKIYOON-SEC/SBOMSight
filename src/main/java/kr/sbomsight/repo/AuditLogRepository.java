package kr.sbomsight.repo;

import kr.sbomsight.domain.AuditEvent;
import kr.sbomsight.domain.AuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

    /**
     * 조회 한 페이지. 최근 것이 먼저.
     *
     * <p>기간은 여기서 거른다. "지난달에 누가 무엇을 지웠나" 가 실제로 묻는
     * 질문이고, 그때 전체를 자바로 끌어와 세면 답이 안 나온다.
     */
    @Query("""
           SELECT a FROM AuditLog a
           WHERE (:actor  IS NULL OR LOWER(a.actor) LIKE LOWER(CONCAT('%', :actor, '%')))
             AND (:action IS NULL OR a.action = :action)
             AND (:from   IS NULL OR a.at >= :from)
             AND (:to     IS NULL OR a.at <  :to)
             AND (:q      IS NULL OR LOWER(a.target) LIKE LOWER(CONCAT('%', :q, '%'))
                                  OR LOWER(a.detail) LIKE LOWER(CONCAT('%', :q, '%')))
           ORDER BY a.at DESC, a.id DESC
           """)
    Page<AuditLog> search(@Param("actor") String actor,
                          @Param("action") AuditEvent action,
                          @Param("from") Instant from,
                          @Param("to") Instant to,
                          @Param("q") String q,
                          Pageable pageable);

    /** 내려받기용 — 페이지 없이 같은 조건으로. 화면의 필터가 그대로 적용된다. */
    @Query("""
           SELECT a FROM AuditLog a
           WHERE (:actor  IS NULL OR LOWER(a.actor) LIKE LOWER(CONCAT('%', :actor, '%')))
             AND (:action IS NULL OR a.action = :action)
             AND (:from   IS NULL OR a.at >= :from)
             AND (:to     IS NULL OR a.at <  :to)
             AND (:q      IS NULL OR LOWER(a.target) LIKE LOWER(CONCAT('%', :q, '%'))
                                  OR LOWER(a.detail) LIKE LOWER(CONCAT('%', :q, '%')))
           ORDER BY a.at DESC, a.id DESC
           """)
    List<AuditLog> export(@Param("actor") String actor,
                          @Param("action") AuditEvent action,
                          @Param("from") Instant from,
                          @Param("to") Instant to,
                          @Param("q") String q);

    /** 한 계정의 최근 로그인 실패 횟수 — 잠금 판단에 쓴다. */
    long countByActorAndActionAndAtAfter(String actor, AuditEvent action, Instant after);
}
