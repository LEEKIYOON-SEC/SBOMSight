package kr.sbomsight.repo;

import kr.sbomsight.domain.RemediationTarget;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Collection;
import java.util.List;

/** 조치 대상 — 조치를 등록할 때 그 패키지에 걸려 있던 탐지(V19). */
public interface RemediationTargetRepository extends JpaRepository<RemediationTarget, Long> {

    /** 조치 하나치 — 조치 상세의 `조치 대상` 표. 화면 순서는 RemediationService.targets 가 정한다. */
    @Query("""
           SELECT t FROM RemediationTarget t WHERE t.remediation.id = :remediationId ORDER BY t.id ASC
           """)
    List<RemediationTarget> findByRemediation(@Param("remediationId") Long remediationId);

    /** 여러 조치치 — 완료 뒤 남은 탐지가 대상인지 가르는 데 쓴다. 줄마다 조치 번호를 함께. */
    @Query("""
           SELECT t.remediation.id AS remediationId, t.cve AS cve, t.relatedCve AS relatedCve
           FROM RemediationTarget t WHERE t.remediation.id IN :ids
           """)
    List<TargetKey> findKeys(@Param("ids") Collection<Long> ids);

    interface TargetKey {
        Long getRemediationId();

        String getCve();

        String getRelatedCve();
    }
}
