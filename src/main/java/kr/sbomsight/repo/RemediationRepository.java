package kr.sbomsight.repo;

import kr.sbomsight.domain.Remediation;
import kr.sbomsight.domain.RemediationStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

public interface RemediationRepository extends JpaRepository<Remediation, Long> {

    Optional<Remediation> findByAssetIdAndPackageName(Long assetId, String packageName);

    List<Remediation> findByAssetIdOrderByStatusAscPackageNameAsc(Long assetId);

    List<Remediation> findByStatusInOrderByDueDateAsc(List<RemediationStatus> statuses);

    /** 기한이 지난 채 아직 안 닫힌 것. 첫 화면에서 먼저 보여야 하는 값이다. */
    @Query("""
           SELECT r FROM Remediation r
           WHERE r.dueDate < :today AND r.status IN ('OPEN', 'IN_PROGRESS')
           ORDER BY r.dueDate ASC
           """)
    List<Remediation> findOverdue(@Param("today") LocalDate today);

    long countByAssetIdAndStatusIn(Long assetId, List<RemediationStatus> statuses);
}
