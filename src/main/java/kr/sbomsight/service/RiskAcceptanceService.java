package kr.sbomsight.service;

import kr.sbomsight.domain.*;
import kr.sbomsight.repo.RiskAcceptanceRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * 위험 수용 관리.
 *
 * <p><b>수용은 판정을 바꾸지 않는다.</b> 수용했다고 해서 그 건이 탐지에서
 * 빠지거나 심각도가 내려가지 않는다. 화면과 보고서는 여전히 그 건을 세고
 * 옆에 "수용됨" 을 붙일 뿐이다. 수용이 건수를 줄이면 그 순간 보고서는
 * 실제보다 안전해 보이는 숫자를 말하게 된다 — 그것이 이 기능을 잘못 만드는
 * 가장 쉬운 길이다.
 */
@Service
public class RiskAcceptanceService {

    /** 사유 없는 수용은 받지 않는다. "그냥" 을 적으려면 적어도 그렇게 적어야 한다. */
    private static final int MIN_REASON = 5;

    private final RiskAcceptanceRepository acceptances;
    private final AuditService audit;

    public RiskAcceptanceService(RiskAcceptanceRepository acceptances, AuditService audit) {
        this.acceptances = acceptances;
        this.audit = audit;
    }

    @Transactional
    public RiskAcceptance accept(Asset asset, String cve, String packageName,
                                 String reason, String compensating, String approvedBy,
                                 LocalDate reviewBy, String actor) {
        String cleanReason = reason == null ? "" : reason.trim();
        if (cleanReason.length() < MIN_REASON) {
            throw new IllegalArgumentException("수용 사유를 적어 주세요.");
        }
        if (approvedBy == null || approvedBy.isBlank()) {
            throw new IllegalArgumentException("승인한 사람을 적어 주세요.");
        }
        if (reviewBy == null) {
            throw new IllegalArgumentException("다시 볼 날짜를 정해 주세요.");
        }
        // 기한 없는 수용은 방치와 구분되지 않는다. 과거 날짜도 같은 뜻이라 막는다.
        if (reviewBy.isBefore(LocalDate.now())) {
            throw new IllegalArgumentException("다시 볼 날짜는 오늘 이후여야 합니다.");
        }
        acceptances.findActive(asset.getId(), cve, packageName).ifPresent(existing -> {
            throw new IllegalArgumentException("이미 수용된 건입니다.");
        });

        RiskAcceptance acceptance = new RiskAcceptance(asset, cve, packageName);
        acceptance.setReason(cleanReason);
        acceptance.setCompensating(compensating);
        acceptance.setApprovedBy(approvedBy);
        acceptance.setReviewBy(reviewBy);
        acceptance.setAcceptedBy(actor);
        acceptances.save(acceptance);

        audit.record(AuditEvent.RISK_ACCEPTED, asset.getName() + " · " + cve,
                     packageName + " · 승인 " + acceptance.getApprovedBy()
                     + " · 재검토 " + reviewBy);
        return acceptance;
    }

    /** 철회 — 지우지 않고 흔적을 남긴다. 누가 언제 왜 거뒀는지도 점검 대상이다. */
    @Transactional
    public void revoke(Long id, String note, String actor) {
        RiskAcceptance acceptance = acceptances.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("없는 수용 기록입니다."));
        if (!acceptance.isActive()) {
            throw new IllegalArgumentException("이미 철회된 기록입니다.");
        }
        acceptance.revoke(actor, note);
        acceptances.save(acceptance);
        audit.record(AuditEvent.RISK_ACCEPTANCE_REVOKED,
                     acceptance.getAsset().getName() + " · " + acceptance.getCve(),
                     acceptance.getPackageName());
    }

    /**
     * 한 자산의 살아 있는 수용을 {@code (CVE, 패키지명)} 키로 준다.
     *
     * <p>화면이 탐지 목록을 그리면서 "이 건은 수용됨" 을 붙이는 데 쓴다.
     * 건마다 질의하면 목록 한 장에 수백 번 왕복한다.
     */
    @Transactional(readOnly = true)
    public Map<String, RiskAcceptance> activeByKey(Long assetId) {
        return acceptances.findActiveByAsset(assetId).stream()
                .collect(Collectors.toMap(RiskAcceptance::key, Function.identity(),
                                          (a, b) -> a));
    }

    /** 키 집합만 필요할 때. */
    @Transactional(readOnly = true)
    public Set<String> activeKeys(Long assetId) {
        return activeByKey(assetId).keySet();
    }

    @Transactional(readOnly = true)
    public List<RiskAcceptance> list(boolean includeRevoked, Long zoneId) {
        return acceptances.findAllWithAsset(includeRevoked, zoneId);
    }

    @Transactional(readOnly = true)
    public List<RiskAcceptance> reviewOverdue() {
        return acceptances.findReviewOverdue(LocalDate.now());
    }
}
