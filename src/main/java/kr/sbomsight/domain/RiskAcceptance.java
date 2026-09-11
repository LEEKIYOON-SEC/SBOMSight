package kr.sbomsight.domain;

import jakarta.persistence.*;

import java.time.Instant;
import java.time.LocalDate;

/**
 * 위험 수용 — 고칠 수 없는 건을 "이런 이유로 그대로 둔다" 고 적어 둔 것.
 *
 * <p><b>왜 필요한가.</b> 점검에서 "이건 왜 안 고쳤냐" 를 반드시 묻는다. 그때
 * 답이 없으면 방치로 읽힌다. 수정본이 없는 건은 조치할 수 없지만, 아무것도
 * 하지 않은 것과 "알고 있고 이렇게 막고 있다" 는 완전히 다르다.
 *
 * <p><b>이것은 grype 의 판정을 바꾸지 않는다.</b> 수용했다고 해서 그 건이
 * 탐지에서 빠지거나 심각도가 내려가지 않는다. 화면과 보고서는 여전히 그
 * 건을 세고, 옆에 "수용됨" 을 붙일 뿐이다. 수용이 건수를 줄이면 그 순간
 * 보고서는 실제보다 안전해 보이는 숫자를 말하게 된다.
 *
 * <p>단위는 {@code (자산, CVE, 패키지명)} 이다. 버전을 넣으면 부분 패치로
 * 버전이 바뀌는 순간 수용이 조용히 풀린다.
 */
@Entity
@Table(name = "risk_acceptances")
public class RiskAcceptance {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "asset_id", nullable = false)
    private Asset asset;

    @Column(nullable = false, length = 64)
    private String cve;

    @Column(name = "package_name", nullable = false, length = 255)
    private String packageName;

    @Column(nullable = false, length = 2000)
    private String reason = "";

    /** 고치는 대신 무엇으로 막고 있는가 — 접근 제한·WAF·모니터링 등. */
    @Column(nullable = false, length = 1000)
    private String compensating = "";

    /** 승인한 사람. 계정 이름이 아니라 결재한 사람의 이름이다. */
    @Column(name = "approved_by", nullable = false, length = 128)
    private String approvedBy = "";

    @Column(name = "accepted_at", nullable = false)
    private Instant acceptedAt = Instant.now();

    @Column(name = "accepted_by", nullable = false, length = 64)
    private String acceptedBy = "";

    /** 다시 볼 날. 기한 없는 수용은 방치와 구분되지 않는다. */
    @Column(name = "review_by", nullable = false)
    private LocalDate reviewBy;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "revoked_by", nullable = false, length = 64)
    private String revokedBy = "";

    @Column(name = "revoke_note", nullable = false, length = 1000)
    private String revokeNote = "";

    protected RiskAcceptance() {
    }

    public RiskAcceptance(Asset asset, String cve, String packageName) {
        this.asset = asset;
        this.cve = cve;
        this.packageName = packageName;
    }

    /** 아직 살아 있는 수용인가. 철회한 것은 기록으로만 남는다. */
    public boolean isActive() {
        return revokedAt == null;
    }

    /** 다시 볼 날이 지났는가. 철회된 것은 해당 없다. */
    public boolean isReviewOverdue() {
        return isActive() && reviewBy != null && reviewBy.isBefore(LocalDate.now());
    }

    /** 이력·보고서가 쓰는 키. 버전은 넣지 않는다. */
    public String key() {
        return cve + "|" + packageName;
    }

    public Long getId() {
        return id;
    }

    public Asset getAsset() {
        return asset;
    }

    public String getCve() {
        return cve;
    }

    public String getPackageName() {
        return packageName;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason == null ? "" : reason.trim();
    }

    public String getCompensating() {
        return compensating;
    }

    public void setCompensating(String compensating) {
        this.compensating = compensating == null ? "" : compensating.trim();
    }

    public String getApprovedBy() {
        return approvedBy;
    }

    public void setApprovedBy(String approvedBy) {
        this.approvedBy = approvedBy == null ? "" : approvedBy.trim();
    }

    public Instant getAcceptedAt() {
        return acceptedAt;
    }

    public String getAcceptedBy() {
        return acceptedBy;
    }

    public void setAcceptedBy(String acceptedBy) {
        this.acceptedBy = acceptedBy == null ? "" : acceptedBy.trim();
    }

    public LocalDate getReviewBy() {
        return reviewBy;
    }

    public void setReviewBy(LocalDate reviewBy) {
        this.reviewBy = reviewBy;
    }

    public Instant getRevokedAt() {
        return revokedAt;
    }

    public String getRevokedBy() {
        return revokedBy;
    }

    public String getRevokeNote() {
        return revokeNote;
    }

    /** 철회 — 지우지 않고 흔적을 남긴다. 누가 언제 왜 거뒀는지도 점검 대상이다. */
    public void revoke(String actor, String note) {
        this.revokedAt = Instant.now();
        this.revokedBy = actor == null ? "" : actor.trim();
        this.revokeNote = note == null ? "" : note.trim();
    }
}
