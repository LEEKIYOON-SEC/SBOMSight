package kr.sbomsight.domain;

import jakarta.persistence.*;

import java.time.Instant;

/** 조치의 발자취 한 줄. 누가 언제 무엇을 바꿨는지. */
@Entity
@Table(name = "remediation_events")
public class RemediationEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    /** 조치를 지우면 그 이력도 함께. {@code V1__init.sql} 의 FK 와 같게 둔다. */
    @JoinColumn(name = "remediation_id", nullable = false)
    @org.hibernate.annotations.OnDelete(action = org.hibernate.annotations.OnDeleteAction.CASCADE)
    private Remediation remediation;

    @Column(nullable = false)
    private Instant at = Instant.now();

    @Column(nullable = false, length = 64)
    private String actor = "";

    /**
     * <b>그때 적힌 상태 이름을 그대로 쥔다.</b> 지금의 {@link RemediationStatus}
     * 로 읽지 않는다.
     *
     * <p>이력은 지난 일이다. V14 가 없앤 {@code ACCEPTED}(하지 않고 닫음)로
     * 닫혀 있던 조치를 대기로 되돌리며 {@code ACCEPTED → OPEN} 줄을 남겼는데,
     * 이 칸을 지금의 상태 목록으로 읽고 있어서 그 줄을 읽는 순간 조치 상세가
     * 500 이 됐다. 상태 목록은 앞으로도 바뀔 수 있고, 바뀔 때마다 지난 이력이
     * 깨지면 안 된다. 열은 V1 부터 VARCHAR 라 스키마는 그대로다.
     */
    @Column(name = "from_status", nullable = false, length = 16)
    private String fromStatus;

    @Column(name = "to_status", nullable = false, length = 16)
    private String toStatus;

    @Column(nullable = false, length = 1000)
    private String comment = "";

    protected RemediationEvent() {
    }

    RemediationEvent(Remediation remediation, String actor,
                     RemediationStatus from, RemediationStatus to, String comment) {
        this.remediation = remediation;
        this.actor = actor == null ? "" : actor;
        this.fromStatus = from.name();
        this.toStatus = to.name();
        this.comment = comment == null ? "" : comment;
    }

    /**
     * 지금은 없는 상태의 화면 이름. V14 의 메모·이력 문구와 같은 말이다
     * ({@code V14__drop_remediation_accepted.sql}).
     */
    private static final java.util.Map<String, String> RETIRED = java.util.Map.of(
            "ACCEPTED", "하지 않고 닫음");

    private static String label(String status) {
        for (RemediationStatus known : RemediationStatus.values()) {
            if (known.name().equals(status)) {
                return known.label();
            }
        }
        return RETIRED.getOrDefault(status, status);
    }

    public Long getId() {
        return id;
    }

    public Instant getAt() {
        return at;
    }

    public String getActor() {
        return actor;
    }

    /** 바뀌기 전 상태의 화면 이름. 없앤 상태도 그때 이름으로 읽는다. */
    public String getFromLabel() {
        return label(fromStatus);
    }

    /** 바뀐 뒤 상태의 화면 이름. */
    public String getToLabel() {
        return label(toStatus);
    }

    public String getComment() {
        return comment;
    }
}
