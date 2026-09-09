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
    @JoinColumn(name = "remediation_id", nullable = false)
    private Remediation remediation;

    @Column(nullable = false)
    private Instant at = Instant.now();

    @Column(nullable = false, length = 64)
    private String actor = "";

    @Enumerated(EnumType.STRING)
    @Column(name = "from_status", nullable = false, length = 16)
    private RemediationStatus fromStatus;

    @Enumerated(EnumType.STRING)
    @Column(name = "to_status", nullable = false, length = 16)
    private RemediationStatus toStatus;

    @Column(nullable = false, length = 1000)
    private String comment = "";

    protected RemediationEvent() {
    }

    RemediationEvent(Remediation remediation, String actor,
                     RemediationStatus from, RemediationStatus to, String comment) {
        this.remediation = remediation;
        this.actor = actor == null ? "" : actor;
        this.fromStatus = from;
        this.toStatus = to;
        this.comment = comment == null ? "" : comment;
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

    public RemediationStatus getFromStatus() {
        return fromStatus;
    }

    public RemediationStatus getToStatus() {
        return toStatus;
    }

    public String getComment() {
        return comment;
    }
}
