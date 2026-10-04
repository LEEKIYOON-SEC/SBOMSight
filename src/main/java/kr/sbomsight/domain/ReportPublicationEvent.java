package kr.sbomsight.domain;

import jakarta.persistence.*;

import java.time.Instant;

/**
 * 발행본의 결재 문서 번호를 바꾼 일 한 줄 — 누가 언제 무엇에서 무엇으로(V20).
 *
 * <p>결재 문서 번호는 발행한 뒤에 적는다. 덮어쓰기만 하면 "언제 누가 이 번호를 붙였나"
 * 에 답할 수 없다. 바뀌는 칸이 하나라 칸 이름은 남기지 않는다.
 */
@Entity
@Table(name = "report_publication_events")
public class ReportPublicationEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "publication_id", nullable = false,
                foreignKey = @ForeignKey(name = "fk_report_publication_event"))
    private ReportPublication publication;

    @Column(nullable = false)
    private Instant at = Instant.now();

    /** 로그인 계정. 사람이 적는 칸이 아니다. */
    @Column(nullable = false, length = 64)
    private String actor = "";

    @Column(name = "before_value", nullable = false, length = 128)
    private String before = "";

    @Column(name = "after_value", nullable = false, length = 128)
    private String after = "";

    protected ReportPublicationEvent() {
    }

    ReportPublicationEvent(ReportPublication publication, String actor, String before, String after) {
        this.publication = publication;
        this.actor = actor == null ? "" : actor.trim();
        this.before = before == null ? "" : before;
        this.after = after == null ? "" : after;
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

    public String getBefore() {
        return before;
    }

    public String getAfter() {
        return after;
    }
}
