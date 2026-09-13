package kr.sbomsight.domain;

import jakarta.persistence.*;

import java.time.Instant;

/**
 * 검토 결과의 변경 이력 한 줄 — 누가 언제 무엇을 어떻게 바꿨는지.
 *
 * <p>덮어쓰기만 하면 "언제부터 해당 없음이었나" 에 답할 수 없다. 점검에서
 * 묻는 것이 그것이다. {@link RemediationEvent} 가 이미 같은 모양이라 그대로
 * 따르되, 여기는 바뀌는 칸이 여럿이라 <b>칸 이름</b>까지 남긴다.
 */
@Entity
@Table(name = "finding_analysis_event")
public class FindingAnalysisEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "analysis_id", nullable = false)
    private FindingAnalysis analysis;

    @Column(nullable = false)
    private Instant at = Instant.now();

    /** 로그인 계정. 사람이 적는 칸이 아니다. */
    @Column(nullable = false, length = 64)
    private String actor = "";

    /** 무엇이 바뀌었나 — {@code 상태} · {@code 근거} · {@code 대응} · {@code 재검토일} … */
    @Column(name = "field_name", nullable = false, length = 32)
    private String field = "";

    /** 바뀌기 전 값. 화면에 찍는 말로 담는다 — 이력은 사람이 읽는 것이다. */
    @Column(name = "before_value", nullable = false, length = 255)
    private String before = "";

    @Column(name = "after_value", nullable = false, length = 255)
    private String after = "";

    protected FindingAnalysisEvent() {
    }

    FindingAnalysisEvent(FindingAnalysis analysis, String actor,
                         String field, String before, String after) {
        this.analysis = analysis;
        this.actor = actor == null ? "" : actor.trim();
        this.field = field == null ? "" : field;
        this.before = clip(before);
        this.after = clip(after);
    }

    private static String clip(String value) {
        String text = value == null ? "" : value.trim();
        return text.length() > 255 ? text.substring(0, 255) : text;
    }

    public Long getId() {
        return id;
    }

    public Instant getAt() {
        return at;
    }

    /** 옮겨 온 이력은 그때의 시각을 그대로 쓴다 — 마이그레이션한 날이 아니다. */
    public void setAt(Instant at) {
        this.at = at;
    }

    public String getActor() {
        return actor;
    }

    public String getField() {
        return field;
    }

    public String getBefore() {
        return before;
    }

    public String getAfter() {
        return after;
    }
}
