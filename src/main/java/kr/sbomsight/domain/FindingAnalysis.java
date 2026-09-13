package kr.sbomsight.domain;

import jakarta.persistence.*;

import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

/**
 * 검토 결과 — 탐지 하나에 대한 <b>우리의 결정</b>.
 *
 * <p><b>이것은 grype 의 판정을 바꾸지 않는다.</b> grype 은 "이 패키지에 이
 * CVE 가 있다" 고 말했고 그 말은 그대로 남는다. 여기에 {@code 해당 없음} 을
 * 적어도 탐지 건수는 줄지 않고 보고서의 원본 숫자도 그대로다. 목록에서
 * 빠질 뿐이고, 보고서는 <b>몇 건이 빠졌는지를 반드시 찍는다</b> — 숫자가
 * 조용히 줄어든 보고서는 점검에서 문제가 된다.
 *
 * <p><b>앞서 '위험 수용' 이라는 별도의 표가 있었다.</b> 그런데 그것은 이
 * 다섯 상태 중 하나({@code 해당됨})와 다섯 대응 중 하나({@code 조치 안 함})의
 * 조합일 뿐이었다. 표를 따로 두니 같은 건에 "수용" 과 "조치" 가 각각 달릴 수
 * 있었고, 둘이 무슨 관계인지는 아무 데도 없었다. 한 표로 합친다.
 *
 * <p>단위는 {@code (자산, CVE, 패키지명)} 이다. 버전을 넣으면 부분 패치로
 * 버전이 바뀌는 순간 검토 결과가 조용히 풀린다.
 */
@Entity
@Table(name = "finding_analysis",
       uniqueConstraints = @UniqueConstraint(
               name = "ux_analysis_key",
               columnNames = { "asset_id", "cve", "package_name" }))
public class FindingAnalysis {

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

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private AnalysisState state = AnalysisState.NOT_SET;

    /** {@code 해당 없음} 일 때만 찬다. 나머지 상태에서는 비어 있다. */
    @Enumerated(EnumType.STRING)
    @Column(length = 64)
    private AnalysisJustification justification;

    @Enumerated(EnumType.STRING)
    @Column(length = 32)
    private AnalysisResponse response;

    /** 사람이 적는 설명. 고르는 값(근거)과 다른 것이라 이름을 가른다. */
    @Column(nullable = false, length = 2000)
    private String note = "";

    /** 고치는 대신 무엇으로 막고 있는가 — 접근 제한·WAF·모니터링 등. */
    @Column(name = "other_control", nullable = false, length = 1000)
    private String otherControl = "";

    /**
     * 사내 결재 문서 번호. 비어 있을 수 있다.
     *
     * <p>이 도구에 승인 절차는 없다. 실제 승인은 사내 결재에서 나고 여기에는
     * 그것을 가리키는 번호만 둔다. 시스템이 아는 값(누가 로그인해서 눌렀는가)은
     * {@link #updatedBy} 로 자동으로 남기고, 모르는 값(누가 결재했는가)은
     * <b>아는 척하지 않는다.</b>
     */
    @Column(name = "approval_doc", nullable = false, length = 128)
    private String approvalDoc = "";

    /**
     * 재검토일. {@link AnalysisResponse#needsReviewDate()} 인 대응에만 받는다.
     *
     * <p>고치지 않고 두기로 한 것에 기한이 없으면 방치와 구분되지 않는다.
     */
    @Column(name = "review_by")
    private LocalDate reviewBy;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    /** 마지막으로 손댄 로그인 계정. 사람이 적는 칸이 아니다. */
    @Column(name = "updated_by", nullable = false, length = 64)
    private String updatedBy = "";

    @OneToMany(mappedBy = "analysis", cascade = CascadeType.ALL, orphanRemoval = true)
    @OrderBy("at ASC, id ASC")
    private List<FindingAnalysisEvent> events = new ArrayList<>();

    protected FindingAnalysis() {
    }

    public FindingAnalysis(Asset asset, String cve, String packageName) {
        this.asset = asset;
        this.cve = cve;
        this.packageName = packageName;
    }

    /**
     * 기본 목록에 보이는가 — <b>상태가 정한다.</b>
     *
     * <p>사람이 켜고 끄는 감추기 칸은 두지 않는다. 두면 같은 상태인데 어떤
     * 건은 보이고 어떤 건은 안 보인다.
     */
    public boolean isOpen() {
        return state.isOpen();
    }

    /** 재검토일이 지났는가. 기한을 받지 않는 대응은 해당 없다. */
    public boolean isReviewOverdue() {
        return reviewBy != null && reviewBy.isBefore(LocalDate.now());
    }

    /** 목록·보고서가 쓰는 키. 버전은 넣지 않는다. */
    public String key() {
        return cve + "|" + packageName;
    }

    /** 아무도 손대지 않은 것과 같은가. 화면에서 표시를 붙일지 가른다. */
    public boolean isUntouched() {
        return state == AnalysisState.NOT_SET && response == null;
    }

    /** 변경 이력 한 줄. 무엇이 무엇에서 무엇으로 바뀌었는지. */
    public void record(String actor, String field, String before, String after) {
        events.add(new FindingAnalysisEvent(this, actor, field, before, after));
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

    public AnalysisState getState() {
        return state;
    }

    public void setState(AnalysisState state) {
        this.state = state == null ? AnalysisState.NOT_SET : state;
    }

    public AnalysisJustification getJustification() {
        return justification;
    }

    public void setJustification(AnalysisJustification justification) {
        this.justification = justification;
    }

    public AnalysisResponse getResponse() {
        return response;
    }

    public void setResponse(AnalysisResponse response) {
        this.response = response;
    }

    public String getNote() {
        return note;
    }

    public void setNote(String note) {
        this.note = note == null ? "" : note.trim();
    }

    public String getOtherControl() {
        return otherControl;
    }

    public void setOtherControl(String otherControl) {
        this.otherControl = otherControl == null ? "" : otherControl.trim();
    }

    public String getApprovalDoc() {
        return approvalDoc;
    }

    public void setApprovalDoc(String approvalDoc) {
        this.approvalDoc = approvalDoc == null ? "" : approvalDoc.trim();
    }

    public LocalDate getReviewBy() {
        return reviewBy;
    }

    public void setReviewBy(LocalDate reviewBy) {
        this.reviewBy = reviewBy;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = updatedAt;
    }

    public String getUpdatedBy() {
        return updatedBy;
    }

    public void setUpdatedBy(String updatedBy) {
        this.updatedBy = updatedBy == null ? "" : updatedBy.trim();
    }

    public List<FindingAnalysisEvent> getEvents() {
        return events;
    }
}
