package kr.sbomsight.domain;

import jakarta.persistence.*;

import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * <b>발행본</b> — 발행한 순간의 보고서를 굳혀 둔 것(R11, D6, V20).
 *
 * <p>보고서는 열 때마다 지금 데이터로 다시 계산된다(재현 시험 P8). 결재에 올린 문서가
 * 무엇이었는지 남기려면 그 순간의 문서를 저장해야 한다 — 그때 그린 화면(HTML)과 계산
 * 결과(JSON), 그리고 문서의 SHA-256.
 *
 * <p><b>문서 안에 든 것과 밖에 있는 것.</b> 발행 번호 · 발행 시각 · 발행자는 문서 정보에
 * 들어가 해시가 함께 묶는다. 결재 문서 번호는 발행한 뒤에 적는 값이라 문서 밖이다 — 바꿔도
 * 해시는 그대로이고, 바꾼 것은 이력({@link ReportPublicationEvent})에 남는다.
 *
 * <p><b>가리키는 것에 FK 가 없다.</b> 자산을 지워도 발행본은 남는다(D6). 대상의 이름은
 * 발행 때의 것을 저장한다({@link #targetName}). 발행본이 가리키는 검사({@link #scanIds})는
 * 하나씩 지우지 못한다 — 앱이 막는다(ScanService.delete).
 *
 * <p>발행본은 지우지 않는다. 앱에 지우는 길이 없다.
 */
@Entity
@Table(name = "report_publications",
       uniqueConstraints = @UniqueConstraint(name = "uk_report_publication_number",
                                             columnNames = { "pub_year", "pub_seq" }))
public class ReportPublication {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private PublicationKind kind;

    /** 발행 번호의 앞 — 발행 시각의 연도(서버 시간대). */
    @Column(name = "pub_year", nullable = false)
    private int pubYear;

    /** 발행 번호의 뒤 — 그해 안의 일련번호, 1 부터. */
    @Column(name = "pub_seq", nullable = false)
    private int pubSeq;

    @Column(name = "published_at", nullable = false)
    private Instant publishedAt;

    /** 발행한 로그인 계정. 사람이 적는 칸이 아니다. */
    @Column(name = "published_by", nullable = false, length = 64)
    private String publishedBy = "";

    /** 대상의 이름 — 발행 때의 자산 이름 · 구역 이름(전체면 `전체`). */
    @Column(name = "target_name", nullable = false, length = 255)
    private String targetName = "";

    @Column(name = "asset_id")
    private Long assetId;

    @Column(name = "scan_id")
    private Long scanId;

    /** 구역 현황 보고서의 구역. 전체 구역이면 {@code null}. */
    @Column(name = "zone_id")
    private Long zoneId;

    @Column(name = "period_from")
    private LocalDate periodFrom;

    @Column(name = "period_to")
    private LocalDate periodTo;

    /** 그때의 계산 결과. */
    @Lob
    @Column(name = "document_json", nullable = false, columnDefinition = "LONGTEXT")
    private String documentJson = "";

    /** 그때 그린 문서 그대로. */
    @Lob
    @Column(name = "document_html", nullable = false, columnDefinition = "LONGTEXT")
    private String documentHtml = "";

    /** {@link #documentHtml} 의 UTF-8 바이트 그대로의 SHA-256(소문자 16진수). */
    @Column(name = "document_sha256", nullable = false, length = 64)
    private String documentSha256 = "";

    /** 사내 결재 문서 번호. 발행한 뒤에 적는다 — 검토 결과의 같은 칸과 같은 너비. */
    @Column(name = "approval_doc", nullable = false, length = 128)
    private String approvalDoc = "";

    /** 발행본의 수가 나온 완료 검사. FK 는 발행본 쪽만 — 자산을 지우면 검사는 사라진다. */
    @ElementCollection
    @CollectionTable(name = "report_publication_scans",
                     joinColumns = @JoinColumn(name = "publication_id"),
                     foreignKey = @ForeignKey(name = "fk_report_publication_scans"))
    @Column(name = "scan_id", nullable = false)
    private Set<Long> scanIds = new LinkedHashSet<>();

    @OneToMany(mappedBy = "publication", cascade = CascadeType.ALL)
    @OrderBy("at ASC, id ASC")
    private List<ReportPublicationEvent> events = new ArrayList<>();

    protected ReportPublication() {
    }

    public ReportPublication(PublicationKind kind, int year, int seq, Instant publishedAt,
                             String publishedBy, String targetName) {
        this.kind = kind;
        this.pubYear = year;
        this.pubSeq = seq;
        this.publishedAt = publishedAt;
        this.publishedBy = publishedBy == null ? "" : publishedBy;
        this.targetName = targetName == null ? "" : targetName;
    }

    /** 발행 번호 — {@code 2026-0001}. 일련번호가 만을 넘으면 자리가 늘어날 뿐 자르지 않는다. */
    public static String number(int year, int seq) {
        return "%d-%04d".formatted(year, seq);
    }

    /** 점검 결과 보고서의 대상 — 자산과 검사. */
    public void targetScan(Long assetId, Long scanId) {
        this.assetId = assetId;
        this.scanId = scanId;
    }

    /** 구역 현황 보고서의 대상 — 구역(전체면 {@code null})과 기간. */
    public void targetZone(Long zoneId, LocalDate from, LocalDate to) {
        this.zoneId = zoneId;
        this.periodFrom = from;
        this.periodTo = to;
    }

    /** 그린 문서 · 계산 결과 · 문서의 해시. 발행할 때 한 번 적는다. */
    public void document(String html, String json, String sha256) {
        this.documentHtml = html;
        this.documentJson = json;
        this.documentSha256 = sha256;
    }

    /**
     * 결재 문서 번호를 바꾼다. 바뀌었으면 이력을 한 줄 남기고 참을 돌려준다 — 같은 값을
     * 다시 적은 것은 남기지 않는다.
     */
    public boolean changeApprovalDoc(String value, String actor) {
        String next = value == null ? "" : value.trim();
        if (next.equals(approvalDoc)) {
            return false;
        }
        events.add(new ReportPublicationEvent(this, actor, approvalDoc, next));
        this.approvalDoc = next;
        return true;
    }

    public Long getId() {
        return id;
    }

    public PublicationKind getKind() {
        return kind;
    }

    public int getPubYear() {
        return pubYear;
    }

    public int getPubSeq() {
        return pubSeq;
    }

    public String getNumber() {
        return number(pubYear, pubSeq);
    }

    public Instant getPublishedAt() {
        return publishedAt;
    }

    public String getPublishedBy() {
        return publishedBy;
    }

    public String getTargetName() {
        return targetName;
    }

    public Long getAssetId() {
        return assetId;
    }

    public Long getScanId() {
        return scanId;
    }

    public Long getZoneId() {
        return zoneId;
    }

    public LocalDate getPeriodFrom() {
        return periodFrom;
    }

    public LocalDate getPeriodTo() {
        return periodTo;
    }

    public String getDocumentJson() {
        return documentJson;
    }

    public String getDocumentHtml() {
        return documentHtml;
    }

    public String getDocumentSha256() {
        return documentSha256;
    }

    public String getApprovalDoc() {
        return approvalDoc;
    }

    public Set<Long> getScanIds() {
        return scanIds;
    }

    public List<ReportPublicationEvent> getEvents() {
        return events;
    }
}
