package kr.sbomsight.domain;

import jakarta.persistence.*;

import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

/**
 * 조치 — <b>이 도구가 만들어 내는 유일한 판단.</b>
 *
 * <p>나머지는 전부 grype 이 낸 것을 옮겨 담은 것이고, 사람이 정하는 것은
 * "이 패키지를 언제까지 누가 올릴 것인가" 하나다.
 *
 * <p>스캔이 아니라 <b>자산 + 패키지</b>에 매단다. grype 결과는 스캔마다 새로
 * 쌓이지만 조치는 그것을 가로지르기 때문이다. openssl 을 3.0.7 로 올리면 CVE
 * 다섯 건이 한 번에 사라지는데, 조치를 CVE 마다 만들면 같은 일을 다섯 번
 * 적어야 한다. 실무자가 실행하는 단위는 패키지 업데이트다.
 */
@Entity
@Table(name = "remediations")
public class Remediation {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    /** {@code V1__init.sql} 의 FK 와 같게 — 자산을 지우면 조치도 사라진다. */
    @JoinColumn(name = "asset_id", nullable = false)
    @org.hibernate.annotations.OnDelete(action = org.hibernate.annotations.OnDeleteAction.CASCADE)
    private Asset asset;

    @Column(name = "package_name", nullable = false, length = 255)
    private String packageName;

    /**
     * 등록 당시의 설치 버전 <b>전부</b> — 수정 버전과 같은 꼴로 잇는다
     * ({@link FixVersions}). 앞서는 CVSS 가 가장 높은 건의 것 하나였다 — 같은
     * 패키지가 두 벌 깔린 자산에서 한 벌이 조치 어디에도 없었다. 넓힌 것은 {@code V16}.
     */
    @Column(name = "from_version", nullable = false, length = 4000)
    private String fromVersion = "";

    /**
     * 등록 당시의 수정 버전 <b>전부</b> — 빈칸으로 잇는다({@link FixVersions}).
     * 앞서는 CVSS 가 가장 높은 건의 것 하나였다. 넓힌 것은 {@code V15}.
     */
    @Column(name = "to_version", nullable = false, length = 4000)
    private String toVersion = "";

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private RemediationStatus status = RemediationStatus.OPEN;

    @Column(nullable = false, length = 64)
    private String owner = "";

    @Column(name = "due_date")
    private LocalDate dueDate;

    @Column(nullable = false, length = 1000)
    private String note = "";

    @Column(name = "opened_scan_id")
    private Long openedScanId;

    @Column(name = "opened_count", nullable = false)
    private int openedCount;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "created_by", nullable = false, length = 64)
    private String createdBy = "";

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    @Column(name = "updated_by", nullable = false, length = 64)
    private String updatedBy = "";

    @Column(name = "closed_at")
    private Instant closedAt;

    @OneToMany(mappedBy = "remediation", cascade = CascadeType.ALL, orphanRemoval = true)
    @OrderBy("at ASC")
    private List<RemediationEvent> events = new ArrayList<>();

    protected Remediation() {
    }

    public Remediation(Asset asset, String packageName, String actor) {
        this.asset = asset;
        this.packageName = packageName;
        this.createdBy = actor == null ? "" : actor;
        this.updatedBy = this.createdBy;
    }

    /**
     * 상태를 바꾸고 그 사실을 발자취에 남긴다.
     *
     * <p>결재나 감사에서 "언제 누가 왜 예외 승인했나"를 묻는다. 상태만 덮어쓰면
     * 그 질문에 답할 수 없다.
     */
    public void moveTo(RemediationStatus next, String actor, String comment) {
        RemediationStatus previous = this.status;
        this.status = next;
        this.updatedAt = Instant.now();
        this.updatedBy = actor == null ? "" : actor;
        this.closedAt = next.isClosed() ? this.updatedAt : null;
        this.events.add(new RemediationEvent(this, actor, previous, next, comment));
    }

    public Long getId() {
        return id;
    }

    public Asset getAsset() {
        return asset;
    }

    public String getPackageName() {
        return packageName;
    }

    public String getFromVersion() {
        return fromVersion;
    }

    public void setFromVersion(String fromVersion) {
        this.fromVersion = fromVersion == null ? "" : fromVersion;
    }

    /** 등록 당시의 설치 버전 — 하나로 고르지 않은 목록. 화면 · CSV 는 이것을 쓴다. */
    public List<String> getFromVersions() {
        return FixVersions.split(fromVersion);
    }

    /** 설치 버전을 모아 적는다. 칸을 넘는 것은 목표 버전과 같이 뒤에서부터 뺀다. */
    public void setFromVersions(List<String> versions) {
        this.fromVersion = fit(versions);
    }

    public String getToVersion() {
        return toVersion;
    }

    public void setToVersion(String toVersion) {
        this.toVersion = toVersion == null ? "" : toVersion;
    }

    /** 등록 당시의 수정 버전 — 하나로 고르지 않은 목록. 화면 · CSV 는 이것을 쓴다. */
    public List<String> getToVersions() {
        return FixVersions.split(toVersion);
    }

    /**
     * 수정 버전을 모아 적는다.
     *
     * <p>칸(4,000자)을 넘으면 넘는 것부터 뺀다 — 넘는 채로 저장하면 조치
     * 등록이 500 으로 끝난다. 버전 스물다섯 가지(openjdk)가 237자였다.
     */
    public void setToVersions(List<String> versions) {
        this.toVersion = fit(versions);
    }

    /** 모아서(FixVersions) 칸(4,000자)에 들어가는 만큼 잇는다. */
    private static String fit(List<String> versions) {
        List<String> kept = new ArrayList<>(FixVersions.collect(versions));
        while (!kept.isEmpty() && FixVersions.join(kept).length() > 4000) {
            kept.remove(kept.size() - 1);
        }
        return FixVersions.join(kept);
    }

    public RemediationStatus getStatus() {
        return status;
    }

    public String getOwner() {
        return owner;
    }

    public void setOwner(String owner) {
        this.owner = owner == null ? "" : owner.trim();
    }

    public LocalDate getDueDate() {
        return dueDate;
    }

    public void setDueDate(LocalDate dueDate) {
        this.dueDate = dueDate;
    }

    /** 기한이 지났는가. 닫힌 조치는 지났다고 하지 않는다. */
    public boolean isOverdue() {
        return dueDate != null && !status.isClosed() && dueDate.isBefore(LocalDate.now());
    }

    public String getNote() {
        return note;
    }

    public void setNote(String note) {
        this.note = note == null ? "" : note;
    }

    public Long getOpenedScanId() {
        return openedScanId;
    }

    public void setOpenedScanId(Long openedScanId) {
        this.openedScanId = openedScanId;
    }

    public int getOpenedCount() {
        return openedCount;
    }

    public void setOpenedCount(int openedCount) {
        this.openedCount = openedCount;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedBy(String updatedBy) {
        this.updatedBy = updatedBy == null ? "" : updatedBy;
        this.updatedAt = Instant.now();
    }

    public String getUpdatedBy() {
        return updatedBy;
    }

    public Instant getClosedAt() {
        return closedAt;
    }

    public List<RemediationEvent> getEvents() {
        return events;
    }
}
