package kr.sbomsight.domain;

import jakarta.persistence.*;

import java.time.Instant;

/**
 * 스캔 — SBOM 한 장에 grype 을 한 번 돌린 결과.
 *
 * <p>{@code grypeVersion} 과 {@code grypeDbBuilt} 를 결과와 함께 남기는 것이
 * 중요하다. 없으면 "이 보고서는 무엇으로 판정했는가"에 답할 수 없고, 몇 달 뒤
 * 같은 SBOM 으로 다시 돌렸을 때 결과가 달라진 이유도 설명할 수 없다.
 */
@Entity
@Table(name = "scans")
public class Scan {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "asset_id", nullable = false)
    private Asset asset;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private ScanStatus status = ScanStatus.QUEUED;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "finished_at")
    private Instant finishedAt;

    @Column(name = "created_by", nullable = false, length = 64)
    private String createdBy = "";

    /**
     * 어느 스캔을 다시 돌린 것인가. 처음 올린 스캔이면 비어 있다.
     *
     * <p>같은 SBOM 을 갱신된 취약점 DB 로 다시 돌린 결과라는 표시다. 이것이
     * 없으면 이력에서 "서버가 바뀐 것" 과 "DB 가 바뀐 것" 을 구분할 수 없다 —
     * 둘은 완전히 다른 이야기다.
     */
    @Column(name = "rescan_of")
    private Long rescanOf;

    @Column(name = "sbom_filename", nullable = false, length = 255)
    private String sbomFilename = "";

    @Column(name = "sbom_format", nullable = false, length = 32)
    private String sbomFormat = "";

    @Column(name = "sbom_bytes", nullable = false)
    private long sbomBytes;

    @Column(name = "sbom_path", nullable = false, length = 500)
    private String sbomPath = "";

    @Column(name = "grype_path", nullable = false, length = 500)
    private String grypePath = "";

    @Column(name = "component_count", nullable = false)
    private int componentCount;

    @Column(name = "grype_version", nullable = false, length = 64)
    private String grypeVersion = "";

    @Column(name = "grype_db_built")
    private Instant grypeDbBuilt;

    @Column(name = "distro_name", nullable = false, length = 64)
    private String distroName = "";

    @Column(name = "distro_version", nullable = false, length = 64)
    private String distroVersion = "";

    // --- 회계 -------------------------------------------------------------
    // grype 이 낸 match 수와 우리가 저장한 건수가 다르면 그 차이를 설명할 수
    // 있어야 한다. 조용히 버리면 몇 건이 사라졌는지 아무도 모른다.

    @Column(name = "match_count", nullable = false)
    private int matchCount;

    @Column(name = "finding_count", nullable = false)
    private int findingCount;

    @Column(name = "merged_count", nullable = false)
    private int mergedCount;

    @Column(name = "dropped_count", nullable = false)
    private int droppedCount;

    @Column(name = "error_message", nullable = false, length = 1000)
    private String errorMessage = "";

    protected Scan() {
    }

    public Scan(Asset asset, String createdBy) {
        this.asset = asset;
        this.createdBy = createdBy == null ? "" : createdBy;
    }

    /** 회계가 맞는가. {@code match = finding + merged + dropped} 여야 한다. */
    public boolean accountsBalance() {
        return matchCount == findingCount + mergedCount + droppedCount;
    }

    public Long getId() {
        return id;
    }

    public Asset getAsset() {
        return asset;
    }

    public ScanStatus getStatus() {
        return status;
    }

    public void setStatus(ScanStatus status) {
        this.status = status;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    /**
     * 검사 시각을 정한다.
     *
     * <p>기본값은 만들어진 시각이다. 이 setter 는 예전 결과를 옮겨 담을 때와
     * 시험에서 쓴다 — 이력 비교는 이 시각으로 앞뒤를 가르므로, 값을 손대면
     * "지난 검사 대비"가 그만큼 달라진다.
     */
    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Instant getFinishedAt() {
        return finishedAt;
    }

    public void setFinishedAt(Instant finishedAt) {
        this.finishedAt = finishedAt;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public String getSbomFilename() {
        return sbomFilename;
    }

    public void setSbomFilename(String sbomFilename) {
        this.sbomFilename = sbomFilename == null ? "" : sbomFilename;
    }

    public String getSbomFormat() {
        return sbomFormat;
    }

    public void setSbomFormat(String sbomFormat) {
        this.sbomFormat = sbomFormat == null ? "" : sbomFormat;
    }

    public long getSbomBytes() {
        return sbomBytes;
    }

    public void setSbomBytes(long sbomBytes) {
        this.sbomBytes = sbomBytes;
    }

    public String getSbomPath() {
        return sbomPath;
    }

    public void setSbomPath(String sbomPath) {
        this.sbomPath = sbomPath == null ? "" : sbomPath;
    }

    public String getGrypePath() {
        return grypePath;
    }

    public void setGrypePath(String grypePath) {
        this.grypePath = grypePath == null ? "" : grypePath;
    }

    public int getComponentCount() {
        return componentCount;
    }

    public void setComponentCount(int componentCount) {
        this.componentCount = componentCount;
    }

    public String getGrypeVersion() {
        return grypeVersion;
    }

    public void setGrypeVersion(String grypeVersion) {
        this.grypeVersion = grypeVersion == null ? "" : grypeVersion;
    }

    public Instant getGrypeDbBuilt() {
        return grypeDbBuilt;
    }

    public void setGrypeDbBuilt(Instant grypeDbBuilt) {
        this.grypeDbBuilt = grypeDbBuilt;
    }

    public String getDistroName() {
        return distroName;
    }

    public void setDistroName(String distroName) {
        this.distroName = distroName == null ? "" : distroName;
    }

    public String getDistroVersion() {
        return distroVersion;
    }

    public void setDistroVersion(String distroVersion) {
        this.distroVersion = distroVersion == null ? "" : distroVersion;
    }

    public int getMatchCount() {
        return matchCount;
    }

    public void setMatchCount(int matchCount) {
        this.matchCount = matchCount;
    }

    public int getFindingCount() {
        return findingCount;
    }

    public void setFindingCount(int findingCount) {
        this.findingCount = findingCount;
    }

    public int getMergedCount() {
        return mergedCount;
    }

    public void setMergedCount(int mergedCount) {
        this.mergedCount = mergedCount;
    }

    public int getDroppedCount() {
        return droppedCount;
    }

    public void setDroppedCount(int droppedCount) {
        this.droppedCount = droppedCount;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage == null ? ""
                : errorMessage.substring(0, Math.min(errorMessage.length(), 1000));
    }

    public Long getRescanOf() {
        return rescanOf;
    }

    public void setRescanOf(Long rescanOf) {
        this.rescanOf = rescanOf;
    }

    /** 다시 돌린 결과인가. */
    public boolean isRescan() {
        return rescanOf != null;
    }
}
