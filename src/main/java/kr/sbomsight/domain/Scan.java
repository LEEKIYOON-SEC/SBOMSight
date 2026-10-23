package kr.sbomsight.domain;

import jakarta.persistence.*;

import java.time.Instant;
import java.util.Comparator;

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

    /**
     * 자산의 검사를 <b>옛것에서 최신으로</b> 줄 세운다 — SBOM 생성 시각, 같으면 검사
     * 시각, 그것도 같으면 번호(D1). 마지막이 그 자산의 최신 검사다.
     *
     * <p>{@code ScanRepository.currentOf} 와 최신 검사를 고르는 질의들이 같은 규칙을
     * 질의로 적고 있다 — 하나를 고치면 같이 고친다.
     */
    public static final Comparator<Scan> BY_SBOM_TIME =
            Comparator.comparing(Scan::getSbomCreatedAt)
                      .thenComparing(Scan::getCreatedAt)
                      .thenComparing(Scan::getId);

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "asset_id", nullable = false)
    private Asset asset;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private ScanStatus status = ScanStatus.QUEUED;

    /**
     * 지금 어느 단계인가. 화면이 진행 상태를 그리는 근거다.
     *
     * <p>V10 이전에 끝난 검사에는 값이 없다. 그때 무엇을 지나갔는지는 기록이
     * 없으므로 지어내 채우지 않는다.
     */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private ScanStage stage = ScanStage.UPLOADED;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "finished_at")
    private Instant finishedAt;

    /**
     * <b>SBOM 생성 시각</b> — 그 SBOM 이 서버를 읽은 시각. 자산의 최신 검사를 이것으로
     * 고른다({@link #BY_SBOM_TIME}).
     *
     * <p>{@link #createdAt} 은 검사가 돈 시각이다. 둘을 하나로 쓰면 옛 SBOM 을 다시
     * 검사한 것이 그 자산의 최신 상태가 되고, 30일 넘은 자산에서 빠지고, 보고서의
     * 점검 일시가 오늘이 된다(재현 시험 P4 · P5 · P10).
     *
     * <p>SBOM 을 읽기 전에는 업로드 시각이 이 자리를 채운다 — 어디서 온 값인지는
     * {@link #sbomTime} 이 말한다.
     */
    @Column(name = "sbom_created_at", nullable = false)
    private Instant sbomCreatedAt = createdAt;

    @Enumerated(EnumType.STRING)
    @Column(name = "sbom_time_source", nullable = false, length = 16)
    private SbomTime sbomTime = SbomTime.PENDING;

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

    /**
     * 올린 SBOM 파일 그대로의 SHA-256 (16진 소문자). 보고서에 찍힌 값과 보관된 파일의
     * 값을 대조하면 그 파일로 만든 보고서인지 확인할 수 있다.
     *
     * <p>V17 이전에 올린 검사는 비어 있다 — 화면은 `확인되지 않음` 이라 적는다.
     */
    @Column(name = "sbom_sha256", length = 64)
    private String sbomSha256;

    /** SBOM 안에 적혀 온 생성 도구와 판 — `syft 1.52.0`. 없으면 빈 글자. */
    @Column(name = "sbom_tool", nullable = false, length = 255)
    private String sbomTool = "";

    /**
     * SBOM 안에 적혀 온 대상 — 디렉터리를 뜨면 그 경로, 이미지를 뜨면 이미지 이름,
     * {@code --source-name} 을 주면 그 이름. 없으면 빈 글자.
     */
    @Column(name = "sbom_target", nullable = false, length = 255)
    private String sbomTarget = "";

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

    public ScanStage getStage() {
        return stage;
    }

    public void setStage(ScanStage stage) {
        this.stage = stage;
    }

    /** 아직 도는 중인가. 화면이 진행 카드를 띄울지 정하는 값이다. */
    public boolean isInFlight() {
        return status == ScanStatus.QUEUED || status == ScanStatus.RUNNING;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    /**
     * 검사 시각을 정한다.
     *
     * <p>기본값은 만들어진 시각이다. 이 setter 는 예전 결과를 옮겨 담을 때와
     * 시험에서 쓴다 — 최신 검사와 "지난 검사 대비"는 SBOM 생성 시각, 그다음 이
     * 시각으로 앞뒤를 가르므로({@link #BY_SBOM_TIME}) 값을 손대면 그만큼 달라진다.
     *
     * <p><b>SBOM 을 아직 읽지 않았으면 SBOM 생성 시각도 따라간다</b> — 읽기 전에는
     * 업로드 시각이 그 자리를 채운다.
     */
    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
        if (sbomTime == SbomTime.PENDING) {
            this.sbomCreatedAt = createdAt;
        }
    }

    public Instant getSbomCreatedAt() {
        return sbomCreatedAt;
    }

    public SbomTime getSbomTime() {
        return sbomTime;
    }

    /**
     * SBOM 에서 읽은 생성 시각을 정한다 — <b>아직 읽지 않은 검사에서만.</b>
     *
     * <p>그 자리에 있던 업로드 시각과 견준다(D1).
     * <ul>
     *   <li>SBOM 에 시각이 없다 → 업로드 시각 그대로 · {@link SbomTime#NO_TIMESTAMP}</li>
     *   <li>업로드보다 늦다(대상 서버의 시계가 틀림) → 업로드 시각 그대로 ·
     *       {@link SbomTime#CLOCK_AHEAD}</li>
     *   <li>그 밖 → SBOM 의 시각 · {@link SbomTime#SBOM}</li>
     * </ul>
     *
     * <p>이미 정해진 것(다시 검사가 물려받은 것 · V17 이전 것)은 바꾸지 않는다 —
     * 바꾸면 다시 검사가 원본의 업로드 시각 대신 제 검사 시각과 견주게 된다.
     *
     * @param fromSbom SBOM 에 적힌 시각, 없거나 읽지 못했으면 {@code null}
     */
    public void resolveSbomTime(Instant fromSbom) {
        if (sbomTime != SbomTime.PENDING) {
            return;
        }
        Instant uploaded = sbomCreatedAt;
        if (fromSbom == null) {
            sbomTime = SbomTime.NO_TIMESTAMP;
        } else if (fromSbom.isAfter(uploaded)) {
            sbomTime = SbomTime.CLOCK_AHEAD;
        } else {
            sbomCreatedAt = fromSbom;
            sbomTime = SbomTime.SBOM;
        }
    }

    /**
     * 다시 검사 — <b>같은 SBOM 이므로 SBOM 이 말하는 것은 원본 것을 그대로 쓴다.</b>
     *
     * <p>생성 시각 · 그 출처 · 해시 · 도구 · 대상. 검사 시각만 새것이다. 원본이 아직
     * SBOM 을 읽기 전에 실패했다면 이 검사가 읽는다 — 그때 견줄 업로드 시각도 원본
     * 것이 넘어온다.
     */
    public void inheritSbomFrom(Scan source) {
        this.sbomCreatedAt = source.sbomCreatedAt;
        this.sbomTime = source.sbomTime;
        this.sbomSha256 = source.sbomSha256;
        this.sbomTool = source.sbomTool;
        this.sbomTarget = source.sbomTarget;
    }

    public String getSbomSha256() {
        return sbomSha256;
    }

    public void setSbomSha256(String sbomSha256) {
        this.sbomSha256 = sbomSha256 == null || sbomSha256.isBlank() ? null : sbomSha256;
    }

    public String getSbomTool() {
        return sbomTool;
    }

    public void setSbomTool(String sbomTool) {
        this.sbomTool = clip(sbomTool, 255);
    }

    public String getSbomTarget() {
        return sbomTarget;
    }

    public void setSbomTarget(String sbomTarget) {
        this.sbomTarget = clip(sbomTarget, 255);
    }

    /** 드라이브 문자로 시작하는 윈도우 경로 — {@code C:\} · {@code D:/data}. */
    private static final java.util.regex.Pattern WINDOWS_PATH =
            java.util.regex.Pattern.compile("^[A-Za-z]:([\\\\/].*)?$");

    /**
     * SBOM 대상이 <b>자산 이름과 다른가</b> — 엉뚱한 자산에 올린 SBOM 을 가리려는 것이다.
     *
     * <p>대상이 경로면 가를 수 없다 — {@code syft dir:/} 로 뜨면 모든 서버가 {@code /} 다.
     * 이름이면(가이드의 {@code --source-name <자산 이름>}, 또는 이미지 이름) 자산 이름과
     * 견준다. 대소문자는 가리지 않는다 — 호스트 이름은 대소문자를 가리지 않는다. 비어
     * 있으면(SBOM 이 대상을 적지 않았거나 V17 전 검사) 다르다고 하지 않는다.
     */
    public boolean sbomTargetDiffersFrom(String assetName) {
        String target = sbomTarget == null ? "" : sbomTarget.trim();
        if (target.isEmpty() || target.startsWith("/") || target.startsWith("\\")
                || target.startsWith(".") || WINDOWS_PATH.matcher(target).matches()) {
            return false;
        }
        return !target.equalsIgnoreCase(assetName == null ? "" : assetName.trim());
    }

    private static String clip(String value, int max) {
        if (value == null) {
            return "";
        }
        String trimmed = value.trim();
        return trimmed.length() <= max ? trimmed : trimmed.substring(0, max);
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
