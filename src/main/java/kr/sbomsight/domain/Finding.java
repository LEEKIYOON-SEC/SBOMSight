package kr.sbomsight.domain;

import jakarta.persistence.*;

import java.math.BigDecimal;

/**
 * 탐지 한 건 — grype match 하나.
 *
 * <p><b>여기 담긴 값은 전부 grype 이 낸 것이다.</b> 설치 버전을 다시 비교하거나
 * 수정 여부를 다시 판단하지 않는다. grype 이 매치를 냈다는 사실 자체가 판정이고,
 * 그것이 틀렸다면 grype 의 오류로 감수한다 — 우리 코드 때문에 결과가 달라지는
 * 것은 감수 대상이 아니다.
 *
 * <p>{@code epss}·{@code kev} 는 {@code Boolean}·{@code BigDecimal} 로 두어
 * <b>null 을 살려 둔다.</b> 옛 grype 은 이 값을 주지 않는데, 없는 것을 0 이나
 * false 로 채우면 "악용 확률 0%"·"악용 안 됨"이라는 없는 판정이 생긴다.
 */
@Entity
@Table(name = "findings")
public class Finding {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "scan_id", nullable = false)
    private Scan scan;

    /** {@code CVE|패키지|버전|purl}. 이력 대조와 중복 제거의 축이다. */
    @Column(name = "finding_key", nullable = false, length = 512)
    private String findingKey;

    @Column(nullable = false, length = 64)
    private String cve;

    @Column(nullable = false, length = 16)
    private String severity = "";

    @Column(name = "cvss_score", precision = 4, scale = 2)
    private BigDecimal cvssScore;

    @Column(name = "cvss_vector", nullable = false, length = 128)
    private String cvssVector = "";

    @Column(name = "cvss_version", nullable = false, length = 8)
    private String cvssVersion = "";

    @Column(precision = 9, scale = 8)
    private BigDecimal epss;

    private Boolean kev;

    @Column(name = "kev_ransomware")
    private Boolean kevRansomware;

    @Column(name = "grype_risk", precision = 9, scale = 4)
    private BigDecimal grypeRisk;

    @Column(name = "package_name", nullable = false, length = 255)
    private String packageName;

    @Column(name = "package_version", nullable = false, length = 128)
    private String packageVersion = "";

    @Column(name = "package_type", nullable = false, length = 32)
    private String packageType = "";

    @Column(name = "package_purl", nullable = false, length = 512)
    private String packagePurl = "";

    @Column(name = "package_language", nullable = false, length = 32)
    private String packageLanguage = "";

    @Column(name = "fix_state", nullable = false, length = 24)
    private String fixState = "";

    @Column(name = "fixed_version", nullable = false, length = 128)
    private String fixedVersion = "";

    @Column(name = "version_constraint", nullable = false, length = 255)
    private String versionConstraint = "";

    @Column(name = "match_type", nullable = false, length = 48)
    private String matchType = "";

    @Column(nullable = false, length = 48)
    private String matcher = "";

    @Column(nullable = false, length = 96)
    private String namespace = "";

    @Column(name = "data_source", nullable = false, length = 500)
    private String dataSource = "";

    @Lob
    @Column(columnDefinition = "TEXT")
    private String description;

    /** 표에 쓰지 않는 나머지(urls·cpes·locations·관련 CVE). 상세에서만 편다. */
    @Lob
    @Column(name = "detail_json", columnDefinition = "LONGTEXT")
    private String detailJson;

    protected Finding() {
    }

    public Finding(Scan scan, String findingKey, String cve, String packageName) {
        this.scan = scan;
        this.findingKey = findingKey;
        this.cve = cve;
        this.packageName = packageName;
    }

    /**
     * 이 건이 지금 조치 가능한가 — grype 의 {@code fix.state} 만 본다.
     *
     * <p>버전 비교를 다시 하지 않는다. 우리 비교자에 흠이 하나만 있어도
     * grype 이 잡은 것이 화면에서 "해당 없음"으로 사라진다.
     */
    public boolean isFixAvailable() {
        return "fixed".equalsIgnoreCase(fixState) && !fixedVersion.isBlank();
    }

    /** 수정본이 없다고 grype 이 밝힌 경우. 조치가 아니라 다른 통제가 필요하다. */
    public boolean isNoFix() {
        return "wont-fix".equalsIgnoreCase(fixState) || "not-fixed".equalsIgnoreCase(fixState);
    }

    public Long getId() {
        return id;
    }

    public Scan getScan() {
        return scan;
    }

    public String getFindingKey() {
        return findingKey;
    }

    public String getCve() {
        return cve;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity == null ? "" : severity;
    }

    public BigDecimal getCvssScore() {
        return cvssScore;
    }

    public void setCvssScore(BigDecimal cvssScore) {
        this.cvssScore = cvssScore;
    }

    public String getCvssVector() {
        return cvssVector;
    }

    public void setCvssVector(String cvssVector) {
        this.cvssVector = cvssVector == null ? "" : cvssVector;
    }

    public String getCvssVersion() {
        return cvssVersion;
    }

    public void setCvssVersion(String cvssVersion) {
        this.cvssVersion = cvssVersion == null ? "" : cvssVersion;
    }

    public BigDecimal getEpss() {
        return epss;
    }

    public void setEpss(BigDecimal epss) {
        this.epss = epss;
    }

    public Boolean getKev() {
        return kev;
    }

    public void setKev(Boolean kev) {
        this.kev = kev;
    }

    public Boolean getKevRansomware() {
        return kevRansomware;
    }

    public void setKevRansomware(Boolean kevRansomware) {
        this.kevRansomware = kevRansomware;
    }

    public BigDecimal getGrypeRisk() {
        return grypeRisk;
    }

    public void setGrypeRisk(BigDecimal grypeRisk) {
        this.grypeRisk = grypeRisk;
    }

    public String getPackageName() {
        return packageName;
    }

    public String getPackageVersion() {
        return packageVersion;
    }

    public void setPackageVersion(String packageVersion) {
        this.packageVersion = packageVersion == null ? "" : packageVersion;
    }

    public String getPackageType() {
        return packageType;
    }

    public void setPackageType(String packageType) {
        this.packageType = packageType == null ? "" : packageType;
    }

    public String getPackagePurl() {
        return packagePurl;
    }

    public void setPackagePurl(String packagePurl) {
        this.packagePurl = packagePurl == null ? "" : packagePurl;
    }

    public String getPackageLanguage() {
        return packageLanguage;
    }

    public void setPackageLanguage(String packageLanguage) {
        this.packageLanguage = packageLanguage == null ? "" : packageLanguage;
    }

    public String getFixState() {
        return fixState;
    }

    public void setFixState(String fixState) {
        this.fixState = fixState == null ? "" : fixState;
    }

    public String getFixedVersion() {
        return fixedVersion;
    }

    public void setFixedVersion(String fixedVersion) {
        this.fixedVersion = fixedVersion == null ? "" : fixedVersion;
    }

    public String getVersionConstraint() {
        return versionConstraint;
    }

    public void setVersionConstraint(String versionConstraint) {
        this.versionConstraint = versionConstraint == null ? "" : versionConstraint;
    }

    public String getMatchType() {
        return matchType;
    }

    public void setMatchType(String matchType) {
        this.matchType = matchType == null ? "" : matchType;
    }

    public String getMatcher() {
        return matcher;
    }

    public void setMatcher(String matcher) {
        this.matcher = matcher == null ? "" : matcher;
    }

    public String getNamespace() {
        return namespace;
    }

    public void setNamespace(String namespace) {
        this.namespace = namespace == null ? "" : namespace;
    }

    public String getDataSource() {
        return dataSource;
    }

    public void setDataSource(String dataSource) {
        this.dataSource = dataSource == null ? "" : dataSource;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getDetailJson() {
        return detailJson;
    }

    public void setDetailJson(String detailJson) {
        this.detailJson = detailJson;
    }
}
