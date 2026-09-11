package kr.sbomsight.domain;

import jakarta.persistence.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

    private static final Logger log = LoggerFactory.getLogger(Finding.class);

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "scan_id", nullable = false)
    private Scan scan;

    /** {@code CVE|패키지|버전|purl}. 이력 대조와 중복 제거의 축이다. */
    @Column(name = "finding_key", nullable = false, length = 512)
    private String findingKey;

    /** grype 의 주 식별자. 언어 생태계에서는 GHSA 번호인 경우가 많다. */
    @Column(nullable = false, length = 128)
    private String cve;

    /**
     * grype 이 {@code relatedVulnerabilities} 로 함께 준 CVE 번호.
     *
     * <p>주 식별자를 바꾸는 것이 아니라 같은 응답 안에 있던 값을 옆에 놓는
     * 것이다. 결재·보고가 CVE 번호로 돌기 때문에 표에 함께 있어야 한다.
     */
    @Column(name = "related_cve", nullable = false, length = 128)
    private String relatedCve = "";

    @Column(nullable = false, length = 32)
    private String severity = "";

    @Column(name = "cvss_score", precision = 4, scale = 2)
    private BigDecimal cvssScore;

    @Column(name = "cvss_vector", nullable = false, length = 512)
    private String cvssVector = "";

    @Column(name = "cvss_version", nullable = false, length = 16)
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

    @Column(name = "package_version", nullable = false, length = 255)
    private String packageVersion = "";

    @Column(name = "package_type", nullable = false, length = 64)
    private String packageType = "";

    @Column(name = "package_purl", nullable = false, length = 512)
    private String packagePurl = "";

    @Column(name = "package_language", nullable = false, length = 64)
    private String packageLanguage = "";

    /**
     * 이 패키지가 실제로 놓여 있는 곳.
     *
     * <p>grype 이 {@code artifact.locations} 로 준다. "어느 파일이냐" 는 조치할
     * 때 반드시 묻는 것인데, 앞서는 {@code detail_json} 안에만 있어 조회도
     * 정렬도 CSV 도 되지 않았다. 여러 곳에 있으면 첫 번째만 담고 남은 수를
     * 덧붙인다 — 전부 담으면 한 칸이 화면을 밀어낸다.
     */
    @Column(name = "install_path", nullable = false, length = 1024)
    private String installPath = "";

    @Column(name = "fix_state", nullable = false, length = 32)
    private String fixState = "";

    @Column(name = "fixed_version", nullable = false, length = 255)
    private String fixedVersion = "";

    @Column(name = "version_constraint", nullable = false, length = 512)
    private String versionConstraint = "";

    @Column(name = "match_type", nullable = false, length = 64)
    private String matchType = "";

    @Column(nullable = false, length = 64)
    private String matcher = "";

    @Column(nullable = false, length = 255)
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
        // 키·CVE·패키지 이름도 자른다. 이 셋이 없으면 건 자체가 성립하지
        // 않으므로 GrypeMapper 가 미리 걸러 내지만, 길이는 여기서 지킨다.
        this.findingKey = clip(findingKey, 512);
        this.cve = clip(cve, 128);
        this.packageName = clip(packageName, 255);
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

    /**
     * 열에 들어갈 만큼만 자른다.
     *
     * <p>값 하나가 길다고 <b>스캔 전체를 잃지 않기 위해서다.</b> 실제로 CVSS 4.0
     * 벡터가 열 폭을 넘겨 98건짜리 스캔이 통째로 실패한 적이 있다. 열은 실측에
     * 여유를 두어 넓혀 두었으므로 여기까지 오는 일은 드물지만, 오더라도 그 한
     * 건의 값만 잘리고 나머지는 그대로 남아야 한다.
     */
    private static String clip(String value, int max) {
        if (value == null) {
            return "";
        }
        String trimmed = value.trim();
        if (trimmed.length() <= max) {
            return trimmed;
        }
        log.warn("값이 열 폭({})을 넘어 잘랐습니다: {}…", max, trimmed.substring(0, Math.min(60, max)));
        return trimmed.substring(0, max);
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

    public String getRelatedCve() {
        return relatedCve;
    }

    public void setRelatedCve(String relatedCve) {
        this.relatedCve = clip(relatedCve, 128);
    }

    /** 표에 크게 쓸 번호 — CVE 가 있으면 CVE, 없으면 grype 이 준 그대로. */
    public String getDisplayId() {
        return relatedCve.isBlank() ? cve : relatedCve;
    }

    /** 위 번호와 다른 식별자가 있으면 그것. 없으면 빈 문자열. */
    public String getSecondaryId() {
        return relatedCve.isBlank() || relatedCve.equals(cve) ? "" : cve;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = clip(severity, 32);
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
        this.cvssVector = clip(cvssVector, 512);
    }

    public String getCvssVersion() {
        return cvssVersion;
    }

    public void setCvssVersion(String cvssVersion) {
        this.cvssVersion = clip(cvssVersion, 16);
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
        this.packageVersion = clip(packageVersion, 255);
    }

    public String getPackageType() {
        return packageType;
    }

    public void setPackageType(String packageType) {
        this.packageType = clip(packageType, 64);
    }

    public String getPackagePurl() {
        return packagePurl;
    }

    public void setPackagePurl(String packagePurl) {
        this.packagePurl = clip(packagePurl, 512);
    }

    public String getPackageLanguage() {
        return packageLanguage;
    }

    public void setPackageLanguage(String packageLanguage) {
        this.packageLanguage = clip(packageLanguage, 64);
    }

    public String getInstallPath() {
        return installPath;
    }

    public void setInstallPath(String installPath) {
        this.installPath = clip(installPath, 1024);
    }

    public String getFixState() {
        return fixState;
    }

    public void setFixState(String fixState) {
        this.fixState = clip(fixState, 32);
    }

    public String getFixedVersion() {
        return fixedVersion;
    }

    public void setFixedVersion(String fixedVersion) {
        this.fixedVersion = clip(fixedVersion, 255);
    }

    public String getVersionConstraint() {
        return versionConstraint;
    }

    public void setVersionConstraint(String versionConstraint) {
        this.versionConstraint = clip(versionConstraint, 512);
    }

    public String getMatchType() {
        return matchType;
    }

    public void setMatchType(String matchType) {
        this.matchType = clip(matchType, 64);
    }

    public String getMatcher() {
        return matcher;
    }

    public void setMatcher(String matcher) {
        this.matcher = clip(matcher, 64);
    }

    public String getNamespace() {
        return namespace;
    }

    public void setNamespace(String namespace) {
        this.namespace = clip(namespace, 255);
    }

    public String getDataSource() {
        return dataSource;
    }

    public void setDataSource(String dataSource) {
        this.dataSource = clip(dataSource, 500);
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
