package kr.sbomsight.domain;

import jakarta.persistence.*;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * <b>조치 대상</b> — 조치를 등록할 때 그 패키지에 걸려 있던 탐지 한 건(R9, V19).
 *
 * <p>조치는 패키지에 매달려 있어 무엇을 고치려던 것인지(CVE)를 몰랐다. 그래서 완료한 뒤
 * 같은 패키지에 새 취약점이 나오면 "조치가 덜 됐다(완료 · 탐지 남음)" 와 "새 취약점이다
 * (완료 · 신규 탐지)" 를 가를 수 없었다. 등록 당시 건수(opened_count)와 같은 건이다.
 *
 * <p>grype 이 낸 값을 그대로 옮겨 둔다 — 번호 · 함께 온 CVE · 설치 버전 · 수정 버전.
 */
@Entity
@Table(name = "remediation_targets")
public class RemediationTarget {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** 조치를 지우면 대상도 함께 (V19 의 FK 와 같게). */
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "remediation_id", nullable = false)
    @org.hibernate.annotations.OnDelete(action = org.hibernate.annotations.OnDeleteAction.CASCADE)
    private Remediation remediation;

    /** grype 의 주 식별자 (CVE 또는 GHSA). 탐지와 같은 너비 — 탐지의 번호를 그대로 옮긴다. */
    @Column(nullable = false, length = 128)
    private String cve = "";

    @Column(name = "related_cve", nullable = false, length = 128)
    private String relatedCve = "";

    @Column(name = "package_version", nullable = false, length = 255)
    private String packageVersion = "";

    @Column(name = "fixed_version", nullable = false, length = 255)
    private String fixedVersion = "";

    protected RemediationTarget() {
    }

    private RemediationTarget(Remediation remediation, Finding f) {
        this.remediation = remediation;
        this.cve = f.getCve();
        this.relatedCve = f.getRelatedCve() == null ? "" : f.getRelatedCve();
        this.packageVersion = f.getPackageVersion() == null ? "" : f.getPackageVersion();
        this.fixedVersion = f.getFixedVersion() == null ? "" : f.getFixedVersion();
    }

    /**
     * 등록한 검사의 그 패키지 탐지에서 — 똑같은 줄(경로만 다른 같은 탐지)은 하나로.
     * 글자 그대로 견준다: {@code RC1} 과 {@code rc1} 은 다른 버전이다(V16 과 같은 까닭).
     */
    public static List<RemediationTarget> of(Remediation remediation, List<Finding> findings) {
        Map<List<String>, RemediationTarget> distinct = new LinkedHashMap<>();
        for (Finding f : findings) {
            RemediationTarget t = new RemediationTarget(remediation, f);
            distinct.putIfAbsent(List.of(t.cve, t.relatedCve, t.packageVersion, t.fixedVersion), t);
        }
        return new ArrayList<>(distinct.values());
    }

    public Long getId() {
        return id;
    }

    public String getCve() {
        return cve;
    }

    public String getRelatedCve() {
        return relatedCve;
    }

    /** 화면에 찍는 번호 — 탐지와 같다({@link Finding#getDisplayId}): 함께 온 CVE 가 있으면 그것. */
    public String getDisplayId() {
        return relatedCve.isBlank() ? cve : relatedCve;
    }

    /** 위 번호와 다른 식별자(별칭)가 있으면 그것. 없으면 빈 문자열. */
    public String getSecondaryId() {
        return relatedCve.isBlank() || relatedCve.equals(cve) ? "" : cve;
    }

    public String getPackageVersion() {
        return packageVersion;
    }

    public String getFixedVersion() {
        return fixedVersion;
    }
}
