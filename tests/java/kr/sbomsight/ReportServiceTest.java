package kr.sbomsight;

import kr.sbomsight.domain.*;
import kr.sbomsight.repo.*;
import kr.sbomsight.service.FindingAnalysisService;
import kr.sbomsight.service.ReportService;
import kr.sbomsight.service.ZoneService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 보고서 — 기승전결.
 *
 * <p>여기서 고정하는 것은 <b>보고서가 grype 이 준 수를 그대로 센다</b>는 것이다.
 * 심각도 분포·조치 가능 건수·패키지 묶음이 원본과 어긋나면 그 보고서로 결재를
 * 올릴 수 없다.
 */
@SpringBootTest
@Transactional
class ReportServiceTest {

    @Autowired ReportService reports;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired RemediationRepository remediations;
    @Autowired ZoneService zoneService;
    @Autowired FindingAnalysisService analyses;

    private Asset asset;

    @BeforeEach
    void setUp() {
        asset = new Asset();
        asset.setName("web-" + System.nanoTime());
        asset.setZone(zoneService.unassigned());
        asset.setOsName("Rocky Linux 9.3");
        assets.save(asset);
    }

    /** 탐지 한 건을 만든다. 값은 전부 grype 이 준 것이라고 가정한다. */
    private Finding finding(Scan scan, String cve, String pkg, String version,
                            String severity, String fixState, String fixedVersion, Double cvss) {
        Finding f = new Finding(scan, cve + "|" + pkg + "|" + version + "|purl", cve, pkg);
        f.setPackageVersion(version);
        f.setPackageType("rpm");
        f.setSeverity(severity);
        f.setFixState(fixState);
        f.setFixedVersion(fixedVersion);
        if (cvss != null) {
            f.setCvssScore(BigDecimal.valueOf(cvss));
        }
        return findings.save(f);
    }

    private Scan seedTypicalScan() {
        Scan scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        scan.setGrypeVersion("0.87.0");
        scan.setSbomFilename("sbom.json");
        scan.setComponentCount(120);
        scans.saveAndFlush(scan);

        // openssl 3건 — 전부 수정본 있음
        finding(scan, "CVE-1", "openssl", "3.0.0", "Critical", "fixed", "3.0.7", 9.8);
        finding(scan, "CVE-2", "openssl", "3.0.0", "High", "fixed", "3.0.7", 7.5);
        finding(scan, "CVE-3", "openssl", "3.0.0", "Medium", "fixed", "3.0.7", 5.3);
        // curl 1건 — 수정본 있음
        finding(scan, "CVE-4", "curl", "8.4.0", "High", "fixed", "8.6.0", 7.5);
        // glibc 2건 — 수정본 없음
        finding(scan, "CVE-5", "glibc", "2.34", "High", "wont-fix", "", 7.8);
        finding(scan, "CVE-6", "glibc", "2.34", "Low", "wont-fix", "", 3.1);

        scan.setMatchCount(6);
        scan.setFindingCount(6);
        scans.saveAndFlush(scan);
        return scan;
    }

    // -----------------------------------------------------------------------

    @Test
    @DisplayName("1장 — 무엇을 무엇으로 봤는지 그대로 싣는다")
    void chapter1CarriesProvenance() {
        Scan scan = seedTypicalScan();
        ReportService.Overview ch = reports.build(scan).overview();

        assertThat(ch.asset().getName()).isEqualTo(asset.getName());
        assertThat(ch.grypeVersion()).isEqualTo("0.87.0");
        assertThat(ch.componentCount()).isEqualTo(120);
        assertThat(ch.findingCount()).isEqualTo(6);
        // 회계가 맞으면 설명할 것이 없다 — 그 문단을 싣지 않는다.
        assertThat(ch.balanced()).isTrue();
        assertThat(ch.hasAccountingNote()).isFalse();
    }

    @Test
    @DisplayName("1장 — 건수가 어긋나면 설명할 것이 생긴다")
    void chapter1FlagsAccountingGap() {
        Scan scan = seedTypicalScan();
        scan.setMatchCount(9);      // grype 은 9건을 냈는데 6건만 담겼다
        scans.saveAndFlush(scan);

        ReportService.Overview ch = reports.build(scan).overview();
        assertThat(ch.balanced()).isFalse();
        assertThat(ch.hasAccountingNote()).isTrue();
    }

    /**
     * <b>2.4 — 우리가 몇 건을 봤는가.</b>
     *
     * <p>2.1~2.3 은 전부 grype 의 축이다. 이 도구가 하는 일은 그 목록을
     * 검토하고 조치를 추적하는 것인데, 그 축이 요약에 한 줄도 없었다.
     *
     * <p><b>`미검토` 와 `검토 중` 이 갈려야 한다.</b> 앞서 4장 각주는 기록이
     * 아예 없는 것만 셌고, `검토 중` 으로 열어 두고 방치한 건은 "설명됨"
     * 으로 집계됐다.
     *
     * <p>적어 둔 것이 없는 건은 <b>미검토</b>다 — "괜찮다" 가 아니다.
     */
    @Test
    @DisplayName("2.4 — 미검토와 검토 중을 갈라 센다")
    void chapter2CountsOurOwnReview() {
        Scan scan = seedTypicalScan();      // 6건

        analyses.record(asset, "CVE-1", "openssl", AnalysisState.IN_TRIAGE,
                        null, null, "", "", "", null, "tester");
        analyses.record(asset, "CVE-2", "openssl", AnalysisState.EXPLOITABLE,
                        null, null, "", "", "", null, "tester");
        analyses.record(asset, "CVE-5", "glibc", AnalysisState.NOT_AFFECTED,
                        AnalysisJustification.CODE_NOT_REACHABLE, null, "", "", "", null, "tester");

        ReportService.Summary ch = reports.build(scan).summary();

        assertThat(ch.reviewOf(AnalysisState.IN_TRIAGE)).as("검토 중").isEqualTo(1);
        assertThat(ch.reviewOf(AnalysisState.EXPLOITABLE)).as("해당됨").isEqualTo(1);
        assertThat(ch.reviewOf(AnalysisState.NOT_AFFECTED)).as("해당 없음").isEqualTo(1);
        assertThat(ch.notReviewed())
                .as("적어 둔 것이 없는 셋은 미검토 — `괜찮다` 가 아니다")
                .isEqualTo(3);

        // 합이 탐지 건수와 같아야 한다. 어긋나면 어느 건이 어디로 샜는지
        // 보고서를 읽는 사람이 알 수 없다.
        assertThat(ch.review().values().stream().mapToLong(Long::longValue).sum())
                .as("2.4 의 합계가 탐지 건수와 다르다")
                .isEqualTo(ch.total());
        assertThat(ch.reviewed()).isEqualTo(3);
    }

    /**
     * 2.4 와 1장의 <b>`제외` 집계가 같은 규칙</b>이어야 한다.
     *
     * <p>둘 다 "적어 둔 번호가 주 식별자일 수도, 함께 온 CVE 일 수도 있다" 를
     * 다뤄야 한다. 한쪽만 그러면 같은 건을 두 수가 다르게 세고, 그때 보고서는
     * 스스로와 어긋난다.
     */
    @Test
    @DisplayName("2.4 는 1장의 제외 집계와 같은 규칙으로 맞춘다")
    void chapter2ReviewMatchesTheSameKeyRuleAsChapter1() {
        Scan scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        scans.saveAndFlush(scan);

        // grype 의 주 식별자는 GHSA 이고, CVE 는 함께 온 번호다.
        Finding f = finding(scan, "GHSA-jfh8-c2jp-5v3q", "log4j-core", "2.14.1",
                            "Critical", "fixed", "2.17.0", 10.0);
        f.setRelatedCve("CVE-2021-44228");
        findings.saveAndFlush(f);
        scan.setMatchCount(1);
        scan.setFindingCount(1);
        scans.saveAndFlush(scan);

        // 사람은 CVE 번호로 적어 둔다.
        analyses.record(asset, "CVE-2021-44228", "log4j-core", AnalysisState.FALSE_POSITIVE,
                        null, null, "", "", "", null, "tester");

        ReportService.Report report = reports.build(scan);
        assertThat(report.summary().reviewOf(AnalysisState.FALSE_POSITIVE))
                .as("함께 온 CVE 로 적어 둔 것을 2.4 가 못 찾았다")
                .isEqualTo(1);
        assertThat(report.summary().notReviewed()).isZero();
        assertThat(report.overview().excludedByAnalysis())
                .as("1장은 찾았는데 2.4 가 못 찾으면 두 수가 어긋난다")
                .isEqualTo(1);
    }

    /**
     * <b>패키지 수와 건수가 맞물린다.</b>
     *
     * <p>조치({@link Remediation})는 <b>(자산, 패키지)</b> 로 등록되고
     * 탐지는 <b>건</b>이다. 보고서가 5장에서 "미등록 15개" 라고만 쓰면
     * 2장의 48건과 이을 수 없다 — 단위가 말없이 바뀌는 자리이고, 결재로
     * 올라가는 문서에서 가장 먼저 의심받는다.
     *
     * <p>여기서 못 박는 것은 <b>두 수가 실제로 맞물린다</b>는 것이다:
     * 대기 · 진행 + 완료 · 탐지 남음 + 미등록 건수 = 2.2 의 `수정 버전 있음`.
     * 어긋나면 어느 쪽이든 틀린 것이고, 보고서가 스스로와 모순된다. 세
     * 갈래가 된 까닭은 {@code RemediationProgressTest} 에 있다.
     */
    @Test
    @DisplayName("5장의 세 갈래 건수가 2.2 의 수정 버전 있음과 맞는다")
    void chapter5FindingCountsReconcileWithChapter2() {
        Scan scan = seedTypicalScan();      // 6건 — openssl 3 · curl 1 (고칠 수 있음), glibc 2 (없음)

        // 아직 아무것도 등록하지 않았다.
        ReportService.Report before = reports.build(scan);
        assertThat(before.progress().openFindings()).isZero();
        assertThat(before.progress().doneRemainingFindings()).isZero();
        assertThat(before.progress().untrackedFindings())
                .as("등록이 없으면 고칠 수 있는 건 전부가 미등록이다")
                .isEqualTo(before.summary().fixable());

        // openssl 하나를 등록한다 — 패키지 하나지만 건은 셋이다.
        remediations.saveAndFlush(new Remediation(asset, "openssl", "tester"));

        ReportService.Report after = reports.build(scan);
        assertThat(after.progress().tracked())
                .as("패키지로는 하나")
                .isEqualTo(1);
        assertThat(after.progress().openFindings())
                .as("건으로는 셋 — 이 차이가 보이지 않으면 두 수를 이을 수 없다")
                .isEqualTo(3);
        assertThat(after.progress().untrackedFindings()).isEqualTo(1);   // curl

        assertThat(after.progress().openFindings() + after.progress().doneRemainingFindings()
                   + after.progress().untrackedFindings())
                .as("세 갈래의 합이 2.2 의 `수정 버전 있음` 과 어긋나면 보고서가 스스로와 모순된다")
                .isEqualTo(after.summary().fixable());
    }

    @Test
    @DisplayName("2장 — 심각도와 조치 가능 여부를 grype 이 준 대로 센다")
    void chapter2CountsMatchGrype() {
        Scan scan = seedTypicalScan();
        ReportService.Summary ch = reports.build(scan).summary();

        assertThat(ch.severityOf("critical")).isEqualTo(1);
        assertThat(ch.severityOf("high")).isEqualTo(3);
        assertThat(ch.severityOf("medium")).isEqualTo(1);
        assertThat(ch.severityOf("low")).isEqualTo(1);
        assertThat(ch.urgent()).isEqualTo(4);          // 심각 + 높음

        assertThat(ch.fixable()).isEqualTo(4);          // openssl 3 + curl 1
        assertThat(ch.noFix()).isEqualTo(2);            // glibc 2
        assertThat(ch.unknownFix()).isZero();
        assertThat(ch.packageCount()).isEqualTo(3);
    }

    @Test
    @DisplayName("2장 — grype 이 KEV 를 주지 않으면 그렇다고 밝힌다")
    void chapter2SaysWhenKevIsUnknown() {
        Scan scan = seedTypicalScan();     // kev 를 채우지 않았다
        ReportService.Summary ch = reports.build(scan).summary();

        // "KEV 0건" 이 아니라 "확인하지 않았다" 여야 한다. 0건이라고 쓰면
        // 아무도 확인하지 않은 판정이 보고서에 실린다.
        assertThat(ch.kevKnown()).isFalse();
        assertThat(ch.kevCount()).isZero();
    }

    @Test
    @DisplayName("3장 — 조치 하나로 몇 건이 사라지는지 패키지로 묶는다")
    void chapter3GroupsByPackage() {
        Scan scan = seedTypicalScan();
        ReportService.Targets ch = reports.build(scan).targets();

        // 수정본이 있는 패키지만 조치 대상이다.
        assertThat(ch.fixTargets()).extracting(ReportService.PackageAction::packageName)
                                .containsExactlyInAnyOrder("openssl", "curl");
        // 손댈 수 없는 것은 지우지 않고 따로 세워 둔다.
        assertThat(ch.blocked()).extracting(ReportService.PackageAction::packageName)
                                .containsExactly("glibc");

        ReportService.PackageAction openssl = ch.fixTargets().stream()
                .filter(a -> a.packageName().equals("openssl")).findFirst().orElseThrow();
        assertThat(openssl.fixableCount()).isEqualTo(3);
        assertThat(openssl.targetVersion()).isEqualTo("3.0.7");
        assertThat(openssl.criticalCount()).isEqualTo(1);
        assertThat(openssl.maxCvss()).isEqualByComparingTo("9.80");

        assertThat(ch.resolvableFindings()).isEqualTo(4);
    }

    @Test
    @DisplayName("3장 — 첫 검사면 지난번 대비를 만들지 않는다")
    void chapter3NoDiffOnFirstScan() {
        Scan scan = seedTypicalScan();
        assertThat(reports.build(scan).targets().diff().hasPrevious()).isFalse();
    }

    @Test
    @DisplayName("3장 — 지난 검사 대비는 (CVE, 패키지) 로 대조한다")
    void chapter3DiffIgnoresVersion() {
        // 지난달: openssl 3.0.0 에서 CVE-1, CVE-2
        Scan before = new Scan(asset, "tester");
        before.setStatus(ScanStatus.DONE);
        scans.saveAndFlush(before);
        finding(before, "CVE-1", "openssl", "3.0.0", "Critical", "fixed", "3.0.7", 9.8);
        finding(before, "CVE-2", "openssl", "3.0.0", "High", "fixed", "3.0.7", 7.5);
        // 검사 시각을 과거로 밀어 "지난 검사"가 되게 한다
        before.setCreatedAt(Instant.now().minus(30, ChronoUnit.DAYS));
        scans.saveAndFlush(before);

        // 이번 달: 부분 패치로 버전만 3.0.5 가 됐고 CVE-1 은 그대로, CVE-2 는
        // 사라졌으며 CVE-9 가 새로 생겼다.
        Scan now = new Scan(asset, "tester");
        now.setStatus(ScanStatus.DONE);
        scans.saveAndFlush(now);
        finding(now, "CVE-1", "openssl", "3.0.5", "Critical", "fixed", "3.0.7", 9.8);
        finding(now, "CVE-9", "openssl", "3.0.5", "High", "fixed", "3.0.7", 7.5);

        ReportService.Diff diff = reports.build(now).targets().diff();

        assertThat(diff.hasPrevious()).isTrue();
        // 버전이 3.0.0 → 3.0.5 로 바뀌었지만 CVE-1 은 "유지" 다. 버전을 대조
        // 축에 넣으면 이것이 "해소 1건 + 신규 1건"으로 갈라져 보인다.
        assertThat(diff.kept()).isEqualTo(1);
        assertThat(diff.added()).isEqualTo(1);      // CVE-9
        assertThat(diff.resolved()).isEqualTo(1);   // CVE-2
    }

    @Test
    @DisplayName("5장 — 등록된 조치와 아직 아닌 것을 가른다")
    void chapter4SplitsTrackedAndUntracked() {
        Scan scan = seedTypicalScan();

        Remediation remediation = new Remediation(asset, "openssl", "admin");
        remediation.setOwner("인프라운영팀");
        remediation.moveTo(RemediationStatus.IN_PROGRESS, "admin", "적용 예정");
        remediations.save(remediation);

        ReportService.Progress ch = reports.build(scan).progress();

        assertThat(ch.rows()).hasSize(2);           // openssl · curl
        assertThat(ch.tracked()).isEqualTo(1);      // openssl 만 등록됨
        assertThat(ch.untracked()).isEqualTo(1);    // curl
        assertThat(ch.overdue()).isZero();
        // 잔여 위험은 손댈 수 없는 것 그대로다.
        assertThat(ch.residual()).extracting(ReportService.PackageAction::packageName)
                                 .containsExactly("glibc");
    }

    // --- 노출면 -------------------------------------------------------------

    /** 벡터까지 지정해 한 건을 만든다. */
    private Finding withVector(Scan scan, String cve, String pkg, String severity,
                               String fixState, String vector) {
        Finding f = finding(scan, cve, pkg, "1.0.0", severity, fixState,
                            "fixed".equals(fixState) ? "2.0.0" : "", 9.8);
        f.setCvssVector(vector);
        return findings.save(f);
    }

    private Scan seedVectorScan() {
        Scan scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        scans.saveAndFlush(scan);

        // 밖에서 바로 · 수정본 있음 — 실제 log4j-core 가 받은 벡터
        withVector(scan, "CVE-A", "log4j-core", "Critical", "fixed",
                   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
        withVector(scan, "CVE-B", "log4j-core", "High", "fixed",
                   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        // 밖에서 바로 · 수정본 없음
        withVector(scan, "CVE-C", "spring-core", "High", "not-fixed",
                   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
        // 사용자 개입 필요 — 바로 닿는 것이 아니다
        withVector(scan, "CVE-D", "lodash", "High", "fixed",
                   "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N");
        // 로컬
        withVector(scan, "CVE-E", "glibc", "Medium", "fixed",
                   "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
        // 벡터 없음 → 판단 불가
        withVector(scan, "CVE-F", "zlib", "Medium", "fixed", "");
        // CVSS 2.0 → 판단 불가 (Au 를 PR 로 오독하면 안 된다)
        withVector(scan, "CVE-G", "openssl", "High", "fixed", "AV:N/AC:L/Au:N/C:P/I:P/A:P");

        scan.setMatchCount(7);
        scan.setFindingCount(7);
        scans.saveAndFlush(scan);
        return scan;
    }

    @Test
    @DisplayName("2장 — 벡터를 풀어 '밖에서 바로 닿는 것'을 센다")
    void countsTheDirectlyReachable() {
        ReportService.Exposure e = reports.build(seedVectorScan()).summary().exposure();

        // AV:N + PR:N + UI:N 인 셋만.
        assertThat(e.reachable()).isEqualTo(3);
        assertThat(e.reachableFixable()).isEqualTo(2);
        assertThat(e.reachableWithoutFix()).isEqualTo(1);   // spring-core
        assertThat(e.scopeChanged()).isEqualTo(1);          // S:C 하나
    }

    /**
     * 이 시험이 이 기능의 핵심이다. 읽지 못한 벡터를 "원격에서 닿지 않는다"로
     * 밀어 넣으면 보고서가 아무도 확인하지 않은 판정을 말하게 된다.
     */
    @Test
    @DisplayName("읽지 못한 벡터는 '아니오'가 아니라 '판단 불가'로 센다")
    void unreadableVectorsAreCountedApart() {
        ReportService.Exposure e = reports.build(seedVectorScan()).summary().exposure();

        // 벡터 없음 1건 + CVSS 2.0 1건.
        assertThat(e.unreadable()).isEqualTo(2);
        // 그 둘은 '닿는다' 에도 '안 닿는다' 에도 들어가지 않았다.
        assertThat(e.reachable() + e.unreadable()).isLessThanOrEqualTo(7);
    }

    @Test
    @DisplayName("3장 — 원격 접근 건이 많은 패키지가 먼저 온다")
    void actionsAreOrderedByReach() {
        ReportService.Targets ch = reports.build(seedVectorScan()).targets();

        // log4j-core 가 2건으로 가장 많다.
        assertThat(ch.fixTargets().get(0).packageName()).isEqualTo("log4j-core");
        assertThat(ch.fixTargets().get(0).reachableCount()).isEqualTo(2);
        // 바로 닿는 건이 하나도 없는 패키지는 뒤로 간다.
        assertThat(ch.fixTargets()).last()
                .extracting(ReportService.PackageAction::reachableCount).isEqualTo(0L);
        // 3장 표가 덮는 원격 접근 건수 합계 — log4j-core 의 2건뿐이다.
        assertThat(ch.resolvableReach()).isEqualTo(2);
    }

    @Test
    @DisplayName("벡터가 하나도 없으면 노출면을 0 이라 말하지 않는다")
    void doesNotClaimZeroWhenNothingWasReadable() {
        Scan scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        scans.saveAndFlush(scan);
        withVector(scan, "CVE-X", "zlib", "High", "fixed", "");
        withVector(scan, "CVE-Y", "curl", "High", "fixed", "");
        scan.setFindingCount(2);
        scan.setMatchCount(2);
        scans.saveAndFlush(scan);

        ReportService.Exposure e = reports.build(scan).summary().exposure();
        assertThat(e.reachable()).isZero();
        assertThat(e.unreadable()).isEqualTo(2);
        // 한 건도 읽지 못했다 — 화면은 이 문단을 싣지 않는다.
        assertThat(e.measured()).isFalse();
    }

    @Test
    @DisplayName("탐지가 없는 스캔도 보고서가 나온다")
    void emptyScanStillReports() {
        Scan scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        scans.saveAndFlush(scan);

        ReportService.Report report = reports.build(scan);
        assertThat(report.overview().findingCount()).isZero();
        assertThat(report.targets().fixTargets()).isEmpty();
        assertThat(report.progress().rows()).isEmpty();
    }
}
