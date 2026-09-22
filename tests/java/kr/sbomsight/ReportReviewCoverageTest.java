package kr.sbomsight;

import kr.sbomsight.domain.*;
import kr.sbomsight.repo.*;
import kr.sbomsight.service.FindingAnalysisService;
import kr.sbomsight.service.ReportService;
import kr.sbomsight.service.ZoneReportService;
import kr.sbomsight.service.ZoneService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 보고서가 <b>검토 범위를 부풀리지 않는가.</b>
 *
 * <p>검토 결과는 {@code (자산, CVE, 패키지)} 하나에 하나씩 달리는데, 보고서
 * 4장(구역 보고서 5장)은 <b>패키지로 한 줄</b>이다. 그 줄에 검토 결과가
 * 하나라도 달려 있으면 상태 딱지를 그대로 찍고 있었다.
 *
 * <p>띄워서 찾았다. {@code sudo} 3건에 검토 결과 <b>한 건</b>만 적었더니
 * 4장이 이렇게 찍었다.
 *
 * <pre>
 *   sudo (rpm) · 1.9.5p2 · 3건 · 최고 CVSS 9.60 · 해당 없음 ·
 *   취약한 코드를 실행하지 않음
 * </pre>
 *
 * <p>적어 둔 것은 <b>CVSS 5.10 짜리 한 건</b>이고 9.60 짜리는 아무도 본 적이
 * 없다. 결재를 올리는 사람이 이 줄을 읽으면 세 건 모두 정리된 것으로 읽는다 —
 * <b>검토가 보고서의 숫자를 실제보다 안전하게 만드는</b> 바로 그 자리다(§11).
 */
@SpringBootTest
@Transactional
class ReportReviewCoverageTest {

    @Autowired ReportService reports;
    @Autowired ZoneReportService zoneReports;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired ZoneService zoneService;
    @Autowired ZoneRepository zones;
    @Autowired FindingAnalysisService analyses;

    private Asset asset;
    private Zone zone;
    private Scan scan;
    private String pkg;

    @BeforeEach
    void setUp() {
        zone = zoneService.create("검토범위-" + System.nanoTime(), "#123456", "");
        asset = new Asset();
        asset.setName("rc-" + System.nanoTime());
        asset.setZone(zone);
        assets.save(asset);
        pkg = "rc-pkg-" + System.nanoTime();

        scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        scan.setCreatedAt(Instant.now());
        scan.setFindingCount(3);
        scans.saveAndFlush(scan);

        // 수정 버전이 하나도 없는 패키지 — 4장에 실리는 것이 이것이다.
        finding("CVE-2099-0001", 9.6);
        finding("CVE-2099-0002", 5.1);
        finding("CVE-2099-0003", 7.0);
    }

    private void finding(String cve, double cvss) {
        Finding f = new Finding(scan, cve + "|" + pkg, cve, pkg);
        f.setPackageVersion("1.9.5p2");
        f.setPackageType("rpm");
        f.setSeverity("High");
        f.setFixState("not-fixed");
        f.setCvssScore(BigDecimal.valueOf(cvss));
        findings.saveAndFlush(f);
    }

    /** 한 건만 적어 둔다 — 가장 낮은 CVSS 짜리. */
    private void reviewOne() {
        analyses.record(asset, "CVE-2099-0002", pkg, AnalysisState.NOT_AFFECTED,
                        AnalysisJustification.CODE_NOT_REACHABLE, null,
                        "우리 환경에서는 실행 경로에 없음", "", "", null, "admin");
    }

    @Test
    @DisplayName("4장 — 세 건 중 한 건만 적었으면 `1 / 3건` 이다")
    void oneOfThreeIsNotTheWholePackage() {
        reviewOne();

        ReportService.NoFixRow row = reports.build(scan).targets().noFixRows().stream()
                .filter(r -> r.action().packageName().equals(pkg))
                .findFirst()
                .orElseThrow(() -> new AssertionError("4장에 그 패키지가 없습니다"));

        assertThat(row.action().total()).isEqualTo(3);
        assertThat(row.reviewed().done())
                .as("적어 둔 것은 한 건입니다")
                .isEqualTo(1);
        assertThat(row.reviewed().total()).isEqualTo(3);
        assertThat(row.reviewed().all())
                .as("한 건만 적어 두고 그 패키지가 검토됐다고 말하면, 결재를 "
                    + "올리는 사람이 나머지 두 건도 정리된 것으로 읽습니다")
                .isFalse();
        // 근거를 붙일 검토 결과는 있다 — 그것과 `검토가 끝났다` 는 다른 말이다.
        assertThat(row.hasAnalysis()).isTrue();
    }

    @Test
    @DisplayName("4장 — 세 건 다 적었으면 `전부 3건` 이다")
    void allThreeCountsAsReviewed() {
        analyses.record(asset, "CVE-2099-0001", pkg, AnalysisState.NOT_AFFECTED,
                        AnalysisJustification.CODE_NOT_REACHABLE, null, "", "", "", null, "admin");
        reviewOne();
        analyses.record(asset, "CVE-2099-0003", pkg, AnalysisState.FALSE_POSITIVE,
                        null, null, "패키지 오인", "", "", null, "admin");

        ReportService.NoFixRow row = reports.build(scan).targets().noFixRows().stream()
                .filter(r -> r.action().packageName().equals(pkg))
                .findFirst().orElseThrow();

        assertThat(row.reviewed().all()).isTrue();
        assertThat(row.reviewed().done()).isEqualTo(3);
    }

    /**
     * 5장의 각주가 세는 수도 같은 규칙이어야 한다.
     *
     * <p>4장의 표가 `1 / 3건` 이라고 찍는데 5장 각주가 `답 없는 건이 남은
     * 패키지 0개` 라고 하면, 한 보고서 안에서 두 장이 서로를 부정한다.
     */
    @Test
    @DisplayName("5장 각주 — 덜 검토된 패키지를 설명된 것으로 세지 않는다")
    void theFootnoteCountsThePartlyReviewedPackage() {
        reviewOne();

        ReportService.Progress progress = reports.build(scan).progress();

        assertThat(progress.isExplained(pkg))
                .as("세 건 중 한 건만 적어 둔 패키지입니다")
                .isFalse();
        assertThat(progress.unexplained())
                .as("답 없는 건이 남은 패키지를 0개로 세면 보고서가 실제보다 "
                    + "안전해 보입니다")
                .isEqualTo(1);
    }

    /** 구역 보고서 5장도 같은 규칙이다 — 자산 수만 가려서는 모자란다. */
    @Test
    @DisplayName("구역 보고서 — 한 자산 안에서 덜 검토된 것도 가린다")
    void theZoneReportCountsFindingsNotAssets() {
        reviewOne();

        // 기간은 컨트롤러가 늘 채워 넘긴다(`ZoneReportController:44`). 여기서도
        // 같은 꼴로 준다 — 오늘이 든 기간이면 방금 만든 검사가 범위에 든다.
        java.time.LocalDate today = java.time.LocalDate.now();
        ZoneReportService.Action action = zoneReports
                .build(zone.getId(), today.minusDays(1), today.plusDays(1)).action();

        assertThat(action.explainedAssets(pkg))
                .as("적어 둔 자산은 한 대입니다 — 이 수는 그대로여야 합니다")
                .isEqualTo(1);
        assertThat(action.reviewedIn(pkg).done()).isEqualTo(1);
        assertThat(action.reviewedIn(pkg).total()).isEqualTo(3);
        assertThat(action.isExplained(pkg))
                .as("그 한 대 안에서도 세 건 중 한 건만 적어 두었습니다")
                .isFalse();
        assertThat(action.unexplained()).isEqualTo(1);
    }
}
