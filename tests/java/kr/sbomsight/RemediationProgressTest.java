package kr.sbomsight;

import kr.sbomsight.domain.*;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.FindingRepository;
import kr.sbomsight.repo.RemediationRepository;
import kr.sbomsight.repo.ScanRepository;
import kr.sbomsight.service.RemediationService;
import kr.sbomsight.service.ReportService;
import kr.sbomsight.service.ZoneReportService;
import kr.sbomsight.service.ZoneService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * <b>조치 진행을 두 보고서가 같은 갈래로 센다</b> — 대기 · 진행 / 완료 · 탐지 남음 /
 * 완료 · 신규 탐지 / 완료 · 검증 대기 / 미등록.
 *
 * <p>조치를 `완료` 로 바꿨는데 검사에 그 패키지의 탐지가 남아 있으면, 자산
 * 보고서 5장은 `등록` 으로(미등록 374건), 구역 보고서 6장은 `미등록` 으로
 * (406건) 셌다 — 띄운 앱에서 같은 자산 하나를 두고 두 보고서의 수가 달랐다.
 * 이 시험의 자료로 고치기 전 코드를 돌리면 자산 보고서 4건 · 구역 보고서
 * 7건이다. 완료했는데 남은 것은 등록도 미등록도 아니다 — 따로 드러나야
 * 한다(사용자 결정: 세 갈래).
 *
 * <p>완료했는데 남은 것은 다시 셋으로 갈린다(R10 · D11) — 앞서는 모두 `완료 · 탐지 남음`
 * 이었다. 그래서 자료에서 <b>완료 시각과 검사 시각의 앞뒤를 일부러 정한다</b>: 검사보다
 * 먼저 완료한 것(탐지 남음 · 신규 탐지)과 검사보다 나중에 완료한 것(검증 대기).
 *
 * <p>`대기 · 진행` 은 <b>그 상태인 조치 전부</b>다. 올려서 탐지가 사라졌는데
 * 아직 완료로 넘기지 않은 조치도 들어간다 — 앞서 자산 보고서는 3장에 없는
 * 조치를 몰랐고 구역 보고서는 셌다.
 */
@SpringBootTest
@Transactional
class RemediationProgressTest {

    @Autowired ReportService reports;
    @Autowired ZoneReportService zoneReports;
    @Autowired RemediationService remediationService;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired RemediationRepository remediations;
    @Autowired ZoneService zoneService;

    private Zone zone;
    private Asset asset;
    private Scan scan;

    @BeforeEach
    void setUp() {
        zone = zoneService.create("진행-" + System.nanoTime(), "#123456", "");
        asset = new Asset();
        asset.setName("progress-" + System.nanoTime());
        asset.setZone(zone);
        assets.saveAndFlush(asset);

        // 앞선 검사 — pg-new 의 조치를 이 검사에서 등록했다. 조치 대상은 CVE-2098-1 하나.
        Scan earlier = scan(Instant.now().minus(1, ChronoUnit.HOURS));
        finding(earlier, "CVE-2098-1", "pg-new");
        Remediation pgNew = remediationService.open(asset, earlier, "pg-new", "tester").remediation();
        remediationService.update(pgNew, RemediationStatus.DONE, "", null, "", "tester", "");

        // 이 검사보다 먼저 정한 조치들 — 완료한 것은 고친 뒤의 SBOM 으로 판정한다.
        remediation("pg-open", RemediationStatus.OPEN);
        remediation("pg-done", RemediationStatus.DONE);
        // 이 검사에 탐지가 없다 — 올렸는데 아직 완료로 넘기지 않은 것
        remediation("pg-gone", RemediationStatus.IN_PROGRESS);
        // 이 검사에 탐지가 없다 — 끝난 것. 어느 갈래에도 들지 않는다
        remediation("pg-fixed", RemediationStatus.DONE);

        scan = scan(Instant.now());
        fixable("pg-open", 2);      // 대기 중인 조치
        fixable("pg-done", 3);      // 완료했는데 남은 것 — 조치 대상을 모르는 조치라 탐지 남음
        fixable("pg-new", 1);       // 완료했는데 남은 것이 조치 대상(CVE-2098-1)이 아님 — 신규 탐지
        fixable("pg-late", 2);      // 이 검사 뒤에 완료한 것 — 검증 대기
        fixable("pg-none", 4);      // 아무도 맡지 않은 것
        scan.setFindingCount(12);
        scans.saveAndFlush(scan);

        // 이 검사(SBOM)보다 나중에 완료했다 — 이 검사는 고치기 전의 서버를 본다.
        remediation("pg-late", RemediationStatus.DONE);
    }

    private Scan scan(Instant at) {
        Scan s = new Scan(asset, "tester");
        s.setStatus(ScanStatus.DONE);
        s.setCreatedAt(at);
        return scans.saveAndFlush(s);
    }

    private void fixable(String pkg, int count) {
        for (int i = 0; i < count; i++) {
            finding(scan, "CVE-2099-" + i, pkg);
        }
    }

    private void finding(Scan in, String cve, String pkg) {
        Finding f = new Finding(in, cve + "|" + pkg, cve, pkg);
        f.setPackageVersion("1.0");
        f.setSeverity("High");
        f.setFixState("fixed");
        f.setFixedVersion("1.1");
        findings.saveAndFlush(f);
    }

    private void remediation(String pkg, RemediationStatus status) {
        Remediation r = new Remediation(asset, pkg, "tester");
        // 등록 당시 건수는 있는데 조치 대상이 없다 — 대상을 모르는 옛 조치의 꼴(V19).
        r.setOpenedCount(1);
        r.moveTo(RemediationStatus.OPEN, "tester", "조치 등록");
        if (status != RemediationStatus.OPEN) {
            r.moveTo(status, "tester", "");
        }
        remediations.saveAndFlush(r);
    }

    @Test
    @DisplayName("자산 보고서 5장과 구역 보고서 6장이 같은 갈래로 같은 수를 낸다")
    void bothReportsSplitTheSameWay() {
        ReportService.Report assetReport = reports.build(scan);
        ReportService.Progress asset5 = assetReport.progress();
        LocalDate today = LocalDate.now();
        ZoneReportService.ZoneReport zoneReport =
                zoneReports.build(zone.getId(), today.minusDays(1), today.plusDays(1));
        ZoneReportService.Action zone6 = zoneReport.action();

        // 대기 · 진행 — 탐지가 사라진 pg-gone 도 아직 대기 · 진행이다
        assertThat(asset5.openPackages()).isEqualTo(2);
        assertThat(asset5.openFindings()).isEqualTo(2);
        assertThat(zone6.open()).isEqualTo(2);
        assertThat(zone6.openFindings()).isEqualTo(2);

        // 완료 · 탐지 남음 — 탐지가 없는 pg-fixed 는 들지 않는다
        assertThat(asset5.doneRemainingPackages())
                .as("완료했는데 남은 것을 `등록` 에 넣었다")
                .isEqualTo(1);
        assertThat(asset5.doneRemainingFindings()).isEqualTo(3);
        assertThat(zone6.doneRemaining())
                .as("완료했는데 남은 것을 `미등록` 에 넣었다")
                .isEqualTo(1);
        assertThat(zone6.doneRemainingFindings()).isEqualTo(3);

        // 완료 · 신규 탐지 — 남은 것이 조치 대상이 아니다
        assertThat(asset5.doneNewPackages()).isEqualTo(1);
        assertThat(asset5.doneNewFindings()).isEqualTo(1);
        assertThat(zone6.doneNew()).isEqualTo(1);
        assertThat(zone6.doneNewFindings()).isEqualTo(1);

        // 완료 · 검증 대기 — 검사의 SBOM 이 완료보다 앞이다
        assertThat(asset5.donePendingPackages()).isEqualTo(1);
        assertThat(asset5.donePendingFindings()).isEqualTo(2);
        assertThat(zone6.donePending()).isEqualTo(1);
        assertThat(zone6.donePendingFindings()).isEqualTo(2);

        // 미등록 — 두 보고서가 같은 수를 말한다
        assertThat(asset5.untracked()).isEqualTo(1);
        assertThat(asset5.untrackedFindings()).isEqualTo(4);
        assertThat(zone6.untrackedFindings())
                .as("같은 자산 하나인데 두 보고서의 미등록이 다르다")
                .isEqualTo(asset5.untrackedFindings());

        // 갈래들의 해소 건수를 더하면 조치 대상 표의 합계다 — 빠지거나
        // 두 번 세는 건이 없다.
        assertThat(asset5.openFindings() + asset5.doneRemainingFindings() + asset5.doneNewFindings()
                   + asset5.donePendingFindings() + asset5.untrackedFindings())
                .as("자산 보고서 5장의 갈래 합이 3장 합계와 다르다")
                .isEqualTo(assetReport.targets().resolvableFindings())
                .isEqualTo(12);
        assertThat(zone6.openFindings() + zone6.doneRemainingFindings() + zone6.doneNewFindings()
                   + zone6.donePendingFindings() + zone6.untrackedFindings())
                .as("구역 보고서 6장의 갈래 합이 4장 합계와 다르다")
                .isEqualTo(zoneReport.judgement().resolvableFindings())
                .isEqualTo(12);

        // 5장 아래 표 — 대기 · 진행 둘과 완료 뒤 셋. 끝난 pg-fixed 는 싣지 않는다.
        assertThat(asset5.tracking())
                .extracting(r -> r.remediation().getPackageName())
                .containsExactlyInAnyOrder("pg-open", "pg-done", "pg-new", "pg-late", "pg-gone");
    }
}
