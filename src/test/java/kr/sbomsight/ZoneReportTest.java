package kr.sbomsight;

import kr.sbomsight.domain.Asset;
import kr.sbomsight.domain.Finding;
import kr.sbomsight.domain.Scan;
import kr.sbomsight.domain.ScanStatus;
import kr.sbomsight.domain.Zone;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.FindingRepository;
import kr.sbomsight.repo.ScanRepository;
import kr.sbomsight.service.ZoneReportService;
import kr.sbomsight.service.ZoneReportService.ZonePackageAction;
import kr.sbomsight.service.ZoneReportService.ZoneReport;
import kr.sbomsight.service.ZoneService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.ZoneId;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 구역 · 기간 보고서.
 *
 * <p>여기서 고정하는 것은 <b>보고서가 무엇을 세고 무엇을 안 세는지</b>다.
 * 자산 한 대짜리 보고서와 달리 이 보고서는 "무엇이 빠졌는가" 를 스스로
 * 밝혀야 한다. 서른 대 중 열 대만 검사하고 "탐지 1,200건" 이라고 쓰면
 * 그것은 구역의 현황이 아니라 열 대의 현황이고, 받는 사람은 그 차이를
 * 알 수 없다.
 *
 * <p>모든 시험은 <b>자기만의 구역</b>을 만들어 그 안에서 논다. 전체 구역으로
 * 부르면 다른 시험이 남긴 자산이 섞여 들어와 수가 흔들린다.
 */
@SpringBootTest
@Transactional
class ZoneReportTest {

    private static final ZoneId WALL = ZoneId.systemDefault();

    /** 밖에서 인증 없이 바로 닿는 벡터. */
    private static final String REACHABLE =
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
    /** 서버에 이미 들어와 있어야 쓸 수 있는 벡터. */
    private static final String NEEDS_LOGIN =
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N";

    @Autowired ZoneReportService reports;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired ZoneService zoneService;

    private Zone zone;

    /** 시험이 보는 달. 고정해 두어야 "이번 달" 에 따라 결과가 흔들리지 않는다. */
    private final LocalDate from = LocalDate.of(2026, 9, 1);
    private final LocalDate to = LocalDate.of(2026, 9, 30);

    @BeforeEach
    void setUp() {
        zone = zoneService.create("구역-" + System.nanoTime(), "#123456", "");
    }

    // --- 거들 -----------------------------------------------------------------

    private Asset asset(String name) {
        Asset a = new Asset();
        a.setName(name + "-" + System.nanoTime());
        a.setZone(zone);
        a.setOsName("Rocky Linux 9.3");
        return assets.saveAndFlush(a);
    }

    private Scan scan(Asset asset, LocalDate day) {
        return scan(asset, day, LocalTime.of(3, 0), "0.87.0");
    }

    private Scan scan(Asset asset, LocalDate day, LocalTime at, String grypeVersion) {
        Scan s = new Scan(asset, "tester");
        s.setStatus(ScanStatus.DONE);
        s.setGrypeVersion(grypeVersion);
        s.setSbomFilename("sbom.json");
        s.setCreatedAt(day.atTime(at).atZone(WALL).toInstant());
        return scans.saveAndFlush(s);
    }

    private Finding finding(Scan scan, String cve, String pkg, String version,
                            String severity, String fixState, String fixedVersion,
                            Double cvss, String vector) {
        Finding f = new Finding(scan, cve + "|" + pkg + "|" + version + "|purl", cve, pkg);
        f.setPackageVersion(version);
        f.setPackageType("rpm");
        f.setSeverity(severity);
        f.setFixState(fixState);
        f.setFixedVersion(fixedVersion);
        if (cvss != null) {
            f.setCvssScore(BigDecimal.valueOf(cvss));
        }
        f.setCvssVector(vector);
        Finding saved = findings.saveAndFlush(f);
        scan.setFindingCount(scan.getFindingCount() + 1);
        scans.saveAndFlush(scan);
        return saved;
    }

    private ZoneReport report() {
        return reports.build(zone.getId(), from, to);
    }

    private ZonePackageAction action(ZoneReport r, String packageName) {
        return r.judgement().actions().stream()
                .filter(a -> a.packageName().equals(packageName))
                .findFirst().orElseThrow(() -> new AssertionError(
                        "조치 대상에 " + packageName + " 이 없습니다: " + r.judgement().actions()));
    }

    // --- 기간 ------------------------------------------------------------------

    @Test
    @DisplayName("기간 밖의 검사는 기준이 되지 않는다")
    void ignoresScansOutsideThePeriod() {
        Asset a = asset("web");
        Scan august = scan(a, LocalDate.of(2026, 8, 20));
        finding(august, "CVE-8", "openssl", "3.0.0", "Critical", "fixed", "3.0.7", 9.8, REACHABLE);
        Scan september = scan(a, LocalDate.of(2026, 9, 10));
        finding(september, "CVE-9", "curl", "8.4.0", "High", "fixed", "8.6.0", 7.5, REACHABLE);

        ZoneReport r = report();

        // 8월 것이 섞이면 "9월 현황" 이 아니다.
        assertThat(r.scope().totalFindings()).isEqualTo(1);
        assertThat(r.judgement().actions()).extracting(ZonePackageAction::packageName)
                .containsExactly("curl");
    }

    @Test
    @DisplayName("종료일 당일 늦은 시각의 검사도 들어간다")
    void includesScansOnTheLastDay() {
        Asset a = asset("web");
        // 23:59:59 로 끊으면 이 검사가 사라진다.
        Scan last = scan(a, to, LocalTime.of(23, 59, 59), "0.87.0");
        finding(last, "CVE-1", "openssl", "3.0.0", "High", "fixed", "3.0.7", 7.5, REACHABLE);

        assertThat(report().scope().assetsScanned()).isEqualTo(1);
        assertThat(report().scope().totalFindings()).isEqualTo(1);
    }

    @Test
    @DisplayName("한 자산에 검사가 여럿이면 기간 안의 마지막 것을 쓴다")
    void usesTheLastScanInsideThePeriod() {
        Asset a = asset("web");
        Scan early = scan(a, LocalDate.of(2026, 9, 3));
        finding(early, "CVE-1", "openssl", "3.0.0", "High", "fixed", "3.0.7", 7.5, REACHABLE);
        finding(early, "CVE-2", "curl", "8.4.0", "High", "fixed", "8.6.0", 7.5, REACHABLE);
        Scan late = scan(a, LocalDate.of(2026, 9, 25));
        finding(late, "CVE-1", "openssl", "3.0.0", "High", "fixed", "3.0.7", 7.5, REACHABLE);

        ZoneReport r = report();

        // 두 검사를 합치면 openssl 이 두 번 세어진다.
        assertThat(r.scope().assetsScanned()).isEqualTo(1);
        assertThat(r.aggregate().total()).isEqualTo(1);
        assertThat(r.judgement().actions()).extracting(ZonePackageAction::packageName)
                .containsExactly("openssl");
    }

    // --- 커버리지 --------------------------------------------------------------

    @Test
    @DisplayName("기간 안에 검사되지 않은 자산을 이름까지 밝힌다")
    void namesAssetsNotScannedInThePeriod() {
        Asset scanned = asset("web");
        Asset staleOnly = asset("db");
        Asset neverScanned = asset("api");
        Scan s = scan(scanned, LocalDate.of(2026, 9, 10));
        finding(s, "CVE-1", "openssl", "3.0.0", "High", "fixed", "3.0.7", 7.5, REACHABLE);
        // 기간 밖에만 검사한 자산도 "이 기간에 검사 없음" 이다.
        scan(staleOnly, LocalDate.of(2026, 8, 10));

        ZoneReport r = report();

        assertThat(r.scope().assetsInScope()).isEqualTo(3);
        assertThat(r.scope().assetsScanned()).isEqualTo(1);
        assertThat(r.scope().fullyCovered()).isFalse();
        assertThat(r.scope().coveragePercent()).isEqualTo(33);
        // 몇 대인지만 말하면 어느 서버가 빠졌는지 찾을 수 없다.
        assertThat(r.scope().notScanned()).extracting(Asset::getName)
                .containsExactlyInAnyOrder(staleOnly.getName(), neverScanned.getName());
    }

    @Test
    @DisplayName("검사되지 않은 자산도 자산 표에 줄을 차지한다")
    void keepsUnscannedAssetsInTheTable() {
        Asset scanned = asset("web");
        Asset missed = asset("db");
        Scan s = scan(scanned, LocalDate.of(2026, 9, 10));
        finding(s, "CVE-1", "openssl", "3.0.0", "Critical", "fixed", "3.0.7", 9.8, REACHABLE);

        var rows = report().aggregate().rows();

        // 목록에서 빠지면 "안 본 것" 과 "문제가 없는 것" 을 구분할 수 없다.
        assertThat(rows).hasSize(2);
        assertThat(rows.get(0).asset().getName()).isEqualTo(scanned.getName());
        assertThat(rows.get(0).scanned()).isTrue();
        assertThat(rows.get(1).asset().getName()).isEqualTo(missed.getName());
        assertThat(rows.get(1).scanned()).isFalse();
    }

    // --- 패키지 묶음 -----------------------------------------------------------

    @Test
    @DisplayName("같은 패키지를 자산 너머로 묶고 몇 대인지 센다")
    void groupsPackagesAcrossAssets() {
        for (int i = 0; i < 3; i++) {
            Scan s = scan(asset("web" + i), LocalDate.of(2026, 9, 10));
            finding(s, "CVE-1", "openssl", "3.0.0", "Critical", "fixed", "3.0.7", 9.8, REACHABLE);
            finding(s, "CVE-2", "openssl", "3.0.0", "High", "fixed", "3.0.7", 7.5, NEEDS_LOGIN);
        }

        ZonePackageAction openssl = action(report(), "openssl");

        // 자산을 하나씩 열어 보면 "여기 2건, 저기 2건" 으로 흩어져 이 판단이 안 선다.
        assertThat(openssl.assetCount()).isEqualTo(3);
        assertThat(openssl.total()).isEqualTo(6);
        assertThat(openssl.fixableCount()).isEqualTo(6);
        assertThat(openssl.reachableCount()).isEqualTo(3);
        assertThat(openssl.oneVersion()).isTrue();
        assertThat(openssl.oneTarget()).isTrue();
        assertThat(openssl.targetVersion()).isEqualTo("3.0.7");
    }

    @Test
    @DisplayName("자산마다 수정 버전이 다르면 목표를 단정하지 않는다")
    void doesNotClaimOneTargetWhenAssetsDisagree() {
        Scan rocky = scan(asset("web"), LocalDate.of(2026, 9, 10));
        finding(rocky, "CVE-1", "openssl", "3.0.0", "High", "fixed", "3.0.7", 7.5, REACHABLE);
        Scan ubuntu = scan(asset("api"), LocalDate.of(2026, 9, 11));
        finding(ubuntu, "CVE-1", "openssl", "3.0.2", "High", "fixed", "3.0.9", 7.5, REACHABLE);

        ZonePackageAction openssl = action(report(), "openssl");

        // 하나를 골라 "3.0.7 로 올리세요" 라고 쓰면 나머지 자산에는 틀린 지시다.
        assertThat(openssl.assetCount()).isEqualTo(2);
        assertThat(openssl.oneVersion()).isFalse();
        assertThat(openssl.oneTarget()).isFalse();
        assertThat(openssl.versionCount()).isEqualTo(2);
    }

    @Test
    @DisplayName("두 대 이상에 걸린 패키지를 따로 가려낸다")
    void findsPackagesSharedAcrossAssets() {
        Scan a = scan(asset("web"), LocalDate.of(2026, 9, 10));
        finding(a, "CVE-1", "openssl", "3.0.0", "High", "fixed", "3.0.7", 7.5, REACHABLE);
        finding(a, "CVE-2", "nginx", "1.20", "Medium", "fixed", "1.22", 5.3, REACHABLE);
        Scan b = scan(asset("api"), LocalDate.of(2026, 9, 10));
        finding(b, "CVE-1", "openssl", "3.0.0", "High", "fixed", "3.0.7", 7.5, REACHABLE);

        assertThat(report().judgement().shared())
                .extracting(ZonePackageAction::packageName).containsExactly("openssl");
    }

    @Test
    @DisplayName("수정본이 없는 패키지는 조치 대상이 아니라 잔여 위험으로 간다")
    void separatesPackagesWithoutAFix() {
        Scan s = scan(asset("web"), LocalDate.of(2026, 9, 10));
        finding(s, "CVE-1", "openssl", "3.0.0", "High", "fixed", "3.0.7", 7.5, REACHABLE);
        finding(s, "CVE-2", "glibc", "2.34", "High", "wont-fix", "", 7.8, NEEDS_LOGIN);

        ZoneReport r = report();

        assertThat(r.judgement().actions()).extracting(ZonePackageAction::packageName)
                .containsExactly("openssl");
        assertThat(r.judgement().blocked()).extracting(ZonePackageAction::packageName)
                .containsExactly("glibc");
        assertThat(r.action().residual()).extracting(ZonePackageAction::packageName)
                .containsExactly("glibc");
        // 수용 기록이 없으면 설명이 비어 있는 자리다.
        assertThat(r.action().unexplained()).isEqualTo(1);
    }

    // --- 노출면 ----------------------------------------------------------------

    @Test
    @DisplayName("벡터가 없는 건은 '닿지 않음' 이 아니라 '판단 불가' 다")
    void countsUnreadableVectorsSeparately() {
        Scan s = scan(asset("web"), LocalDate.of(2026, 9, 10));
        finding(s, "CVE-1", "openssl", "3.0.0", "High", "fixed", "3.0.7", 7.5, REACHABLE);
        finding(s, "CVE-2", "curl", "8.4.0", "High", "fixed", "8.6.0", 7.5, NEEDS_LOGIN);
        finding(s, "CVE-3", "zlib", "1.2.11", "High", "fixed", "1.2.13", 7.5, "");

        var exposure = report().aggregate().exposure();

        assertThat(exposure.reachable()).isEqualTo(1);
        // 읽지 못한 것을 '아니오' 로 밀어 넣으면 아무도 확인하지 않은 판정이 실린다.
        assertThat(exposure.unreadable()).isEqualTo(1);
    }

    // --- 증감 ------------------------------------------------------------------

    @Test
    @DisplayName("기간 시작 직전 검사와 대조해 신규·해소·유지를 낸다")
    void comparesAgainstTheStateBeforeThePeriod() {
        Asset a = asset("web");
        Scan before = scan(a, LocalDate.of(2026, 8, 28));
        finding(before, "CVE-1", "openssl", "3.0.0", "High", "fixed", "3.0.7", 7.5, REACHABLE);
        finding(before, "CVE-2", "curl", "8.4.0", "High", "fixed", "8.6.0", 7.5, REACHABLE);
        Scan now = scan(a, LocalDate.of(2026, 9, 25));
        finding(now, "CVE-1", "openssl", "3.0.0", "High", "fixed", "3.0.7", 7.5, REACHABLE);
        finding(now, "CVE-3", "nginx", "1.20", "High", "fixed", "1.22", 7.5, REACHABLE);

        var m = report().judgement().movement();

        assertThat(m.comparable()).isTrue();
        assertThat(m.added()).isEqualTo(1);      // nginx/CVE-3
        assertThat(m.resolved()).isEqualTo(1);   // curl/CVE-2
        assertThat(m.kept()).isEqualTo(1);       // openssl/CVE-1
        assertThat(m.net()).isZero();
    }

    @Test
    @DisplayName("기간 중 처음 검사한 자산은 대조에서 빼고 몇 대인지 밝힌다")
    void excludesAssetsWithoutABaseline() {
        Asset old = asset("web");
        Scan before = scan(old, LocalDate.of(2026, 8, 28));
        finding(before, "CVE-1", "openssl", "3.0.0", "High", "fixed", "3.0.7", 7.5, REACHABLE);
        Scan now = scan(old, LocalDate.of(2026, 9, 25));
        finding(now, "CVE-1", "openssl", "3.0.0", "High", "fixed", "3.0.7", 7.5, REACHABLE);

        Asset fresh = asset("api");
        Scan first = scan(fresh, LocalDate.of(2026, 9, 20));
        for (int i = 0; i < 50; i++) {
            finding(first, "CVE-N" + i, "pkg" + i, "1.0", "High", "fixed", "2.0", 7.5, REACHABLE);
        }

        var m = report().judgement().movement();

        // 50건을 전부 '신규' 로 세면 "9월에 50건 늘었다" 가 된다. 새로 본 것이지
        // 새로 생긴 것이 아니다.
        assertThat(m.assetsCompared()).isEqualTo(1);
        assertThat(m.assetsWithoutBase()).isEqualTo(1);
        assertThat(m.added()).isZero();
        assertThat(m.kept()).isEqualTo(1);
    }

    @Test
    @DisplayName("A 에서 고치고 B 에서 생긴 것이 상쇄되지 않는다")
    void keepsAssetsApartWhenComparing() {
        Asset a = asset("web");
        Asset b = asset("api");
        Scan aBefore = scan(a, LocalDate.of(2026, 8, 28));
        finding(aBefore, "CVE-1", "openssl", "3.0.0", "High", "fixed", "3.0.7", 7.5, REACHABLE);
        Scan bBefore = scan(b, LocalDate.of(2026, 8, 28));
        finding(bBefore, "CVE-2", "curl", "8.4.0", "High", "fixed", "8.6.0", 7.5, REACHABLE);

        Scan aNow = scan(a, LocalDate.of(2026, 9, 25));   // openssl 해소
        finding(aNow, "CVE-2", "curl", "8.4.0", "High", "fixed", "8.6.0", 7.5, REACHABLE);
        Scan bNow = scan(b, LocalDate.of(2026, 9, 25));   // curl 그대로 + openssl 신규
        finding(bNow, "CVE-1", "openssl", "3.0.0", "High", "fixed", "3.0.7", 7.5, REACHABLE);
        finding(bNow, "CVE-2", "curl", "8.4.0", "High", "fixed", "8.6.0", 7.5, REACHABLE);

        var m = report().judgement().movement();

        // 자산을 축에서 빼면 openssl 도 curl 도 "전에도 있었고 지금도 있다" 가
        // 되어 아무 일도 없던 것이 된다. 실제로는 A 에서 openssl 이 사라지고
        // A 에 curl 이, B 에 openssl 이 새로 생겼다.
        assertThat(m.added()).isEqualTo(2);     // a|curl, b|openssl
        assertThat(m.resolved()).isEqualTo(1);  // a|openssl
        assertThat(m.kept()).isEqualTo(1);      // b|curl
    }

    // --- 구역 ------------------------------------------------------------------

    @Test
    @DisplayName("다른 구역의 자산은 들어오지 않는다")
    void doesNotLeakOtherZones() {
        Scan mine = scan(asset("web"), LocalDate.of(2026, 9, 10));
        finding(mine, "CVE-1", "openssl", "3.0.0", "High", "fixed", "3.0.7", 7.5, REACHABLE);

        Zone other = zoneService.create("남의구역-" + System.nanoTime(), "", "");
        Asset theirs = new Asset();
        theirs.setName("their-" + System.nanoTime());
        theirs.setZone(other);
        assets.saveAndFlush(theirs);
        Scan theirScan = new Scan(theirs, "tester");
        theirScan.setStatus(ScanStatus.DONE);
        theirScan.setCreatedAt(LocalDate.of(2026, 9, 10).atTime(3, 0).atZone(WALL).toInstant());
        scans.saveAndFlush(theirScan);
        Finding f = new Finding(theirScan, "k", "CVE-9", "nginx");
        f.setPackageVersion("1.20");
        f.setPackageType("rpm");
        f.setSeverity("Critical");
        f.setFixState("fixed");
        f.setFixedVersion("1.22");
        findings.saveAndFlush(f);

        ZoneReport r = report();

        assertThat(r.scope().assetsInScope()).isEqualTo(1);
        assertThat(r.judgement().actions()).extracting(ZonePackageAction::packageName)
                .containsExactly("openssl");
    }

    // --- 빈 경우 ---------------------------------------------------------------

    @Test
    @DisplayName("기간 안에 검사가 하나도 없어도 터지지 않는다")
    void survivesAnEmptyPeriod() {
        asset("web");

        ZoneReport r = report();

        // 스캔 id 목록이 비어 있는 채로 IN 질의를 던지면 그 자리에서 깨진다.
        assertThat(r.scope().nothingScanned()).isTrue();
        assertThat(r.scope().assetsInScope()).isEqualTo(1);
        assertThat(r.scope().notScanned()).hasSize(1);
        assertThat(r.aggregate().total()).isZero();
        assertThat(r.judgement().actions()).isEmpty();
        assertThat(r.judgement().movement().comparable()).isFalse();
        assertThat(r.action().total()).isZero();
    }

    @Test
    @DisplayName("자산이 없는 구역도 보고서가 나온다")
    void survivesAnEmptyZone() {
        ZoneReport r = report();

        assertThat(r.scope().assetsInScope()).isZero();
        assertThat(r.scope().coveragePercent()).isZero();
        assertThat(r.scope().fullyCovered()).isFalse();
    }

    // --- 도구 변화 -------------------------------------------------------------

    @Test
    @DisplayName("기간 중 grype 판이 바뀌면 그 사실을 남긴다")
    void flagsWhenTheToolChangedDuringThePeriod() {
        Scan older = scan(asset("web"), LocalDate.of(2026, 9, 5), LocalTime.of(3, 0), "0.87.0");
        finding(older, "CVE-1", "openssl", "3.0.0", "High", "fixed", "3.0.7", 7.5, REACHABLE);
        Scan newer = scan(asset("api"), LocalDate.of(2026, 9, 20), LocalTime.of(3, 0), "0.92.1");
        finding(newer, "CVE-2", "curl", "8.4.0", "High", "fixed", "8.6.0", 7.5, REACHABLE);

        ZoneReport r = report();

        // 새 판이 규칙을 더 가지면 같은 서버에서도 탐지가 는다. 그것을 서버가
        // 나빠진 것으로 읽으면 안 된다.
        assertThat(r.scope().toolChanged()).isTrue();
        assertThat(r.scope().grypeVersions()).containsExactly("0.87.0", "0.92.1");
    }

    @Test
    @DisplayName("같은 판으로만 돌았으면 도구 변화 문구를 싣지 않는다")
    void staysQuietWhenTheToolDidNotChange() {
        Scan s = scan(asset("web"), LocalDate.of(2026, 9, 5));
        finding(s, "CVE-1", "openssl", "3.0.0", "High", "fixed", "3.0.7", 7.5, REACHABLE);

        assertThat(report().scope().toolChanged()).isFalse();
    }
}
