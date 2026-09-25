package kr.sbomsight;

import kr.sbomsight.domain.*;
import kr.sbomsight.repo.*;
import kr.sbomsight.service.ComponentInventoryService;
import kr.sbomsight.service.PackageService;
import kr.sbomsight.service.SbomStorage;
import kr.sbomsight.service.ZoneService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 패키지 인벤토리 — 무엇이 어디에 몇 버전으로 깔려 있나.
 *
 * <p>여기서 고정하는 것 넷.
 *
 * <ol>
 *   <li><b>SBOM 형식 셋을 다 읽는다.</b> syft 가 무엇으로 내보냈는지에 따라
 *       syft-json · CycloneDX · SPDX 가 다 들어온다. 같은 것을 다른 이름으로
 *       부르므로 하나만 맞춰 두면 나머지 둘에서 조용히 빈 칸이 된다.</li>
 *   <li><b>다시 검사해도 행이 두 배가 되지 않는다.</b> 자산마다 최신 검사
 *       것만 남긴다.</li>
 *   <li><b>자산·스캔을 지우면 함께 사라진다.</b> 남으면 없는 자산의 패키지
 *       목록이 화면에 뜬다.</li>
 *   <li><b>취약한 버전과 안전한 버전이 섞인 것을 가려낸다.</b> 이 화면을 두는
 *       이유에 가장 가까운 신호다 — "이미 올린 자산이 있는데 안 올린 자산이
 *       남았다".</li>
 * </ol>
 */
@SpringBootTest
@AutoConfigureMockMvc
class ComponentInventoryTest {

    @Autowired MockMvc mvc;
    @Autowired SbomStorage storage;
    @Autowired ComponentInventoryService inventory;
    @Autowired ComponentRepository components;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired ZoneService zoneService;
    @Autowired PackageService packages;
    @Autowired kr.sbomsight.service.ScanService scanService;

    // --- 거들 -----------------------------------------------------------------

    private Asset asset(String name) {
        Asset a = new Asset();
        a.setName(name + "-" + System.nanoTime());
        a.setZone(zoneService.unassigned());
        return assets.saveAndFlush(a);
    }

    private Scan doneScan(Asset asset) {
        Scan scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        return scans.saveAndFlush(scan);
    }

    private Path write(String json) throws IOException {
        Path file = Files.createTempFile("sbom-", ".json");
        Files.writeString(file, json);
        return file;
    }

    /** SBOM 을 읽어 그 자산의 인벤토리로 만든다 — ScanService.run 이 하는 것과 같은 순서. */
    private SbomStorage.SbomInfo ingest(Asset asset, Scan scan, String json) throws IOException {
        Path file = write(json);
        try (ComponentInventoryService.Sink sink = inventory.open(asset.getId(), scan.getId())) {
            SbomStorage.SbomInfo info = storage.inspect(file, sink);
            inventory.makeCurrent(asset.getId(), scan.getId());
            return info;
        } finally {
            Files.deleteIfExists(file);
        }
    }

    // --- 형식 셋 ---------------------------------------------------------------

    /**
     * 트랜잭션 없이 도는 시험 전용 픽스처.
     *
     * <p><b>이름이 달라야 한다.</b> {@code SYFT_JSON} 은 {@code log4j-core} 를
     * 담고 있고, 트랜잭션 없는 시험은 실제로 커밋한다 — 그래서 "log4j-core 가
     * 몇 대에 깔렸나" 를 세는 다른 시험이 흔들렸다(2대인데 3대로 보였다).
     */
    private static final String FAILED_FIXTURE = """
            { "artifacts": [
                { "name": "notx-openssl", "version": "3.0.7-24", "type": "rpm",
                  "purl": "pkg:rpm/rocky/notx-openssl@3.0.7-24" },
                { "name": "notx-log4j", "version": "2.14.1",
                  "purl": "pkg:maven/org.apache.logging.log4j/notx-log4j@2.14.1" } ] }
            """;

    private static final String SYFT_JSON = """
            { "artifacts": [
                { "name": "openssl-libs", "version": "3.0.7-24", "type": "rpm",
                  "purl": "pkg:rpm/rocky/openssl-libs@3.0.7-24?arch=x86_64",
                  "locations": [ { "path": "/usr/lib64/libssl.so.3" } ] },
                { "name": "log4j-core", "version": "2.14.1", "type": "java-archive",
                  "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                  "locations": [ { "path": "/opt/app/lib/log4j-core-2.14.1.jar" } ] } ],
              "descriptor": { "name": "syft" } }
            """;

    @Test
    @DisplayName("syft-json 에서 이름·버전·유형·purl·경로를 읽는다")
    @Transactional
    void readsSyftJson() throws IOException {
        Asset asset = asset("syft");
        Scan scan = doneScan(asset);

        SbomStorage.SbomInfo info = ingest(asset, scan, SYFT_JSON);

        assertThat(info.format()).isEqualTo("syft-json");
        assertThat(info.componentCount()).isEqualTo(2);

        List<Component> rows = ofAsset(asset.getId());
        assertThat(rows).extracting(Component::getName)
                .containsExactly("log4j-core", "openssl-libs");

        Component openssl = rows.stream()
                .filter(c -> c.getName().equals("openssl-libs")).findFirst().orElseThrow();
        assertThat(openssl.getVersion()).isEqualTo("3.0.7-24");
        assertThat(openssl.getType()).isEqualTo("rpm");
        assertThat(openssl.getLocation()).isEqualTo("/usr/lib64/libssl.so.3");
    }

    /**
     * CycloneDX 의 {@code type} 은 {@code library}/{@code application} 뿐이라
     * rpm 과 deb 를 가르지 못한다. <b>유형은 purl 에서 딴다.</b>
     */
    private static final String CYCLONEDX_JSON = """
            { "bomFormat": "CycloneDX", "specVersion": "1.5",
              "components": [
                { "type": "library", "name": "openssl-libs", "version": "3.0.7-24",
                  "purl": "pkg:rpm/rocky/openssl-libs@3.0.7-24?arch=x86_64",
                  "properties": [
                    { "name": "syft:package:foundBy", "value": "rpm-db-cataloger" },
                    { "name": "syft:location:0:path", "value": "/usr/lib64/libssl.so.3" } ] } ] }
            """;

    @Test
    @DisplayName("CycloneDX 는 유형을 purl 에서 딴다 — type 은 library 뿐이다")
    @Transactional
    void readsCycloneDx() throws IOException {
        Asset asset = asset("cdx");
        Scan scan = doneScan(asset);

        assertThat(ingest(asset, scan, CYCLONEDX_JSON).format()).isEqualTo("cyclonedx-json");

        Component only = ofAsset(asset.getId()).get(0);
        assertThat(only.getName()).isEqualTo("openssl-libs");
        // `library` 를 유형으로 찍으면 유형 거르개가 전부 library 가 된다.
        assertThat(only.getType()).isEqualTo("rpm");
        assertThat(only.getLocation()).isEqualTo("/usr/lib64/libssl.so.3");
    }

    /** SPDX 는 버전을 {@code versionInfo}, purl 을 {@code externalRefs} 안에 둔다. */
    private static final String SPDX_JSON = """
            { "spdxVersion": "SPDX-2.3", "name": "web-01",
              "packages": [
                { "SPDXID": "SPDXRef-Package-rpm-openssl-libs",
                  "name": "openssl-libs", "versionInfo": "3.0.7-24",
                  "externalRefs": [
                    { "referenceCategory": "SECURITY", "referenceType": "cpe23Type",
                      "referenceLocator": "cpe:2.3:a:openssl:openssl:3.0.7-24:*:*:*:*:*:*:*" },
                    { "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                      "referenceLocator": "pkg:rpm/rocky/openssl-libs@3.0.7-24?arch=x86_64" } ] } ] }
            """;

    @Test
    @DisplayName("SPDX 는 versionInfo 와 externalRefs 에서 읽는다")
    @Transactional
    void readsSpdx() throws IOException {
        Asset asset = asset("spdx");
        Scan scan = doneScan(asset);

        assertThat(ingest(asset, scan, SPDX_JSON).format()).isEqualTo("spdx-json");

        Component only = ofAsset(asset.getId()).get(0);
        assertThat(only.getName()).isEqualTo("openssl-libs");
        assertThat(only.getVersion()).isEqualTo("3.0.7-24");
        assertThat(only.getType()).isEqualTo("rpm");
        // SPDX 에는 설치 경로 자리가 없다. 지어내지 않는다.
        assertThat(only.getLocation()).isEmpty();
    }

    @Test
    @DisplayName("이름이 없는 원소는 담지 않지만 세기는 센다")
    @Transactional
    void skipsNamelessButStillCounts() throws IOException {
        Asset asset = asset("nameless");
        Scan scan = doneScan(asset);

        SbomStorage.SbomInfo info = ingest(asset, scan, """
                { "artifacts": [
                    { "name": "curl", "version": "8.4.0", "purl": "pkg:rpm/rocky/curl@8.4.0" },
                    { "version": "1.0.0", "purl": "pkg:generic/?" } ] }
                """);

        // 센 것은 둘이다 — 버리고 세지 않으면 회계가 어긋난다.
        assertThat(info.componentCount()).isEqualTo(2);
        // 담은 것은 하나다. 이름이 없으면 목록에서 가리킬 수 없다.
        assertThat(ofAsset(asset.getId())).hasSize(1);
    }

    /** 그 자산에 깔린 것 전부. 화면은 쪽으로 나눠 보지만 시험은 전부 본다. */
    private List<Component> ofAsset(Long assetId) {
        return components.findByAsset(assetId, null, Pageable.unpaged()).getContent();
    }

    /** 거른 뒤 전체 줄. 화면은 첫 쪽만 그린다. */
    private List<PackageService.PackageRow> rows(String type, String q,
                                                 boolean vulnerableOnly, boolean mixedOnly) {
        return packages.list(null, type, q, vulnerableOnly, mixedOnly, 0, null)
                       .rows().getContent();
    }

    // --- 다시 검사 -------------------------------------------------------------

    /**
     * <b>다시 검사해도 행이 두 배가 되지 않는다.</b>
     *
     * <p>자산마다 최신 검사 것만 둔다. 검사마다 쌓으면 컴포넌트 12만 개 ×
     * 100대 × 12개월이 1억 4천만 행이다.
     */
    @Test
    @DisplayName("다시 검사하면 행이 늘지 않고 새 검사 것으로 바뀐다")
    @Transactional
    void rescanReplacesInsteadOfPilingUp() throws IOException {
        Asset asset = asset("again");

        Scan first = doneScan(asset);
        ingest(asset, first, SYFT_JSON);
        assertThat(components.countByAssetId(asset.getId())).isEqualTo(2);

        // 같은 SBOM 을 다시 돌린다. 그리고 한 패키지가 올라갔다.
        Scan second = doneScan(asset);
        ingest(asset, second, """
                { "artifacts": [
                    { "name": "openssl-libs", "version": "3.0.7-25", "type": "rpm",
                      "purl": "pkg:rpm/rocky/openssl-libs@3.0.7-25" },
                    { "name": "log4j-core", "version": "2.17.1", "type": "java-archive",
                      "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1" } ] }
                """);

        assertThat(components.countByAssetId(asset.getId()))
                .as("다시 검사했더니 행이 쌓였다")
                .isEqualTo(2);
        // 남아 있는 것은 새 검사 것이다.
        assertThat(ofAsset(asset.getId()))
                .extracting(Component::getVersion)
                .containsExactly("2.17.1", "3.0.7-25");
        assertThat(ofAsset(asset.getId()))
                .allMatch(c -> c.getScan().getId().equals(second.getId()));
    }

    /** 읽다가 터지면 이전 인벤토리가 그대로 남아 있어야 한다. */
    @Test
    @DisplayName("새 검사를 담기 전까지 이전 인벤토리가 남아 있다")
    @Transactional
    void keepsThePreviousInventoryUntilTheNewOneLands() throws IOException {
        Asset asset = asset("keep");
        Scan first = doneScan(asset);
        ingest(asset, first, SYFT_JSON);

        // 새 스캔을 만들기만 하고 담지는 않았다 — 읽다가 실패한 상태.
        doneScan(asset);

        assertThat(components.countByAssetId(asset.getId()))
                .as("담기 전에 지워 버리면 '이 자산에는 패키지가 없다' 가 된다")
                .isEqualTo(2);
    }

    /**
     * <b>도는 중인 검사의 패키지는 끝날 때까지 보이지 않는다.</b>
     *
     * <p>담기는 SBOM 을 읽을 때 하고, grype 은 그 뒤에 몇 분씩 돈다. 그동안
     * 새 검사 것이 보이면 패키지 화면은 새 SBOM 을, 취약점 화면은 이전 검사를
     * 말한다 — 두 화면이 서로 다른 검사를 본다. 끝난 뒤에 함께 바뀌어야 한다.
     */
    @Test
    @DisplayName("도는 중인 검사의 패키지는 검사가 끝나기 전까지 목록에 보이지 않는다")
    @Transactional
    void aRunningScanStaysOutOfTheInventory() throws IOException {
        Asset asset = asset("running");
        Scan done = doneScan(asset);
        ingest(asset, done, SYFT_JSON);

        // 담기만 하고 아직 도는 중이다.
        Scan running = new Scan(asset, "tester");
        running.setStatus(ScanStatus.RUNNING);
        scans.saveAndFlush(running);
        try (ComponentInventoryService.Sink sink = inventory.open(asset.getId(), running.getId())) {
            storage.inspect(write("""
                    { "artifacts": [ { "name": "openssl-libs", "version": "3.0.7-99", "type": "rpm",
                                       "purl": "pkg:rpm/rocky/openssl-libs@3.0.7-99" } ] }
                    """), sink);
        }

        assertThat(ofAsset(asset.getId()))
                .as("끝나지 않은 검사의 패키지가 목록에 섞였다")
                .allMatch(c -> c.getScan().getId().equals(done.getId()));
        assertThat(components.countCurrentByAssetId(asset.getId())).isEqualTo(2);
        assertThat(rows(null, "openssl-libs", false, false).stream()
                        .filter(r -> r.name().equals("openssl-libs"))
                        .flatMap(r -> r.versions().stream())
                        .map(PackageService.VersionSlice::version))
                .as("버전 분포에 끝나지 않은 검사의 버전이 섞였다")
                .doesNotContain("3.0.7-99");
    }

    // --- 지우면 함께 사라진다 --------------------------------------------------

    @Test
    @DisplayName("스캔을 지우면 그 스캔에서 온 인벤토리도 사라진다")
    @Transactional
    void deletingAScanTakesItsInventory() throws IOException {
        Asset asset = asset("delscan");
        Scan scan = doneScan(asset);
        ingest(asset, scan, SYFT_JSON);
        assertThat(components.countByAssetId(asset.getId())).isEqualTo(2);

        scans.delete(scan);
        scans.flush();

        assertThat(components.countByAssetId(asset.getId()))
                .as("없는 스캔의 패키지 목록이 남았다")
                .isZero();
    }

    @Test
    @DisplayName("자산을 지우면 그 자산의 인벤토리도 사라진다")
    @Transactional
    void deletingAnAssetTakesItsInventory() throws IOException {
        Asset asset = asset("delasset");
        Scan scan = doneScan(asset);
        ingest(asset, scan, SYFT_JSON);
        Long assetId = asset.getId();

        // 스캔이 자산을 참조하므로 스캔부터 지운다 — 화면의 삭제도 그 순서다.
        scans.delete(scan);
        assets.delete(asset);
        assets.flush();

        assertThat(components.countByAssetId(assetId)).isZero();
    }

    // --- 취약한 버전과 안전한 버전 ---------------------------------------------

    /**
     * <b>이 화면을 두는 이유에 가장 가까운 신호.</b>
     *
     * <p>같은 패키지에 취약한 버전과 안전한 버전이 섞여 있으면 "이미 올린
     * 자산이 있는데 안 올린 자산이 남았다" 는 뜻이다. 자산 하나씩 열어 보면
     * 그 판단이 서지 않는다.
     */
    @Test
    @DisplayName("한 패키지에 취약한 버전과 안전한 버전이 섞인 것을 가려낸다")
    @Transactional
    void tellsTheVulnerableVersionFromTheSafeOne() throws IOException {
        // 안 올린 자산 — 2.14.1 에 심각이 걸려 있다.
        Asset stale = asset("stale");
        Scan staleScan = doneScan(stale);
        ingest(stale, staleScan, """
                { "artifacts": [ { "name": "log4j-core", "version": "2.14.1",
                                   "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" } ] }
                """);
        Finding hit = new Finding(staleScan, "CVE-2021-44228|log4j-core",
                                  "CVE-2021-44228", "log4j-core");
        hit.setPackageVersion("2.14.1");
        hit.setSeverity("Critical");
        hit.setCvssScore(BigDecimal.valueOf(10.0));
        findings.saveAndFlush(hit);
        staleScan.setFindingCount(1);
        scans.saveAndFlush(staleScan);

        // 이미 올린 자산 — 2.17.1 에는 걸린 것이 없다.
        Asset fixed = asset("fixed");
        Scan fixedScan = doneScan(fixed);
        ingest(fixed, fixedScan, """
                { "artifacts": [ { "name": "log4j-core", "version": "2.17.1",
                                   "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1" } ] }
                """);

        PackageService.PackageRow row = rows(null, "log4j-core", false, false).stream()
                .filter(r -> r.name().equals("log4j-core"))
                .findFirst().orElseThrow(() -> new AssertionError("목록에 log4j-core 가 없습니다"));

        assertThat(row.assetCount()).isEqualTo(2);
        assertThat(row.versions()).hasSize(2);

        PackageService.VersionSlice vulnerable = slice(row, "2.14.1");
        PackageService.VersionSlice safe = slice(row, "2.17.1");

        assertThat(vulnerable.vulnerable()).isTrue();
        assertThat(vulnerable.worst()).isEqualTo(Severity.CRITICAL);
        // 올리면 뜨는 줄. 색만으로 가르지 않는다(§5-15).
        assertThat(vulnerable.title()).contains("심각 1").contains("1대");

        assertThat(safe.vulnerable())
                .as("걸린 것이 없는 버전을 취약하다고 표시하면 이미 올린 자산까지 다시 올리게 된다")
                .isFalse();
        assertThat(safe.worst()).isNull();
        assertThat(safe.title()).contains("걸린 것 없음");

        // 섞여 있다 — 이 줄에 표시를 따로 단다.
        assertThat(row.mixed()).isTrue();
        // `일부 자산만 업그레이드` 거르개에 걸린다.
        assertThat(rows(null, "log4j-core", false, true))
                .extracting(PackageService.PackageRow::name)
                .contains("log4j-core");
    }

    /**
     * <b>구역을 고르면 그 구역 자산의 탐지만 센다.</b> 운영 종료한 자산도 뺀다.
     *
     * <p>버전마다 붙는 취약점 수를 {@code (이름, 버전)} 으로 <b>모든 자산</b>의
     * 최신 검사에서 세고 있었다. 같은 버전이 두 구역에 깔려 있으면 DMZ 를 골라도
     * 내부업무 자산의 탐지까지 합쳐졌고(띄운 앱에서 libc6 — 패키지 화면 58건,
     * 취약점 화면 29건), 운영 종료한 자산의 탐지도 그대로 남았다. 취약점 화면과
     * 같은 범위여야 두 화면의 숫자가 맞는다.
     */
    @Test
    @DisplayName("구역을 고르면 그 구역 자산의 탐지만 센다 — 운영 종료 자산도 뺀다")
    @Transactional
    void countsOnlyTheChosenZoneAndLiveAssets() throws IOException {
        long nano = System.nanoTime();
        Zone dmz = zoneService.create("pz-dmz-" + nano, "#a71922", "");
        Zone inner = zoneService.create("pz-inner-" + nano, "#c3571a", "");

        Asset web = inZone("pz-web", dmz);
        Asset was = inZone("pz-was", inner);
        Asset retired = inZone("pz-retired", dmz);
        affected(web, 1);
        affected(was, 2);
        affected(retired, 4);
        retired.setArchivedAt(java.time.Instant.now());
        assets.saveAndFlush(retired);

        assertThat(findingsFor("pz-glibc", dmz.getId()))
                .as("DMZ 를 골랐는데 다른 구역이나 운영 종료 자산의 탐지가 섞였다")
                .isEqualTo(1);
        assertThat(findingsFor("pz-glibc", inner.getId())).isEqualTo(2);
        assertThat(findingsFor("pz-glibc", null))
                .as("운영 종료한 자산의 탐지가 전체 수에 남았다")
                .isEqualTo(3);
    }

    private Asset inZone(String name, Zone zone) {
        Asset a = new Asset();
        a.setName(name + "-" + System.nanoTime());
        a.setZone(zone);
        return assets.saveAndFlush(a);
    }

    /** 같은 {@code (이름, 버전)} 을 깔고 그 버전에 탐지 {@code count} 건을 단다. */
    private void affected(Asset asset, int count) throws IOException {
        Scan scan = doneScan(asset);
        ingest(asset, scan, """
                { "artifacts": [ { "name": "pz-glibc", "version": "2.28-10",
                                   "purl": "pkg:deb/debian/pz-glibc@2.28-10" } ] }
                """);
        for (int i = 0; i < count; i++) {
            Finding f = new Finding(scan, "CVE-2099-" + i + "|pz-glibc", "CVE-2099-" + i, "pz-glibc");
            f.setPackageVersion("2.28-10");
            f.setSeverity("High");
            findings.saveAndFlush(f);
        }
    }

    private long findingsFor(String name, Long zoneId) {
        return packages.list(zoneId, null, name, false, false, 0, null).rows().getContent().stream()
                       .filter(r -> r.name().equals(name))
                       .mapToLong(PackageService.PackageRow::findingCount)
                       .sum();
    }

    @Test
    @DisplayName("버전이 하나뿐이면 일부만 업그레이드한 것이 아니다")
    @Transactional
    void oneVersionIsNotMixed() throws IOException {
        Asset asset = asset("single");
        Scan scan = doneScan(asset);
        ingest(asset, scan, """
                { "artifacts": [ { "name": "glibc", "version": "2.34-83",
                                   "purl": "pkg:rpm/rocky/glibc@2.34-83" } ] }
                """);

        PackageService.PackageRow row = rows(null, "glibc", false, false).stream()
                .filter(r -> r.name().equals("glibc"))
                .findFirst().orElseThrow();

        assertThat(row.versions()).hasSize(1);
        assertThat(row.mixed()).isFalse();
        assertThat(row.findingCount()).isZero();
        // 걸린 것이 없으면 `취약점 있는 것만` 에 걸리지 않는다.
        assertThat(rows(null, "glibc", true, false))
                .extracting(PackageService.PackageRow::name)
                .doesNotContain("glibc");
    }

    // --- 트랜잭션 -------------------------------------------------------------

    /**
     * <b>바깥 트랜잭션이 없어도 인벤토리를 바꿀 수 있는가.</b>
     *
     * <p>이 시험에는 {@code @Transactional} 이 없다. <b>일부러 없다.</b> 실제
     * 검사는 {@code @Async} 로 돌고, {@code ScanService.runAsync} 가 같은 빈의
     * {@code run} 을 부르기 때문에 프록시를 지나지 않는다 — 즉 그 자리에
     * 트랜잭션이 없다. 그래서 {@code @Modifying} 질의가
     * {@code Executing an update/delete query} 로 터진다.
     *
     * <p>다른 시험들은 메서드에 {@code @Transactional} 이 붙어 있어서 시험이
     * 트랜잭션을 대신 열어 준다. 운영에 없는 것을 시험이 주고 있었으므로,
     * <b>시험 11개가 전부 통과한 채로 실제 업로드는 READING 단계에서
     * 실패했다.</b>
     */
    @Test
    @DisplayName("바깥 트랜잭션이 없어도 인벤토리를 바꾼다 (@Async 와 같은 조건)")
    void managesItsOwnTransaction() throws IOException {
        Asset asset = asset("no-tx");
        Scan first = doneScan(asset);
        Scan second = doneScan(asset);
        try {
            // 담기 — 이쪽은 순수 JDBC 라 트랜잭션이 없어도 들어간다.
            try (ComponentInventoryService.Sink sink =
                         inventory.open(asset.getId(), first.getId())) {
                storage.inspect(write(FAILED_FIXTURE), sink);
            }
            assertThat(components.countByAssetId(asset.getId())).isEqualTo(2);

            // 기준 바꾸기 — @Modifying 질의. 여기가 터지던 자리다.
            try (ComponentInventoryService.Sink sink =
                         inventory.open(asset.getId(), second.getId())) {
                storage.inspect(write(FAILED_FIXTURE), sink);
            }
            inventory.makeCurrent(asset.getId(), second.getId());
            assertThat(components.countByAssetId(asset.getId()))
                    .as("이전 검사 것이 남았다 — 다시 검사할 때마다 행이 두 배가 된다")
                    .isEqualTo(2);

            // 버리기 — 실패한 검사를 되돌리는 자리. 여기도 같은 질의다.
            inventory.discard(second.getId());
            assertThat(components.countByAssetId(asset.getId()))
                    .as("실패한 검사의 인벤토리가 화면에 남는다")
                    .isZero();
        } finally {
            // 트랜잭션이 없으니 롤백도 없다. 손으로 치운다.
            inventory.discard(first.getId());
            inventory.discard(second.getId());
            scans.deleteAll(List.of(first, second));
            assets.delete(asset);
        }
    }

    // --- 머리의 수 -------------------------------------------------------------

    /**
     * 머리에 적힌 수가 <b>표에 실린 줄 수와 맞는가.</b>
     *
     * <p>거르개 전 이름 수를 그대로 찍고 있었다. 그래서 `일부 자산만 업그레이드` 를
     * 켜서 한 줄만 남은 화면 머리에 {@code 6개} 가 적혔다 — 화면은 멀쩡히 뜨고
     * 시험도 전부 통과했다. 0건인데 {@code 100%} 를 찍던 것과 같은 종류다.
     */
    @Test
    @DisplayName("머리의 수가 표에 실린 줄 수와 맞는다")
    @Transactional
    void headCountMatchesTheRowsOnScreen() throws Exception {
        // 일부만 업그레이드한 패키지 하나 — 2.14.1 에 심각이 걸려 있고 2.17.1 은 깨끗하다.
        Asset stale = asset("head-stale");
        Scan staleScan = doneScan(stale);
        ingest(stale, staleScan, """
                { "artifacts": [
                    { "name": "head-log4j", "version": "2.14.1",
                      "purl": "pkg:maven/org.apache.logging.log4j/head-log4j@2.14.1" },
                    { "name": "head-glibc", "version": "2.34-83",
                      "purl": "pkg:rpm/rocky/head-glibc@2.34-83" } ] }
                """);
        Finding hit = new Finding(staleScan, "CVE-2021-44228|head-log4j",
                                  "CVE-2021-44228", "head-log4j");
        hit.setPackageVersion("2.14.1");
        hit.setSeverity("Critical");
        findings.saveAndFlush(hit);

        Asset fixed = asset("head-fixed");
        Scan fixedScan = doneScan(fixed);
        ingest(fixed, fixedScan, """
                { "artifacts": [ { "name": "head-log4j", "version": "2.17.1",
                                   "purl": "pkg:maven/org.apache.logging.log4j/head-log4j@2.17.1" } ] }
                """);

        // 거르개 없이 — 이름 둘이 다 실린다.
        assertThat(rows(null, "head-", false, false)).hasSize(2);
        assertThat(subtitle("/packages?q=head-")).isEqualTo("2개");

        // 거르개를 켜면 한 줄만 남는다. 그때 `2개` 라고 적으면 거짓이다.
        assertThat(rows(null, "head-", false, true)).hasSize(1);
        assertThat(subtitle("/packages?q=head-&mixed=true"))
                .as("머리에 적힌 수는 거른 뒤 전체 줄 수다 — 다르면 어느 쪽이 맞는지 물어볼 자리가 없다")
                .isEqualTo("1개");
    }

    // --- 실패한 검사 -----------------------------------------------------------

    /**
     * <b>담다가 실패하면 그 검사에서 온 행이 남지 않는가.</b>
     *
     * <p>담기는 쓰는 대로 커밋되고 {@code makeCurrent} 는 다 담은 뒤에 부른다.
     * 그래서 중간에 터지면 <b>새 검사 것과 이전 검사 것이 그 자산에 함께
     * 남는다</b> — 패키지 화면이 한 패키지를 두 버전으로 보여 주고, 그것이
     * "두 대에 다르게 깔렸다" 와 구분되지 않는다.
     *
     * <p>실제로 그랬다. 검사가 {@code READING} 에서 실패한 뒤 79행이 남아
     * 화면에 떠 있었고 손으로 지웠다. {@code runAsync} 의 실패 처리에
     * {@code discard} 가 없었다.
     */
    @Test
    @DisplayName("검사가 실패하면 담다 만 인벤토리를 버린다")
    void failedScanLeavesNoInventory() throws IOException, InterruptedException {
        Asset asset = asset("failed");
        Scan good = doneScan(asset);
        Scan broken = scans.saveAndFlush(new Scan(asset, "tester"));
        try {
            ingest(asset, good, FAILED_FIXTURE);

            // 읽다가 터질 검사 — SBOM 경로가 없다. 담기는 시작된 셈으로 두어
            // 그 검사에서 온 행을 미리 넣는다.
            try (ComponentInventoryService.Sink sink =
                         inventory.open(asset.getId(), broken.getId())) {
                storage.inspect(write(FAILED_FIXTURE), sink);
            }
            assertThat(components.countByAssetId(asset.getId()))
                    .as("담는 중이라 두 검사 것이 함께 있다")
                    .isEqualTo(4);

            // 실제 실패 경로. run 이 inflate 에서 터지고 catch 가 치운다.
            //
            // `runAsync` 는 이름 그대로 **다른 스레드**에서 돈다(@Async).
            // 그리고 그 catch 는 `markFailed` 를 먼저, `discard` 를 나중에
            // 부른다 — 상태만 보고 기다리면 **discard 전에 깨어난다.**
            // 처음에 그렇게 짰다가 전체 시험에서만 어긋났다. 재어야 하는 것은
            // 상태가 아니라 남은 행이다.
            scanService.runAsync(broken.getId());
            long remaining = 4;
            for (int i = 0; i < 100 && remaining != 2; i++) {
                Thread.sleep(50);
                remaining = components.countByAssetId(asset.getId());
            }

            assertThat(scans.findById(broken.getId()).orElseThrow().getStatus())
                    .isEqualTo(ScanStatus.FAILED);
            assertThat(remaining)
                    .as("실패한 검사의 패키지가 남아 한 패키지가 두 버전으로 보인다")
                    .isEqualTo(2);
            assertThat(ofAsset(asset.getId()))
                    .allMatch(c -> c.getScan().getId().equals(good.getId()));
        } finally {
            // 트랜잭션이 없으니 롤백도 없다. 실패해도 치운다 — 남기면 다른
            // 시험이 흔들린다.
            inventory.discard(good.getId());
            inventory.discard(broken.getId());
            scans.deleteAll(List.of(good, broken));
            assets.delete(asset);
        }
    }

    // --- CSV 내보내기 -----------------------------------------------------------

    /**
     * 내보낸 파일이 <b>화면과 같은 것을 말하는가.</b>
     *
     * <p>한 줄이 {@code (패키지, 버전)} 하나다 — 버전 분포를 한 칸에 몰아 넣으면
     * 엑셀에서 거르지도 정렬하지도 못한다. 거르개는 화면과 같이 걸리고,
     * <b>화면의 200개 상한은 따르지 않는다</b> — 잘린 파일은 그것이 잘렸다는
     * 사실을 들고 다니지 않는다.
     */
    @Test
    @DisplayName("내보낸 CSV 가 버전마다 한 줄이고, 거르개를 화면과 같이 따른다")
    @Transactional
    void exportsOneRowPerVersion() throws Exception {
        Asset stale = asset("csv-stale");
        Scan staleScan = doneScan(stale);
        ingest(stale, staleScan, """
                { "artifacts": [
                    { "name": "csv-log4j", "version": "2.14.1", "type": "java-archive",
                      "purl": "pkg:maven/org.apache.logging.log4j/csv-log4j@2.14.1" },
                    { "name": "csv-glibc", "version": "2.34-83",
                      "purl": "pkg:rpm/rocky/csv-glibc@2.34-83" } ] }
                """);
        Finding hit = new Finding(staleScan, "CVE-2021-44228|csv-log4j",
                                  "CVE-2021-44228", "csv-log4j");
        hit.setPackageVersion("2.14.1");
        hit.setSeverity("Critical");
        findings.saveAndFlush(hit);

        Asset fixed = asset("csv-fixed");
        Scan fixedScan = doneScan(fixed);
        ingest(fixed, fixedScan, """
                { "artifacts": [ { "name": "csv-log4j", "version": "2.17.1", "type": "java-archive",
                                   "purl": "pkg:maven/org.apache.logging.log4j/csv-log4j@2.17.1" } ] }
                """);

        String csv = mvc.perform(get("/packages/export.csv?q=csv-")
                                         .with(user("tester").roles("ADMIN")))
                        .andExpect(status().isOk())
                        .andReturn().getResponse().getContentAsString();

        // 엑셀이 UTF-8 로 읽는 유일한 방법.
        assertThat(csv).startsWith("﻿");
        assertThat(csv.lines().toList())
                .containsSubsequence("﻿\"패키지\",\"유형\",\"버전\",\"자산 수\",\"취약점\",\"최고 심각도\"",
                                     "\"csv-glibc\",\"rpm\",\"2.34-83\",\"1\",\"0\",\"\"",
                                     "\"csv-log4j\",\"maven\",\"2.14.1\",\"1\",\"1\",\"심각\"",
                                     "\"csv-log4j\",\"maven\",\"2.17.1\",\"1\",\"0\",\"\"");

        // 걸린 것이 없는 버전에 등급을 적으면 아무도 내리지 않은 판정이 된다.
        assertThat(csv)
                .as("걸린 것이 없는 버전에 등급이 적혔다")
                .doesNotContain("\"2.17.1\",\"1\",\"0\",\"없음\"");

        // `일부 자산만 업그레이드` — 화면과 같이 걸린다. 두 버전이 함께 남아야
        // 한다: 한 줄만 남기면 무엇이 갈렸는지 알 수 없다.
        String mixedOnly = mvc.perform(get("/packages/export.csv?q=csv-&mixed=true")
                                               .with(user("tester").roles("ADMIN")))
                              .andReturn().getResponse().getContentAsString();
        assertThat(mixedOnly).contains("\"csv-log4j\",\"maven\",\"2.14.1\"")
                             .contains("\"csv-log4j\",\"maven\",\"2.17.1\"")
                             .doesNotContain("csv-glibc");
    }

    /** 화면 머리의 부제를 그대로 꺼낸다. */
    private String subtitle(String url) throws Exception {
        String html = mvc.perform(get(url).with(user("tester").roles("ADMIN")))
                         .andExpect(status().isOk())
                         .andReturn().getResponse().getContentAsString();
        Matcher m = Pattern.compile("class=\"page-subtitle[^\"]*\"[^>]*>([^<]*)<").matcher(html);
        assertThat(m.find()).as("화면 머리에 부제가 없습니다: %s", url).isTrue();
        return m.group(1).trim();
    }

    private static PackageService.VersionSlice slice(PackageService.PackageRow row, String version) {
        return row.versions().stream()
                .filter(v -> v.version().equals(version))
                .findFirst()
                .orElseThrow(() -> new AssertionError("버전 " + version + " 이 없습니다: "
                                                      + row.versions()));
    }
}
