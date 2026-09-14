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

        List<Component> rows = components.findByAsset(asset.getId(), null);
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

        Component only = components.findByAsset(asset.getId(), null).get(0);
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

        Component only = components.findByAsset(asset.getId(), null).get(0);
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
        assertThat(components.findByAsset(asset.getId(), null)).hasSize(1);
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
        assertThat(components.findByAsset(asset.getId(), null))
                .extracting(Component::getVersion)
                .containsExactly("2.17.1", "3.0.7-25");
        assertThat(components.findByAsset(asset.getId(), null))
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

        PackageService.PackageRow row = packages.list(null, null, "log4j-core", false, false)
                .rows().stream()
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
        // `버전이 갈린 것만` 거르개에 걸린다.
        assertThat(packages.list(null, null, "log4j-core", false, true).rows())
                .extracting(PackageService.PackageRow::name)
                .contains("log4j-core");
    }

    @Test
    @DisplayName("버전이 하나뿐이면 갈린 것이 아니다")
    @Transactional
    void oneVersionIsNotMixed() throws IOException {
        Asset asset = asset("single");
        Scan scan = doneScan(asset);
        ingest(asset, scan, """
                { "artifacts": [ { "name": "glibc", "version": "2.34-83",
                                   "purl": "pkg:rpm/rocky/glibc@2.34-83" } ] }
                """);

        PackageService.PackageRow row = packages.list(null, null, "glibc", false, false)
                .rows().stream().filter(r -> r.name().equals("glibc"))
                .findFirst().orElseThrow();

        assertThat(row.versions()).hasSize(1);
        assertThat(row.mixed()).isFalse();
        assertThat(row.findingCount()).isZero();
        // 걸린 것이 없으면 `취약점 있는 것만` 에 걸리지 않는다.
        assertThat(packages.list(null, null, "glibc", true, false).rows())
                .extracting(PackageService.PackageRow::name)
                .doesNotContain("glibc");
    }

    // --- 머리의 수 -------------------------------------------------------------

    /**
     * 머리에 적힌 수가 <b>표에 실린 줄 수와 맞는가.</b>
     *
     * <p>거르개 전 이름 수를 그대로 찍고 있었다. 그래서 `버전이 갈린 것만` 을
     * 켜서 한 줄만 남은 화면 머리에 {@code 6개} 가 적혔다 — 화면은 멀쩡히 뜨고
     * 시험도 전부 통과했다. 0건인데 {@code 100%} 를 찍던 것과 같은 종류다.
     */
    @Test
    @DisplayName("머리의 수가 표에 실린 줄 수와 맞는다")
    @Transactional
    void headCountMatchesTheRowsOnScreen() throws Exception {
        // 버전이 갈린 패키지 하나 — 2.14.1 에 심각이 걸려 있고 2.17.1 은 깨끗하다.
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

        // 거르개 없이 — 이름 둘이 다 실린다. 그러면 수 하나만 적는다.
        assertThat(packages.list(null, null, "head-", false, false).rows()).hasSize(2);
        assertThat(subtitle("/packages?q=head-")).isEqualTo("2개");

        // 거르개를 켜면 한 줄만 남는다. 그때 `2개` 라고 적으면 거짓이다.
        assertThat(packages.list(null, null, "head-", false, true).rows()).hasSize(1);
        assertThat(subtitle("/packages?q=head-&mixed=true"))
                .as("머리에 적힌 수가 표에 실린 줄 수와 다르면 어느 쪽이 맞는지 물어볼 자리가 없다")
                .isEqualTo("2개 중 1개");
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
                .containsSubsequence("﻿\"패키지\",\"유형\",\"버전\",\"자산 수\",\"취약점\",\"최고 등급\"",
                                     "\"csv-glibc\",\"rpm\",\"2.34-83\",\"1\",\"0\",\"\"",
                                     "\"csv-log4j\",\"maven\",\"2.14.1\",\"1\",\"1\",\"심각\"",
                                     "\"csv-log4j\",\"maven\",\"2.17.1\",\"1\",\"0\",\"\"");

        // 걸린 것이 없는 버전에 등급을 적으면 아무도 내리지 않은 판정이 된다.
        assertThat(csv)
                .as("걸린 것이 없는 버전에 등급이 적혔다")
                .doesNotContain("\"2.17.1\",\"1\",\"0\",\"없음\"");

        // `버전이 갈린 것만` — 화면과 같이 걸린다. 두 버전이 함께 남아야
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
        Matcher m = Pattern.compile("class=\"page-subtitle\"[^>]*>([^<]*)<").matcher(html);
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
