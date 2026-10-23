package kr.sbomsight;

import kr.sbomsight.domain.Asset;
import kr.sbomsight.domain.Scan;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.ScanRepository;
import kr.sbomsight.service.GrypeRunner;
import kr.sbomsight.service.ZoneService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * <b>SBOM 이 언제 · 무엇으로 · 무엇을 떠서 만들어졌는가</b>를 검사에 남기고 보고서가 말하는가.
 *
 * <p>앞서 화면과 보고서의 시각은 전부 <b>검사가 돈 시각</b>이었다. 40일 전에 뜬 SBOM 을
 * 오늘 다시 검사하면 보고서의 `점검 일시` 가 오늘이 되어, 서버를 오늘 점검한 것처럼
 * 읽혔다(재현 시험 P10). SBOM 은 그 자체로 생성 시각 · 생성 도구 · 대상을 적어 온다 —
 * syft 1.52.0 으로 직접 떠서 확인한 자리를 그대로 읽는다.
 *
 * <pre>
 *   CycloneDX   metadata.timestamp · metadata.tools.components[] · metadata.component.name
 *   SPDX        creationInfo.created · creationInfo.creators "Tool: syft-1.52.0" · name
 *   syft JSON   (시각 없음) · descriptor · source.name
 * </pre>
 *
 * <p>SBOM 들은 진짜 syft 출력의 짜임을 그대로 따른다. 다른 것은 시험이 고르는 시각 ·
 * 대상과, {@link FakeGrype} 가 결과를 고르는 {@code marker} 하나다.
 */
@SpringBootTest
@AutoConfigureMockMvc
class SbomMetadataTest {

    @Autowired MockMvc mvc;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired ZoneService zoneService;

    @MockBean GrypeRunner grype;

    @BeforeEach
    void fakeGrype() {
        FakeGrype.on(grype);
    }

    /** 화면이 시각을 찍는 꼴 — 검사 이력 · 보고서와 같다. */
    static final DateTimeFormatter WHEN =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(ZoneId.systemDefault());

    // --- 진짜 syft 1.52.0 출력의 짜임 ---------------------------------------------

    static String cyclonedx(Instant timestamp, String target) {
        return """
                {
                  "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "serialNumber": "urn:uuid:5a1f0e7c-3b1e-4d38-9a51-6d1a3c2f0b11",
                  "version": 1,
                  "metadata": {
                    "timestamp": "%s",
                    "tools": {
                      "components": [
                        {"type": "application", "author": "anchore", "name": "syft", "version": "1.52.0"}
                      ]
                    },
                    "component": {"bom-ref": "4ce576eff7727d8a", "type": "file", "name": "%s"}
                  },
                  "components": [
                    {"bom-ref": "pkg:deb/debian/openssl@1.1.1k", "type": "library", "name": "openssl",
                     "version": "1.1.1k", "purl": "pkg:deb/debian/openssl@1.1.1k"},
                    {"bom-ref": "pkg:npm/lodash@4.17.0", "type": "library", "name": "lodash",
                     "version": "4.17.0", "purl": "pkg:npm/lodash@4.17.0"}
                  ],
                  "marker": "sbom-v1"
                }
                """.formatted(timestamp, target);
    }

    static String spdx(Instant created, String target) {
        return """
                {
                  "spdxVersion": "SPDX-2.3",
                  "dataLicense": "CC0-1.0",
                  "SPDXID": "SPDXRef-DOCUMENT",
                  "name": "%s",
                  "documentNamespace": "https://anchore.com/syft/dir/web-01-6f1c2b0e",
                  "creationInfo": {
                    "licenseListVersion": "3.28",
                    "creators": ["Organization: Anchore, Inc", "Tool: syft-1.52.0"],
                    "created": "%s"
                  },
                  "packages": [
                    {"name": "openssl", "SPDXID": "SPDXRef-Package-deb-openssl-1", "versionInfo": "1.1.1k",
                     "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                       "referenceLocator": "pkg:deb/debian/openssl@1.1.1k"}]},
                    {"name": "lodash", "SPDXID": "SPDXRef-Package-npm-lodash-2", "versionInfo": "4.17.0",
                     "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                       "referenceLocator": "pkg:npm/lodash@4.17.0"}]}
                  ],
                  "marker": "sbom-v1"
                }
                """.formatted(target, created);
    }

    /** syft JSON 에는 생성 시각 칸이 없다 — source · descriptor 가 맨 뒤에 온다. */
    static String syftJson(String target) {
        return """
                {
                  "artifacts": [
                    {"id": "a1", "name": "openssl", "version": "1.1.1k", "type": "deb",
                     "purl": "pkg:deb/debian/openssl@1.1.1k"},
                    {"id": "a2", "name": "lodash", "version": "4.17.0", "type": "npm",
                     "purl": "pkg:npm/lodash@4.17.0"}
                  ],
                  "artifactRelationships": [],
                  "files": [],
                  "source": {"id": "25586ed496ecc861", "name": "%s", "version": "", "type": "directory",
                             "metadata": {"path": "%s"}},
                  "distro": {"prettyName": "Debian GNU/Linux 11", "name": "debian", "id": "debian", "versionID": "11"},
                  "descriptor": {"name": "syft", "version": "1.52.0"},
                  "schema": {"version": "16.0.38", "url": "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.0.38.json"},
                  "marker": "sbom-v1"
                }
                """.formatted(target, target);
    }

    // --- 시험 ---------------------------------------------------------------------

    @Test
    @DisplayName("CycloneDX — 생성 시각 · 도구 · 대상 · 해시를 보고서 문서 정보에 찍는다")
    void cyclonedxMetadataReachesTheReport() throws Exception {
        Asset asset = asset("cdx");
        Instant made = minutes(Instant.now().minus(2, ChronoUnit.DAYS));
        String sbom = cyclonedx(made, asset.getName());
        Scan scan = upload(asset, "web.cdx.json", sbom);

        String info = docinfo(page("/reports/scan/" + scan.getId()));
        assertThat(info).contains("SBOM 생성 시각").contains(WHEN.format(made));
        assertThat(info).as("SBOM 에 적힌 시각을 썼다 — 대신 넣은 것이 아니다").doesNotContain("대체");
        assertThat(info).contains("검사 시각").contains(WHEN.format(scan.getCreatedAt()));
        assertThat(info).contains("SBOM 해시").contains("sha256:" + sha256(sbom));
        assertThat(info).contains("SBOM 생성 도구").contains("syft 1.52.0");
        assertThat(info).contains("SBOM 대상").contains(asset.getName());
        assertThat(info).as("'점검 일시' 는 SBOM 생성 시각과 검사 시각으로 나뉘었다")
                        .doesNotContain("점검 일시");
    }

    @Test
    @DisplayName("SPDX — creationInfo.created 와 'Tool: syft-1.52.0' · 문서 이름을 읽는다")
    void spdxMetadataReachesTheReport() throws Exception {
        Asset asset = asset("spdx");
        Instant made = minutes(Instant.now().minus(3, ChronoUnit.DAYS));
        Scan scan = upload(asset, "web.spdx.json", spdx(made, asset.getName()));

        String info = docinfo(page("/reports/scan/" + scan.getId()));
        assertThat(info).contains(WHEN.format(made)).doesNotContain("대체");
        assertThat(info).contains("syft 1.52.0");
        assertThat(info).contains(asset.getName());
    }

    @Test
    @DisplayName("syft JSON — 생성 시각이 없으면 업로드 시각으로 대체하고 그렇다고 적는다")
    void syftJsonHasNoTimestamp() throws Exception {
        Asset asset = asset("syft");
        Scan scan = upload(asset, "web.syft.json", syftJson(asset.getName()));

        String info = docinfo(page("/reports/scan/" + scan.getId()));
        assertThat(info).contains("업로드 시각으로 대체 (SBOM에 생성 시각 없음)");
        assertThat(info).contains(WHEN.format(scan.getCreatedAt()));
        assertThat(info).contains("syft 1.52.0").contains(asset.getName());
    }

    @Test
    @DisplayName("SBOM 생성 시각이 업로드보다 늦으면(서버 시계가 틀림) 업로드 시각으로 대체하고 그렇다고 적는다")
    void aTimestampFromTheFutureIsNotTrusted() throws Exception {
        Asset asset = asset("clock");
        Instant ahead = minutes(Instant.now().plus(1, ChronoUnit.DAYS));
        Scan scan = upload(asset, "web.cdx.json", cyclonedx(ahead, asset.getName()));

        String info = docinfo(page("/reports/scan/" + scan.getId()));
        assertThat(info).contains("업로드 시각으로 대체 (SBOM 생성 시각이 업로드보다 늦음)");
        assertThat(info).doesNotContain(WHEN.format(ahead));
    }

    @Test
    @DisplayName("다시 검사는 원본 SBOM 의 생성 시각 · 해시를 물려받는다 — 검사 시각만 새것")
    void aRescanInheritsTheSbomFacts() throws Exception {
        Asset asset = asset("inherit");
        Instant made = minutes(Instant.now().minus(40, ChronoUnit.DAYS));
        String sbom = cyclonedx(made, asset.getName());
        Scan original = upload(asset, "web.cdx.json", sbom);

        mvc.perform(post("/scans/" + original.getId() + "/rescan")
                            .with(user("tester").roles("ADMIN")).with(csrf()))
           .andExpect(status().is3xxRedirection());
        Scan copy = FakeGrype.awaitFinished(scans,
                scans.findByAssetIdOrderByCreatedAtDesc(asset.getId()).get(0).getId());
        assertThat(copy.getId()).isNotEqualTo(original.getId());

        String info = docinfo(page("/reports/scan/" + copy.getId()));
        assertThat(info).as("SBOM 은 40일 전 것 그대로다").contains(WHEN.format(made));
        assertThat(info).contains("sha256:" + sha256(sbom));
        assertThat(info).contains("syft 1.52.0").contains(asset.getName());
        assertThat(info).doesNotContain("대체");
    }

    @Test
    @DisplayName("검사 이력은 검사 시각과 SBOM 생성 시각을 따로 적는다")
    void historyShowsBothTimes() throws Exception {
        Asset asset = asset("history");
        Instant made = minutes(Instant.now().minus(5, ChronoUnit.DAYS));
        upload(asset, "web.cdx.json", cyclonedx(made, asset.getName()));

        String history = page("/assets/" + asset.getId() + "?tab=history");
        assertThat(history).contains("<th class=\"tight\">검사 시각</th>")
                           .contains("SBOM 생성 시각")
                           .contains(WHEN.format(made));
    }

    // --- 씨앗 ---------------------------------------------------------------------

    private Asset asset(String prefix) {
        Asset asset = new Asset();
        asset.setName(prefix + "-" + System.nanoTime());
        asset.setZone(zoneService.unassigned());
        return assets.saveAndFlush(asset);
    }

    private Scan upload(Asset asset, String filename, String sbom) throws Exception {
        mvc.perform(multipart("/assets/" + asset.getId() + "/sbom")
                            .file(new MockMultipartFile("file", filename, "application/json",
                                                        sbom.getBytes(StandardCharsets.UTF_8)))
                            .with(user("tester").roles("ADMIN")).with(csrf()))
           .andExpect(status().is3xxRedirection());
        Scan scan = FakeGrype.awaitFinished(scans,
                scans.findByAssetIdOrderByCreatedAtDesc(asset.getId()).get(0).getId());
        assertThat(scan.getStatus().name()).as(scan.getErrorMessage()).isEqualTo("DONE");
        return scan;
    }

    private String page(String url) throws Exception {
        return mvc.perform(get(url).with(user("tester").roles("ADMIN")))
                  .andExpect(status().isOk())
                  .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    /** 보고서 머리의 문서 정보 표만. */
    private static String docinfo(String report) {
        Matcher m = Pattern.compile("(?s)<table class=\"table docinfo\">(.*?)</table>").matcher(report);
        assertThat(m.find()).as("보고서에 문서 정보 표가 없다").isTrue();
        return m.group(1);
    }

    private static Instant minutes(Instant at) {
        return at.truncatedTo(ChronoUnit.MINUTES);
    }

    private static String sha256(String text) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                                                     .digest(text.getBytes(StandardCharsets.UTF_8)));
    }
}
