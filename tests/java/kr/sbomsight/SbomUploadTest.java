package kr.sbomsight;

import kr.sbomsight.domain.Asset;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.ScanRepository;
import kr.sbomsight.service.ZoneService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * <b>받는 SBOM 은 JSON 셋뿐이다</b> — CycloneDX JSON · SPDX JSON · syft JSON.
 *
 * <p>앞서 업로드는 {@code .xml}·{@code .spdx} 까지 받았는데 패키지 목록은 JSON
 * 에서만 읽었다. CycloneDX XML 을 올리면 grype 검사는 되지만 패키지 탭이
 * 비었고, 그 자산의 이전 패키지 목록까지 지워졌다(띄운 앱에서 142개 → 0개).
 * 읽지 못하는 것은 올리는 자리에서 돌려보낸다 — 검사 이력에 반쪽짜리 검사를
 * 남기지 않는다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class SbomUploadTest {

    @Autowired MockMvc mvc;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired ZoneService zoneService;

    private Asset asset;

    @BeforeEach
    void setUp() {
        asset = new Asset();
        asset.setName("upload-" + System.nanoTime());
        asset.setZone(zoneService.unassigned());
        assets.saveAndFlush(asset);
    }

    private MvcResult upload(String filename, String body) throws Exception {
        return mvc.perform(multipart("/assets/" + asset.getId() + "/sbom")
                                   .file(new MockMultipartFile("file", filename,
                                                               "application/octet-stream",
                                                               body.getBytes()))
                                   .with(user("tester").roles("ADMIN")).with(csrf()))
                  .andExpect(status().is3xxRedirection())
                  .andReturn();
    }

    @Test
    @DisplayName("CycloneDX XML 은 받지 않는다 — 검사도 만들지 않는다")
    void refusesCycloneDxXml() throws Exception {
        MvcResult result = upload("sbom.cdx.xml", """
                <?xml version="1.0" encoding="UTF-8"?>
                <bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">
                  <components><component type="library"><name>zlib</name></component></components>
                </bom>
                """);

        assertThat(result.getFlashMap().get("error")).asString()
                .as("왜 안 받는지와 무엇을 받는지를 말해야 한다")
                .contains("CycloneDX JSON").contains("SPDX JSON").contains("syft JSON");
        assertThat(scans.findByAssetIdOrderByCreatedAtDesc(asset.getId()))
                .as("읽지 못하는 SBOM 으로 검사가 만들어졌다")
                .isEmpty();
    }

    @Test
    @DisplayName("SPDX tag-value 는 받지 않는다")
    void refusesSpdxTagValue() throws Exception {
        upload("sbom.spdx", """
                SPDXVersion: SPDX-2.3
                DataLicense: CC0-1.0
                PackageName: zlib
                PackageVersion: 1.2.13
                """);

        assertThat(scans.findByAssetIdOrderByCreatedAtDesc(asset.getId())).isEmpty();
    }

    @Test
    @DisplayName("JSON 이라도 SBOM 이 아니면 받지 않는다")
    void refusesJsonThatIsNotAnSbom() throws Exception {
        upload("grype.json", """
                { "matches": [], "source": { "type": "sbom" } }
                """);

        assertThat(scans.findByAssetIdOrderByCreatedAtDesc(asset.getId())).isEmpty();
    }

    @Test
    @DisplayName("CycloneDX JSON 은 받는다 — 확장자가 아니라 내용으로 가린다")
    void acceptsCycloneDxJson() throws Exception {
        MvcResult result = upload("sbom.cdx", """
                { "bomFormat": "CycloneDX", "specVersion": "1.5",
                  "components": [ { "type": "library", "name": "zlib", "version": "1.2.13",
                                    "purl": "pkg:rpm/rocky/zlib@1.2.13" } ] }
                """);

        assertThat(result.getFlashMap().get("error")).isNull();
        assertThat(scans.findByAssetIdOrderByCreatedAtDesc(asset.getId())).hasSize(1);
    }
}
