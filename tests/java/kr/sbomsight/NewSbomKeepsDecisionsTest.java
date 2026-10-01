package kr.sbomsight;

import kr.sbomsight.domain.*;
import kr.sbomsight.repo.*;
import kr.sbomsight.service.AssetService;
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
import java.time.LocalDate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * <b>새 SBOM 이 들어와도 앞서 적은 검토 결과와 조치가 그대로 남는가.</b>
 *
 * <p>검토 결과는 (자산, 취약점, 패키지), 조치는 (자산, 패키지) 에 붙고 검사에
 * 붙지 않는다 — 검사가 바뀌어도 사라지지 않아야 하는 것이 그 이유다. 지금은
 * 그렇게 돈다(앞서 재현 시험으로 확인). 이 시험은 그것이 <b>앞으로도</b>
 * 그렇게 도는지를 지킨다 — 검사 · 조치 · 검토 결과를 크게 손보는 일이 이어진다.
 *
 * <p>업로드 → 뒤에서 검사 → 저장까지 앱의 코드가 돈다. grype 만
 * {@link FakeGrype} 다.
 */
@SpringBootTest
@AutoConfigureMockMvc
class NewSbomKeepsDecisionsTest {

    /** openssl 1.1.1k(CVE-2023-0001 → 1.1.1n) · lodash 4.17.0(GHSA 하나). */
    static final String SBOM_V1 = """
            {"artifacts":[
              {"name":"openssl","version":"1.1.1k","type":"deb","purl":"pkg:deb/debian/openssl@1.1.1k"},
              {"name":"lodash","version":"4.17.0","type":"npm","purl":"pkg:npm/lodash@4.17.0"}],
             "marker":"sbom-v1"}
            """;

    /** openssl 을 1.1.1n 으로 올렸다 — CVE-2023-0001 은 사라지고 CVE-2024-0002 가 걸린다. */
    static final String SBOM_V2 = """
            {"artifacts":[
              {"name":"openssl","version":"1.1.1n","type":"deb","purl":"pkg:deb/debian/openssl@1.1.1n"},
              {"name":"lodash","version":"4.17.0","type":"npm","purl":"pkg:npm/lodash@4.17.0"}],
             "marker":"sbom-v2"}
            """;

    @Autowired MockMvc mvc;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingAnalysisRepository analyses;
    @Autowired RemediationRepository remediations;
    @Autowired AssetService assetService;
    @Autowired ZoneService zoneService;

    @MockBean GrypeRunner grype;

    @BeforeEach
    void fakeGrype() {
        FakeGrype.on(grype);
    }

    @Test
    @DisplayName("새 SBOM 이 들어와도 앞서 적은 검토 결과와 조치가 그대로 남는다")
    void decisionsSurviveANewSbom() throws Exception {
        Asset asset = new Asset();
        asset.setName("keep-" + System.nanoTime());
        asset.setZone(zoneService.unassigned());
        assets.saveAndFlush(asset);
        try {
            upload(asset, SBOM_V1);

            // 우회 조치를 적고, 조치를 맡긴다.
            mvc.perform(post("/analyses").with(admin()).with(csrf())
                            .param("assetId", String.valueOf(asset.getId()))
                            .param("cve", "CVE-2023-0001").param("packageName", "openssl")
                            .param("state", "EXPLOITABLE").param("response", "WORKAROUND_AVAILABLE")
                            .param("note", "패치 전까지 우회")
                            .param("otherControl", "WAF 규칙 적용")
                            .param("approvalDoc", "보안-2026-0001"))
               .andExpect(status().is3xxRedirection());
            mvc.perform(post("/assets/" + asset.getId() + "/remediations").with(admin()).with(csrf())
                            .param("packageName", "openssl"))
               .andExpect(status().is3xxRedirection());
            Remediation remediation = remediations
                    .findByAssetIdAndPackageName(asset.getId(), "openssl").orElseThrow();
            mvc.perform(post("/actions/" + remediation.getId()).with(admin()).with(csrf())
                            .param("status", "IN_PROGRESS").param("owner", "홍길동")
                            .param("dueDate", LocalDate.now().plusDays(30).toString())
                            .param("note", "정기 점검 창에서").param("comment", "착수"))
               .andExpect(status().is3xxRedirection());

            upload(asset, SBOM_V2);

            FindingAnalysis kept = analyses.findOne(asset.getId(), "CVE-2023-0001", "openssl")
                    .orElseThrow(() -> new AssertionError("새 SBOM 뒤에 검토 결과가 사라졌다"));
            assertThat(kept.getState()).isEqualTo(AnalysisState.EXPLOITABLE);
            assertThat(kept.getResponse()).isEqualTo(AnalysisResponse.WORKAROUND_AVAILABLE);
            assertThat(kept.getOtherControl()).isEqualTo("WAF 규칙 적용");
            assertThat(kept.getApprovalDoc()).isEqualTo("보안-2026-0001");

            Remediation after = remediations.findDetail(remediation.getId())
                    .orElseThrow(() -> new AssertionError("새 SBOM 뒤에 조치가 사라졌다"));
            assertThat(after.getStatus()).isEqualTo(RemediationStatus.IN_PROGRESS);
            assertThat(after.getOwner()).isEqualTo("홍길동");

            // 화면에서도 — 해소된 취약점의 검토 결과는 자산의 `조치·검토 결과` 탭에 남는다.
            String tab = page("/assets/" + asset.getId() + "?tab=actions");
            assertThat(tab).contains("CVE-2023-0001").contains("/actions/" + remediation.getId());
            assertThat(page("/analyses/" + kept.getId()))
                    .as("최신 검사에 없는 탐지의 검토 결과는 없어진 것이 아니라 남아 있다고 말해야 한다")
                    .contains("검토 결과는 그대로 남음");
        } finally {
            // 트랜잭션 없이 커밋된다(검사가 뒤에서 돈다). 손으로 치운다.
            assetService.delete(assets.findById(asset.getId()).orElseThrow(), "tester");
        }
    }

    private void upload(Asset asset, String sbom) throws Exception {
        mvc.perform(multipart("/assets/" + asset.getId() + "/sbom")
                        .file(new MockMultipartFile("file", "web.sbom.json", "application/json",
                                                    sbom.getBytes(StandardCharsets.UTF_8)))
                        .with(admin()).with(csrf()))
           .andExpect(status().is3xxRedirection());
        Scan scan = scans.findByAssetIdOrderByCreatedAtDesc(asset.getId()).get(0);
        assertThat(FakeGrype.awaitFinished(scans, scan.getId()).getStatus())
                .as("가짜 grype 로 도는 검사가 완료되지 않았다")
                .isEqualTo(ScanStatus.DONE);
    }

    private String page(String url) throws Exception {
        return mvc.perform(get(url).with(admin()))
                  .andExpect(status().isOk())
                  .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    private static org.springframework.test.web.servlet.request.RequestPostProcessor admin() {
        return user("tester").roles("ADMIN");
    }
}
