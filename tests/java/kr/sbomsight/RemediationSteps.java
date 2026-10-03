package kr.sbomsight;

import kr.sbomsight.domain.Asset;
import kr.sbomsight.domain.Scan;
import kr.sbomsight.domain.ScanStatus;
import kr.sbomsight.repo.ScanRepository;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 조치 시험들이 함께 밟는 걸음 — 업로드 · 다시 검사 · 조치 등록 · 조치 저장 · 화면 읽기.
 *
 * <p>화면이 쓰는 길(주소)을 그대로 지난다. 검사는 {@link FakeGrype} 가 미리 만든 결과로
 * 끝난다 — 업로드부터 화면까지 앱의 코드가 그대로 돈다.
 */
final class RemediationSteps {

    private final MockMvc mvc;
    private final ScanRepository scans;

    RemediationSteps(MockMvc mvc, ScanRepository scans) {
        this.mvc = mvc;
        this.scans = scans;
    }

    /** SBOM 을 올리고 검사가 끝날 때까지 기다린다. */
    Scan upload(Asset asset, Instant sbomAt, String openssl, String marker) throws Exception {
        String sbom = CurrentScanRuleTest.cyclonedx(sbomAt, openssl, marker);
        mvc.perform(multipart("/assets/" + asset.getId() + "/sbom")
                            .file(new MockMultipartFile("file", "web.cdx.json", "application/json",
                                                        sbom.getBytes(StandardCharsets.UTF_8)))
                            .with(user("tester").roles("ADMIN")).with(csrf()))
           .andExpect(status().is3xxRedirection());
        return newest(asset);
    }

    /**
     * <b>지금 뜬 SBOM</b> — 조치를 끝낸 <b>뒤에</b> 서버를 다시 읽었다. 앞 단계가 남긴
     * 시각과 겹치지 않게 조금 쉬었다가 지금 시각을 SBOM 생성 시각으로 쓴다.
     */
    Scan uploadNow(Asset asset, String openssl, String marker) throws Exception {
        Thread.sleep(5);
        return upload(asset, Instant.now(), openssl, marker);
    }

    /** 그 검사를 다시 검사한다 — 같은 SBOM, 새 검사 시각. */
    Scan rescan(Asset asset, Scan scan) throws Exception {
        mvc.perform(post("/scans/" + scan.getId() + "/rescan")
                            .with(user("tester").roles("ADMIN")).with(csrf()))
           .andExpect(status().is3xxRedirection());
        Scan copy = newest(asset);
        assertThat(copy.getId()).isNotEqualTo(scan.getId());
        return copy;
    }

    private Scan newest(Asset asset) throws Exception {
        Scan scan = FakeGrype.awaitFinished(scans,
                scans.findByAssetIdOrderByCreatedAtDesc(asset.getId()).get(0).getId());
        assertThat(scan.getStatus()).as(scan.getErrorMessage()).isEqualTo(ScanStatus.DONE);
        return scan;
    }

    /** 취약점 화면 · 검토 결과 탭의 `조치 등록` — 자산의 지금 검사에서. */
    MvcResult register(Asset asset, String packageName) throws Exception {
        return mvc.perform(post("/assets/" + asset.getId() + "/remediations")
                                   .param("packageName", packageName)
                                   .with(user("tester").roles("ADMIN")).with(csrf()))
                  .andExpect(status().is3xxRedirection())
                  .andReturn();
    }

    /** `조치 등록` 이 보낸 조치의 번호(`/actions/{id}`). */
    static long idOf(MvcResult result) {
        String url = result.getResponse().getRedirectedUrl();
        assertThat(url).startsWith("/actions/");
        return Long.parseLong(url.substring("/actions/".length()));
    }

    /** 조치 상세의 [저장] — 상태만 바꾼다(담당 · 기한 · 설명은 비워 둔 그대로). */
    MvcResult save(long id, String status, String comment) throws Exception {
        return mvc.perform(post("/actions/" + id)
                                   .param("status", status)
                                   .param("comment", comment)
                                   .with(user("tester").roles("ADMIN")).with(csrf()))
                  .andExpect(status().is3xxRedirection())
                  .andReturn();
    }

    String page(String url) throws Exception {
        return mvc.perform(get(url).with(user("tester").roles("ADMIN")))
                  .andExpect(status().isOk())
                  .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    /** {@code marker} 가 든 표 줄 하나. */
    static String row(String html, String marker) {
        int at = html.indexOf(marker);
        assertThat(at).as(marker + " 가 없다").isNotNegative();
        int start = html.lastIndexOf("<tr", at);
        return html.substring(start, html.indexOf("</tr>", at));
    }

    /** 태그 사이의 빈칸을 없애고 나머지 빈칸은 하나로 — 칸과 칸을 붙여 읽는다. */
    static String tight(String html) {
        return html.replaceAll(">\\s+<", "><").replaceAll("\\s+", " ");
    }
}
