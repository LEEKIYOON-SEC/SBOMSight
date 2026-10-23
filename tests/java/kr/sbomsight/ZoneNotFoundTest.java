package kr.sbomsight;

import kr.sbomsight.domain.Asset;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.service.ZoneService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * <b>없는 구역 번호는 500 도, 빈 "전체" 보고서도 아니다.</b>
 *
 * <p>구역을 지운 뒤 그 구역의 주소(즐겨찾기 · 결재 문서에 붙은 링크)를 열거나,
 * 다른 창에서 지운 구역을 고르개로 고르면:
 * <ul>
 *   <li>취약점 화면 — 500(ZoneService 의 IllegalArgumentException 이 그대로 올라감)</li>
 *   <li>구역 보고서 — 200 으로 <b>자산 0대짜리 "전체" 보고서</b>. 깨끗한 전체로 읽힌다</li>
 *   <li>자산 등록 · 구역 옮기기 — 500</li>
 * </ul>
 * 조회 화면은 404 "구역을 찾을 수 없습니다", 폼은 그 말을 안내로 띄운다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class ZoneNotFoundTest {

    private static final long GONE = 987_654_321L;

    @Autowired MockMvc mvc;
    @Autowired AssetRepository assets;
    @Autowired ZoneService zoneService;

    @Test
    @DisplayName("취약점 화면 · CVE 상세 · CSV 에 없는 구역 — 404")
    void vulnScreensSayNotFound() throws Exception {
        for (String url : new String[] { "/vulns?zone=" + GONE, "/vulns/export.csv?zone=" + GONE }) {
            mvc.perform(get(url).with(user("tester").roles("ADMIN")))
               .andExpect(status().isNotFound());
        }
    }

    @Test
    @DisplayName("구역 보고서에 없는 구역 — 빈 '전체' 보고서가 아니라 404")
    void zoneReportSaysNotFound() throws Exception {
        mvc.perform(get("/reports/zone?zone=" + GONE).with(user("tester").roles("ADMIN")))
           .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("없는 구역으로 옮기면 500 이 아니라 안내가 뜨고 자산은 그대로다")
    void movingToAMissingZoneIsRefusedPolitely() throws Exception {
        Asset asset = new Asset();
        asset.setName("zone-gone-" + System.nanoTime());
        asset.setZone(zoneService.unassigned());
        assets.saveAndFlush(asset);

        MvcResult r = mvc.perform(post("/assets/" + asset.getId() + "/zone").param("zoneId", String.valueOf(GONE))
                                          .with(user("tester").roles("ADMIN")).with(csrf()))
                         .andExpect(status().is3xxRedirection())
                         .andReturn();
        assertThat((String) r.getFlashMap().get("error")).contains("구역을 찾을 수 없습니다");
        assertThat(assets.findById(asset.getId()).orElseThrow().getZone().getId())
                .isEqualTo(zoneService.unassigned().getId());
    }

    @Test
    @DisplayName("없는 구역으로 자산을 등록하면 500 이 아니라 안내가 뜨고 등록되지 않는다")
    void creatingInAMissingZoneIsRefusedPolitely() throws Exception {
        String name = "zone-gone-new-" + System.nanoTime();
        MvcResult r = mvc.perform(post("/assets").param("name", name).param("zoneId", String.valueOf(GONE))
                                          .with(user("tester").roles("ADMIN")).with(csrf()))
                         .andExpect(status().is3xxRedirection())
                         .andReturn();
        assertThat((String) r.getFlashMap().get("error")).contains("구역을 찾을 수 없습니다");
        assertThat(assets.existsByName(name)).isFalse();
    }
}
