package kr.sbomsight;

import kr.sbomsight.domain.Asset;
import kr.sbomsight.domain.Scan;
import kr.sbomsight.domain.ScanStage;
import kr.sbomsight.domain.ScanStatus;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.ScanRepository;
import kr.sbomsight.service.ZoneService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 검사 진행 상태.
 *
 * <p>고정하는 것은 <b>눈금이 실제 단계와 맞물린다</b>는 것이다. 보여 주기
 * 위해 지어낸 진행률이면 없느니만 못하다 — 90%에서 멈춘 막대를 보며 기다리는
 * 것이 "검사 중" 한 마디보다 나을 것이 없다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class ScanProgressTest {

    @Autowired MockMvc mvc;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired ZoneService zoneService;

    private Scan scanAt(ScanStatus status, ScanStage stage) {
        Asset asset = new Asset();
        asset.setName("web-" + System.nanoTime());
        asset.setZone(zoneService.unassigned());
        assets.saveAndFlush(asset);

        Scan scan = new Scan(asset, "tester");
        scan.setStatus(status);
        scan.setStage(stage);
        scan.setSbomFilename("sbom.json");
        return scans.saveAndFlush(scan);
    }

    @Test
    @DisplayName("도는 중이면 그 단계가 running, 지난 것은 done, 남은 것은 todo")
    void marksTheCurrentStep() throws Exception {
        Scan scan = scanAt(ScanStatus.RUNNING, ScanStage.SCANNING);

        mvc.perform(get("/scans/" + scan.getId() + "/status").with(user("t").roles("ADMIN")))
           .andExpect(status().isOk())
           .andExpect(jsonPath("$.running").value(true))
           .andExpect(jsonPath("$.stage").value("SCANNING"))
           .andExpect(jsonPath("$.stageLabel").value("grype 검사"))
           .andExpect(jsonPath("$.steps[0].state").value("done"))      // 올리기
           .andExpect(jsonPath("$.steps[1].state").value("done"))      // SBOM 읽기
           .andExpect(jsonPath("$.steps[2].state").value("running"))   // grype 검사
           .andExpect(jsonPath("$.steps[3].state").value("todo"));     // 결과 정리
    }

    @Test
    @DisplayName("끝나면 눈금이 전부 done 이고 더 묻지 않는다")
    void completesEveryStep() throws Exception {
        Scan scan = scanAt(ScanStatus.DONE, ScanStage.DONE);

        mvc.perform(get("/scans/" + scan.getId() + "/status").with(user("t").roles("ADMIN")))
           .andExpect(status().isOk())
           .andExpect(jsonPath("$.done").value(true))
           .andExpect(jsonPath("$.running").value(false))
           .andExpect(jsonPath("$.steps[0].state").value("done"))
           .andExpect(jsonPath("$.steps[3].state").value("done"));
    }

    /**
     * 실패하면 그 자리에서 멈춘 것으로 둔다. 남은 눈금을 회색으로 흘려
     * 보내면 아직 도는 것처럼 읽힌다.
     */
    @Test
    @DisplayName("실패하면 그 자리에서 멈추고 남은 눈금은 흐려진다")
    void stopsWhereItFailed() throws Exception {
        Scan scan = scanAt(ScanStatus.FAILED, ScanStage.SCANNING);
        scan.setErrorMessage("grype 이 60분 안에 끝나지 않았습니다.");
        scans.saveAndFlush(scan);

        mvc.perform(get("/scans/" + scan.getId() + "/status").with(user("t").roles("ADMIN")))
           .andExpect(status().isOk())
           .andExpect(jsonPath("$.failed").value(true))
           .andExpect(jsonPath("$.running").value(false))
           .andExpect(jsonPath("$.error").value("grype 이 60분 안에 끝나지 않았습니다."))
           .andExpect(jsonPath("$.steps[2].state").value("failed"))
           .andExpect(jsonPath("$.steps[3].state").value("skipped"));
    }

    @Test
    @DisplayName("로그인하지 않으면 진행 상태도 알려 주지 않는다")
    void needsLogin() throws Exception {
        Scan scan = scanAt(ScanStatus.RUNNING, ScanStage.SCANNING);

        // 어느 서버에 검사가 돌고 있는지도 내부 정보다.
        mvc.perform(get("/scans/" + scan.getId() + "/status"))
           .andExpect(status().is3xxRedirection());
    }

    @Test
    @DisplayName("없는 스캔은 404")
    void missingScan() throws Exception {
        mvc.perform(get("/scans/999999/status").with(user("t").roles("ADMIN")))
           .andExpect(status().isNotFound());
    }

    /** V10 이전에 끝난 검사에는 단계가 없다. 그래도 화면이 터지지 않아야 한다. */
    @Test
    @DisplayName("옛 검사는 단계가 DONE 으로 남아 그대로 그려진다")
    void oldScansStillRender() throws Exception {
        Scan scan = scanAt(ScanStatus.DONE, ScanStage.DONE);
        assertThat(scan.getStage()).isEqualTo(ScanStage.DONE);

        mvc.perform(get("/assets/" + scan.getAsset().getId()).with(user("t").roles("ADMIN")))
           .andExpect(status().isOk());
    }
}
