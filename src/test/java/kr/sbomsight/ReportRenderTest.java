package kr.sbomsight;

import kr.sbomsight.domain.*;
import kr.sbomsight.repo.*;
import kr.sbomsight.service.ZoneService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 보고서가 실제로 그려지는가.
 *
 * <p><b>왜 따로 있는가.</b> {@link ReportServiceTest} 는 계산이 맞는지만 본다.
 * 화면은 렌더링해 봐야 깨지는지 알 수 있다 — 타임리프의 잘못된 식은 컴파일에
 * 걸리지 않고 그 화면을 열 때 500 으로 터진다. 보고서는 결재로 올라가는
 * 문서라 그 자리에서 터지면 곤란하다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class ReportRenderTest {

    @Autowired MockMvc mvc;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired ZoneService zoneService;

    private Scan seed(boolean withVectors) {
        Asset asset = new Asset();
        asset.setName("render-" + System.nanoTime());
        asset.setZone(zoneService.unassigned());
        assets.save(asset);

        Scan scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        scan.setGrypeVersion("0.87.0");
        scan.setSbomFilename("sbom.json");
        scan.setComponentCount(120);
        scans.saveAndFlush(scan);

        String[][] rows = {
            { "CVE-2021-44228", "log4j-core", "Critical", "fixed",     "2.15.0",
              "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" },
            { "CVE-2025-41249", "spring-core", "High",    "not-fixed", "",
              "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" },
            { "CVE-2023-32681", "requests",   "Medium",   "fixed",     "2.31.0",
              "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N" }
        };
        for (String[] r : rows) {
            Finding f = new Finding(scan, r[0] + "|" + r[1], r[0], r[1]);
            f.setPackageVersion("1.0.0");
            f.setPackageType("java-archive");
            f.setSeverity(r[2]);
            f.setFixState(r[3]);
            f.setFixedVersion(r[4]);
            f.setCvssScore(BigDecimal.valueOf(9.8));
            if (withVectors) {
                f.setCvssVector(r[5]);
            }
            findings.save(f);
        }
        scan.setMatchCount(rows.length);
        scan.setFindingCount(rows.length);
        scans.saveAndFlush(scan);
        return scan;
    }

    @Test
    @DisplayName("보고서가 200 으로 뜨고 노출면이 실려 있다")
    void rendersWithExposure() throws Exception {
        Scan scan = seed(true);

        String html = mvc.perform(get("/report/" + scan.getId()).with(user("tester").roles("ADMIN")))
                         .andExpect(status().isOk())
                         .andReturn().getResponse().getContentAsString();

        assertThat(html).contains("어떻게 닿을 수 있는가");
        assertThat(html).contains("밖에서 바로");
        // 셋 중 둘이 AV:N/PR:N/UI:N 이다 (requests 는 UI:R).
        assertThat(html).contains("바로 닿음");
    }

    /**
     * 벡터가 하나도 없는 스캔(옛 grype·다른 자문 DB)에서도 터지지 않아야 한다.
     * 그럴 때 노출면 문단은 "0건"이라고 말하는 대신 빠진다.
     */
    @Test
    @DisplayName("벡터가 없어도 보고서가 뜬다")
    void rendersWithoutVectors() throws Exception {
        Scan scan = seed(false);

        mvc.perform(get("/report/" + scan.getId()).with(user("tester").roles("ADMIN")))
           .andExpect(status().isOk());
    }

    @Test
    @DisplayName("탐지가 없는 스캔의 보고서도 뜬다")
    void rendersAnEmptyScan() throws Exception {
        Asset asset = new Asset();
        asset.setName("empty-" + System.nanoTime());
        asset.setZone(zoneService.unassigned());
        assets.save(asset);
        Scan scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        scans.saveAndFlush(scan);

        mvc.perform(get("/report/" + scan.getId()).with(user("tester").roles("ADMIN")))
           .andExpect(status().isOk());
    }
}
