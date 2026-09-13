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
        assertThat(html).contains("원격 접근");
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

    // --- 구역 · 기간 보고서 ---------------------------------------------------

    private Asset assetIn(Zone zone, String name) {
        Asset a = new Asset();
        a.setName(name + "-" + System.nanoTime());
        a.setZone(zone);
        assets.saveAndFlush(a);
        return a;
    }

    /** 오늘 날짜로 검사 하나. 기본 기간(이번 달)에 들어오도록 오늘로 둔다. */
    private Scan doneToday(Asset asset, String pkg, String fixedVersion) {
        Scan scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        scan.setGrypeVersion("0.87.0");
        scans.saveAndFlush(scan);

        Finding f = new Finding(scan, "CVE-2021-44228|" + pkg, "CVE-2021-44228", pkg);
        f.setPackageVersion("1.0.0");
        f.setPackageType("rpm");
        f.setSeverity("Critical");
        f.setFixState("fixed");
        f.setFixedVersion(fixedVersion);
        f.setCvssScore(BigDecimal.valueOf(9.8));
        f.setCvssVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
        findings.saveAndFlush(f);

        scan.setMatchCount(1);
        scan.setFindingCount(1);
        scans.saveAndFlush(scan);
        return scan;
    }

    @Test
    @DisplayName("구역 보고서가 뜨고 검사되지 않은 자산을 이름으로 밝힌다")
    void rendersZoneReport() throws Exception {
        Zone zone = zoneService.create("render구역-" + System.nanoTime(), "#123456", "");
        Asset a = assetIn(zone, "web");
        Asset b = assetIn(zone, "api");
        Asset missed = assetIn(zone, "db");
        doneToday(a, "openssl", "3.0.7");
        doneToday(b, "openssl", "3.0.7");

        String html = mvc.perform(get("/report/zone").param("zone", zone.getId().toString())
                                                     .with(user("tester").roles("ADMIN")))
                         .andExpect(status().isOk())
                         .andReturn().getResponse().getContentAsString();

        // 몇 대를 안 봤는지가 이 보고서에서 가장 먼저 읽혀야 하는 문장이다.
        assertThat(html).contains("1대는 이 기간에 검사 기록이 없습니다");
        assertThat(html).contains(missed.getName());
        // 구역 단위로만 나오는 값 — 같은 패키지가 몇 대에 걸려 있는가.
        assertThat(html).contains("2대");
        assertThat(html).contains("두 대 이상에 공통");
    }

    @Test
    @DisplayName("기간 안에 검사가 없는 구역도 500 이 아니다")
    void rendersZoneReportWithNoScans() throws Exception {
        Zone zone = zoneService.create("빈구역-" + System.nanoTime(), "", "");
        assetIn(zone, "web");

        mvc.perform(get("/report/zone").param("zone", zone.getId().toString())
                                       .with(user("tester").roles("ADMIN")))
           .andExpect(status().isOk());
    }

    @Test
    @DisplayName("자산이 하나도 없는 구역도 뜬다")
    void rendersZoneReportWithNoAssets() throws Exception {
        Zone zone = zoneService.create("무자산-" + System.nanoTime(), "", "");

        String html = mvc.perform(get("/report/zone").param("zone", zone.getId().toString())
                                                     .with(user("tester").roles("ADMIN")))
                         .andExpect(status().isOk())
                         .andReturn().getResponse().getContentAsString();

        assertThat(html).contains("이 구역에 등록된 자산이 없습니다");
    }

    /**
     * 전 구역을 한 장에 볼 때는 자산마다 구역 칸이 하나 더 붙는다. 검사되지
     * 않은 자산 줄은 칸을 합쳐 채우므로, 칸 수가 어긋나면 표가 밀린다.
     */
    @Test
    @DisplayName("기간을 주지 않으면 이번 달 전체 구역으로 뜨고 구역 칸이 붙는다")
    void rendersZoneReportWithDefaults() throws Exception {
        Zone zone = zoneService.create("전체구역-" + System.nanoTime(), "", "");
        Asset a = assetIn(zone, "web");
        Asset missed = assetIn(zone, "db");
        doneToday(a, "openssl", "3.0.7");

        String html = mvc.perform(get("/report/zone").with(user("tester").roles("ADMIN")))
                         .andExpect(status().isOk())
                         .andReturn().getResponse().getContentAsString();

        // 구역 이름이 자산 표에 실려야 어느 구역의 서버인지 알 수 있다.
        assertThat(html).contains(zone.getName());
        assertThat(html).contains(a.getName());
        assertThat(html).contains(missed.getName());
    }

    @Test
    @DisplayName("시작일이 종료일보다 늦으면 바꾸고 알린다")
    void swapsReversedDates() throws Exception {
        String html = mvc.perform(get("/report/zone")
                                          .param("from", "2026-09-30").param("to", "2026-09-01")
                                          .with(user("tester").roles("ADMIN")))
                         .andExpect(status().isOk())
                         .andReturn().getResponse().getContentAsString();

        // 말없이 빈 보고서를 내면 "이 구역은 깨끗하다" 로 읽힌다.
        assertThat(html).contains("두 날짜를 바꿨습니다");
        assertThat(html).contains("2026년 9월 1일");
    }
}
