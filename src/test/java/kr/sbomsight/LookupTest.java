package kr.sbomsight;

import kr.sbomsight.domain.*;
import kr.sbomsight.repo.*;
import kr.sbomsight.service.ZoneService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 전사 조회 — "이 취약점이 어느 서버에 있나".
 *
 * <p>여기서 고정하는 것은 <b>지금 상태만 답한다</b>는 것이다. 이력 전체를
 * 훑으면 이미 조치가 끝난 옛 스캔이 섞여 나와 "아직 있다" 고 말하게 된다 —
 * 그 답을 믿고 서버에 들어가면 없다. 긴급 상황에 쓰는 화면이 그러면 안 된다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class LookupTest {

    @Autowired MockMvc mvc;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired ZoneService zoneService;
    @Autowired ZoneRepository zones;

    private Zone dmz;
    private Zone inner;

    @BeforeEach
    void setUp() {
        dmz = zones.findByName("DMZ").orElseGet(() -> zoneService.create("DMZ", "#a71922", ""));
        inner = zones.findByName("내부업무")
                     .orElseGet(() -> zoneService.create("내부업무", "#c3571a", ""));
    }

    private Asset asset(String name, Zone zone) {
        Asset a = new Asset();
        a.setName(name + "-" + System.nanoTime());
        a.setZone(zone);
        return assets.save(a);
    }

    private Scan scan(Asset asset, Instant when) {
        Scan s = new Scan(asset, "tester");
        s.setStatus(ScanStatus.DONE);
        scans.saveAndFlush(s);
        s.setCreatedAt(when);
        return scans.saveAndFlush(s);
    }

    private Finding finding(Scan scan, String cve, String pkg, String severity, String fixState) {
        Finding f = new Finding(scan, cve + "|" + pkg + "|" + scan.getId(), cve, pkg);
        f.setPackageVersion("2.14.1");
        f.setPackageType("java-archive");
        f.setSeverity(severity);
        f.setFixState(fixState);
        f.setFixedVersion("fixed".equals(fixState) ? "2.17.0" : "");
        f.setCvssScore(BigDecimal.valueOf(9.8));
        return findings.save(f);
    }

    private java.util.List<Finding> lookup(String q) {
        return findings.lookup(q, null, null, null, PageRequest.of(0, 100)).getContent();
    }

    /**
     * 이 시험이 이 기능의 핵심이다. 지난달 스캔에는 log4j 가 있었고 이번 달
     * 스캔에는 없다 — 그 서버는 답에 나와서는 안 된다.
     */
    @Test
    @DisplayName("조치가 끝난 옛 스캔은 답에 나오지 않는다")
    void onlyTheLatestScanCounts() {
        Asset patched = asset("patched", dmz);

        // 지난달: log4j 있음
        Scan before = scan(patched, Instant.now().minus(30, ChronoUnit.DAYS));
        finding(before, "CVE-2021-44228", "log4j-core", "Critical", "fixed");

        // 이번 달: 올렸고 log4j 없음. 다른 것만 있다.
        Scan now = scan(patched, Instant.now());
        finding(now, "CVE-2023-32681", "requests", "Medium", "fixed");

        assertThat(lookup("log4j"))
                .as("이미 올린 서버가 아직 취약한 것으로 나왔다")
                .isEmpty();
        assertThat(lookup("requests")).hasSize(1);
    }

    @Test
    @DisplayName("여러 자산에 걸친 것을 한 번에 찾는다")
    void findsAcrossAssets() {
        Asset web = asset("web", dmz);
        Asset api = asset("api", dmz);
        Asset db = asset("db", inner);

        finding(scan(web, Instant.now()), "CVE-2021-44228", "log4j-core", "Critical", "fixed");
        finding(scan(api, Instant.now()), "CVE-2021-44228", "log4j-core", "Critical", "fixed");
        finding(scan(db, Instant.now()), "CVE-2023-32681", "requests", "Medium", "fixed");

        assertThat(lookup("log4j"))
                .hasSize(2)
                .extracting(f -> f.getScan().getAsset().getName())
                .containsExactlyInAnyOrder(web.getName(), api.getName());
    }

    @Test
    @DisplayName("CVE 번호로도 패키지 이름으로도 찾힌다")
    void searchesByEitherKey() {
        Asset web = asset("web", dmz);
        Scan s = scan(web, Instant.now());
        Finding f = finding(s, "GHSA-jfh8-c2jp-5v3q", "log4j-core", "Critical", "fixed");
        f.setRelatedCve("CVE-2021-44228");
        findings.save(f);

        assertThat(lookup("log4j-core")).hasSize(1);
        // grype 의 주 식별자가 GHSA 인 경우에도 CVE 번호로 찾혀야 한다 —
        // 결재·보고는 CVE 번호로 돈다.
        assertThat(lookup("CVE-2021-44228")).hasSize(1);
        assertThat(lookup("GHSA-jfh8")).hasSize(1);
    }

    @Test
    @DisplayName("완료되지 않은 스캔은 보지 않는다")
    void ignoresUnfinishedScans() {
        Asset web = asset("web", dmz);
        Scan running = new Scan(web, "tester");
        running.setStatus(ScanStatus.RUNNING);
        scans.saveAndFlush(running);
        finding(running, "CVE-2021-44228", "log4j-core", "Critical", "fixed");

        // 아직 도는 중인 스캔의 중간 결과로 답하면 그 답이 곧 바뀐다.
        assertThat(lookup("log4j")).isEmpty();
    }

    @Test
    @DisplayName("시각이 같은 스캔이 둘이어도 자산은 한 번만 나온다")
    void doesNotDuplicateAnAssetOnTiedTimestamps() {
        Asset web = asset("web", dmz);
        Instant sameMoment = Instant.now();

        // 같은 시각에 완료된 스캔 둘. createdAt 만으로 고르면 두 행이 나온다.
        Scan first = scan(web, sameMoment);
        finding(first, "CVE-2021-44228", "log4j-core", "Critical", "fixed");
        Scan second = scan(web, sameMoment);
        finding(second, "CVE-2021-44228", "log4j-core", "Critical", "fixed");

        assertThat(lookup("log4j"))
                .as("같은 자산이 두 번 나왔다")
                .hasSize(1);
    }

    @Test
    @DisplayName("구역으로 좁힐 수 있다")
    void filtersByZone() {
        Asset web = asset("web", dmz);
        Asset db = asset("db", inner);
        finding(scan(web, Instant.now()), "CVE-2021-44228", "log4j-core", "Critical", "fixed");
        finding(scan(db, Instant.now()), "CVE-2021-44228", "log4j-core", "Critical", "fixed");

        assertThat(findings.lookup("log4j", dmz.getId(), null, null, PageRequest.of(0, 100)))
                .hasSize(1);
    }

    @Test
    @DisplayName("수정본 없는 것만 걸러 볼 수 있다")
    void filtersByFixability() {
        Asset web = asset("web", dmz);
        Scan s = scan(web, Instant.now());
        finding(s, "CVE-A", "log4j-core", "Critical", "fixed");
        finding(s, "CVE-B", "log4j-api", "High", "not-fixed");

        assertThat(findings.lookup("log4j", null, null, false, PageRequest.of(0, 100)))
                .extracting(Finding::getPackageName).containsExactly("log4j-api");
    }

    @Test
    @DisplayName("검색어가 없으면 아무것도 쏟아 내지 않는다")
    void emptyQueryShowsNothing() throws Exception {
        String html = mvc.perform(get("/lookup").with(user("tester").roles("VIEWER")))
                         .andExpect(status().isOk())
                         .andReturn().getResponse().getContentAsString();

        assertThat(html).contains("찾을 CVE 번호나 패키지 이름을 입력하세요");
    }

    @Test
    @DisplayName("화면과 CSV 가 뜬다")
    void screensRender() throws Exception {
        Asset web = asset("web", dmz);
        finding(scan(web, Instant.now()), "CVE-2021-44228", "log4j-core", "Critical", "fixed");

        String html = mvc.perform(get("/lookup").param("q", "log4j")
                        .with(user("tester").roles("VIEWER")))
                         .andExpect(status().isOk())
                         .andReturn().getResponse().getContentAsString();
        assertThat(html).contains(web.getName());
        assertThat(html).contains("DMZ");

        String csv = mvc.perform(get("/lookup/export.csv").param("q", "log4j")
                        .with(user("tester").roles("VIEWER")))
                         .andExpect(status().isOk())
                         .andReturn().getResponse().getContentAsString();
        assertThat(csv).startsWith("﻿");
        assertThat(csv).contains("구역");
        assertThat(csv).contains(web.getName());
    }
}
