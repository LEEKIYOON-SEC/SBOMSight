package kr.sbomsight;

import kr.sbomsight.domain.*;
import kr.sbomsight.repo.*;
import kr.sbomsight.service.VulnQuery;
import kr.sbomsight.service.ZoneService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 취약점 화면의 <b>범위</b> — 무엇을 세고 있는가.
 *
 * <p>여기서 고정하는 것은 두 가지다.
 *
 * <p><b>하나.</b> 구역·전체 범위는 <b>지금 상태만</b> 답한다. 이력 전체를 훑으면
 * 이미 조치가 끝난 옛 검사가 섞여 나와 "아직 있다" 고 말하게 된다 — 그 답을
 * 믿고 서버에 들어가면 없다. 긴급 상황에 쓰는 화면이 그러면 안 된다.
 *
 * <p><b>둘.</b> 범위 × 묶기 조합이 전부 열린다. 범위 셋(전체·구역·검사)과
 * 묶기 셋(항목별·CVE별·패키지별)은 서로 곱해지는데, 한 칸만 깨져도 그 링크는
 * 막다른 길이 된다 — 사람은 조합을 하나씩 눌러 보지 않는다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class VulnScopeTest {

    @Autowired MockMvc mvc;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired ZoneService zoneService;
    @Autowired ZoneRepository zones;
    @Autowired VulnQuery query;

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

    /** 전체 범위(각 자산의 최신 완료 검사)에서 검색어로 걸린 것. */
    private List<Finding> lookup(String q) {
        VulnQuery.Scope scope = query.ofZone(null);
        return scope.scanIds().isEmpty() ? List.of()
                : findings.findInBySeverity(scope.scanIds(), q, null, null, null,
                                            PageRequest.of(0, 100)).getContent();
    }

    // --- 범위 -----------------------------------------------------------------

    /**
     * 이 시험이 이 기능의 핵심이다. 지난달 검사에는 log4j 가 있었고 이번 달
     * 검사에는 없다 — 그 자산은 답에 나와서는 안 된다.
     */
    @Test
    @DisplayName("조치가 끝난 옛 검사는 답에 나오지 않는다")
    void onlyTheLatestScanCounts() {
        Asset patched = asset("patched", dmz);

        // 지난달: log4j 있음
        Scan before = scan(patched, Instant.now().minus(30, ChronoUnit.DAYS));
        finding(before, "CVE-2021-44228", "log4j-core", "Critical", "fixed");

        // 이번 달: 올렸고 log4j 없음. 다른 것만 있다.
        Scan now = scan(patched, Instant.now());
        finding(now, "CVE-2023-32681", "requests", "Medium", "fixed");

        assertThat(lookup("log4j"))
                .as("이미 올린 자산이 아직 취약한 것으로 나왔다")
                .isEmpty();
        assertThat(lookup("requests")).hasSize(1);

        // 다만 그 옛 검사를 직접 열면 그때 있던 것이 그대로 나와야 한다 —
        // 검사 하나를 여는 것은 "그때 무엇이 있었나" 를 묻는 일이다.
        VulnQuery.Scope old = query.ofScan(before.getId());
        assertThat(findings.findInBySeverity(old.scanIds(), "log4j", null, null, null,
                                             PageRequest.of(0, 100)))
                .hasSize(1);
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
    @DisplayName("완료되지 않은 검사는 보지 않는다")
    void ignoresUnfinishedScans() {
        Asset web = asset("web", dmz);
        Scan running = new Scan(web, "tester");
        running.setStatus(ScanStatus.RUNNING);
        scans.saveAndFlush(running);
        finding(running, "CVE-2021-44228", "log4j-core", "Critical", "fixed");

        // 아직 도는 중인 검사의 중간 결과로 답하면 그 답이 곧 바뀐다.
        assertThat(lookup("log4j")).isEmpty();
    }

    @Test
    @DisplayName("시각이 같은 검사가 둘이어도 자산은 한 번만 나온다")
    void doesNotDuplicateAnAssetOnTiedTimestamps() {
        Asset web = asset("web", dmz);
        Instant sameMoment = Instant.now();

        // 같은 시각에 완료된 검사 둘. createdAt 만으로 고르면 두 행이 나온다.
        Scan first = scan(web, sameMoment);
        finding(first, "CVE-2021-44228", "log4j-core", "Critical", "fixed");
        Scan second = scan(web, sameMoment);
        finding(second, "CVE-2021-44228", "log4j-core", "Critical", "fixed");

        assertThat(lookup("log4j"))
                .as("같은 자산이 두 번 나왔다")
                .hasSize(1);
    }

    /** 보관한 자산은 운영에서 내린 것이다. 현황 숫자에 섞이면 안 된다. */
    @Test
    @DisplayName("보관한 자산은 범위에서 빠진다")
    void archivedAssetsLeaveTheScope() {
        Asset retired = asset("retired", dmz);
        finding(scan(retired, Instant.now()), "CVE-2021-44228", "log4j-core", "Critical", "fixed");
        assertThat(lookup("log4j")).hasSize(1);

        retired.setArchivedAt(Instant.now());
        assets.saveAndFlush(retired);

        assertThat(lookup("log4j"))
                .as("보관한 자산이 아직 현황에 섞여 있다")
                .isEmpty();
    }

    @Test
    @DisplayName("구역으로 좁힐 수 있다")
    void filtersByZone() {
        Asset web = asset("web", dmz);
        Asset db = asset("db", inner);
        finding(scan(web, Instant.now()), "CVE-2021-44228", "log4j-core", "Critical", "fixed");
        finding(scan(db, Instant.now()), "CVE-2021-44228", "log4j-core", "Critical", "fixed");

        VulnQuery.Scope scope = query.ofZone(dmz.getId());
        assertThat(findings.findInBySeverity(scope.scanIds(), "log4j", null, null, null,
                                             PageRequest.of(0, 100)))
                .hasSize(1)
                .extracting(f -> f.getScan().getAsset().getName())
                .containsExactly(web.getName());
    }

    @Test
    @DisplayName("수정 버전 없는 것만 걸러 볼 수 있다")
    void filtersByFixability() {
        Asset web = asset("web", dmz);
        Scan s = scan(web, Instant.now());
        finding(s, "CVE-A", "log4j-core", "Critical", "fixed");
        finding(s, "CVE-B", "log4j-api", "High", "not-fixed");

        VulnQuery.Scope scope = query.ofScan(s.getId());
        assertThat(findings.findInBySeverity(scope.scanIds(), "log4j", null, false, null,
                                             PageRequest.of(0, 100)))
                .extracting(Finding::getPackageName).containsExactly("log4j-api");
    }

    // --- 정렬 -----------------------------------------------------------------

    /**
     * 심각도 순은 <b>글자 순서가 아니다.</b> Critical 이 High 보다 앞이라는 것은
     * 우리가 아는 뜻이지 알파벳이 아니다 — 알파벳이면 Critical, High, Low,
     * Medium 이 되어 Low 가 Medium 위로 올라온다.
     *
     * <p>그리고 <b>grype 이 심각도를 주지 않은 건은 맨 뒤</b>다. 빈 값을
     * 'Low' 로 놓으면 아무도 내리지 않은 판정이 화면에 뜬다.
     */
    @Test
    @DisplayName("심각도 순은 뜻의 순서이고, 값 없는 것은 맨 뒤다")
    void severityOrderIsMeaningNotAlphabet() {
        Asset web = asset("web", dmz);
        Scan s = scan(web, Instant.now());
        finding(s, "CVE-LOW", "a-low", "Low", "fixed");
        finding(s, "CVE-NONE", "b-none", "", "fixed");
        finding(s, "CVE-CRIT", "c-crit", "Critical", "fixed");
        finding(s, "CVE-MED", "d-med", "Medium", "fixed");
        finding(s, "CVE-HIGH", "e-high", "High", "fixed");

        VulnQuery.Scope scope = query.ofScan(s.getId());
        assertThat(findings.findInBySeverity(scope.scanIds(), null, null, null, null,
                                             PageRequest.of(0, 100)).getContent())
                .extracting(Finding::getCve)
                .containsExactly("CVE-CRIT", "CVE-HIGH", "CVE-MED", "CVE-LOW", "CVE-NONE");
    }

    /**
     * CVSS·EPSS 가 없는 건도 마찬가지다. 0 으로 줄 세우면 "안전하다" 가 된다.
     *
     * <p><b>정렬 결과가 아니라 정렬 지시를 본다.</b> 결과로 보면 이 시험은
     * 아무것도 지키지 못한다 — H2 도 MySQL 도 {@code DESC} 에서는 NULL 을
     * 알아서 뒤로 보내므로, {@code nullsLast()} 를 통째로 지워도 시험은
     * 통과한다. 실제로 지워 보고 확인했다. 지시 자체를 못 박아야 한 줄이
     * 사라진 것을 잡는다.
     */
    @Test
    @DisplayName("값이 비어 있을 수 있는 축은 전부 NULL 을 뒤로 보내라고 지시한다")
    void nullableSortKeysAlwaysAskForNullsLast() {
        for (String sort : new String[] { "", "cvss", "epss", "package", "cve", "없는이름" }) {
            for (Sort.Order o : VulnQuery.order(sort)) {
                if (o.getProperty().equals("cvssScore") || o.getProperty().equals("epss")) {
                    assertThat(o.getNullHandling())
                            .as("정렬 '%s' 의 %s 축이 NULL 을 뒤로 보내지 않는다", sort, o.getProperty())
                            .isEqualTo(Sort.NullHandling.NULLS_LAST);
                }
            }
        }
    }

    // --- 범위 × 묶기 ----------------------------------------------------------

    /**
     * 범위 셋 × 묶기 셋이 전부 열린다.
     *
     * <p>조합은 주소에 남는 값이라 사람이 링크로 밟는다. 하나라도 500 이면
     * 그 링크는 막다른 길이다 — 묶기 단추를 눌렀을 뿐인데 화면이 죽는다.
     */
    @Test
    @DisplayName("범위 × 묶기 조합이 전부 열린다")
    void everyScopeAndGroupCombinationOpens() throws Exception {
        Asset web = asset("web", dmz);
        Scan s = scan(web, Instant.now());
        finding(s, "CVE-2021-44228", "log4j-core", "Critical", "fixed");

        for (String scope : new String[] { "", "?zone=" + dmz.getId(), "?scan=" + s.getId() }) {
            for (String group : new String[] { "item", "cve", "package" }) {
                String url = "/vulns" + (scope.isEmpty() ? "?" : scope + "&") + "group=" + group;
                mvc.perform(get(url).with(user("tester").roles("VIEWER")))
                   .andExpect(status().isOk());
            }
        }
    }

    /**
     * 묶는 축은 <b>화면에 찍는 번호와 같아야 한다.</b>
     *
     * <p>grype 의 주 식별자가 GHSA 이고 CVE 번호가 따로 붙어 있는 건이 있다.
     * 항목별 목록은 CVE 번호를 찍는데 CVE별 묶기가 {@code cve} 열로만 묶으면
     * 같은 취약점이 한 화면에서는 {@code CVE-2021-44228}, 다른 화면에서는
     * {@code GHSA-jfh8-c2jp-5v3q} 로 보인다. 결재와 보고는 CVE 번호로 도는데
     * 목록마다 번호가 다르면 대조가 안 된다.
     *
     * <p>그리고 <b>한 자산은 CVE 번호가 붙어 있고 다른 자산은 안 붙어 있으면
     * 두 묶음으로 갈린다</b> — "2대에 있다" 가 "1대 + 1대" 가 된다.
     */
    @Test
    @DisplayName("CVE별 묶기는 목록에 찍히는 번호와 같은 축으로 묶는다")
    void cveGroupingUsesTheIdentifierTheListShows() {
        Asset web = asset("web", dmz);
        Asset api = asset("api", dmz);

        Scan a = scan(web, Instant.now());
        Finding withCve = finding(a, "GHSA-jfh8-c2jp-5v3q", "log4j-core", "Critical", "fixed");
        withCve.setRelatedCve("CVE-2021-44228");
        findings.saveAndFlush(withCve);

        // 같은 취약점인데 이쪽은 CVE 번호가 안 붙어 있다.
        Scan b = scan(api, Instant.now());
        finding(b, "CVE-2021-44228", "log4j-core", "Critical", "fixed");

        VulnQuery.Scope scope = query.ofZone(null);
        var groups = findings.groupByCveIn(scope.scanIds(), "log4j", null, null, null);

        assertThat(groups)
                .as("같은 취약점이 번호가 달라 두 묶음으로 갈렸다")
                .hasSize(1);
        assertThat(groups.get(0).getCve()).isEqualTo("CVE-2021-44228");
        assertThat(groups.get(0).getAssetCount())
                .as("갈린 묶음은 '2대에 있다' 를 '1대' 라고 말한다")
                .isEqualTo(2);
    }

    /** 걸리는 것이 없어도 화면은 열려야 한다. 빈 목록에서 터지는 자리가 흔하다. */
    @Test
    @DisplayName("걸리는 것이 없어도 세 묶기 모두 열린다")
    void emptyResultsStillRender() throws Exception {
        for (String group : new String[] { "item", "cve", "package" }) {
            mvc.perform(get("/vulns").param("q", "존재하지않는패키지").param("group", group)
                            .with(user("tester").roles("VIEWER")))
               .andExpect(status().isOk());
        }
    }

    /**
     * 검색어가 없어도 답한다.
     *
     * <p>앞서 전사 조회는 검색어를 넣어야만 답했다. 그래서 "우리 전체에 심각이
     * 몇 건인가" 를 물을 자리가 아예 없었다.
     */
    @Test
    @DisplayName("검색어 없이도 전체 현황을 답한다")
    void answersWithoutASearchTerm() throws Exception {
        Asset web = asset("web", dmz);
        finding(scan(web, Instant.now()), "CVE-2021-44228", "log4j-core", "Critical", "fixed");

        String html = mvc.perform(get("/vulns").with(user("tester").roles("VIEWER")))
                         .andExpect(status().isOk())
                         .andReturn().getResponse().getContentAsString();

        assertThat(html).contains("CVE-2021-44228");
        assertThat(html).contains(web.getName());
        assertThat(html).contains("DMZ");
    }

    // --- CVE 상세 -------------------------------------------------------------

    @Test
    @DisplayName("CVE 상세가 걸린 자산을 전부 보여 준다")
    void cveDetailListsEveryAffectedAsset() throws Exception {
        Asset web = asset("web", dmz);
        Asset db = asset("db", inner);
        finding(scan(web, Instant.now()), "CVE-2021-44228", "log4j-core", "Critical", "fixed");
        finding(scan(db, Instant.now()), "CVE-2021-44228", "log4j-core", "Critical", "fixed");

        String html = mvc.perform(get("/vulns/CVE-2021-44228").with(user("tester").roles("VIEWER")))
                         .andExpect(status().isOk())
                         .andReturn().getResponse().getContentAsString();

        assertThat(html).contains(web.getName()).contains(db.getName());
        // 구역 분포 — "어디까지 번졌나".
        assertThat(html).contains("DMZ").contains("내부업무");
    }

    /** 걸리는 것이 없는 번호는 빈 화면이 아니라 404 다. 빈 화면은 "없다" 와 "틀렸다" 를 섞는다. */
    @Test
    @DisplayName("걸리는 것이 없는 CVE 번호는 404")
    void unknownCveIsNotFound() throws Exception {
        mvc.perform(get("/vulns/CVE-0000-0000").with(user("tester").roles("VIEWER")))
           .andExpect(status().isNotFound());
    }

    // --- 내려받기 -------------------------------------------------------------

    /**
     * 내려받기는 <b>한 페이지가 아니라 걸린 것 전부</b>다. 화면에 100건만 보이는데
     * 파일도 100건이면 그 파일로 대조를 할 수 없다.
     */
    @Test
    @DisplayName("CSV 는 화면 한 페이지가 아니라 걸린 것 전부를 담는다")
    void csvCarriesEverythingNotOnePage() throws Exception {
        Asset web = asset("web", dmz);
        Scan s = scan(web, Instant.now());
        for (int i = 0; i < VulnQuery.PAGE_SIZE + 20; i++) {
            finding(s, String.format("CVE-2024-%04d", i), "pkg-" + i, "High", "fixed");
        }

        String csv = mvc.perform(get("/vulns/export.csv?scan=" + s.getId())
                            .with(user("tester").roles("VIEWER")))
                        .andExpect(status().isOk())
                        .andReturn().getResponse().getContentAsString();

        assertThat(csv).startsWith("﻿");
        assertThat(csv).contains("구역");
        // 머리줄 하나 + 탐지 전부.
        assertThat(csv.lines().count()).isEqualTo(VulnQuery.PAGE_SIZE + 20 + 1);
    }
}
