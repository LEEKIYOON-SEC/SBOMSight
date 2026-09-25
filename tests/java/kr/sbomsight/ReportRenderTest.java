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

        String html = mvc.perform(get("/reports/scan/" + scan.getId()).with(user("tester").roles("ADMIN")))
                         .andExpect(status().isOk())
                         .andReturn().getResponse().getContentAsString();

        assertThat(html).contains("2.3 접근 경로");
        // 셋 중 둘이 AV:N/PR:N/UI:N 이다 (requests 는 UI:R).
        assertThat(html).contains("원격 접근");
        // 약어는 표 안이 아니라 표 아래 각주 한 줄로 푼다.
        assertThat(html).contains("AV:N / PR:N / UI:N");
    }

    /**
     * {@code 조치 대상} 의 <b>비고</b> 칸은 줄로 쌓는다.
     *
     * <p>두 값을 한 줄에 흘려 두었더니 칸이 좁아졌을 때 딱지가
     * {@code 실/제/악/용} 으로 한 글자씩 세로로 쪼개졌다 — 한국어는 글자
     * 단위로 줄바꿈된다. 칸에 {@code remark} 를 붙여
     * {@code white-space: nowrap} 을 걸고, 값마다 {@code <div>} 로 쌓는다.
     *
     * <p>여기서 잴 수 있는 것은 <b>markup</b> 까지다. 실제 픽셀은
     * {@code tests/check-rows.py} 와 화면에서 본다.
     */
    @Test
    @DisplayName("조치 대상의 비고는 줄로 쌓는다")
    void remarkCellStacks() throws Exception {
        Scan scan = seed(true);

        String html = mvc.perform(get("/reports/scan/" + scan.getId()).with(user("tester").roles("ADMIN")))
                         .andExpect(status().isOk())
                         .andReturn().getResponse().getContentAsString();

        assertThat(html).contains("<td class=\"remark\">");
        // 딱지가 `<td>` 에 바로 붙어 있으면 옛 모양이다 — 줄로 감싸야 한다.
        assertThat(html)
                .as("딱지는 `<div>` 안에 든다")
                .doesNotContain("<td class=\"remark\">\n          <span");
    }

    /**
     * <b>구역 보고서의 `비고` 도 같다.</b>
     *
     * <p>앞 판에 자산 보고서만 고치고 여기를 빼먹었다. 쓰는 사람이 커널이
     * 걸린 구역 보고서를 열어 `실/제/악/용` 이 세로로 쪼개진 것을 다시
     * 보냈다. <b>같은 것을 두 군데 두면 한쪽만 고치는 날이 온다.</b>
     * 그래서 두 보고서를 한 시험에서 함께 본다.
     */
    @Test
    @DisplayName("구역 보고서의 비고도 줄로 쌓는다")
    void zoneRemarkCellStacks() throws Exception {
        Zone zone = zoneService.create("비고-" + System.nanoTime(), "#123456", "");
        doneToday(assetIn(zone, "web"), "openssl", "3.0.7");

        String html = mvc.perform(get("/reports/zone").param("zone", zone.getId().toString())
                                                     .with(user("tester").roles("ADMIN")))
                         .andExpect(status().isOk())
                         .andReturn().getResponse().getContentAsString();

        assertThat(html).contains("<td class=\"remark\">");
        assertThat(html)
                .as("딱지는 `<div>` 안에 든다")
                .doesNotContain("<td class=\"remark\">\n            <span");
    }

    /**
     * <b>장 번호가 건너뛰지 않는다.</b>
     *
     * <p>4장(`수정 버전 없는 항목`)과 5장(`조치 진행 현황`)을 비면 통째로
     * 감추고 있었다. 실제 자료에서 `1 · 2 · 3 · 5 · 6` 으로 나왔다 —
     * 결재로 올라가는 문서에서 번호가 비면 읽는 사람은 빠진 장을 찾는다.
     *
     * <p>더 나쁜 것은 <b>세는 단위가 다른 것이 가려졌다</b>는 점이다.
     * 2.2 는 `건` 으로 `수정 버전 없음 12` 라고 적는데, 4장은 <b>한 건도
     * 올릴 수 없는 패키지</b>만 센다. 4장이 사라지면 그 12건이 어디로
     * 갔는지 문서 안에 답이 없다.
     *
     * <p>세 가지로 돌린다 — 4장만 빈 것 · 5장만 빈 것 · 둘 다 찬 것.
     */
    @Test
    @DisplayName("장 번호가 1부터 6까지 건너뛰지 않는다")
    void chapterNumbersNeverSkip() throws Exception {
        // ① 4장만 빔 — 패키지 하나에 고칠 수 있는 건과 없는 건이 섞여 있다.
        //    (패키지 전체가 막힌 것은 없으므로 4장은 비지만 2.2 는 1건을 센다)
        String mixed = report(seedPackages("openssl", "fixed", "openssl", "not-fixed"));
        assertChaptersRunTo(mixed, 6);
        assertThat(mixed)
                .as("4장이 비어도 2.2 의 건수가 어디로 갔는지 말한다")
                .contains("3장 패키지에 섞임");

        // ② 5장만 빔 — 고칠 수 있는 것이 하나도 없으니 조치 대상이 안 잡힌다.
        assertChaptersRunTo(report(seedPackages("glibc", "not-fixed")), 6);

        // ③ 둘 다 참.
        assertChaptersRunTo(report(seed(true)), 6);
    }

    /** 장 제목의 번호가 1부터 {@code last} 까지 빠짐없이 있는가. */
    private void assertChaptersRunTo(String html, int last) {
        for (int n = 1; n <= last; n++) {
            assertThat(html).as("%d장이 없다 — 번호가 건너뛴다", n).contains("<h2>" + n + ". ");
        }
    }

    private String report(Scan scan) throws Exception {
        return mvc.perform(get("/reports/scan/" + scan.getId()).with(user("tester").roles("ADMIN")))
                  .andExpect(status().isOk())
                  .andReturn().getResponse().getContentAsString();
    }

    /** {@code 패키지명, 수정 상태} 쌍을 그대로 담은 검사 하나. */
    private Scan seedPackages(String... pairs) {
        Asset asset = new Asset();
        asset.setName("chapters-" + System.nanoTime());
        asset.setZone(zoneService.unassigned());
        assets.save(asset);

        Scan scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        scan.setSbomFilename("sbom.json");
        scans.saveAndFlush(scan);

        for (int i = 0; i < pairs.length; i += 2) {
            String pkg = pairs[i];
            String fixState = pairs[i + 1];
            Finding f = new Finding(scan, "CVE-2000-" + i + "|" + pkg, "CVE-2000-" + i, pkg);
            f.setPackageVersion("1.0.0");
            f.setPackageType("rpm");
            f.setSeverity("High");
            f.setFixState(fixState);
            f.setFixedVersion("fixed".equals(fixState) ? "1.0.1" : "");
            f.setCvssScore(BigDecimal.valueOf(7.5));
            findings.save(f);
        }
        scan.setMatchCount(pairs.length / 2);
        scan.setFindingCount(pairs.length / 2);
        scans.saveAndFlush(scan);
        return scan;
    }

    /**
     * `조치 진행 현황` 에 <b>머리만 있는 빈 표</b>가 남지 않는다.
     *
     * <p>등록된 조치만 싣기로 하면서 조건을 {@code rows.isEmpty()} 에
     * 걸었는데, 그 목록은 <b>미등록까지 들고 있어서 거의 비지 않는다.</b>
     * 그래서 등록이 하나도 없을 때 열 머리만 있고 줄이 없는 표가 남았다 —
     * 띄워서 보고 찾았다. 가르는 것은 <b>실을 조치가 있는가</b>다.
     *
     * <p>미등록이 몇 개 · 몇 건인지는 세 갈래 표(대기 · 진행 / 완료 · 탐지
     * 남음 / 미등록)가 말한다. 앞서는 `※ 해당 없음 — 등록된 조치 없음 ·
     * 미등록 2개 패키지` 각주 한 줄이었다.
     */
    @Test
    @DisplayName("등록된 조치가 없으면 조치 표를 그리지 않는다")
    void progressShowsNoEmptyTable() throws Exception {
        // 조치 대상은 있고(고칠 수 있는 패키지) 등록된 조치는 없는 상태.
        Scan scan = seedPackages("openssl", "fixed", "curl", "fixed");

        String html = report(scan);

        assertThat(html).contains("<h2>5. 조치 진행 현황</h2>");
        String chapter5 = html.substring(html.indexOf("<h2>5. 조치 진행 현황</h2>"),
                                         html.indexOf("<h2>6."));
        // 5장 안에 `<th>담당</th>` 이 있으면 조치 표가 그려진 것이다.
        assertThat(chapter5)
                .as("빈 표가 남아 있다")
                .doesNotContain("<th class=\"tight\">담당</th>");
        assertThat(chapter5.replaceAll("\\s+", " "))
                .as("몇 개 · 몇 건이 미등록인지는 남긴다")
                .contains("<td class=\"tight\">미등록</td> <td class=\"num tight\">2개</td>")
                .contains("2건");
    }

    /**
     * 벡터가 하나도 없는 스캔(옛 grype·다른 자문 DB)에서도 터지지 않아야 한다.
     * 그럴 때 노출면 문단은 "0건"이라고 말하는 대신 빠진다.
     */
    @Test
    @DisplayName("벡터가 없어도 보고서가 뜬다")
    void rendersWithoutVectors() throws Exception {
        Scan scan = seed(false);

        mvc.perform(get("/reports/scan/" + scan.getId()).with(user("tester").roles("ADMIN")))
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

        mvc.perform(get("/reports/scan/" + scan.getId()).with(user("tester").roles("ADMIN")))
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

        String html = mvc.perform(get("/reports/zone").param("zone", zone.getId().toString())
                                                     .with(user("tester").roles("ADMIN")))
                         .andExpect(status().isOk())
                         .andReturn().getResponse().getContentAsString();

        // 몇 대를 안 봤는지가 이 보고서에서 가장 먼저 읽혀야 하는 문장이다.
        assertThat(html).contains("1대는 이 기간에 검사 기록이 없습니다");
        assertThat(html).contains(missed.getName());
        // 구역 단위로만 나오는 값 — 같은 패키지가 몇 대에 걸려 있는가.
        // 표가 `2대` 로 쓰므로 각주도 `2대 이상 공통` 이다. 한쪽은 `두 대`,
        // 다른 쪽은 `2대` 로 쓰면 같은 것을 두 모양으로 부르게 된다 (§4.0.2).
        assertThat(html).contains("2대");
        assertThat(html).contains("2대 이상 공통");
    }

    /**
     * 구역 보고서도 장 번호가 건너뛰지 않는다.
     *
     * <p>5장(`수정 버전 없는 항목`)만 조건부였다. 고칠 수 있는 것만 걸린
     * 구역에서는 `4 · 6 · 7` 로 나왔다.
     */
    @Test
    @DisplayName("구역 보고서의 장 번호도 건너뛰지 않는다")
    void zoneChapterNumbersNeverSkip() throws Exception {
        Zone zone = zoneService.create("장번호-" + System.nanoTime(), "#123456", "");
        // 전부 고칠 수 있는 것 — 5장에 실을 것이 없다.
        doneToday(assetIn(zone, "web"), "openssl", "3.0.7");

        String html = mvc.perform(get("/reports/zone").param("zone", zone.getId().toString())
                                                     .with(user("tester").roles("ADMIN")))
                         .andExpect(status().isOk())
                         .andReturn().getResponse().getContentAsString();

        assertChaptersRunTo(html, 7);
    }

    @Test
    @DisplayName("기간 안에 검사가 없는 구역도 500 이 아니다")
    void rendersZoneReportWithNoScans() throws Exception {
        Zone zone = zoneService.create("빈구역-" + System.nanoTime(), "", "");
        assetIn(zone, "web");

        mvc.perform(get("/reports/zone").param("zone", zone.getId().toString())
                                       .with(user("tester").roles("ADMIN")))
           .andExpect(status().isOk());
    }

    @Test
    @DisplayName("자산이 하나도 없는 구역도 뜬다")
    void rendersZoneReportWithNoAssets() throws Exception {
        Zone zone = zoneService.create("무자산-" + System.nanoTime(), "", "");

        String html = mvc.perform(get("/reports/zone").param("zone", zone.getId().toString())
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

        String html = mvc.perform(get("/reports/zone").with(user("tester").roles("ADMIN")))
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
        String html = mvc.perform(get("/reports/zone")
                                          .param("from", "2026-09-30").param("to", "2026-09-01")
                                          .with(user("tester").roles("ADMIN")))
                         .andExpect(status().isOk())
                         .andReturn().getResponse().getContentAsString();

        // 말없이 빈 보고서를 내면 "이 구역은 깨끗하다" 로 읽힌다.
        assertThat(html).contains("두 날짜를 바꿨습니다");
        assertThat(html).contains("2026년 9월 1일");
    }
}
