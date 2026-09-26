package kr.sbomsight;

import kr.sbomsight.domain.Asset;
import kr.sbomsight.domain.Scan;
import kr.sbomsight.domain.ScanStatus;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.ScanRepository;
import kr.sbomsight.service.ZoneService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * <b>취약점 CSV 는 걸린 것 전부를 담는다 — 말없이 자르지 않는다.</b>
 *
 * <p>앞서 내려받기가 {@code PageRequest.of(0, 100_000)} 한 번이었다. 10만 건을
 * 넘으면 파일이 거기서 끝났고, 잘렸다는 표시도 없었다. 서버 한 대가 5만 건을
 * 내는 일이 있어(FindingRepository 머리 주석) 전체 범위로 받으면 넘는다 —
 * 잘린 파일로 결재를 올리면 빠진 건은 아무도 모른다.
 *
 * <p>이제 나눠 읽어(2,000건씩) 흘려 쓴다. 한 번에 다 올리면 탐지마다 붙은
 * 설명 · 원문(실측 평균 1.1KB)까지 메모리에 함께 오른다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class VulnExportTest {

    private static final int ROWS = 100_001;

    @Autowired MockMvc mvc;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired ZoneService zoneService;
    @Autowired JdbcTemplate jdbc;

    @Test
    @DisplayName("10만 건을 넘어도 CSV 가 전부를 한 번씩 담는다")
    void theCsvCarriesEveryRowOnce() throws Exception {
        Asset asset = new Asset();
        asset.setName("export-" + System.nanoTime());
        asset.setZone(zoneService.unassigned());
        assets.saveAndFlush(asset);
        Scan scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        scan.setCreatedAt(Instant.now());
        scans.saveAndFlush(scan);

        // 엔티티로 10만 번 저장하면 시험 하나가 몇 분이다. 행만 넣는다.
        List<Object[]> rows = new ArrayList<>(ROWS);
        for (int i = 0; i < ROWS; i++) {
            // 같은 CVE · 같은 패키지를 여럿 둔다 — 정렬 값이 같은 줄이 쪽 경계에
            // 걸려도 빠지거나 두 번 나오지 않아야 한다. 설치 버전은 정렬 축이
            // 아니고 CSV 에 찍힌다 — 줄마다 달라 겹침을 셀 수 있다.
            rows.add(new Object[] { scan.getId(), "k" + i, "CVE-2099-" + (i % 7),
                                    "pkg-" + (i % 3), "High", "1." + i });
        }
        jdbc.batchUpdate("INSERT INTO findings (scan_id, finding_key, cve, package_name, severity, "
                         + "related_cve, cvss_vector, cvss_version, package_version, package_type, "
                         + "package_purl, package_language, install_path, fix_state, fixed_version, "
                         + "version_constraint, match_type, matcher, namespace, data_source) "
                         + "VALUES (?, ?, ?, ?, ?, '', '', '', ?, '', '', '', '', 'fixed', '9.9', "
                         + "'', '', '', '', '')", rows);

        byte[] body = mvc.perform(get("/vulns/export.csv?scan=" + scan.getId())
                                          .with(user("tester").roles("VIEWER")))
                         .andReturn().getResponse().getContentAsByteArray();
        List<String> lines = new String(body, StandardCharsets.UTF_8).lines().toList();

        assertThat(lines.size() - 1)
                .as("머리줄을 뺀 줄 수 — 10만 건에서 말없이 잘렸다")
                .isEqualTo(ROWS);
        assertThat(lines.stream().skip(1).distinct().count())
                .as("같은 줄이 두 번 나왔다 — 나눠 읽는 경계에서 겹쳤다")
                .isEqualTo(ROWS);
    }

    /**
     * <b>심각도 · 수정 상태는 화면 말로 적고, 원문은 맨 뒤 칸에 따로 둔다.</b>
     *
     * <p>앞서 두 칸에 검사 결과의 글자({@code Critical} · {@code wont-fix})가
     * 그대로 나갔다. 화면은 같은 건을 {@code 심각} · {@code 수정 버전 없음} 이라
     * 부르므로, 파일을 결재에 붙이면 한 건을 두 말로 부른다. 원문은 버리지
     * 않는다 — {@code wont-fix} 와 {@code not-fixed} 는 화면에서 둘 다
     * {@code 수정 버전 없음} 인데 그 차이가 필요한 사람이 있다.
     */
    @Test
    @DisplayName("심각도 · 수정 상태는 화면 말로, 원문은 맨 뒤 두 칸에")
    void severityAndFixStateUseScreenWordsAndKeepTheRaw() throws Exception {
        Scan scan = scanOfNewAsset();
        insert(scan, "CVE-2099-0001", "Critical", "fixed", "1.1");
        insert(scan, "CVE-2099-0002", "Negligible", "wont-fix", "");
        insert(scan, "CVE-2099-0003", "High", "not-fixed", "");
        insert(scan, "CVE-2099-0004", "", "unknown", "");
        // 수정됐다고는 하는데 버전이 비었다 — 화면은 `확인 필요` 로 적는다.
        insert(scan, "CVE-2099-0005", "Unknown", "fixed", "");

        List<String> lines = new String(mvc.perform(get("/vulns/export.csv?scan=" + scan.getId())
                                                            .with(user("tester").roles("VIEWER")))
                                           .andReturn().getResponse().getContentAsByteArray(),
                                       StandardCharsets.UTF_8).lines().toList();
        List<String> header = cells(lines.get(0).replace("﻿", ""));
        assertThat(header).containsExactly("자산", "구역", "CVE", "별칭", "심각도", "CVSS", "패키지",
                "설치 버전", "수정 버전", "수정 상태", "검사 시각", "심각도 원문", "수정 상태 원문");

        assertThat(row(lines, header, "CVE-2099-0001"))
                .containsExactly("심각", "수정 버전 있음", "Critical", "fixed");
        assertThat(row(lines, header, "CVE-2099-0002"))
                .containsExactly("무시 가능", "수정 버전 없음", "Negligible", "wont-fix");
        assertThat(row(lines, header, "CVE-2099-0003"))
                .containsExactly("높음", "수정 버전 없음", "High", "not-fixed");
        assertThat(row(lines, header, "CVE-2099-0004"))
                .containsExactly("미확인", "확인 필요", "", "unknown");
        assertThat(row(lines, header, "CVE-2099-0005"))
                .containsExactly("미확인", "확인 필요", "Unknown", "fixed");
    }

    /**
     * 화면도 같은 말이다. 앞서 목록 · CVE별 · CVE 상세는 네 단계만 우리말로
     * 적고 {@code Negligible} · {@code Unknown} 은 원문 그대로 찍었다 — 보고서와
     * 패키지 화면은 같은 값을 {@code 무시 가능} · {@code 미확인} 이라 불렀다.
     */
    @Test
    @DisplayName("목록 · CVE별 · CVE 상세의 심각도도 무시 가능 · 미확인으로 적는다")
    void theScreensUseTheSameSeverityWords() throws Exception {
        Scan scan = scanOfNewAsset();
        insert(scan, "CVE-2099-0006", "Negligible", "fixed", "1.1");
        insert(scan, "CVE-2099-0007", "Unknown", "fixed", "1.1");

        for (String path : List.of("/vulns?scan=" + scan.getId(),
                                   "/vulns?scan=" + scan.getId() + "&group=cve",
                                   "/vulns/CVE-2099-0006", "/vulns/CVE-2099-0007")) {
            String html = mvc.perform(get(path).with(user("tester").roles("VIEWER")))
                             .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
            assertThat(html).as(path)
                    .doesNotContainPattern(">\\s*Negligible\\s*<")
                    .doesNotContainPattern(">\\s*Unknown\\s*<");
            if (!path.endsWith("0007")) {
                assertThat(html).as(path).contains("무시 가능");
            }
            if (!path.endsWith("0006")) {
                assertThat(html).as(path).contains("미확인");
            }
        }
    }

    // --- 씨앗 · 읽기 ------------------------------------------------------------

    private Scan scanOfNewAsset() {
        Asset asset = new Asset();
        asset.setName("words-" + System.nanoTime());
        asset.setZone(zoneService.unassigned());
        assets.saveAndFlush(asset);
        Scan scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        scan.setCreatedAt(Instant.now());
        return scans.saveAndFlush(scan);
    }

    private void insert(Scan scan, String cve, String severity, String fixState, String fixedVersion) {
        jdbc.update("INSERT INTO findings (scan_id, finding_key, cve, package_name, severity, "
                    + "related_cve, cvss_vector, cvss_version, package_version, package_type, "
                    + "package_purl, package_language, install_path, fix_state, fixed_version, "
                    + "version_constraint, match_type, matcher, namespace, data_source) "
                    + "VALUES (?, ?, ?, 'zlib', ?, '', '', '', '1.0', '', '', '', '', ?, ?, "
                    + "'', '', '', '', '')",
                    scan.getId(), cve + "|zlib", cve, severity, fixState, fixedVersion);
    }

    /** 이 시험의 값에는 쉼표 · 따옴표가 없다 — 칸 사이 {@code ","} 로 자른다. */
    private static List<String> cells(String line) {
        return List.of(line.substring(1, line.length() - 1).split("\",\"", -1));
    }

    /** 그 CVE 줄의 심각도 · 수정 상태 · 심각도 원문 · 수정 상태 원문. */
    private static List<String> row(List<String> lines, List<String> header, String cve) {
        List<String> cells = lines.stream().skip(1).map(VulnExportTest::cells)
                .filter(c -> c.get(header.indexOf("CVE")).equals(cve))
                .findFirst().orElseThrow();
        return List.of(cells.get(header.indexOf("심각도")), cells.get(header.indexOf("수정 상태")),
                       cells.get(header.indexOf("심각도 원문")), cells.get(header.indexOf("수정 상태 원문")));
    }
}
