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
}
