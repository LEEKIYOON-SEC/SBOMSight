package kr.sbomsight;

import kr.sbomsight.domain.*;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.AuditLogRepository;
import kr.sbomsight.repo.FindingRepository;
import kr.sbomsight.repo.RemediationRepository;
import kr.sbomsight.repo.ScanRepository;
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
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * <b>조치의 현재 버전도 하나로 고르지 않는다</b> (V16).
 *
 * <p>한 자산에 같은 패키지가 두 벌 깔려 있다 — 서로 다른 앱이 들고 온
 * log4j-core 2.14.1 과 2.9.1. 보고서 3장은 두 줄로 따로 싣는데, 조치는 등록한
 * 검사에서 CVSS 가 가장 높은 건의 버전 하나(2.14.1)만 적었다. 2.9.1 은 조치
 * 화면 · CSV · 감사 로그 어디에도 없었다. 목표 버전(V15)과 같은 규칙으로
 * 적는다 — 하나면 그 버전, 여럿이면 `현재 버전 N가지` 와 그 목록(글자 순).
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class CurrentVersionRuleTest {

    /** 글자 순 — 버전 순(2.9.1 → 2.14.1)이 아니다. */
    private static final List<String> BOTH = List.of("2.14.1", "2.9.1");

    @Autowired MockMvc mvc;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired RemediationRepository remediations;
    @Autowired AuditLogRepository audit;
    @Autowired ZoneService zoneService;

    private Asset asset;
    private Scan scan;

    @BeforeEach
    void setUp() {
        Zone zone = zoneService.create("현재버전-" + System.nanoTime(), "#123456", "");
        asset = new Asset();
        asset.setName("curv-" + System.nanoTime());
        asset.setZone(zone);
        assets.saveAndFlush(asset);

        scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        scan.setCreatedAt(Instant.now());
        scans.saveAndFlush(scan);

        finding("CVE-2021-44228", "2.14.1", "10.0");   // CVSS 가 가장 높다 — 앞서는 이것 하나
        finding("CVE-2021-45046", "2.14.1", "9.0");    // 같은 버전이 둘
        finding("CVE-2019-17571", "2.9.1", "9.8");
        scan.setFindingCount(3);
        scans.saveAndFlush(scan);
    }

    private void finding(String cve, String version, String cvss) {
        Finding f = new Finding(scan, cve + "|log4j-core|" + version, cve, "log4j-core");
        f.setPackageVersion(version);
        f.setPackageType("java-archive");
        f.setSeverity("Critical");
        f.setFixState("fixed");
        f.setFixedVersion("2.17.1");
        f.setCvssScore(new BigDecimal(cvss));
        findings.saveAndFlush(f);
    }

    @Test
    @DisplayName("조치 · 조치 목록 · 조치 상세 · 자산의 조치 탭 · CSV · 감사 로그가 두 벌을 다 적는다")
    void everyPlaceListsBothInstalledVersions() throws Exception {
        mvc.perform(post("/assets/" + asset.getId() + "/remediations")
                            .param("packageName", "log4j-core")
                            .with(user("tester").roles("ADMIN")).with(csrf()));
        Remediation opened = remediations
                .findByAssetIdAndPackageName(asset.getId(), "log4j-core").orElseThrow();

        assertThat(opened.getFromVersions())
                .as("CVSS 가 가장 높은 건의 버전 하나만 적었다")
                .containsExactlyElementsOf(BOTH);
        assertThat(opened.getOpenedCount()).as("같은 건에서 모은다 — 등록 당시 건수").isEqualTo(3);

        String described = "현재 버전 2가지: 2.14.1 · 2.9.1";
        assertThat(open("/actions/export.csv")).contains(described);
        assertThat(audit.search(null, AuditEvent.REMEDIATION_CREATED, null, null, "log4j-core",
                                PageRequest.of(0, 5)).getContent())
                .extracting(AuditLog::getDetail)
                .anySatisfy(d -> assertThat(d).contains(described));

        for (String url : List.of("/actions", "/actions/" + opened.getId(),
                                  "/assets/" + asset.getId() + "?tab=actions")) {
            String html = open(url);
            assertThat(html).as(url).contains("현재 버전 2가지");
            BOTH.forEach(v -> assertThat(html).as(url).contains("<span>" + v + "</span>"));
        }
    }

    @Test
    @DisplayName("설치 버전이 하나면 그 버전 — `1가지` 라고 쓰지 않는다")
    void oneInstalledVersionIsTheVersion() throws Exception {
        Finding other = new Finding(scan, "CVE-2099-1|zlib", "CVE-2099-1", "zlib");
        other.setPackageVersion("1.2.11");
        other.setSeverity("High");
        other.setFixState("fixed");
        other.setFixedVersion("1.2.13");
        findings.saveAndFlush(other);

        mvc.perform(post("/assets/" + asset.getId() + "/remediations")
                            .param("packageName", "zlib")
                            .with(user("tester").roles("ADMIN")).with(csrf()));
        Remediation opened = remediations
                .findByAssetIdAndPackageName(asset.getId(), "zlib").orElseThrow();

        assertThat(opened.getFromVersion()).isEqualTo("1.2.11");
        String html = open("/actions/" + opened.getId());
        assertThat(html).contains("<span class=\"ver\">1.2.11</span>").doesNotContain("현재 버전 1가지");
        assertThat(open("/actions/export.csv")).contains("\"zlib\",\"1.2.11\",\"1.2.13\"");
    }

    private String open(String url) throws Exception {
        return mvc.perform(get(url).with(user("tester").roles("ADMIN")))
                  .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
    }
}
