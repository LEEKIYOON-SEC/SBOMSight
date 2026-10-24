package kr.sbomsight;

import jakarta.persistence.EntityManager;
import kr.sbomsight.domain.*;
import kr.sbomsight.repo.*;
import kr.sbomsight.service.ComponentInventoryService;
import kr.sbomsight.service.SbomStorage;
import kr.sbomsight.service.ZoneService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * <b>purl 칸(512자)보다 긴 purl</b> — 칸에는 잘려 담기지만, 패키지 식별자는 자르기 전 purl 로 만든다.
 *
 * <p>잘린 글자로 만들면 칸 뒤로 잘려 나간 한정자를 모른다. 아래 purl 은 받은 곳(버리는 한정자)이 길고
 * classifier 가 뒤에 있다 — 잘린 글자로는 순수 jar({@code pkg:maven/g/a})가 되어, 네이티브 jar 의 탐지에
 * 순수 jar 의 검토 결과 · 조치가 붙는다. 탐지(Finding — grype 의 artifact.purl) · 패키지(Component 생성자
 * · 인벤토리의 일괄 적재) 세 길을 다 본다.
 */
@SpringBootTest
@Transactional
class LongPurlTest {

    static final String FULL = "pkg:maven/g/a@1.0?repository_url=https%3A%2F%2Frepo.example%2F" + "x".repeat(500)
                               + "&classifier=linux-x86_64";
    static final String NATIVE = "pkg:maven/g/a?classifier=linux-x86_64";

    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired ComponentRepository components;
    @Autowired ComponentInventoryService inventory;
    @Autowired SbomStorage storage;
    @Autowired ZoneService zoneService;
    @Autowired JdbcTemplate jdbc;
    @Autowired EntityManager em;

    @Test
    @DisplayName("탐지 — 식별자는 자르기 전 purl 로, 칸에는 잘린 purl · 읽어 와 고쳐 써도 식별자는 그대로")
    void findingKeyComesFromTheWholePurl() {
        Scan scan = scan();
        Finding f = new Finding(scan, "CVE-2023-44487|long", "CVE-2023-44487", "a");
        f.setPackageType("java-archive");
        f.setPackagePurl(FULL);
        f.setSeverity("High");
        long id = findings.saveAndFlush(f).getId();

        String stored = jdbc.queryForObject("SELECT package_purl FROM findings WHERE id = ?", String.class, id);
        assertThat(stored).hasSize(PackageKey.PURL_COLUMN).isEqualTo(FULL.substring(0, PackageKey.PURL_COLUMN));
        assertThat(key("findings", id)).isEqualTo(NATIVE)
                .isNotEqualTo(PackageKey.of(stored, "java-archive", "a"));

        // 읽어 온 엔티티는 자르기 전 purl 을 모른다 — 잘린 칸으로 다시 만들지 않는다.
        em.clear();
        Finding loaded = findings.findById(id).orElseThrow();
        loaded.setSeverity("Critical");
        findings.saveAndFlush(loaded);
        assertThat(key("findings", id)).isEqualTo(NATIVE);
    }

    @Test
    @DisplayName("패키지 — Component 생성자도 인벤토리 일괄 적재도 자르기 전 purl 로")
    void inventoryKeyComesFromTheWholePurl() throws Exception {
        Scan scan = scan();
        Component row = components.saveAndFlush(
                new Component(scan.getAsset(), scan, "a", "1.0", "maven", FULL, ""));
        assertThat(row.getPurl()).hasSize(PackageKey.PURL_COLUMN);
        assertThat(key("component", row.getId())).isEqualTo(NATIVE);

        Scan next = scan();
        Path sbom = Files.createTempFile("long-purl-", ".json");
        try {
            Files.writeString(sbom, """
                    { "artifacts": [ { "name": "a", "version": "1.0", "type": "java-archive", "purl": "%s" } ] }
                    """.formatted(FULL));
            try (ComponentInventoryService.Sink sink = inventory.open(next.getAsset().getId(), next.getId())) {
                storage.inspect(sbom, sink);
            }
        } finally {
            Files.deleteIfExists(sbom);
        }
        assertThat(jdbc.queryForObject("SELECT package_key FROM component WHERE scan_id = ?", String.class, next.getId()))
                .isEqualTo(NATIVE);
        assertThat(jdbc.queryForObject("SELECT CHAR_LENGTH(purl) FROM component WHERE scan_id = ?", Integer.class,
                                       next.getId()))
                .isEqualTo(PackageKey.PURL_COLUMN);
    }

    private String key(String table, long id) {
        return jdbc.queryForObject("SELECT package_key FROM " + table + " WHERE id = ?", String.class, id);
    }

    private Scan scan() {
        Asset asset = new Asset();
        asset.setName("long-purl-" + System.nanoTime());
        asset.setZone(zoneService.unassigned());
        assets.saveAndFlush(asset);
        Scan scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        return scans.saveAndFlush(scan);
    }
}
