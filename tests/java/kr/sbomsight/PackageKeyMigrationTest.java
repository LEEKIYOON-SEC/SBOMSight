package kr.sbomsight;

import db.migration.V25__package_key_qualifiers;
import jakarta.persistence.EntityManager;
import kr.sbomsight.domain.*;
import kr.sbomsight.repo.*;
import kr.sbomsight.service.ZoneService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.PageRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.transaction.annotation.Transactional;

import javax.sql.DataSource;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * <b>V25 — 패키지 식별자를 새 규칙으로 다시 만든다</b>({@link PackageKey} · 한정자).
 *
 * <p>V24 는 purl 의 한정자를 통째로 버렸다 — classifier 만 다른 netty 네이티브(linux-x86_64)와 순수
 * jar 가 한 식별자였고, 한쪽에 적은 검토 결과 · 연 조치가 다른 쪽에도 붙었다. 다시 만들 때 그 기록이
 * <b>어느 쪽의 것이었는지 가를 근거가 없으면 비운다</b> — 하나를 고르는 것이 곧 임의로 붙이는 것이다.
 *
 * <p>시험의 H2 에는 Flyway 가 돌지 않는다(스키마는 엔티티에서). 마이그레이션의 본체
 * ({@link V25__package_key_qualifiers#reidentify})를 시험의 트랜잭션 연결로 부른다. 진짜 DB 에서
 * Flyway 로 도는 것 · SQL 이 아닌 자바가 벡터와 같은 값을 내는 것은 tests/check-migrations.sh 가 본다.
 *
 * <p>V24 가 남긴 상태를 만든다 — 엔티티는 담을 때 새 식별자를 채우므로, 담은 뒤 칸을 V24 의 값으로
 * 덮는다.
 *
 * <p><b>고친 수({@link V25__package_key_qualifiers.Summary})는 DB 전체의 것이라 여기서 견주지 않는다</b> —
 * 시험의 H2 에는 다른 시험이 커밋해 둔 행이 있다. 기록마다의 결과를 본다. 수는 데이터를 정해 둔
 * tests/check-migrations.sh 가 견준다.
 */
@SpringBootTest
@Transactional
class PackageKeyMigrationTest {

    static final String CVE = "CVE-2023-44487";
    /** V24 의 식별자 — classifier 를 버렸다. 새 규칙에서는 순수 jar 의 것이다. */
    static final String V24_KEY = "pkg:maven/io.netty/netty-transport-native-epoll";
    static final String PLAIN = "pkg:maven/io.netty/netty-transport-native-epoll";
    static final String NATIVE = "pkg:maven/io.netty/netty-transport-native-epoll?classifier=linux-x86_64";
    static final String PLAIN_PURL = "pkg:maven/io.netty/netty-transport-native-epoll@4.1.100.Final";
    static final String NATIVE_PURL = PLAIN_PURL + "?classifier=linux-x86_64";

    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired ComponentRepository components;
    @Autowired FindingAnalysisRepository analysisRows;
    @Autowired RemediationRepository remediations;
    @Autowired ZoneService zoneService;
    @Autowired JdbcTemplate jdbc;
    @Autowired DataSource dataSource;
    @Autowired EntityManager em;

    private Asset asset;
    private int findingNo;

    @BeforeEach
    void setUp() {
        asset = new Asset();
        asset.setName("v25-" + System.nanoTime());
        asset.setZone(zoneService.create("V25-" + System.nanoTime(), "", ""));
        assets.saveAndFlush(asset);
    }

    @Test
    @DisplayName("탐지 · 패키지는 행의 purl 에서 — classifier 가 다른 둘이 다른 식별자가 된다")
    void findingsAndInventoryTakeTheNewKey() throws Exception {
        Scan scan = scan();
        Finding plain = finding(scan, PLAIN_PURL);
        Finding nativeJar = finding(scan, NATIVE_PURL);
        Finding lodash = finding(scan, "pkg:npm/lodash@4.17.20");
        Component plainRow = component(scan, PLAIN_PURL);
        Component nativeRow = component(scan, NATIVE_PURL);
        v24(plain, V24_KEY);
        v24(nativeJar, V24_KEY);
        v24(plainRow, V24_KEY);
        v24(nativeRow, V24_KEY);

        migrate();

        assertThat(key("findings", plain.getId())).isEqualTo(PLAIN);
        assertThat(key("findings", nativeJar.getId())).isEqualTo(NATIVE);
        assertThat(key("findings", lodash.getId())).isEqualTo("pkg:npm/lodash");
        assertThat(key("component", plainRow.getId())).isEqualTo(PLAIN);
        assertThat(key("component", nativeRow.getId())).isEqualTo(NATIVE);
        // 앱이 새로 담는 값과 같다 — 같은 SBOM 을 다시 올린 탐지가 이관한 기록에 이어진다.
        assertThat(key("findings", nativeJar.getId())).isEqualTo(PackageKey.of(NATIVE_PURL, "java-archive", "x"));
    }

    @Test
    @DisplayName("붙던 탐지가 한 변형뿐이면 그 식별자로 옮긴다 — 검토 결과 · 조치")
    void oneVariantTakesTheRecord() throws Exception {
        Scan scan = scan();
        v24(finding(scan, NATIVE_PURL), V24_KEY);
        FindingAnalysis review = notAffected(V24_KEY);
        Remediation remediation = remediation(V24_KEY, scan);

        migrate();

        assertThat(key("finding_analysis", review.getId())).isEqualTo(NATIVE);
        assertThat(key("remediations", remediation.getId())).isEqualTo(NATIVE);
        assertThat(listed(scan)).as("옮긴 해당 없음이 제 탐지를 계속 뺀다").isEmpty();
    }

    @Test
    @DisplayName("붙던 탐지가 두 변형이면 어느 쪽에도 붙이지 않고 비운다 — 둘 다 목록에 돌아온다")
    void twoVariantsLeaveTheRecordUnresolved() throws Exception {
        Scan scan = scan();
        v24(finding(scan, PLAIN_PURL), V24_KEY);
        v24(finding(scan, NATIVE_PURL), V24_KEY);
        FindingAnalysis review = notAffected(V24_KEY);
        Remediation remediation = remediation(V24_KEY, scan);
        assertThat(listed(scan)).as("V24: 한 식별자라 해당 없음 하나가 둘을 다 뺐다").isEmpty();

        migrate();

        assertThat(key("finding_analysis", review.getId()))
                .as("옛 식별자가 새 규칙에서 순수 jar 의 것과 같은 글자여도 그쪽에 남기지 않는다").isNull();
        assertThat(key("remediations", remediation.getId())).isNull();
        assertThat(analysisRows.findById(review.getId())).as("지우지 않는다").isPresent();
        assertThat(listed(scan)).extracting(Finding::getPackageKey).containsExactlyInAnyOrder(PLAIN, NATIVE);
    }

    @Test
    @DisplayName("검토 결과는 그 자산의 검사 전부, 조치는 등록한 검사로 가른다")
    void reviewsLookAtEveryScanRemediationsAtTheirOwn() throws Exception {
        Scan first = scan();
        v24(finding(first, PLAIN_PURL), V24_KEY);
        Scan second = scan();
        v24(finding(second, PLAIN_PURL), V24_KEY);
        v24(finding(second, NATIVE_PURL), V24_KEY);
        FindingAnalysis review = notAffected(V24_KEY);
        Remediation openedFirst = remediation(V24_KEY, first);
        Remediation openedSecond = remediation(V24_KEY, second);

        migrate();

        assertThat(key("finding_analysis", review.getId()))
                .as("두 번째 검사에서 네이티브에도 붙었다 — 어느 쪽에 적은 것인지 모른다").isNull();
        assertThat(key("remediations", openedFirst.getId()))
                .as("등록한 검사에는 순수 jar 뿐이었다 — 조치 대상도 그것이다").isEqualTo(PLAIN);
        assertThat(key("remediations", openedSecond.getId())).isNull();
    }

    @Test
    @DisplayName("옛 식별자가 다른 둘이 한 식별자에 모이면 둘 다 비운다 — 이름 맞춤(PyYAML · pyyaml)")
    void recordsThatNowMeetAreNotMerged() throws Exception {
        Scan scan = scan();
        v24(finding(scan, "pkg:pypi/PyYAML@5.3.1"), "pkg:pypi/PyYAML");
        v24(finding(scan, "pkg:pypi/pyyaml@5.3.1"), "pkg:pypi/pyyaml");
        FindingAnalysis upper = notAffected("pkg:pypi/PyYAML");
        FindingAnalysis lower = notAffected("pkg:pypi/pyyaml");
        Remediation upperFix = remediation("pkg:pypi/PyYAML", scan);
        Remediation lowerFix = remediation("pkg:pypi/pyyaml", scan);

        migrate();   // (자산, 번호, 식별자)의 유일 키에 걸리지 않는다

        assertThat(key("finding_analysis", upper.getId())).isNull();
        assertThat(key("finding_analysis", lower.getId()))
                .as("새 식별자와 같은 글자였던 쪽도 남기지 않는다 — 남기면 다른 쪽을 버린 것이다").isNull();
        assertThat(key("remediations", upperFix.getId())).isNull();
        assertThat(key("remediations", lowerFix.getId())).isNull();
        assertThat(listed(scan)).extracting(Finding::getPackageKey)
                                .containsExactly("pkg:pypi/pyyaml", "pkg:pypi/pyyaml");
    }

    @Test
    @DisplayName("한 기록의 옛 식별자가 다른 기록의 새 식별자여도 유일 키에 걸리지 않는다")
    void keysThatTradePlacesDoNotCollide() throws Exception {
        Scan scan = scan();
        String encoded = "pkg:maven/io%2Enetty/netty-transport-native-epoll";   // V24 는 적힌 글자 그대로
        v24(finding(scan, encoded + "@4.1.100.Final"), encoded);
        v24(finding(scan, NATIVE_PURL), V24_KEY);
        // 먼저 적은 쪽(id 가 작은 쪽)이 다른 쪽의 지금 식별자(PLAIN)로 간다 — 한 줄씩 바꾸면 겹친다.
        FindingAnalysis toPlain = notAffected(encoded);
        FindingAnalysis toNative = notAffected(V24_KEY);

        migrate();

        assertThat(key("finding_analysis", toPlain.getId())).isEqualTo(PLAIN);
        assertThat(key("finding_analysis", toNative.getId())).isEqualTo(NATIVE);
    }

    /**
     * <b>앞서 칸(512자)에서 잘린 채 담긴 purl</b> — 원래 purl 을 되살릴 수 없다. 잘린 글자로는 순수 jar
     * 이지만 칸 뒤로 classifier 가 잘려 나갔을 수 있다. 정상 식별자 어느 것과도 겹치지 않게 표시를 단
     * 식별자를 준다. 그 행에 붙던 기록은 같은 규칙으로 가른다 — 붙던 탐지가 잘린 행뿐이면 그 식별자로
     * 옮기고(붙던 탐지 그대로다), 순수 jar 와 함께 붙던 것은 비운다.
     */
    @Test
    @DisplayName("잘린 채 담긴 purl 은 표시를 단 식별자 · 그 행에만 붙던 기록은 따라가고 순수 jar 와 섞인 것은 비운다")
    void clippedPurlsAreNotReadAsWholePurls() throws Exception {
        String stored = ("pkg:maven/io.netty/netty-transport-native-epoll@4.1.100.Final?repository_url="
                         + "https%3A%2F%2Frepo.example%2F" + "x".repeat(600)).substring(0, PackageKey.PURL_COLUMN);
        String marked = "pkg:maven/io.netty/netty-transport-native-epoll#truncated";
        Scan scan = scan();
        Finding clippedRow = finding(scan, stored);
        Finding plainRow = finding(scan, PLAIN_PURL);
        Finding clippedOther = finding(scan, stored, "CVE-2023-99999");
        Component inventoryRow = component(scan, stored);
        v24(clippedRow, V24_KEY);
        v24(plainRow, V24_KEY);
        v24(clippedOther, V24_KEY);
        v24(inventoryRow, V24_KEY);
        FindingAnalysis mixed = notAffected(V24_KEY);                       // 잘린 행과 순수 jar 에 붙던 것
        FindingAnalysis onlyClipped = notAffected(V24_KEY, "CVE-2023-99999"); // 잘린 행에만 붙던 것
        Remediation remediation = remediation(V24_KEY, scan);

        migrate();

        assertThat(key("findings", clippedRow.getId())).isEqualTo(marked)
                .isEqualTo(PackageKey.truncated(stored, "java-archive", "x"));
        assertThat(key("findings", clippedOther.getId())).isEqualTo(marked);
        assertThat(key("findings", plainRow.getId())).isEqualTo(PLAIN);
        assertThat(key("component", inventoryRow.getId())).isEqualTo(marked);
        assertThat(key("finding_analysis", mixed.getId())).isNull();
        assertThat(key("finding_analysis", onlyClipped.getId())).isEqualTo(marked);
        assertThat(key("remediations", remediation.getId())).isNull();
        assertThat(migrate()).as("다시 돌려도 같다 — 표시를 단 식별자를 다시 만들지 않는다")
                             .isEqualTo(new V25__package_key_qualifiers.Summary(0, 0, 0, 0, 0, 0));
    }

    @Test
    @DisplayName("붙던 탐지가 남아 있지 않으면 비운다 · 이미 비운 것과 바뀌지 않는 것은 그대로 · 다시 돌려도 같다")
    void evidenceDecidesAndRerunsChangeNothing() throws Exception {
        Scan scan = scan();
        finding(scan, "pkg:npm/lodash@4.17.20");
        FindingAnalysis same = notAffected("pkg:npm/lodash");
        FindingAnalysis orphan = notAffected(V24_KEY);   // 그 검사를 지웠다
        FindingAnalysis legacy = notAffected(null);       // V24 가 비운 것
        Remediation orphanFix = remediation(V24_KEY, null);

        migrate();

        assertThat(key("finding_analysis", same.getId())).isEqualTo("pkg:npm/lodash");
        assertThat(key("finding_analysis", orphan.getId())).isNull();
        assertThat(key("finding_analysis", legacy.getId())).isNull();
        assertThat(key("remediations", orphanFix.getId())).isNull();

        // DB 전체에서 — 다른 시험이 남긴 행까지 이미 새 규칙이다.
        assertThat(migrate()).as("두 번째는 바꿀 것이 없다")
                             .isEqualTo(new V25__package_key_qualifiers.Summary(0, 0, 0, 0, 0, 0));
    }

    // -----------------------------------------------------------------------

    private V25__package_key_qualifiers.Summary migrate() throws Exception {
        em.flush();
        V25__package_key_qualifiers.Summary summary =
                V25__package_key_qualifiers.reidentify(DataSourceUtils.getConnection(dataSource));
        em.clear();   // 엔티티가 옛 식별자를 들고 있지 않게
        return summary;
    }

    private String key(String table, Long id) {
        return jdbc.queryForObject("SELECT package_key FROM " + table + " WHERE id = ?", String.class, id);
    }

    private void v24(Finding f, String key) {
        jdbc.update("UPDATE findings SET package_key = ? WHERE id = ?", key, f.getId());
    }

    private void v24(Component c, String key) {
        jdbc.update("UPDATE component SET package_key = ? WHERE id = ?", key, c.getId());
    }

    /** 해당 없음 · 오탐을 빼고 남은 탐지. */
    private List<Finding> listed(Scan scan) {
        em.flush();
        return findings.findInBySeverity(List.of(scan.getId()), null, null, null, null, null,
                                         false, false, PageRequest.of(0, 10)).getContent();
    }

    private Scan scan() {
        Scan scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        scan.setCreatedAt(Instant.now());
        return scans.saveAndFlush(scan);
    }

    private Finding finding(Scan scan, String purl) {
        return finding(scan, purl, CVE);
    }

    private Finding finding(Scan scan, String purl, String cve) {
        String coordinates = purl.substring(0, purl.indexOf('@'));
        String name = coordinates.substring(coordinates.lastIndexOf('/') + 1);
        // 탐지 키에 차례를 붙인다 — (검사, 키) 유일 키는 MariaDB 에서 대소문자를 가리지 않아
        // PyYAML · pyyaml 의 purl 만으로는 겹친다. 긴 purl 은 칸(512)을 넘지 않게 해시로.
        Finding f = new Finding(scan, cve + "|" + purl.hashCode() + "|" + (++findingNo), cve, name);
        f.setPackageVersion(purl.substring(purl.indexOf('@') + 1).replaceAll("\\?.*", ""));
        f.setPackageType(purl.startsWith("pkg:maven/") ? "java-archive" : purl.startsWith("pkg:npm/") ? "npm" : "python");
        f.setPackagePurl(purl);
        f.setSeverity("High");
        f.setFixState("fixed");
        f.setFixedVersion("9.9");
        return findings.saveAndFlush(f);
    }

    private Component component(Scan scan, String purl) {
        String coordinates = purl.substring(0, purl.indexOf('@'));
        String name = coordinates.substring(coordinates.lastIndexOf('/') + 1);
        return components.saveAndFlush(new Component(asset, scan, name, "4.1.100.Final", "maven", purl, ""));
    }

    /** V24 가 남긴 해당 없음 — 식별자는 V24 의 것(비었으면 V24 가 가르지 못한 것). */
    private FindingAnalysis notAffected(String v24Key) {
        return notAffected(v24Key, CVE);
    }

    private FindingAnalysis notAffected(String v24Key, String cve) {
        FindingAnalysis review = new FindingAnalysis(asset, cve, "x", v24Key);
        review.setState(AnalysisState.NOT_AFFECTED);
        review.setJustification(AnalysisJustification.CODE_NOT_REACHABLE);
        review.setUpdatedBy("tester");
        return analysisRows.saveAndFlush(review);
    }

    private Remediation remediation(String v24Key, Scan opened) {
        Remediation remediation = new Remediation(asset, "x", v24Key, "tester");
        remediation.setOpenedScanId(opened == null ? null : opened.getId());
        return remediations.saveAndFlush(remediation);
    }
}
