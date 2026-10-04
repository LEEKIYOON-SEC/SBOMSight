package kr.sbomsight;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import kr.sbomsight.domain.*;
import kr.sbomsight.repo.*;
import kr.sbomsight.service.ZoneService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 보고서 발행 (R11 · D6).
 *
 * <p><b>무엇이 문제였나.</b> 보고서는 열 때마다 지금 데이터로 다시 계산됐다(재현 시험 P8).
 * 결재에 올린 뒤 검토 결과를 하나 적거나 자산을 운영 종료하면, 같은 검사 · 같은 기간의
 * 보고서가 다른 숫자를 냈다 — 결재 문서의 근거가 남지 않았다. 문서 정보의 `작성자` ·
 * `작성일` 은 보고서를 연 사람과 연 날이었다.
 *
 * <p>여기서 보는 것:
 * <ol>
 *   <li>발행하면 그때 그린 문서와 계산 결과가 저장되고, 데이터가 바뀌어도 그대로다(P8 뒤집기)</li>
 *   <li>발행본은 볼 때마다 해시를 다시 대조한다 — 맞지 않으면 보이지 않는다</li>
 *   <li>발행 번호는 연도-일련번호 · 결재 문서 번호는 발행 뒤에 적고 이력이 남는다</li>
 *   <li>발행본이 가리키는 검사는 지우지 못하고, 자산을 지워도 발행본은 남는다</li>
 *   <li>발행하지 않은 보고서는 `초안 (발행 전)` · `출력자` · `출력 시각` 이다</li>
 * </ol>
 *
 * <p><b>고치기 전 코드에서 돈다.</b> 새 클래스를 부르지 않는다 — 주소와 표만 본다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class PublicationTest {

    @Autowired MockMvc mvc;
    @Autowired JdbcTemplate jdbc;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired ZoneService zoneService;
    @PersistenceContext EntityManager em;

    private static final ObjectMapper JSON = new ObjectMapper();

    // --- 자료 -----------------------------------------------------------------

    private Asset asset(Zone zone, String name) {
        Asset a = new Asset();
        a.setName(name + "-" + System.nanoTime());
        a.setZone(zone);
        return assets.saveAndFlush(a);
    }

    /** 완료 검사 하나 — 패키지마다 고칠 수 있는 탐지 한 건. */
    private Scan done(Asset asset, Instant at, String... packages) {
        Scan scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        scan.setGrypeVersion("0.87.0");
        scan.setSbomFilename("sbom.json");
        scan.setCreatedAt(at);
        scans.saveAndFlush(scan);
        int i = 0;
        for (String pkg : packages) {
            String cve = "CVE-2099-" + (1000 + i++);
            Finding f = new Finding(scan, cve + "|" + pkg, cve, pkg);
            f.setPackageVersion("1.0.0");
            f.setPackageType("rpm");
            f.setSeverity("High");
            f.setFixState("fixed");
            f.setFixedVersion("1.0.1");
            f.setCvssScore(BigDecimal.valueOf(7.5));
            f.setCvssVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
            findings.saveAndFlush(f);
        }
        scan.setMatchCount(packages.length);
        scan.setFindingCount(packages.length);
        return scans.saveAndFlush(scan);
    }

    private static Instant ago(int days) {
        return Instant.now().minus(days, ChronoUnit.DAYS);
    }

    // --- 요청 -----------------------------------------------------------------

    private String open(String url) throws Exception {
        return mvc.perform(get(url).with(user("tester").roles("ADMIN")))
                  .andExpect(status().isOk())
                  .andReturn().getResponse().getContentAsString();
    }

    /** 발행하고 발행본 번호(행 id)를 돌려준다. */
    private long publishScan(Scan scan) throws Exception {
        MvcResult r = mvc.perform(post("/reports/scan/" + scan.getId() + "/publish")
                                          .with(user("tester").roles("ADMIN")).with(csrf()))
                         .andExpect(redirectedUrlPattern("/reports/publications/*"))
                         .andReturn();
        return idOf(r);
    }

    private long publishZone(Zone zone, LocalDate from, LocalDate to) throws Exception {
        MvcResult r = mvc.perform(post("/reports/zone/publish")
                                          .param("zone", zone.getId().toString())
                                          .param("from", from.toString()).param("to", to.toString())
                                          .with(user("tester").roles("ADMIN")).with(csrf()))
                         .andExpect(redirectedUrlPattern("/reports/publications/*"))
                         .andReturn();
        return idOf(r);
    }

    private static long idOf(MvcResult r) {
        String url = r.getResponse().getRedirectedUrl();
        return Long.parseLong(url.substring(url.lastIndexOf('/') + 1));
    }

    private Map<String, Object> row(long id) {
        return jdbc.queryForMap("SELECT * FROM report_publications WHERE id = ?", id);
    }

    private String number(long id) {
        Map<String, Object> r = row(id);
        return "%d-%04d".formatted(((Number) r.get("pub_year")).intValue(),
                                   ((Number) r.get("pub_seq")).intValue());
    }

    private static String sha256(String text) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                                                     .digest(text.getBytes(StandardCharsets.UTF_8)));
    }

    // --- 초안 -----------------------------------------------------------------

    /**
     * 발행하지 않은 보고서는 초안이다 — 그리고 문서 정보의 사람 · 날짜는 <b>여는 사람 ·
     * 여는 시각</b>이다. 앞서 그것을 `작성자` · `작성일` 이라 불러, 결재 문서를 쓴 사람과
     * 날처럼 읽혔다(R11).
     */
    @Test
    @DisplayName("발행하지 않은 보고서는 초안이고, 문서 정보는 출력자 · 출력 시각이다")
    void draftsSayTheyAreDrafts() throws Exception {
        Zone zone = zoneService.create("초안-" + System.nanoTime(), "#123456", "");
        Scan scan = done(asset(zone, "web"), ago(0), "openssl");

        for (String url : List.of("/reports/scan/" + scan.getId(),
                                  "/reports/zone?zone=" + zone.getId())) {
            String html = open(url);
            assertThat(html).as(url).contains("초안 (발행 전)")
                            .contains("<th>출력 시각</th>").contains("<th>출력자</th>")
                            .doesNotContain("<th>작성일</th>").doesNotContain("<th>작성자</th>");
        }
    }

    // --- P8 뒤집기 -------------------------------------------------------------

    /**
     * <b>P8 을 뒤집는다.</b> 발행한 뒤 검토 결과를 적고 자산을 운영 종료해도 발행본은
     * 그때 그린 그대로다 — 문서도 해시도. 지금 보고서(초안)만 바뀐다.
     */
    @Test
    @DisplayName("발행 뒤 데이터가 바뀌어도 발행본과 해시는 그대로다")
    void publishedDocumentDoesNotMove() throws Exception {
        Zone zone = zoneService.create("발행-" + System.nanoTime(), "#123456", "");
        Asset a = asset(zone, "web");
        done(a, ago(3), "openssl", "curl");
        Scan scan = done(a, ago(0), "openssl", "curl");

        long id = publishScan(scan);
        String stored = (String) row(id).get("document_html");
        String hash = (String) row(id).get("document_sha256");
        assertThat(hash).as("해시는 저장한 문서 그대로의 SHA-256").isEqualTo(sha256(stored));
        assertThat(stored).doesNotContain("해당 없음 · 오탐");

        String view = open("/reports/publications/" + id);
        assertThat(view).contains("sha256:" + hash).contains(stored.substring(0, 200));

        // 발행 뒤에 일어난 일 — P8 과 같다.
        mvc.perform(post("/analyses").param("assetId", a.getId().toString())
                                     .param("cve", "CVE-2099-1000").param("packageName", "openssl")
                                     .param("state", "FALSE_POSITIVE").param("note", "발행 뒤")
                                     .with(user("tester").roles("ADMIN")).with(csrf()))
           .andExpect(status().is3xxRedirection());
        mvc.perform(post("/assets/" + a.getId() + "/archive")
                            .with(user("tester").roles("ADMIN")).with(csrf()))
           .andExpect(status().is3xxRedirection());

        assertThat(open("/reports/scan/" + scan.getId()))
                .as("지금 보고서는 바뀐다 — 오탐 한 건이 목록에서 빠진다")
                .contains("해당 없음 · 오탐");
        assertThat(row(id).get("document_html")).as("저장한 문서").isEqualTo(stored);
        assertThat(row(id).get("document_sha256")).as("저장한 해시").isEqualTo(hash);
        assertThat(open("/reports/publications/" + id))
                .as("발행본은 그때 그린 그대로")
                .contains(stored.substring(0, 200))
                .doesNotContain("해당 없음 · 오탐");
    }

    /**
     * 구역 보고서도 같다 — 발행한 뒤 자산 하나를 운영 종료하면 지금 보고서의 범위는 한 대
     * 줄지만, 발행본에는 두 대가 그대로 있다.
     */
    @Test
    @DisplayName("구역 보고서의 발행본은 자산을 운영 종료해도 그때의 범위 그대로다")
    void zonePublicationKeepsItsScope() throws Exception {
        Zone zone = zoneService.create("구역발행-" + System.nanoTime(), "#123456", "");
        Asset web = asset(zone, "web");
        Asset db = asset(zone, "db");
        done(web, ago(0), "openssl");
        done(db, ago(0), "openssl");
        LocalDate today = LocalDate.now();

        long id = publishZone(zone, today.withDayOfMonth(1), today);
        mvc.perform(post("/assets/" + db.getId() + "/archive")
                            .with(user("tester").roles("ADMIN")).with(csrf()))
           .andExpect(status().is3xxRedirection());

        assertThat(open("/reports/zone?zone=" + zone.getId())).doesNotContain(db.getName());
        assertThat(open("/reports/publications/" + id))
                .contains(web.getName()).contains(db.getName());
        Map<String, Object> r = row(id);
        assertThat(r.get("kind")).isEqualTo("ZONE");
        assertThat(r.get("zone_id")).isNotNull();
        assertThat(r.get("period_from").toString()).isEqualTo(today.withDayOfMonth(1).toString());
    }

    // --- 문서 -----------------------------------------------------------------

    /**
     * 저장하는 것은 <b>문서</b>다 — 화면의 단추 · 폼은 빼고, 발행 정보는 문서 정보 안에 든다.
     * 해시가 그것까지 묶는다. 결재 문서 번호는 나중에 적는 값이라 문서 밖(발행본 머리)이다.
     */
    @Test
    @DisplayName("발행본 문서에는 폼과 단추가 없고 발행 번호 · 발행 시각 · 발행자가 든다")
    void storedDocumentIsADocument() throws Exception {
        Zone zone = zoneService.create("문서-" + System.nanoTime(), "#123456", "");
        Scan scan = done(asset(zone, "web"), ago(0), "openssl");

        long id = publishScan(scan);
        String stored = (String) row(id).get("document_html");

        assertThat(stored)
                .doesNotContain("<form").doesNotContain("_csrf").doesNotContain("조치 등록")
                .doesNotContain("data-print").doesNotContain("초안 (발행 전)")
                .doesNotContain("출력자").doesNotContain("<!--")
                .contains("<th>발행 번호</th>").contains(number(id))
                .contains("<th>발행 시각</th>").contains("<th>발행자</th>").contains("tester")
                .contains("1. 점검 개요");

        JsonNode json = JSON.readTree((String) row(id).get("document_json"));
        assertThat(json.path("number").asText()).isEqualTo(number(id));
        assertThat(json.path("kind").asText()).isEqualTo("SCAN");
        assertThat(json.path("report").path("overview").path("findingCount").asInt()).isEqualTo(1);
    }

    @Test
    @DisplayName("발행 번호는 연도-일련번호이고 이어진다")
    void numbersRunWithinTheYear() throws Exception {
        Zone zone = zoneService.create("번호-" + System.nanoTime(), "#123456", "");
        Scan scan = done(asset(zone, "web"), ago(0), "openssl");

        long first = publishScan(scan);
        long second = publishScan(scan);

        int year = LocalDate.now().getYear();
        assertThat(number(first)).startsWith(year + "-").matches("\\d{4}-\\d{4,}");
        assertThat(((Number) row(second).get("pub_seq")).intValue())
                .isEqualTo(((Number) row(first).get("pub_seq")).intValue() + 1);
        // 같은 보고서를 두 번 발행해도 두 발행본이다 — 그 사이에 데이터가 바뀌었을 수 있다.
        assertThat(open("/reports/scan/" + scan.getId()))
                .as("지금 보고서가 제 발행본을 가리킨다")
                .contains(number(first)).contains(number(second))
                .contains("/reports/publications/" + second);
    }

    /**
     * 발행본은 볼 때마다 해시를 다시 대조한다. DB 에서 문서를 고치면 그 문서를 보이지
     * 않고 맞지 않는다고 말한다 — 고친 문서를 발행본인 척 보이면 해시를 찍은 뜻이 없다.
     */
    @Test
    @DisplayName("저장한 문서가 해시와 맞지 않으면 보이지 않는다")
    void tamperedDocumentIsNotShown() throws Exception {
        Zone zone = zoneService.create("변조-" + System.nanoTime(), "#123456", "");
        Scan scan = done(asset(zone, "web"), ago(0), "openssl");
        long id = publishScan(scan);

        jdbc.update("UPDATE report_publications SET document_html = ? WHERE id = ?",
                    "<p>고친 문서-" + id + "</p>", id);
        // 이 시험은 한 트랜잭션이라 발행한 엔티티가 아직 손에 있다 — 실제 요청은 매번 새로 읽는다.
        em.clear();

        assertThat(open("/reports/publications/" + id))
                .contains("발행본 해시와 맞지 않습니다")
                .doesNotContain("고친 문서-" + id);
    }

    // --- 결재 문서 번호 ---------------------------------------------------------

    @Test
    @DisplayName("결재 문서 번호는 발행 뒤에 적고, 바꾼 것이 이력과 감사 로그에 남고, 해시는 그대로다")
    void approvalDocIsWrittenLaterWithHistory() throws Exception {
        Zone zone = zoneService.create("결재-" + System.nanoTime(), "#123456", "");
        Scan scan = done(asset(zone, "web"), ago(0), "openssl");
        long id = publishScan(scan);
        String hash = (String) row(id).get("document_sha256");

        for (String doc : List.of("보안-2026-0143", "보안-2026-0150", "보안-2026-0150")) {
            mvc.perform(post("/reports/publications/" + id + "/approval-doc").param("approvalDoc", doc)
                                .with(user("tester").roles("ADMIN")).with(csrf()))
               .andExpect(redirectedUrl("/reports/publications/" + id));
        }
        // 한 트랜잭션이라 아직 DB 에 안 나갔다 — 표를 SQL 로 읽기 전에 내보낸다.
        em.flush();

        assertThat(row(id).get("approval_doc")).isEqualTo("보안-2026-0150");
        assertThat(row(id).get("document_sha256")).isEqualTo(hash);
        assertThat(jdbc.queryForObject(
                "SELECT COUNT(*) FROM report_publication_events WHERE publication_id = ?", Long.class, id))
                .as("같은 값을 다시 적은 것은 남기지 않는다").isEqualTo(2L);
        assertThat(open("/reports/publications/" + id))
                .contains("보안-2026-0150")
                .contains("— → 보안-2026-0143")
                .contains("보안-2026-0143 → 보안-2026-0150");
        assertThat(jdbc.queryForObject(
                "SELECT COUNT(*) FROM audit_log WHERE action = 'PUBLICATION_APPROVAL_DOC_CHANGED' AND target LIKE ?",
                Long.class, number(id) + "%"))
                .isEqualTo(2L);
    }

    @Test
    @DisplayName("발행은 감사 로그에 남는다")
    void publishingIsAudited() throws Exception {
        Zone zone = zoneService.create("감사-" + System.nanoTime(), "#123456", "");
        Scan scan = done(asset(zone, "web"), ago(0), "openssl");
        long id = publishScan(scan);

        assertThat(jdbc.queryForObject(
                "SELECT COUNT(*) FROM audit_log WHERE action = 'REPORT_PUBLISHED' AND target LIKE ?",
                Long.class, number(id) + "%"))
                .isEqualTo(1L);
    }

    // --- 권한 -----------------------------------------------------------------

    @Test
    @DisplayName("조회 계정은 발행본을 보되 발행 · 결재 문서 번호는 못 한다")
    void viewerReadsButDoesNotPublish() throws Exception {
        Zone zone = zoneService.create("조회-" + System.nanoTime(), "#123456", "");
        Scan scan = done(asset(zone, "web"), ago(0), "openssl");
        long id = publishScan(scan);

        mvc.perform(get("/reports/publications/" + id).with(user("viewer").roles("VIEWER")))
           .andExpect(status().isOk());
        mvc.perform(get("/reports/publications").with(user("viewer").roles("VIEWER")))
           .andExpect(status().isOk());
        mvc.perform(post("/reports/scan/" + scan.getId() + "/publish")
                            .with(user("viewer").roles("VIEWER")).with(csrf()))
           .andExpect(status().isForbidden());
        mvc.perform(post("/reports/zone/publish").param("zone", zone.getId().toString())
                            .with(user("viewer").roles("VIEWER")).with(csrf()))
           .andExpect(status().isForbidden());
        mvc.perform(post("/reports/publications/" + id + "/approval-doc").param("approvalDoc", "x")
                            .with(user("viewer").roles("VIEWER")).with(csrf()))
           .andExpect(status().isForbidden());
        assertThat(mvc.perform(get("/reports/scan/" + scan.getId()).with(user("viewer").roles("VIEWER")))
                      .andReturn().getResponse().getContentAsString())
                .as("조회 계정에는 발행 단추가 없다")
                .doesNotContain("/publish\"");
    }

    // --- 지우기 ---------------------------------------------------------------

    /**
     * 발행본이 가리키는 검사는 지우지 못한다(D6) — 그 검사(와 6장의 이전 검사)가 발행본의
     * 근거다. 가리키지 않는 검사는 그대로 지울 수 있다.
     */
    @Test
    @DisplayName("발행본이 가리키는 검사는 지우지 못하고, 가리키지 않는 검사는 지운다")
    void referencedScansCannotBeDeleted() throws Exception {
        Zone zone = zoneService.create("검사삭제-" + System.nanoTime(), "#123456", "");
        Asset a = asset(zone, "web");
        Scan previous = done(a, ago(3), "openssl");
        Scan scan = done(a, ago(1), "openssl");
        long id = publishScan(scan);
        Scan later = done(a, ago(0), "openssl");

        for (Scan s : List.of(scan, previous)) {
            mvc.perform(post("/scans/" + s.getId() + "/delete")
                                .with(user("tester").roles("ADMIN")).with(csrf()))
               .andExpect(status().is3xxRedirection())
               .andExpect(flash().attribute("error",
                       allOf(containsString("발행본"), containsString(number(id)))));
            assertThat(scans.findById(s.getId())).as("검사 %d 가 지워졌다", s.getId()).isPresent();
        }
        mvc.perform(post("/scans/" + later.getId() + "/delete")
                            .with(user("tester").roles("ADMIN")).with(csrf()))
           .andExpect(status().is3xxRedirection());
        assertThat(scans.findById(later.getId())).isEmpty();
        assertThat(jdbc.queryForList(
                "SELECT scan_id FROM report_publication_scans WHERE publication_id = ?", Long.class, id))
                .containsExactlyInAnyOrder(scan.getId(), previous.getId());
    }

    /** 자산을 지워도 발행본은 남는다(D6) — 이름은 발행 때의 것으로 문서 안에 있다. */
    @Test
    @DisplayName("자산을 지워도 발행본은 남고 해시도 맞는다")
    void publicationOutlivesItsAsset() throws Exception {
        Zone zone = zoneService.create("자산삭제-" + System.nanoTime(), "#123456", "");
        Asset a = asset(zone, "web");
        Scan scan = done(a, ago(0), "openssl");
        long id = publishScan(scan);

        mvc.perform(post("/assets/" + a.getId() + "/delete").param("confirm", a.getName())
                            .with(user("tester").roles("ADMIN")).with(csrf()))
           .andExpect(status().is3xxRedirection());
        assertThat(assets.findById(a.getId())).isEmpty();

        assertThat(open("/reports/publications/" + id))
                .contains(a.getName())
                .contains(number(id))
                .doesNotContain("발행본 해시와 맞지 않습니다");
        assertThat(open("/reports/publications")).contains(number(id)).contains(a.getName());
    }

    // --- 목록 -----------------------------------------------------------------

    @Test
    @DisplayName("보고서 화면과 발행본 목록에 발행본이 나온다")
    void publicationsAreListed() throws Exception {
        Zone zone = zoneService.create("목록-" + System.nanoTime(), "#123456", "");
        Asset a = asset(zone, "web");
        done(a, ago(0), "openssl");
        LocalDate today = LocalDate.now();
        long id = publishZone(zone, today.withDayOfMonth(1), today);

        assertThat(open("/reports")).contains(number(id)).contains("/reports/publications/" + id);
        assertThat(open("/reports/publications")).contains(number(id)).contains(zone.getName());
        assertThat(open("/reports/zone?zone=" + zone.getId() + "&from=" + today.withDayOfMonth(1)
                        + "&to=" + today))
                .as("같은 구역 · 같은 기간의 지금 보고서가 그 발행본을 가리킨다")
                .contains("/reports/publications/" + id);
    }

    // --- th:utext ------------------------------------------------------------

    /**
     * {@code th:utext} 는 발행본 보기 <b>한 곳</b>뿐이다 — 저장한 문서를 그대로 내보내는
     * 자리. 그 문서는 이 앱이 이스케이프하며 그린 것이고, 볼 때마다 해시를 대조한다.
     * 다른 자리에 생기면 SecurityConfig 의 CSP 주석이 말하는 전제(글자는 전부
     * 이스케이프)가 깨진다.
     */
    @Test
    @DisplayName("th:utext 는 발행본 보기 한 곳뿐이다")
    void unescapedTextOnlyInThePublicationView() throws Exception {
        Map<String, Long> uses = new java.util.TreeMap<>();
        try (Stream<Path> files = Files.walk(Path.of("src/main/resources/templates"))) {
            for (Path file : files.filter(p -> p.toString().endsWith(".html")).toList()) {
                String text = Files.readString(file).replaceAll("(?s)<!--.*?-->", "");
                long n = java.util.regex.Pattern.compile("th:utext=").matcher(text).results().count();
                if (n > 0) {
                    uses.put(file.getFileName().toString(), n);
                }
            }
        }
        assertThat(uses).isEqualTo(Map.of("publication.html", 1L));
    }
}
