package kr.sbomsight;

import kr.sbomsight.domain.*;
import kr.sbomsight.repo.*;
import kr.sbomsight.service.AssetService;
import kr.sbomsight.service.ZoneService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.math.BigDecimal;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDate;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * 발행 번호가 <b>동시에 눌려도 겹치지 않는다</b>(D6).
 *
 * <p>번호는 그해의 마지막 번호에 하나를 더한다. 두 발행이 겹치면 둘 다 같은 마지막
 * 번호를 보고 같은 번호를 매기려 한다 — 유일 키가 뒤의 것을 막고, 막힌 쪽은 새로
 * 읽어 다음 번호를 받는다. 사람에게 "다시 눌러 주세요" 를 돌려주지 않는다.
 *
 * <p><b>진짜로 겹치게 만든다.</b> 앞 발행을 흉내 내어 다음 번호의 줄을 넣고 커밋하기
 * 전에 붙잡아 둔 채, 뒤 발행을 보낸다. 뒤 발행은 앞 줄을 아직 못 보므로 같은 번호를
 * 매긴다. 데이터는 커밋되어야 다른 스레드가 보므로 이 시험은 트랜잭션으로 감싸지 않고
 * 끝나면 지운다.
 */
@SpringBootTest
@AutoConfigureMockMvc
class PublicationNumberRaceTest {

    @Autowired MockMvc mvc;
    @Autowired JdbcTemplate jdbc;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired AssetService assetService;
    @Autowired ZoneService zoneService;
    @Autowired PlatformTransactionManager transactionManager;

    private Asset asset;
    private Scan scan;
    private final java.util.List<Long> made = new java.util.ArrayList<>();

    @BeforeEach
    void setUp() {
        asset = new Asset();
        asset.setName("pubrace-" + System.nanoTime());
        asset.setZone(zoneService.unassigned());
        asset = assets.saveAndFlush(asset);

        scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        scan.setCreatedAt(Instant.now());
        scan = scans.saveAndFlush(scan);

        Finding f = new Finding(scan, "CVE-2099-8888|zlib", "CVE-2099-8888", "zlib");
        f.setPackageVersion("1.0.0");
        f.setSeverity("High");
        f.setFixState("fixed");
        f.setFixedVersion("1.0.1");
        f.setCvssScore(BigDecimal.valueOf(7.5));
        findings.saveAndFlush(f);
        scan.setFindingCount(1);
        scan.setMatchCount(1);
        scan = scans.saveAndFlush(scan);
    }

    @AfterEach
    void cleanUp() {
        // 발행본은 앱에 지우는 길이 없다 — 시험이 남긴 것만 걷는다.
        for (Long id : made) {
            jdbc.update("DELETE FROM report_publication_scans WHERE publication_id = ?", id);
            jdbc.update("DELETE FROM report_publication_events WHERE publication_id = ?", id);
            jdbc.update("DELETE FROM report_publications WHERE id = ?", id);
        }
        assets.findById(asset.getId()).ifPresent(a -> assetService.delete(a, "tester"));
    }

    @Test
    @DisplayName("겹친 발행은 같은 번호를 받지 않는다 — 막힌 쪽이 다음 번호를 받는다")
    void overlappingPublishesGetDifferentNumbers() throws Exception {
        int year = LocalDate.now().getYear();
        TransactionTemplate tx = new TransactionTemplate(transactionManager);
        CountDownLatch inserted = new CountDownLatch(1);
        CountDownLatch go = new CountDownLatch(1);
        AtomicReference<Integer> frontSeq = new AtomicReference<>();
        AtomicReference<Throwable> failure = new AtomicReference<>();

        // 앞 발행 — 다음 번호의 줄을 넣고 커밋하기 전에 멈춘다.
        Thread front = new Thread(() -> {
            try {
                tx.executeWithoutResult(s -> {
                    Integer max = jdbc.queryForObject(
                            "SELECT MAX(pub_seq) FROM report_publications WHERE pub_year = ?",
                            Integer.class, year);
                    int seq = (max == null ? 0 : max) + 1;
                    jdbc.update("""
                            INSERT INTO report_publications
                              (kind, pub_year, pub_seq, published_at, published_by, target_name,
                               document_json, document_html, document_sha256, approval_doc)
                            VALUES ('SCAN', ?, ?, ?, 'front', 'front', '{}', '', ?, '')
                            """, year, seq, Timestamp.from(Instant.now()), "0".repeat(64));
                    frontSeq.set(seq);
                    inserted.countDown();
                    await(go);
                });
            } catch (Throwable e) {
                failure.compareAndSet(null, e);
                inserted.countDown();
            }
        });
        front.start();
        await(inserted);
        assertThat(failure.get()).as("앞 발행을 흉내 내지 못했다").isNull();

        // 뒤 발행 — 앞 줄이 커밋되기 전이라 같은 번호를 매기려 한다.
        AtomicReference<MvcResult> back = new AtomicReference<>();
        Thread backThread = new Thread(() -> {
            try {
                back.set(mvc.perform(post("/reports/scan/" + scan.getId() + "/publish")
                                             .with(user("tester").roles("ADMIN")).with(csrf()))
                            .andReturn());
            } catch (Throwable e) {
                failure.compareAndSet(null, e);
            }
        });
        backThread.start();
        Thread.sleep(300);
        go.countDown();
        front.join(30_000);
        backThread.join(30_000);

        made.addAll(jdbc.queryForList(
                "SELECT id FROM report_publications WHERE pub_year = ? AND pub_seq >= ?",
                Long.class, year, frontSeq.get()));
        assertThat(failure.get()).isNull();
        String url = back.get().getResponse().getRedirectedUrl();
        assertThat(url).as("뒤 발행이 발행본으로 가지 않았다 — %s",
                           back.get().getFlashMap()).startsWith("/reports/publications/");
        long id = Long.parseLong(url.substring(url.lastIndexOf('/') + 1));
        assertThat(jdbc.queryForObject("SELECT pub_seq FROM report_publications WHERE id = ?",
                                       Integer.class, id))
                .as("뒤 발행은 앞 번호의 다음을 받는다")
                .isEqualTo(frontSeq.get() + 1);
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(30, TimeUnit.SECONDS)) {
                throw new IllegalStateException("30초 안에 풀리지 않았습니다");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }
}
