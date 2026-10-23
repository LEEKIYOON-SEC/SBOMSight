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
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Instant;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 자산 삭제도 <b>자산 행을 먼저</b> 잠근다 — 발행과 차례가 엇갈려 서로 기다리지 않게.
 *
 * <p>발행은 근거가 된 검사의 자산 행을 잠근 뒤 그 검사가 아직 있는지 잠그며 읽는다
 * (PublicationService). 자산 삭제는 검사를 먼저 지우고(검사 행이 잠긴다) 자산 행을 나중에
 * 지웠다. 같은 자산에서 둘이 겹치면 발행은 자산을 쥐고 검사를 기다리고, 삭제는 검사를 쥐고
 * 자산을 기다린다 — DB 가 한쪽을 오류로 끊는다. 검사 삭제 · 업로드 · 조치 등록은 이미 자산
 * 행을 먼저 잠근다(ScanService · RemediationService). 자산 삭제만 차례가 거꾸로였다.
 *
 * <p><b>진짜로 겹치게 만든다.</b> 발행의 잠금 두 걸음을 그대로 흉내 내되 그 사이에 멈춰,
 * 그동안 자산 삭제를 보낸다. 데이터는 커밋되어야 다른 스레드가 보므로 트랜잭션으로 감싸지
 * 않고 끝나면 지운다.
 */
@SpringBootTest
class AssetDeleteLockOrderTest {

    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired AssetService assetService;
    @Autowired ZoneService zoneService;
    @Autowired JdbcTemplate jdbc;
    @Autowired PlatformTransactionManager transactionManager;

    private Asset asset;
    private Scan scan;

    @BeforeEach
    void setUp() {
        asset = new Asset();
        asset.setName("lockorder-" + System.nanoTime());
        asset.setZone(zoneService.unassigned());
        asset = assets.saveAndFlush(asset);
        scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        scan.setCreatedAt(Instant.now());
        scan = scans.saveAndFlush(scan);
    }

    @AfterEach
    void cleanUp() {
        assets.findById(asset.getId()).ifPresent(a -> assetService.delete(a, "tester"));
    }

    @Test
    @DisplayName("발행이 자산을 쥔 사이에 자산을 지우면, 삭제가 자산에서 기다린다 — 서로 막히지 않는다")
    void deleteWaitsOnTheAssetRowFirst() throws Exception {
        TransactionTemplate tx = new TransactionTemplate(transactionManager);
        CountDownLatch assetLocked = new CountDownLatch(1);
        AtomicReference<Integer> scansSeen = new AtomicReference<>();
        AtomicReference<Throwable> frontFailure = new AtomicReference<>();
        AtomicReference<Throwable> backFailure = new AtomicReference<>();

        // 발행의 잠금 두 걸음 — 자산 행, 그다음 검사 행. 그 사이에 멈춘다.
        Thread front = new Thread(() -> {
            try {
                tx.executeWithoutResult(s -> {
                    jdbc.queryForList("SELECT id FROM assets WHERE id = ? FOR UPDATE", asset.getId());
                    assetLocked.countDown();
                    sleep(700);
                    scansSeen.set(jdbc.queryForList("SELECT id FROM scans WHERE id = ? FOR UPDATE",
                                                    scan.getId()).size());
                });
            } catch (Throwable e) {
                frontFailure.set(e);
                assetLocked.countDown();
            }
        });
        front.start();
        assertThat(assetLocked.await(30, TimeUnit.SECONDS)).isTrue();

        Thread back = new Thread(() -> {
            try {
                assetService.delete(assets.findById(asset.getId()).orElseThrow(), "tester");
            } catch (Throwable e) {
                backFailure.set(e);
            }
        });
        back.start();
        front.join(30_000);
        back.join(30_000);

        assertThat(frontFailure.get()).as("발행 쪽이 끊겼다 — 삭제가 검사를 먼저 쥐었다").isNull();
        assertThat(backFailure.get()).as("삭제 쪽이 끊겼다").isNull();
        assertThat(scansSeen.get()).as("발행이 잠그며 본 검사 — 삭제는 아직 자산에서 기다려야 한다").isEqualTo(1);
        assertThat(assets.findById(asset.getId())).as("발행이 끝난 뒤 삭제는 마저 된다").isEmpty();
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
