package kr.sbomsight.service;

import kr.sbomsight.config.SbomSightProperties;
import kr.sbomsight.domain.Scan;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.ComponentRepository;
import kr.sbomsight.repo.ScanRepository;
import kr.sbomsight.service.SbomStorage.ParsedComponent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * 패키지 인벤토리를 채운다.
 *
 * <p><b>왜 JPA 가 아니라 JDBC 배치인가.</b> 컴포넌트 12만 개짜리 SBOM 이
 * 예사다. {@code saveAll()} 로 넣으면 엔티티 12만 개와 그만큼의 스냅샷이
 * 영속성 컨텍스트에 쌓인다 — SBOM 을 스트리밍으로 읽어 메모리를 아낀 것이
 * 그 자리에서 무의미해진다. 여기서는 {@code BATCH}개마다 흘려보내고 아무것도
 * 들고 있지 않는다.
 *
 * <p>{@code rewriteBatchedStatements=true} 가 URL 에 이미 있어서 드라이버가
 * 한 문장으로 묶어 보낸다.
 */
@Service
public class ComponentInventoryService {

    private static final Logger log = LoggerFactory.getLogger(ComponentInventoryService.class);

    /** 한 번에 보낼 줄 수. 이 이상 들고 있지 않는다. */
    private static final int BATCH = 1_000;

    private static final String INSERT = """
            INSERT INTO component (asset_id, scan_id, name, version, type, purl, location)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """;

    private final JdbcTemplate jdbc;
    private final ComponentRepository components;
    private final ScanRepository scans;
    private final AssetRepository assets;
    private final SbomStorage storage;
    private final SbomSightProperties properties;

    public ComponentInventoryService(JdbcTemplate jdbc, ComponentRepository components,
                                     ScanRepository scans, AssetRepository assets,
                                     SbomStorage storage, SbomSightProperties properties) {
        this.jdbc = jdbc;
        this.components = components;
        this.scans = scans;
        this.assets = assets;
        this.storage = storage;
        this.properties = properties;
    }

    /**
     * 컴포넌트를 받아 넣는 자리. 다 넣었으면 {@link Sink#close()} 를 부른다.
     *
     * <p>{@code try-with-resources} 로 쓴다 — 닫지 않으면 마지막 배치가
     * 안 들어간다.
     */
    public Sink open(long assetId, long scanId) {
        return new Sink(assetId, scanId);
    }

    /**
     * 검사가 끝났다 — <b>그 검사가 자산의 지금 검사이면</b> 패키지 목록을 그 검사
     * 것으로 바꾸고, <b>아니면</b> 그 검사가 담은 것을 버린다.
     *
     * <p>넣기 전에 지우지 않고 <b>검사가 끝난 뒤에</b> 지운다({@code ScanService.run}
     * 이 완료 표시와 한 트랜잭션으로 부른다). 읽다가든 grype 에서든 터지면 이전
     * 인벤토리가 그대로 남아 있어야 한다 — 앞서 담자마자 지웠더니 grype 이 실패한
     * 자산의 패키지 목록이 통째로 사라졌다.
     *
     * <p><b>지우는 것은 끝난 검사의 행뿐이다.</b> 앞서는 "그 자산의 다른 검사에서
     * 온 행" 을 전부 지웠는데, 아직 도는 검사가 이미 담아 둔 행도 거기 들었다.
     * 검사 둘이 겹치면 먼저 끝난 쪽이 나중 것의 행을, 나중 것이 먼저 것의 행을
     * 지워 패키지가 0행이 됐다. 그리고 <b>늦게 끝났다고 기준이 되지 않는다</b> —
     * 기준은 자산의 지금 검사({@link ScanRepository#currentOf})다. 취약점 화면이
     * 같은 것을 기준으로 삼는다(ScanOverlapTest).
     *
     * <p>자산 행을 잠근다. 같은 자산의 검사를 만드는 자리(ScanService)와 차례를
     * 맞춘다.
     *
     * <p><b>트랜잭션을 제 것으로도 연다.</b> 부르는 쪽에 트랜잭션이 없으면
     * {@code @Modifying} 질의가 {@code Executing an update/delete query} 로
     * 터진다 — {@code runAsync} 가 같은 빈의 {@code run} 을 부르면 프록시를
     * 지나지 않아 실제로 그랬다. 시험 11개가 전부 통과한 채로(시험이 트랜잭션을
     * 대신 열어 주고 있었다).
     *
     * @return 그 검사가 지금 검사가 됐는가 — 아니면 담은 것을 버렸다
     */
    @Transactional
    public boolean makeCurrent(long assetId, long scanId) {
        assets.lockById(assetId);
        Long current = scans.currentOf(assetId).map(Scan::getId).orElse(null);
        if (current == null || current != scanId) {
            int dropped = components.deleteByScanId(scanId);
            log.info("검사 {} 는 자산 {} 의 지금 검사(검사 {})가 아니라 담은 {}행을 버렸습니다",
                    scanId, assetId, current, dropped);
            return false;
        }
        int removed = components.deleteFinishedOtherScans(assetId, scanId);
        if (removed > 0) {
            log.info("자산 {} 의 이전 인벤토리 {}행을 새 검사 {} 것으로 바꿨습니다",
                    assetId, removed, scanId);
        }
        return true;
    }

    /**
     * 다시 담은 결과.
     *
     * @param from    다시 담은 검사 — 할 일이 없었거나 그 검사를 고르기 전에 멈췄으면 {@code null}
     * @param rows    담은 행 수
     * @param problem 담지 못한 까닭 — 담았으면 빈 글자
     */
    public record Restored(Scan from, long rows, String problem) {

        static final Restored NOTHING = new Restored(null, 0, "");

        public boolean happened() {
            return from != null && problem.isEmpty();
        }

        public boolean failed() {
            return !problem.isEmpty();
        }
    }

    /**
     * 자산의 지금 검사에 패키지 목록이 없으면 <b>그 검사의 보관 SBOM 에서 다시 담는다.</b>
     *
     * <p>패키지 목록은 지금 검사 것만 둔다. 그래서 지금 검사를 지우면 — 엉뚱한
     * 자산에 올린 SBOM 을 지울 때가 그렇다 — 취약점 화면은 그 전 검사를 말하는데
     * 패키지 목록은 0행이었다. 그 전 검사의 행은 새 검사가 끝날 때 이미 지웠다.
     * SBOM 은 보관되어 있으므로 다시 읽는다.
     *
     * <p><b>검사 삭제가 커밋된 뒤에 제 트랜잭션으로 부른다</b>(ScanService.delete).
     * 담다가 터지면 이 트랜잭션과 함께 되돌려져 담다 만 것이 남지 않는다. 보관
     * 파일이 없거나 풀지 못하면 던지지 않고 까닭을 돌려준다 — 그때는 아직 한 줄도
     * 담기 전이다. 읽다가 깨진 곳을 만나면 {@link SbomStorage#inspect} 가 거기서
     * 멈추고 경고만 남기므로 거기까지 담긴다 — grype 이 이미 읽고 끝낸 SBOM 이라
     * 그럴 일은 드물다.
     *
     * <p><b>자산 행을 맨 먼저 잠근다.</b> 같은 자산을 건드리는 쓰기(검사를 만들 때 ·
     * 끝낼 때 · 지울 때)와 같은 차례다 — 자산 → 검사 → 패키지 행. 앞서는 읽고 담은
     * 뒤에야 잠갔는데 MariaDB 에서 둘 다 재현됐다. 담을 때 외래 키가 자산 행에 건
     * 공유 잠금을 배타 잠금으로 올리는 사이에 같은 자산의 업로드 · 검사 마무리가
     * 끼면 교착이 났다. 그리고 잠그기 전에 읽은 스냅숏으로 지금 검사를 골라, 그
     * 사이에 끝난 새 검사의 행을 지웠다.
     */
    @Transactional
    public Restored restoreCurrent(long assetId) {
        assets.lockById(assetId);
        Scan current = scans.currentOf(assetId).orElse(null);
        if (current == null || components.countByScanId(current.getId()) > 0) {
            return Restored.NOTHING;
        }
        String stored = current.getSbomPath();
        if (stored == null || stored.isBlank() || !Files.exists(Path.of(stored))) {
            return new Restored(current, 0, "그 검사의 보관 SBOM 파일이 없습니다.");
        }
        Path dir = properties.scanDir(assetId, current.getId());
        Path plain = dir.resolve("sbom-restore.json");
        try {
            storage.inflate(Path.of(stored), dir, plain.getFileName().toString());
            try (Sink sink = open(assetId, current.getId())) {
                storage.inspect(plain, sink);
            }
        } catch (IOException e) {
            log.warn("자산 {} 의 패키지 목록을 다시 담지 못했습니다: {}", assetId, e.getMessage());
            return new Restored(current, 0, "보관된 SBOM을 읽지 못했습니다(" + e.getMessage() + ").");
        } finally {
            // 풀다가 멈춘 것도 지운다 — 다 풀리지 않은 파일이 남는다.
            try {
                Files.deleteIfExists(plain);
            } catch (IOException e) {
                log.warn("임시 파일을 지우지 못했습니다: {}", plain);
            }
        }
        // 잠금을 쥐고 있어 그사이 지금 검사가 바뀌지 않는다. 바뀌었다면 담은 것은
        // makeCurrent 가 이미 버렸다.
        if (!makeCurrent(assetId, current.getId())) {
            return Restored.NOTHING;
        }
        long rows = components.countByScanId(current.getId());
        log.info("자산 {} 의 패키지 목록을 검사 {} 의 보관 SBOM 에서 다시 담았습니다 ({}행)",
                assetId, current.getId(), rows);
        return new Restored(current, rows, "");
    }

    /**
     * 이 검사에서 온 행을 버린다 — 읽다가 실패했을 때.
     *
     * <p>여기도 제 트랜잭션이 필요하다. 없으면 <b>실패를 되돌리는 길이 같은
     * 이유로 또 실패</b>하고, 실패한 검사의 인벤토리가 화면에 남는다.
     */
    @Transactional
    public void discard(long scanId) {
        int removed = components.deleteByScanId(scanId);
        if (removed > 0) {
            log.info("검사 {} 의 인벤토리 {}행을 버렸습니다", scanId, removed);
        }
    }

    /**
     * {@link SbomStorage#inspect} 가 컴포넌트를 하나씩 넘기는 자리.
     *
     * <p>모으지 않는다 — {@link #BATCH}개가 차면 보내고 비운다.
     */
    public final class Sink implements Consumer<ParsedComponent>, AutoCloseable {

        private final long assetId;
        private final long scanId;
        private final List<Object[]> pending = new ArrayList<>(BATCH);
        private long total;

        private Sink(long assetId, long scanId) {
            this.assetId = assetId;
            this.scanId = scanId;
        }

        @Override
        public void accept(ParsedComponent parsed) {
            pending.add(new Object[] {
                    assetId, scanId,
                    clip(parsed.name(), 255),
                    clip(parsed.version(), 255),
                    clip(parsed.type(), 64),
                    clip(parsed.purl(), 512),
                    clip(parsed.location(), 1000) });
            if (pending.size() >= BATCH) {
                flush();
            }
        }

        @Override
        public void close() {
            flush();
            log.info("자산 {} · 검사 {} — 패키지 {}개 담았습니다", assetId, scanId, total);
        }

        public long total() {
            return total;
        }

        private void flush() {
            if (pending.isEmpty()) {
                return;
            }
            jdbc.batchUpdate(INSERT, pending);
            total += pending.size();
            pending.clear();
        }

        /**
         * 열 폭을 넘으면 자른다.
         *
         * <p>자르지 않으면 12만 개 중 하나가 길다는 이유로 검사 전체가
         * 실패한다. 어느 값이 길었는지는 남기지 않는다 — 12만 개마다
         * 경고를 찍으면 로그가 그것으로 덮인다.
         */
        private String clip(String value, int max) {
            if (value == null) {
                return "";
            }
            String trimmed = value.trim();
            return trimmed.length() <= max ? trimmed : trimmed.substring(0, max);
        }
    }
}
