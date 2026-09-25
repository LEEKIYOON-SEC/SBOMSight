package kr.sbomsight.service;

import kr.sbomsight.repo.ComponentRepository;
import kr.sbomsight.service.SbomStorage.ParsedComponent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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

    public ComponentInventoryService(JdbcTemplate jdbc, ComponentRepository components) {
        this.jdbc = jdbc;
        this.components = components;
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
     * 이 검사가 기준이 된다 — 같은 자산의 <b>다른 검사에서 온 행을 지운다.</b>
     *
     * <p>넣기 전에 지우지 않고 <b>검사가 끝난 뒤에</b> 지운다({@code ScanService.run}
     * 이 완료 표시와 한 트랜잭션으로 부른다). 읽다가든 grype 에서든 터지면 이전
     * 인벤토리가 그대로 남아 있어야 한다 — 앞서 담자마자 지웠더니 grype 이 실패한
     * 자산의 패키지 목록이 통째로 사라졌다.
     *
     * <p><b>트랜잭션을 제 것으로도 연다.</b> 부르는 쪽에 트랜잭션이 없으면
     * {@code @Modifying} 질의가 {@code Executing an update/delete query} 로
     * 터진다 — {@code runAsync} 가 같은 빈의 {@code run} 을 부르면 프록시를
     * 지나지 않아 실제로 그랬다. 시험 11개가 전부 통과한 채로(시험이 트랜잭션을
     * 대신 열어 주고 있었다).
     */
    @Transactional
    public void makeCurrent(long assetId, long scanId) {
        int removed = components.deleteOtherScans(assetId, scanId);
        if (removed > 0) {
            log.info("자산 {} 의 이전 인벤토리 {}행을 새 검사 {} 것으로 바꿨습니다",
                    assetId, removed, scanId);
        }
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
