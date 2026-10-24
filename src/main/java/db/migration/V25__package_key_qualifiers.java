package db.migration;

import kr.sbomsight.domain.PackageKey;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;

/**
 * 패키지 식별자를 새 규칙으로 다시 만든다 — 한정자 가운데 패키지를 가르는 것은 남긴다({@link PackageKey}).
 *
 * <p>V24 는 purl 의 한정자를 통째로 버렸다. 그래서 Maven 의 classifier · type 만 다른 둘(linux-x86_64
 * 네이티브와 순수 jar, test-jar)이 한 식별자였고, 한쪽에 적은 검토 결과 · 연 조치가 다른 쪽에도 붙었다.
 * 이제 식별자는 표준 파서로 읽은 정규형에서 버전 · 하위 경로와 유형별 표의 한정자만 뗀 것이다.
 *
 * <p><b>왜 SQL 이 아니라 자바인가.</b> 정규형은 규격의 파서 · 인코딩 · 유형별 이름 맞춤 · 유형별
 * 한정자 표가 정한다. SQL 로 한 벌 더 적으면 두 벌이 어긋나는 날 새로 올린 SBOM 의 탐지가 이관한
 * 기록에 이어지지 않는다. 앱이 새 행에 쓰는 {@link PackageKey#of} 를 그대로 부른다. 칸은 V24 가
 * 만든 것을 쓴다 — 스키마는 바꾸지 않고, 그래서 한 트랜잭션이다(중간에 멈추면 V24 의 상태 그대로).
 *
 * <p><b>탐지 · 패키지</b>는 행의 purl · 유형 · 이름에서 다시 만든다 — 근거가 행 안에 있다. 다만 purl 이
 * 칸(512자)을 꽉 채운 행은 담을 때 잘렸을 수 있고, 원래 purl 은 DB 어디에도 없다. 잘린 글자를 온전한
 * purl 로 읽지 않고 표시를 단 식별자를 준다({@link PackageKey#truncated}) — 어느 정상 식별자와도 겹치지
 * 않아 다른 패키지의 기록이 붙지 않는다. 같은 SBOM 을 다시 검사하면 새 탐지는 제 식별자를 받는다.
 *
 * <p><b>검토 결과 · 조치</b>는 식별자만 있고 purl 이 없다. 그 기록이 <b>지금까지 붙던 탐지</b>로 가른다
 * (V24 와 같은 규칙) — 검토 결과는 그 자산의 검사 전부에서 옛 식별자 · 번호(주 식별자 또는 함께 온
 * CVE)가 같은 탐지, 조치는 회차마다 등록한 검사의 옛 식별자 탐지(조치 대상도 거기서 왔다).
 * <ul>
 *   <li>그 탐지들의 새 식별자가 하나 → 그 식별자.</li>
 *   <li><b>둘 이상 → 비운다.</b> 어느 쪽에 적은 것인지 가를 근거가 없다 — 하나를 고르는 것이 곧
 *       임의로 붙이는 것이다.</li>
 *   <li>붙던 탐지가 남아 있지 않다(그 검사를 지웠다) → 비운다. 새 식별자를 고를 근거가 없다.</li>
 *   <li>옛 식별자가 다른 기록들이 한 새 식별자에 모인다(이름 맞춤 — {@code PyYAML} 과 {@code pyyaml}) →
 *       모두 비운다. 하나를 남기는 것이 곧 합치는 것이다.</li>
 * </ul>
 * 비운 기록은 지우지 않는다 — 어느 탐지에도 붙지 않고 `패키지 확인 필요` 로 남는다(docs/operations.md · V25).
 *
 * <p><b>나눠서 하되 한 트랜잭션이다.</b> 검토 결과 · 조치를 한꺼번에 메모리에 올리지 않는다 — 자산을
 * 기록 수({@link #RECORDS})로 묶어 묶음마다 읽고 · 가르고 · 고친다. 유일 키(자산, 번호, 식별자)와
 * "한 새 식별자에 모인 기록" 은 자산 안의 일이라 한 자산의 기록은 한 묶음에 든다. 붙던 탐지는 흘려
 * 읽는다({@link #FETCH}). 탐지 · 패키지는 id 순으로 쪽씩({@link #PAGE}). 어디서도 커밋하지 않는다 —
 * 중간에 멈추면 부르는 쪽(Flyway)이 V24 의 상태로 되돌린다. 다시 돌려도 같다 — 이미 새 규칙인 행은
 * 그대로 두고, 표시를 단 식별자({@link PackageKey#truncated})도 같은 값이 다시 나온다.
 */
public class V25__package_key_qualifiers extends BaseJavaMigration {

    private static final Logger log = LoggerFactory.getLogger(V25__package_key_qualifiers.class);

    /** 한 번에 읽는 탐지 · 패키지 행. */
    private static final int PAGE = 5_000;

    /** 한 번에 보내는 갱신. */
    private static final int BATCH = 1_000;

    /**
     * 한 묶음의 검토 결과 · 조치 — 대략 이만큼씩 자산을 묶는다. 한 자산의 기록은 쪼개지 않으므로 한
     * 자산이 이보다 많으면 그 자산 하나가 한 묶음이다.
     */
    static final int RECORDS = 5_000;

    /** 붙던 탐지를 흘려 읽는 단위 — 질의 결과를 통째로 받지 않게(드라이버는 기본으로 다 받는다). */
    private static final int FETCH = 1_000;

    @Override
    public void migrate(Context context) throws SQLException {
        reidentify(context.getConnection());
    }

    /**
     * 다시 만든 수.
     *
     * @param findings               식별자가 바뀐 탐지
     * @param components             식별자가 바뀐 패키지(인벤토리)
     * @param analysesRekeyed        새 식별자로 옮긴 검토 결과
     * @param analysesUnresolved     비운 검토 결과 — 어느 패키지의 것인지 가를 근거가 없던 것
     * @param remediationsRekeyed    새 식별자로 옮긴 조치(회차)
     * @param remediationsUnresolved 비운 조치(회차)
     */
    public record Summary(int findings, int components, int analysesRekeyed, int analysesUnresolved,
                          int remediationsRekeyed, int remediationsUnresolved) {

        @Override
        public String toString() {
            return "탐지 " + findings + " · 패키지 " + components
                   + " · 검토 결과 옮김 " + analysesRekeyed + " / 비움 " + analysesUnresolved
                   + " · 조치 옮김 " + remediationsRekeyed + " / 비움 " + remediationsUnresolved;
        }
    }

    /** 다시 만든다 — 묶음은 {@link #RECORDS}. */
    public static Summary reidentify(Connection connection) throws SQLException {
        return reidentify(connection, RECORDS);
    }

    /**
     * 다시 만든다. 커밋하지 않는다 — 부르는 쪽(Flyway · 시험 · tests/check-migrations.sh)의 트랜잭션이다.
     *
     * <p>검토 결과 · 조치를 먼저 가른다 — 붙던 탐지를 <b>옛 식별자로</b> 찾아야 하므로 탐지를 고치기 전에.
     * 자산 묶음마다 가르고 바로 고친다 — 다른 묶음의 기록은 다른 자산의 것이라 서로 근거가 되지 않는다.
     *
     * @param recordsPerBatch 한 묶음의 검토 결과 · 조치 수(대략 — 한 자산은 쪼개지 않는다)
     */
    public static Summary reidentify(Connection connection, int recordsPerBatch) throws SQLException {
        Keys keys = new Keys();
        Tally analyses = new Tally();
        Tally remediations = new Tally();
        List<long[]> batches = batches(connection, recordsPerBatch);
        for (long[] assets : batches) {
            Map<Long, String> analysisChanges = resolveAnalyses(connection, keys, assets[0], assets[1]);
            // 검토 결과는 (자산, 번호, 식별자)에 하나다(ux_analysis_key). 바뀌는 행을 먼저 모두 비우고
            // 채운다 — 한 행씩 바꾸면 아직 안 바꾼 행과 사이에 겹친다. 끝의 값은 겹치지 않게 골랐다.
            update(connection, "UPDATE finding_analysis SET package_key = NULL WHERE id = ?",
                   nullsFor(analysisChanges.keySet()));
            update(connection, "UPDATE finding_analysis SET package_key = ? WHERE id = ?",
                   withoutNulls(analysisChanges));
            analyses.add(analysisChanges);

            Map<Long, String> remediationChanges = resolveRemediations(connection, keys, assets[0], assets[1]);
            update(connection, "UPDATE remediations SET package_key = ? WHERE id = ?", remediationChanges);
            remediations.add(remediationChanges);
        }

        int findings = rekey(connection, "findings", "package_purl", "package_type", "package_name", keys);
        int components = rekey(connection, "component", "purl", "type", "name", keys);

        Summary summary = new Summary(findings, components, analyses.rekeyed, analyses.unresolved,
                                      remediations.rekeyed, remediations.unresolved);
        log.info("패키지 식별자를 다시 만들었습니다 (V25) — {} · 자산 묶음 {}", summary, batches.size());
        if (summary.analysesUnresolved() > 0 || summary.remediationsUnresolved() > 0) {
            log.warn("어느 패키지의 것인지 가를 근거가 없어 비운 기록 — 검토 결과 {} (id {}) · 조치 {} (id {}). "
                     + "대응 화면에 `패키지 확인 필요` 로 남는다.",
                     analyses.unresolved, analyses.ids(), remediations.unresolved, remediations.ids());
        }
        return summary;
    }

    /**
     * 자산 묶음 — {@code [첫 자산 id, 끝 자산 id]}. 식별자가 있는 검토 결과 · 조치를 자산마다 세어 id 순으로
     * 이어 붙이다 {@code records} 를 넘기 전에 끊는다. 한 자산은 한 묶음에만 든다. 자산 수만큼만 담는다.
     */
    private static List<long[]> batches(Connection connection, int records) throws SQLException {
        TreeMap<Long, Long> perAsset = new TreeMap<>();
        for (String table : List.of("finding_analysis", "remediations")) {
            try (PreparedStatement ps = connection.prepareStatement(
                    "SELECT asset_id, COUNT(*) FROM " + table + " WHERE package_key IS NOT NULL GROUP BY asset_id");
                 ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    perAsset.merge(rs.getLong(1), rs.getLong(2), Long::sum);
                }
            }
        }
        List<long[]> batches = new ArrayList<>();
        long[] current = null;
        long size = 0;
        for (Map.Entry<Long, Long> asset : perAsset.entrySet()) {
            if (current != null && size + asset.getValue() > records) {
                batches.add(current);
                current = null;
                size = 0;
            }
            if (current == null) {
                current = new long[] {asset.getKey(), asset.getKey()};
            }
            current[1] = asset.getKey();
            size += asset.getValue();
        }
        if (current != null) {
            batches.add(current);
        }
        return batches;
    }

    // -----------------------------------------------------------------------
    // 검토 결과 · 조치 — 붙던 탐지로 가른다(자산 묶음 하나씩)
    // -----------------------------------------------------------------------

    /** 식별자가 바뀌는 검토 결과 — id → 새 식별자(비우면 {@code null}). 자산 id 가 그 범위인 것. */
    private static Map<Long, String> resolveAnalyses(Connection connection, Keys keys, long firstAsset,
                                                     long lastAsset) throws SQLException {
        record Row(long assetId, String cve, String oldKey) {
        }
        Map<Long, Row> rows = new LinkedHashMap<>();
        try (PreparedStatement ps = connection.prepareStatement(
                "SELECT id, asset_id, cve, package_key FROM finding_analysis"
                + " WHERE package_key IS NOT NULL AND asset_id BETWEEN ? AND ? ORDER BY id")) {
            ps.setLong(1, firstAsset);
            ps.setLong(2, lastAsset);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    rows.put(rs.getLong(1), new Row(rs.getLong(2), rs.getString(3), rs.getString(4)));
                }
            }
        }
        // 그 자산의 검사 전부에서 옛 식별자 · 번호가 같은 탐지 — 목록 · 보고서가 검토 결과를 붙이던 식
        // (FindingRepository)과 같다. 함께 온 CVE 로 적힌 것도 찾는다.
        Map<Long, Set<String>> evidence = evidence(connection, keys, firstAsset, lastAsset, """
                SELECT fa.id, f.package_purl, f.package_type, f.package_name
                FROM finding_analysis fa
                JOIN scans s ON s.asset_id = fa.asset_id
                JOIN findings f ON f.scan_id = s.id AND f.package_key = fa.package_key
                               AND (f.cve = fa.cve OR (f.related_cve <> '' AND f.related_cve = fa.cve))
                WHERE fa.package_key IS NOT NULL AND fa.asset_id BETWEEN ? AND ?
                """);

        Map<Long, String> decided = new HashMap<>();
        Map<List<Object>, List<Long>> landing = new HashMap<>();
        rows.forEach((id, row) -> {
            String key = single(evidence.get(id));
            decided.put(id, key);
            if (key != null) {
                // 번호 칸의 정렬 규칙(utf8mb4_unicode_ci)은 대소문자와 끝 공백을 가리지 않는다 —
                // 유일 키도 그렇게 겹친다.
                String cve = row.cve().replaceAll(" +$", "").toUpperCase(Locale.ROOT);
                landing.computeIfAbsent(List.of(row.assetId(), cve, key),
                                        k -> new ArrayList<>()).add(id);
            }
        });
        // 한 (자산, 번호, 새 식별자)에 둘 이상 — 옛 식별자가 서로 달랐다(옛 유일 키). 하나를 고르면 합친다.
        landing.values().stream().filter(ids -> ids.size() > 1).flatMap(List::stream)
               .forEach(id -> decided.put(id, null));

        Map<Long, String> changes = new LinkedHashMap<>();
        rows.forEach((id, row) -> {
            if (!Objects.equals(decided.get(id), row.oldKey())) {
                changes.put(id, decided.get(id));
            }
        });
        return changes;
    }

    /** 식별자가 바뀌는 조치(회차) — id → 새 식별자(비우면 {@code null}). 자산 id 가 그 범위인 것. */
    private static Map<Long, String> resolveRemediations(Connection connection, Keys keys, long firstAsset,
                                                         long lastAsset) throws SQLException {
        record Row(long assetId, String oldKey) {
        }
        Map<Long, Row> rows = new LinkedHashMap<>();
        try (PreparedStatement ps = connection.prepareStatement(
                "SELECT id, asset_id, package_key FROM remediations"
                + " WHERE package_key IS NOT NULL AND asset_id BETWEEN ? AND ? ORDER BY id")) {
            ps.setLong(1, firstAsset);
            ps.setLong(2, lastAsset);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    rows.put(rs.getLong(1), new Row(rs.getLong(2), rs.getString(3)));
                }
            }
        }
        // 등록한 검사의 옛 식별자 탐지 — 등록 당시 건수 · 현재 버전 · 조치 대상이 거기서 왔다. 다른 검사에서
        // 찾지 않는다 — 그 검사에 있던 것이 지금 남은 것과 같은 패키지라는 근거가 없다(V24 와 같다).
        Map<Long, Set<String>> evidence = evidence(connection, keys, firstAsset, lastAsset, """
                SELECT r.id, f.package_purl, f.package_type, f.package_name
                FROM remediations r
                JOIN scans s ON s.id = r.opened_scan_id AND s.asset_id = r.asset_id
                JOIN findings f ON f.scan_id = s.id AND f.package_key = r.package_key
                WHERE r.package_key IS NOT NULL AND r.asset_id BETWEEN ? AND ?
                """);

        Map<Long, String> decided = new HashMap<>();
        Map<List<Object>, Set<String>> oldKeys = new HashMap<>();
        rows.forEach((id, row) -> {
            String key = single(evidence.get(id));
            decided.put(id, key);
            if (key != null) {
                oldKeys.computeIfAbsent(List.of(row.assetId(), key), k -> new HashSet<>()).add(row.oldKey());
            }
        });
        // 옛 식별자가 다른 조치들이 한 (자산, 새 식별자)에 모이면 모두 비운다 — 회차는 같은 식별자로만
        // 이어졌으니(앱이 (자산, 식별자)로 최신 회차를 찾았다) 옛 식별자가 다르면 다른 기록이다.
        rows.forEach((id, row) -> {
            String key = decided.get(id);
            if (key != null && oldKeys.get(List.of(row.assetId(), key)).size() > 1) {
                decided.put(id, null);
            }
        });

        Map<Long, String> changes = new LinkedHashMap<>();
        rows.forEach((id, row) -> {
            if (!Objects.equals(decided.get(id), row.oldKey())) {
                changes.put(id, decided.get(id));
            }
        });
        return changes;
    }

    /**
     * 기록 id → 그것이 붙던 탐지들의 새 식별자. 질의의 칸: 기록 id · purl · 유형 · 이름, 자리표 둘은
     * 자산 id 의 범위.
     *
     * <p>질의에서 DISTINCT 로 줄이지 않는다 — purl 칸의 정렬 규칙(대소문자 무시)으로 {@code Foo} 와
     * {@code foo} 가 한 줄로 줄어, 두 패키지에 붙던 기록이 하나에 붙던 것으로 보인다. 그 대신 흘려
     * 읽는다({@link #FETCH}) — 한 기록에 검사마다 한 줄씩 나와도 담는 것은 기록마다의 식별자 몇 개다.
     */
    private static Map<Long, Set<String>> evidence(Connection connection, Keys keys, long firstAsset,
                                                   long lastAsset, String sql) throws SQLException {
        Map<Long, Set<String>> out = new HashMap<>();
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setFetchSize(FETCH);
            ps.setLong(1, firstAsset);
            ps.setLong(2, lastAsset);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    out.computeIfAbsent(rs.getLong(1), k -> new HashSet<>())
                       .add(keys.of(rs.getString(2), rs.getString(3), rs.getString(4)));
                }
            }
        }
        return out;
    }

    /** 하나뿐이면 그것, 없거나 둘 이상이면 {@code null}. */
    private static String single(Set<String> keys) {
        return keys != null && keys.size() == 1 ? keys.iterator().next() : null;
    }

    // -----------------------------------------------------------------------
    // 탐지 · 패키지 — 행 안의 purl · 유형 · 이름에서
    // -----------------------------------------------------------------------

    /** 표 하나를 id 순으로 쪽씩 읽어 식별자가 바뀐 행만 고친다. 바뀐 행 수를 돌려준다. */
    private static int rekey(Connection connection, String table, String purl, String type, String name,
                             Keys keys) throws SQLException {
        String select = "SELECT id, " + purl + ", " + type + ", " + name + ", package_key FROM " + table
                        + " WHERE id > ? ORDER BY id LIMIT " + PAGE;
        int changed = 0;
        long after = 0;
        try (PreparedStatement read = connection.prepareStatement(select)) {
            while (true) {
                read.setLong(1, after);
                Map<Long, String> page = new LinkedHashMap<>();
                int seen = 0;
                try (ResultSet rs = read.executeQuery()) {
                    while (rs.next()) {
                        seen++;
                        after = rs.getLong(1);
                        String key = keys.of(rs.getString(2), rs.getString(3), rs.getString(4));
                        if (!key.equals(rs.getString(5))) {
                            page.put(after, key);
                        }
                    }
                }
                update(connection, "UPDATE " + table + " SET package_key = ? WHERE id = ?", page);
                changed += page.size();
                if (seen < PAGE) {
                    return changed;
                }
            }
        }
    }

    // -----------------------------------------------------------------------

    /** {@code UPDATE … SET package_key = ? WHERE id = ?} 를 묶어 보낸다. 값이 {@code null} 이면 비운다. */
    private static void update(Connection connection, String sql, Map<Long, String> values) throws SQLException {
        if (values.isEmpty()) {
            return;
        }
        boolean keyed = sql.contains("= ? WHERE");
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            int pending = 0;
            for (Map.Entry<Long, String> e : values.entrySet()) {
                if (keyed) {
                    if (e.getValue() == null) {
                        ps.setNull(1, Types.VARCHAR);
                    } else {
                        ps.setString(1, e.getValue());
                    }
                    ps.setLong(2, e.getKey());
                } else {
                    ps.setLong(1, e.getKey());
                }
                ps.addBatch();
                if (++pending >= BATCH) {
                    ps.executeBatch();
                    pending = 0;
                }
            }
            if (pending > 0) {
                ps.executeBatch();
            }
        }
    }

    private static Map<Long, String> nullsFor(Set<Long> ids) {
        Map<Long, String> out = new LinkedHashMap<>();
        ids.forEach(id -> out.put(id, null));
        return out;
    }

    private static Map<Long, String> withoutNulls(Map<Long, String> values) {
        Map<Long, String> out = new LinkedHashMap<>();
        values.forEach((id, key) -> {
            if (key != null) {
                out.put(id, key);
            }
        });
        return out;
    }

    /** 묶음마다 고친 기록을 센다 — 비운 기록의 id 는 앞 스무 개만 들고 있는다(기록에 남길 것). */
    private static final class Tally {

        int rekeyed;
        int unresolved;
        private final List<Long> firstUnresolved = new ArrayList<>();

        void add(Map<Long, String> changes) {
            changes.forEach((id, key) -> {
                if (key != null) {
                    rekeyed++;
                } else if (++unresolved <= 20) {
                    firstUnresolved.add(id);
                }
            });
        }

        String ids() {
            return unresolved <= 20 ? firstUnresolved.toString() : firstUnresolved + " 외 " + (unresolved - 20);
        }
    }

    /**
     * 담긴 행 하나의 새 식별자 — purl · 유형 · 이름마다 한 번(같은 패키지가 검사마다 수백 번 나온다).
     * purl 이 칸을 꽉 채운 행은 표시를 단 식별자다({@link PackageKey#truncated}) — 탐지 · 패키지를 고칠
     * 때도, 검토 결과 · 조치가 붙던 탐지를 볼 때도 같은 값이다. 오래 안 쓴 것부터 버린다 — 검사가 많은
     * DB 에서 서로 다른 purl 이 끝없이 쌓여 힙을 다 쓰지 않게.
     */
    private static final class Keys {

        private static final int KEEP = 100_000;

        private final Map<List<String>, String> cache = new LinkedHashMap<>(1024, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<List<String>, String> eldest) {
                return size() > KEEP;
            }
        };

        String of(String purl, String type, String name) {
            return cache.computeIfAbsent(Arrays.asList(purl, type, name),
                                         k -> PackageKey.clipped(purl) ? PackageKey.truncated(purl, type, name)
                                                                       : PackageKey.of(purl, type, name));
        }
    }
}
