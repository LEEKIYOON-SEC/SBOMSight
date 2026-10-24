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
 * <p><b>탐지 · 패키지</b>는 행의 purl · 유형 · 이름에서 다시 만든다 — 근거가 행 안에 있다.
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
 */
public class V25__package_key_qualifiers extends BaseJavaMigration {

    private static final Logger log = LoggerFactory.getLogger(V25__package_key_qualifiers.class);

    /** 한 번에 읽는 행. */
    private static final int PAGE = 5_000;

    /** 한 번에 보내는 갱신. */
    private static final int BATCH = 1_000;

    @Override
    public void migrate(Context context) throws SQLException {
        Summary summary = reidentify(context.getConnection());
        log.info("패키지 식별자를 다시 만들었습니다 (V25) — {}", summary);
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

    /**
     * 다시 만든다. 커밋하지 않는다 — 부르는 쪽(Flyway · 시험 · tests/check-migrations.sh)의 트랜잭션이다.
     *
     * <p>검토 결과 · 조치를 먼저 가른다 — 붙던 탐지를 <b>옛 식별자로</b> 찾아야 하므로 탐지를 고치기 전에.
     */
    public static Summary reidentify(Connection connection) throws SQLException {
        Keys keys = new Keys();
        Map<Long, String> analyses = resolveAnalyses(connection, keys);
        Map<Long, String> remediations = resolveRemediations(connection, keys);

        int findings = rekey(connection, "findings", "package_purl", "package_type", "package_name", keys);
        int components = rekey(connection, "component", "purl", "type", "name", keys);

        // 검토 결과는 (자산, 번호, 식별자)에 하나다(ux_analysis_key). 바뀌는 행을 먼저 모두 비우고
        // 채운다 — 한 행씩 바꾸면 아직 안 바꾼 행과 사이에 겹친다. 끝의 값은 겹치지 않게 골랐다.
        update(connection, "UPDATE finding_analysis SET package_key = NULL WHERE id = ?",
               nullsFor(analyses.keySet()));
        update(connection, "UPDATE finding_analysis SET package_key = ? WHERE id = ?",
               withoutNulls(analyses));
        update(connection, "UPDATE remediations SET package_key = ? WHERE id = ?", remediations);

        Summary summary = new Summary(findings, components,
                count(analyses, false), count(analyses, true),
                count(remediations, false), count(remediations, true));
        if (summary.analysesUnresolved() > 0 || summary.remediationsUnresolved() > 0) {
            log.warn("어느 패키지의 것인지 가를 근거가 없어 비운 기록 — 검토 결과 {} (id {}) · 조치 {} (id {}). "
                     + "대응 화면에 `패키지 확인 필요` 로 남는다.",
                     summary.analysesUnresolved(), ids(analyses), summary.remediationsUnresolved(), ids(remediations));
        }
        return summary;
    }

    // -----------------------------------------------------------------------
    // 검토 결과 · 조치 — 붙던 탐지로 가른다
    // -----------------------------------------------------------------------

    /** 식별자가 바뀌는 검토 결과 — id → 새 식별자(비우면 {@code null}). */
    private static Map<Long, String> resolveAnalyses(Connection connection, Keys keys) throws SQLException {
        record Row(long assetId, String cve, String oldKey) {
        }
        Map<Long, Row> rows = new LinkedHashMap<>();
        try (PreparedStatement ps = connection.prepareStatement(
                "SELECT id, asset_id, cve, package_key FROM finding_analysis WHERE package_key IS NOT NULL ORDER BY id");
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                rows.put(rs.getLong(1), new Row(rs.getLong(2), rs.getString(3), rs.getString(4)));
            }
        }
        // 그 자산의 검사 전부에서 옛 식별자 · 번호가 같은 탐지 — 목록 · 보고서가 검토 결과를 붙이던 식
        // (FindingRepository)과 같다. 함께 온 CVE 로 적힌 것도 찾는다.
        Map<Long, Set<String>> evidence = evidence(connection, keys, """
                SELECT fa.id, f.package_purl, f.package_type, f.package_name
                FROM finding_analysis fa
                JOIN scans s ON s.asset_id = fa.asset_id
                JOIN findings f ON f.scan_id = s.id AND f.package_key = fa.package_key
                               AND (f.cve = fa.cve OR (f.related_cve <> '' AND f.related_cve = fa.cve))
                WHERE fa.package_key IS NOT NULL
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

    /** 식별자가 바뀌는 조치(회차) — id → 새 식별자(비우면 {@code null}). */
    private static Map<Long, String> resolveRemediations(Connection connection, Keys keys) throws SQLException {
        record Row(long assetId, String oldKey) {
        }
        Map<Long, Row> rows = new LinkedHashMap<>();
        try (PreparedStatement ps = connection.prepareStatement(
                "SELECT id, asset_id, package_key FROM remediations WHERE package_key IS NOT NULL ORDER BY id");
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                rows.put(rs.getLong(1), new Row(rs.getLong(2), rs.getString(3)));
            }
        }
        // 등록한 검사의 옛 식별자 탐지 — 등록 당시 건수 · 현재 버전 · 조치 대상이 거기서 왔다. 다른 검사에서
        // 찾지 않는다 — 그 검사에 있던 것이 지금 남은 것과 같은 패키지라는 근거가 없다(V24 와 같다).
        Map<Long, Set<String>> evidence = evidence(connection, keys, """
                SELECT r.id, f.package_purl, f.package_type, f.package_name
                FROM remediations r
                JOIN scans s ON s.id = r.opened_scan_id AND s.asset_id = r.asset_id
                JOIN findings f ON f.scan_id = s.id AND f.package_key = r.package_key
                WHERE r.package_key IS NOT NULL
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
     * 기록 id → 그것이 붙던 탐지들의 새 식별자. 질의의 칸: 기록 id · purl · 유형 · 이름.
     *
     * <p>질의에서 DISTINCT 로 줄이지 않는다 — purl 칸의 정렬 규칙(대소문자 무시)으로 {@code Foo} 와
     * {@code foo} 가 한 줄로 줄어, 두 패키지에 붙던 기록이 하나에 붙던 것으로 보인다.
     */
    private static Map<Long, Set<String>> evidence(Connection connection, Keys keys, String sql) throws SQLException {
        Map<Long, Set<String>> out = new HashMap<>();
        try (PreparedStatement ps = connection.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                out.computeIfAbsent(rs.getLong(1), k -> new HashSet<>())
                   .add(keys.of(rs.getString(2), rs.getString(3), rs.getString(4)));
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

    private static int count(Map<Long, String> changes, boolean unresolved) {
        return (int) changes.values().stream().filter(key -> (key == null) == unresolved).count();
    }

    /** 기록에 남길 id — 많으면 앞 스무 개. */
    private static String ids(Map<Long, String> changes) {
        List<Long> ids = changes.entrySet().stream().filter(e -> e.getValue() == null)
                                .map(Map.Entry::getKey).toList();
        return ids.size() <= 20 ? ids.toString() : ids.subList(0, 20) + " 외 " + (ids.size() - 20);
    }

    /**
     * purl · 유형 · 이름마다 한 번 — 같은 패키지가 검사마다 수백 번 나온다. 오래 안 쓴 것부터 버린다 —
     * 검사가 많은 DB 에서 서로 다른 purl 이 끝없이 쌓여 힙을 다 쓰지 않게.
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
                                         k -> PackageKey.of(purl, type, name));
        }
    }
}
