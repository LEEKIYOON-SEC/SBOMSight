package kr.sbomsight;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * <b>시험하는 스키마와 운영하는 스키마가 같은가</b> — 삭제 규칙만.
 *
 * <p>시험은 H2 에 {@code ddl-auto=create-drop} 으로 돈다. 스키마를
 * 하이버네이트가 만들고, {@code db/migration/*.sql} 은 <b>시험에서 한 번도
 * 실행되지 않는다</b>(§10). 그래서 FK 의 {@code ON DELETE CASCADE} 는 두 곳에
 * 따로 적혀 있다.
 *
 * <ul>
 *   <li>운영 — 마이그레이션 SQL 의 {@code ON DELETE CASCADE}</li>
 *   <li>시험 — 엔티티의 {@code @OnDelete(action = CASCADE)}</li>
 * </ul>
 *
 * <p>둘이 어긋나면 <b>운영은 되는데 시험에서만 참조 제약 위반이 난다.</b>
 * 그러면 그 삭제를 도는 시험을 아무도 쓸 수 없고, 실제로 그렇게 됐다 —
 * {@code AssetService.delete} 를 지나가는 시험이 하나도 없었다. 지우는 것이
 * 몇 건인지 세어 화면에 보여 주는 기능까지 있었는데도.
 *
 * <p>같은 일이 두 번 났다(N9 의 {@code component}, 그 뒤 나머지 다섯) —
 * 그래서 사람이 기억하는 대신 여기서 맞춰 본다.
 *
 * <p><b>반대 방향도 본다.</b> 마이그레이션에 CASCADE 가 없는 FK 에 엔티티
 * 표시를 붙이면, 이번에는 시험이 운영보다 관대해진다 — 시험은 지워지는데
 * 운영에서는 FK 위반으로 실패한다. {@code scans → assets} 가 일부러 그런
 * 관계다(코드가 스캔을 먼저 지운다).
 */
class CascadeParityTest {

    private static final Path MIGRATIONS = Path.of("src/main/resources/db/migration");
    private static final Path DOMAIN = Path.of("src/main/java/kr/sbomsight/domain");

    /**
     * 표 이름을 무는 자리와 FK 를 한 번에 훑는다.
     *
     * <p><b>열 이름만으로는 묶을 수 없다.</b> {@code scan_id} 는
     * {@code findings} 와 {@code component} 양쪽에 있고, 삭제 규칙은 표마다
     * 따로다. 처음에 열 이름만 키로 썼더니 한쪽의 CASCADE 가 다른 쪽의 빈
     * 자리를 덮어서, <b>표시를 떼 보고도 시험이 통과했다.</b>
     */
    private static final Pattern TABLE_OR_FK = Pattern.compile(
            "(?is)(?:(?:CREATE\\s+TABLE(?:\\s+IF\\s+NOT\\s+EXISTS)?|ALTER\\s+TABLE)\\s+`?(\\w+)`?)"
            + "|(?:FOREIGN\\s+KEY\\s*\\(\\s*`?(\\w+)`?\\s*\\)\\s*REFERENCES\\s+`?\\w+`?"
            + "\\s*\\(\\s*\\w+\\s*\\)\\s*(?:ON\\s+DELETE\\s+(CASCADE|SET\\s+NULL|RESTRICT|NO\\s+ACTION))?)");

    /** {@code @JoinColumn(name = "col" ...)} 과 그 뒤에 붙은 {@code @OnDelete} 여부. */
    private static final Pattern JOIN = Pattern.compile(
            "(?s)@JoinColumn\\s*\\([^)]*name\\s*=\\s*\"(\\w+)\"[^)]*\\)(.{0,240}?)private\\s");

    /** {@code 표.열} → 마이그레이션이 정한 삭제 규칙. 나중 판이 앞 판을 덮는다. */
    private Map<String, String> fromMigrations() throws IOException {
        Map<String, String> rules = new LinkedHashMap<>();
        try (Stream<Path> files = Files.walk(MIGRATIONS)) {
            // V2 가 V10 보다 앞이어야 한다 — 이름순으로 세면 V10 이 V2 앞에 온다.
            List<Path> sorted = files.filter(p -> p.toString().endsWith(".sql"))
                    .sorted((a, b) -> Integer.compare(number(a), number(b)))
                    .toList();
            for (Path file : sorted) {
                Matcher m = TABLE_OR_FK.matcher(Files.readString(file));
                String table = "?";
                while (m.find()) {
                    if (m.group(1) != null) {
                        table = m.group(1);
                        continue;
                    }
                    String rule = m.group(3) == null ? "NONE"
                            : m.group(3).toUpperCase().replaceAll("\\s+", " ");
                    rules.put(table + "." + m.group(2), rule);
                }
            }
        }
        return rules;
    }

    private static int number(Path file) {
        Matcher m = Pattern.compile("^V(\\d+)__").matcher(file.getFileName().toString());
        return m.find() ? Integer.parseInt(m.group(1)) : Integer.MAX_VALUE;
    }

    /** {@code 표.열} → 엔티티에 {@code @OnDelete(CASCADE)} 가 붙어 있나. */
    private Map<String, Boolean> fromEntities() throws IOException {
        Map<String, Boolean> marked = new LinkedHashMap<>();
        // `[^)]*` 를 탐욕적으로 두면 `@Table(name = "finding_analysis",
        //   uniqueConstraints = @UniqueConstraint(name = "ux_analysis_key" ...))` 에서
        // **뒤쪽 이름**을 표 이름으로 읽는다. 그러면 그 엔티티가 조용히 빠진다.
        Pattern table = Pattern.compile("@Table\\s*\\([^)]*?name\\s*=\\s*\"(\\w+)\"");
        try (Stream<Path> files = Files.walk(DOMAIN)) {
            for (Path file : files.filter(p -> p.toString().endsWith(".java")).sorted().toList()) {
                String text = Files.readString(file);
                Matcher t = table.matcher(text);
                if (!t.find()) {
                    continue;   // @Table 이 없으면 어느 표인지 알 수 없다
                }
                Matcher m = JOIN.matcher(text);
                while (m.find()) {
                    boolean cascade = m.group(2).contains("OnDelete")
                                      && m.group(2).contains("CASCADE");
                    marked.put(t.group(1) + "." + m.group(1), cascade);
                }
            }
        }
        return marked;
    }

    @Test
    @DisplayName("마이그레이션의 CASCADE 와 엔티티의 @OnDelete 가 일치한다")
    void cascadeRulesMatch() throws IOException {
        Map<String, String> migration = fromMigrations();
        Map<String, Boolean> entity = fromEntities();

        assertThat(migration)
                .as("마이그레이션에서 FK 를 하나도 읽지 못했다 — 정규식을 보라")
                .isNotEmpty();
        assertThat(entity)
                .as("엔티티에서 @JoinColumn 을 하나도 읽지 못했다 — 정규식을 보라")
                .isNotEmpty();

        List<String> mismatches = new ArrayList<>();
        for (var column : entity.entrySet()) {
            String rule = migration.get(column.getKey());
            if (rule == null) {
                continue;   // 엔티티에만 있는 관계 (마이그레이션 전의 열)
            }
            boolean sqlCascades = rule.equals("CASCADE");
            if (sqlCascades && !column.getValue()) {
                mismatches.add(("%s — SQL 은 CASCADE 인데 엔티티에 @OnDelete 가 없다. "
                                + "H2 에만 CASCADE 가 빠져 그 삭제를 시험으로 지킬 수 없다")
                                       .formatted(column.getKey()));
            }
            if (!sqlCascades && column.getValue()) {
                mismatches.add(("%s — 엔티티는 CASCADE 인데 SQL 은 %s 다. "
                                + "시험이 운영보다 관대해져서, 시험은 지워지는데 운영에서 FK 위반이 난다")
                                       .formatted(column.getKey(), rule));
            }
        }

        assertThat(mismatches)
                .as("docs/rework-plan.md §10 — 스키마를 바꾸면 양쪽을 함께 본다")
                .isEmpty();
    }
}
