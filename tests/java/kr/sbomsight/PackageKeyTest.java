package kr.sbomsight;

import kr.sbomsight.domain.PackageKey;
import kr.sbomsight.domain.PackageTypes;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 패키지 식별자 — 탐지 · 인벤토리 · 검토 결과 · 조치가 "같은 패키지인가" 를 이것 하나로 가른다.
 *
 * <p>정의: purl 에서 버전 · 한정자 · 하위 경로를 뗀 것. 네임스페이스(Maven groupId · npm scope ·
 * 배포판)는 넣는다. purl 이 없으면 유형 · 이름으로 만든다(PackageKey 머리말).
 *
 * <p><b>같은 규칙이 두 곳에 있다</b> — 자바(새로 담는 행)와 V24 의 SQL(이미 담긴 행). 마이그레이션은
 * 시험에서 돌지 않으므로(H2 · create-drop) 같은 입력과 기대값을 파일 하나
 * ({@code tests/resources/package-key-vectors.tsv})에 두고 여기와 {@code tests/check-migrations.sh}
 * 가 함께 견준다. 둘이 다르면 새로 올린 SBOM 의 탐지가 이관한 검토 결과에 이어지지 않는다.
 */
class PackageKeyTest {

    static final Path VECTORS = Path.of("tests/resources/package-key-vectors.tsv");

    /** 벡터 한 줄 — purl · 유형 · 이름 · 기대 식별자. */
    record Vector(String purl, String type, String name, String key) {
    }

    static List<Vector> vectors() throws IOException {
        List<Vector> out = new ArrayList<>();
        for (String line : Files.readAllLines(VECTORS, StandardCharsets.UTF_8)) {
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            String[] cells = line.split("\t", -1);
            assertThat(cells).as(line).hasSize(4);
            out.add(new Vector(cells[0], cells[1], cells[2], cells[3]));
        }
        return out;
    }

    @Test
    @DisplayName("벡터 전부 — 탐지의 유형(grype 의 이름)으로도 인벤토리의 유형(purl 의 이름)으로도 같은 식별자")
    void vectorsGiveTheSameKeyFromBothSides() throws IOException {
        List<Vector> vectors = vectors();
        assertThat(vectors).hasSizeGreaterThan(30);
        for (Vector v : vectors) {
            assertThat(PackageKey.of(v.purl(), v.type(), v.name()))
                    .as("탐지 쪽 %s · %s · %s", v.purl(), v.type(), v.name())
                    .isEqualTo(v.key());
            // 인벤토리는 담을 때 유형을 purl 의 이름으로 옮겨 둔다(ComponentReader) — 그래도 같아야 이어진다.
            assertThat(PackageKey.of(v.purl(), PackageTypes.of(v.purl(), v.type()), v.name()))
                    .as("인벤토리 쪽 %s · %s · %s", v.purl(), v.type(), v.name())
                    .isEqualTo(v.key());
        }
    }

    @Test
    @DisplayName("버전 · 한정자 · 하위 경로는 넣지 않는다 — 올리거나 OS 를 바꿔도 같은 패키지")
    void versionAndQualifiersAreLeftOut() {
        assertThat(PackageKey.of("pkg:rpm/rocky/openssl-libs@3.0.7-24.el9?arch=x86_64&distro=rocky-9.3", "rpm", "openssl-libs"))
                .isEqualTo(PackageKey.of("pkg:rpm/rocky/openssl-libs@3.0.7-27.el9?arch=x86_64&distro=rocky-9.4", "rpm", "openssl-libs"))
                .isEqualTo("pkg:rpm/rocky/openssl-libs");
        assertThat(PackageKey.of("pkg:maven/org.example/lib@1.0#sub/path", "java-archive", "lib"))
                .isEqualTo(PackageKey.of("pkg:maven/org.example/lib@2.0", "java-archive", "lib"));
    }

    @Test
    @DisplayName("같은 이름도 유형 · 네임스페이스가 다르면 다른 패키지 — npm/PyPI, Maven groupId")
    void sameNameDifferentCoordinates() {
        assertThat(PackageKey.of("pkg:npm/semver@7.5.1", "npm", "semver"))
                .isNotEqualTo(PackageKey.of("pkg:pypi/semver@2.13.0", "python", "semver"));
        assertThat(PackageKey.of("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.8",
                                 "java-archive", "jackson-databind"))
                .isNotEqualTo(PackageKey.of("pkg:maven/org.codehaus.jackson/jackson-databind@1.9.13",
                                            "java-archive", "jackson-databind"));
    }

    @Test
    @DisplayName("purl 이 없으면 네임스페이스를 지어내지 않는다 — purl 이 있는 같은 이름과 합치지 않는다")
    void withoutPurlNothingIsInvented() {
        assertThat(PackageKey.of("", "java-archive", "jackson-databind")).isEqualTo("pkg:maven/jackson-databind");
        assertThat(PackageKey.of(null, null, "busybox")).isEqualTo("pkg:/busybox");
        assertThat(PackageKey.of("", "java-archive", "jackson-databind"))
                .isNotEqualTo(PackageKey.of("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.8",
                                            "java-archive", "jackson-databind"));
    }

    @Test
    @DisplayName("앞뒤 빈칸은 뗀다 — 담는 칸(clip)과 같다")
    void surroundingBlanksAreTrimmed() {
        assertThat(PackageKey.of(" pkg:npm/semver@7.5.1 ", "npm", "semver")).isEqualTo("pkg:npm/semver");
        assertThat(PackageKey.of("", "npm", " semver ")).isEqualTo("pkg:npm/semver");
    }

    @Test
    @DisplayName("화면에 이름 곁에 적는 네임스페이스 — 없으면 빈 글자, 인코딩은 풀어서")
    void namespaceForDisplay() {
        assertThat(PackageKey.namespace("pkg:maven/com.fasterxml.jackson.core/jackson-databind"))
                .isEqualTo("com.fasterxml.jackson.core");
        assertThat(PackageKey.namespace("pkg:npm/%40angular/core")).isEqualTo("@angular");
        assertThat(PackageKey.namespace("pkg:golang/github.com/gin-gonic/gin")).isEqualTo("github.com/gin-gonic");
        assertThat(PackageKey.namespace("pkg:npm/semver")).isEmpty();
        assertThat(PackageKey.namespace("pkg:/busybox")).isEmpty();
        assertThat(PackageKey.namespace(null)).isEmpty();
        // `+` 는 purl 에서 그대로의 글자다 — 빈칸으로 풀지 않는다.
        assertThat(PackageKey.namespace("pkg:generic/a+b/c")).isEqualTo("a+b");
    }

    /**
     * 이미 담긴 행은 V24 가 SQL 로 만든다 — purl 이 없을 때 쓰는 유형 옮김표가 앱의 표와 한 줄씩
     * 같아야 한다(V22 와 같은 시험). 탐지 · 인벤토리 두 벌이 다 같아야 한다.
     */
    @Test
    @DisplayName("V24 의 유형 옮김표(탐지 · 인벤토리)가 앱의 표와 같다")
    void v24MatchesTheTable() throws IOException {
        String sql = Files.readString(Path.of("src/main/resources/db/migration/V24__package_key.sql"));
        Matcher block = Pattern.compile("(?s)CASE (\\w+) COLLATE utf8mb4_bin(.*?)ELSE (\\w+)\\s+END").matcher(sql);
        List<String> columns = new ArrayList<>();
        while (block.find()) {
            assertThat(block.group(3)).as("모르는 유형은 받은 그대로").isEqualTo(block.group(1));
            columns.add(block.group(1));
            Map<String, String> renamed = new LinkedHashMap<>();
            Matcher when = Pattern.compile("WHEN '([^']+)'\\s+THEN '([^']*)'").matcher(block.group(2));
            while (when.find()) {
                renamed.put(when.group(1), when.group(2));
            }
            assertThat(renamed).as(block.group(1)).hasSize(20);
            renamed.forEach((syft, purl) ->
                    assertThat(PackageTypes.purlName(syft)).as("V24 의 %s", syft).isEqualTo(purl));
        }
        assertThat(columns).containsExactly("package_type", "type");
    }
}
