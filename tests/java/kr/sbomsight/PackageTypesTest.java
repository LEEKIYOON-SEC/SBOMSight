package kr.sbomsight;

import kr.sbomsight.domain.PackageTypes;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 패키지 유형 — syft · grype 의 이름({@code java-archive})과 purl 의 이름({@code maven})을 한쪽으로.
 *
 * <p>인벤토리는 SBOM 에서, 탐지는 grype 결과에서 유형을 딴다. 둘이 같은 규칙으로 옮겨야
 * 패키지 화면의 줄(이름 · 유형)에 탐지가 이어진다.
 */
class PackageTypesTest {

    @Test
    @DisplayName("purl 이 있으면 purl 의 유형이 먼저다")
    void purlComesFirst() {
        assertThat(PackageTypes.of("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "java-archive"))
                .isEqualTo("maven");
        // syft 의 binary 는 purl 의 이름이 없다 — purl 은 따로 달고 온다.
        assertThat(PackageTypes.of("pkg:generic/python@3.9.2", "binary")).isEqualTo("generic");
        assertThat(PackageTypes.of("pkg:rpm/rocky/openssl-libs@3.0.7-24?arch=x86_64", "rpm"))
                .isEqualTo("rpm");
    }

    @Test
    @DisplayName("purl 이 없으면 syft 의 유형을 purl 의 이름으로 — 표에 없는 것은 그대로, 없는 것은 빈 칸")
    void withoutPurlTheSyftTypeIsRenamed() {
        assertThat(PackageTypes.of("", "java-archive")).isEqualTo("maven");
        assertThat(PackageTypes.of(null, "python")).isEqualTo("pypi");
        assertThat(PackageTypes.of("", "go-module")).isEqualTo("golang");
        assertThat(PackageTypes.of("", "rpm")).isEqualTo("rpm");
        // 지어내지 않는다.
        assertThat(PackageTypes.of("", "binary")).isEqualTo("binary");
        assertThat(PackageTypes.of("", "UnknownPackage")).isEmpty();
        assertThat(PackageTypes.of("", "")).isEmpty();
        assertThat(PackageTypes.of(null, null)).isEmpty();
        // 대소문자를 가린다 — syft 의 이름은 정해진 글자다.
        assertThat(PackageTypes.of("", "Python")).isEqualTo("Python");
    }

    @Test
    @DisplayName("purl 이 아닌 것은 purl 로 읽지 않는다 — pkg: 다음에 / 앞의 한 글자 이상")
    void notAPurl() {
        assertThat(PackageTypes.fromPurl("pkg:npm/semver@7.5.2")).isEqualTo("npm");
        assertThat(PackageTypes.fromPurl("pkg://semver@7.5.2")).isNull();
        assertThat(PackageTypes.fromPurl("PKG:npm/semver@7.5.2")).isNull();
        assertThat(PackageTypes.fromPurl("pkg:npm")).isNull();
        assertThat(PackageTypes.fromPurl("")).isNull();
        assertThat(PackageTypes.fromPurl(null)).isNull();
        assertThat(PackageTypes.of("pkg://weird@0.1", "go-module")).isEqualTo("golang");
    }

    /**
     * 이미 담긴 행은 V22 가 옮긴다. <b>마이그레이션의 표가 이 표와 한 줄씩 같아야 한다</b> —
     * 다르면 새로 담는 행과 옮겨진 행이 같은 패키지를 다른 이름으로 부른다. 마이그레이션은
     * 시험에서 돌지 않으므로(H2 · create-drop) 글자로 견준다.
     */
    @Test
    @DisplayName("V22 의 옮김표가 앱의 표와 같다")
    void v22MatchesTheTable() throws IOException {
        String sql = Files.readString(
                Path.of("src/main/resources/db/migration/V22__component_type_purl_names.sql"));

        Map<String, String> renamed = new LinkedHashMap<>();
        Matcher when = Pattern.compile("WHEN '([^']+)'\\s+THEN '([^']*)'").matcher(sql);
        while (when.find()) {
            renamed.put(when.group(1), when.group(2));
        }
        assertThat(renamed).hasSize(20);
        renamed.forEach((syft, purl) ->
                assertThat(PackageTypes.purlName(syft)).as("V22 의 %s", syft).isEqualTo(purl));

        // 옮길 행을 고르는 목록이 옮김표와 같아야 한다 — 빠지면 그 유형은 옮겨지지 않는다.
        Matcher in = Pattern.compile("IN \\(([^)]*)\\)").matcher(sql);
        assertThat(in.find()).isTrue();
        Set<String> listed = new LinkedHashSet<>();
        Matcher quoted = Pattern.compile("'([^']+)'").matcher(in.group(1));
        while (quoted.find()) {
            listed.add(quoted.group(1));
        }
        assertThat(listed).isEqualTo(renamed.keySet());
    }
}
