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
 * <p>정의: purl 을 표준 파서로 읽은 정규형에서 버전 · 하위 경로와 표의 한정자를 뗀 것. Maven 의
 * classifier · type 처럼 아티팩트를 가르는 한정자는 남는다. 네임스페이스(Maven groupId · npm scope ·
 * 배포판)는 넣는다. purl 이 없으면 유형 · 이름으로 만든다(PackageKey 머리말).
 *
 * <p><b>이미 담긴 행은 마이그레이션이 만든다</b> — V24 의 SQL(한정자를 통째로 버렸다)과 그 위의 V25
 * (이 함수로 다시 만든다). 마이그레이션은 시험에서 돌지 않으므로(H2 · create-drop) 같은 입력과
 * 기대값을 파일 하나({@code tests/resources/package-key-vectors.tsv})에 두고 여기와
 * {@code tests/check-migrations.sh} 가 함께 견준다 — V24 뒤의 값(넷째 칸)과 지금 값(다섯째 칸).
 * 지금 값이 어긋나면 새로 올린 SBOM 의 탐지가 이관한 검토 결과에 이어지지 않는다.
 */
class PackageKeyTest {

    static final Path VECTORS = Path.of("tests/resources/package-key-vectors.tsv");

    /** 벡터 한 줄 — purl · 유형 · 이름 · V24 뒤 식별자 · 지금 식별자. */
    record Vector(String purl, String type, String name, String v24Key, String key) {
    }

    static List<Vector> vectors() throws IOException {
        List<Vector> out = new ArrayList<>();
        for (String line : Files.readAllLines(VECTORS, StandardCharsets.UTF_8)) {
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            String[] cells = line.split("\t", -1);
            assertThat(cells).as(line).hasSize(5);
            out.add(new Vector(cells[0], cells[1], cells[2], cells[3], cells[4]));
        }
        return out;
    }

    @Test
    @DisplayName("벡터 전부 — 탐지의 유형(grype 의 이름)으로도 인벤토리의 유형(purl 의 이름)으로도 같은 식별자")
    void vectorsGiveTheSameKeyFromBothSides() throws IOException {
        List<Vector> vectors = vectors();
        assertThat(vectors).hasSizeGreaterThan(60);
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
    @DisplayName("버전 · 하위 경로와 놓인 모양(arch · distro · epoch · upstream)은 넣지 않는다 — 올리거나 OS 를 바꿔도 같은 패키지")
    void versionAndPlacementAreLeftOut() {
        assertThat(PackageKey.of("pkg:rpm/rocky/openssl-libs@3.0.7-24.el9?arch=x86_64&distro=rocky-9.3", "rpm", "openssl-libs"))
                .isEqualTo(PackageKey.of("pkg:rpm/rocky/openssl-libs@1:3.0.7-27.el9?arch=aarch64&epoch=1&distro=rocky-9.4"
                                         + "&upstream=openssl-3.0.7-27.el9.src.rpm", "rpm", "openssl-libs"))
                .isEqualTo("pkg:rpm/rocky/openssl-libs");
        assertThat(PackageKey.of("pkg:maven/org.example/lib@1.0#sub/path", "java-archive", "lib"))
                .isEqualTo(PackageKey.of("pkg:maven/org.example/lib@2.0", "java-archive", "lib"));
    }

    /**
     * <b>아티팩트를 가르는 한정자는 남는다.</b> Maven 의 classifier · type 은 같은 좌표의 다른 파일이다
     * — 앞서(V24) 한정자를 통째로 버려 linux-x86_64 네이티브와 순수 jar 가 한 패키지였다. 버전이
     * 바뀌어도 그 갈래는 그 갈래다. type 의 기본값(jar)은 안 적은 것과 같다(규격).
     */
    @Test
    @DisplayName("Maven classifier · type 은 남는다 — 버전을 넘어 같고, 서로 다르며, type=jar 는 안 적은 것과 같다")
    void variantQualifiersStay() {
        String plain = PackageKey.of("pkg:maven/io.netty/netty-transport-native-epoll@4.1.86.Final",
                                     "java-archive", "netty-transport-native-epoll");
        String x86 = PackageKey.of("pkg:maven/io.netty/netty-transport-native-epoll@4.1.86.Final?classifier=linux-x86_64",
                                   "java-archive", "netty-transport-native-epoll");
        String arm = PackageKey.of("pkg:maven/io.netty/netty-transport-native-epoll@4.1.86.Final?classifier=linux-aarch_64",
                                   "java-archive", "netty-transport-native-epoll");
        assertThat(List.of(plain, x86, arm)).doesNotHaveDuplicates();
        assertThat(x86).isEqualTo("pkg:maven/io.netty/netty-transport-native-epoll?classifier=linux-x86_64")
                .isEqualTo(PackageKey.of("pkg:maven/io.netty/netty-transport-native-epoll@4.1.100.Final"
                                         + "?type=jar&classifier=linux-x86_64", "java-archive", "x"));
        assertThat(PackageKey.of("pkg:maven/org.example/lib@1.0?type=test-jar", "java-archive", "lib"))
                .isNotEqualTo(PackageKey.of("pkg:maven/org.example/lib@1.0?type=jar", "java-archive", "lib"))
                .isEqualTo("pkg:maven/org.example/lib?type=test-jar");
        assertThat(PackageKey.of("pkg:maven/org.example/lib@1.0?type=jar", "java-archive", "lib"))
                .isEqualTo(PackageKey.of("pkg:maven/org.example/lib@1.0", "java-archive", "lib"));
        // 순서 · 키의 대소문자 · 빈 값은 가르지 않는다(정규형).
        assertThat(PackageKey.of("pkg:maven/g/a@1?type=war&classifier=x", "java-archive", "a"))
                .isEqualTo(PackageKey.of("pkg:maven/g/a@2?Classifier=x&type=war&empty=", "java-archive", "a"))
                .isEqualTo("pkg:maven/g/a?classifier=x&type=war");
    }

    /**
     * <b>버리는 것은 유형마다 표로 적혀 있다</b> — 표에 없는 한정자는 남는다. 모르는 것을 버리면 서로
     * 다른 패키지가 합쳐지고, 남기면 같은 패키지가 둘로 갈려 보일 뿐이다(검토 결과가 다시 `작성` 이 된다).
     */
    @Test
    @DisplayName("버리는 한정자는 유형별 표 — 받은 곳 · 빌드 해시는 버리고, nix output · conan channel · 모르는 것은 남긴다")
    void ignoredQualifiersArePerType() {
        assertThat(PackageKey.of("pkg:nix/glibc@2.37-8?output=bin&outputhash=0c2rbyg2&drvpath=xq5b-glibc.drv", "nix", "glibc"))
                .isEqualTo("pkg:nix/glibc?output=bin");
        assertThat(PackageKey.of("pkg:conan/conan/zlib@1.2.13?channel=stable&rrev=abc", "conan", "zlib"))
                .isEqualTo("pkg:conan/conan/zlib?channel=stable");
        assertThat(PackageKey.of("pkg:pypi/requests@2.31.0?vcs_url=git%2Bhttps%3A%2F%2Fgithub.com%2Fpsf%2Frequests",
                                 "python", "requests"))
                .as("받은 곳(vcs_url)은 모든 유형에서 버린다").isEqualTo("pkg:pypi/requests");
        assertThat(PackageKey.of("pkg:generic/foo@1?arch=x86_64", "binary", "foo"))
                .as("표에 없는 유형의 arch 는 남는다 — 버리는 것은 유형마다 적은 것뿐")
                .isEqualTo("pkg:generic/foo?arch=x86_64");
        assertThat(PackageKey.of("pkg:npm/semver@7.5.4?future=1", "npm", "semver"))
                .as("모르는 한정자는 남는다").isEqualTo("pkg:npm/semver?future=1");
    }

    /**
     * 같은 패키지를 도구마다 다르게 적는다 — scope 의 {@code @} 를 인코딩했느냐, 한글 이름을 그대로
     * 적었느냐. 정규형이 같은 글자로 맞춘다. packageurl-java 1.5.0 은 ASCII 밖 글자를 풀 때도 쓸 때도
     * 깨뜨려({@code %FFFFFFED}) 그 두 자리를 우리가 한다.
     */
    @Test
    @DisplayName("인코딩은 가르지 않는다 — @scope · 한글 이름을 인코딩해 적든 그대로 적든 같은 식별자")
    void encodingDoesNotMatter() {
        assertThat(PackageKey.of("pkg:npm/@scope/name@1.0.0", "npm", "@scope/name"))
                .isEqualTo(PackageKey.of("pkg:npm/%40scope/name@1.0.0", "npm", "@scope/name"))
                .isEqualTo(PackageKey.of("", "npm", "@scope/name"))
                .isEqualTo("pkg:npm/%40scope/name");
        assertThat(PackageKey.of("pkg:npm/한글@1.0", "npm", "한글"))
                .isEqualTo(PackageKey.of("pkg:npm/%ED%95%9C%EA%B8%80@1.0", "npm", "한글"))
                .isEqualTo(PackageKey.of("", "npm", "한글"))
                .isEqualTo("pkg:npm/%ED%95%9C%EA%B8%80");
        assertThat(PackageKey.of("pkg:pypi/Django_Rest@3.0", "python", "Django_Rest"))
                .as("pypi 이름은 규격대로 맞춘다").isEqualTo("pkg:pypi/django-rest");
    }

    /**
     * 표준 파서가 받지 않는 purl 은 V24 의 좌표로 — 이름으로 내려가면 네임스페이스를 잃는다.
     * 겹친 한정자 키는 어느 값이 맞는지 모르므로 한정자를 남기지 않는다(V24 와 같다).
     */
    @Test
    @DisplayName("규격에 맞지 않는 purl 은 V24 의 좌표로 — 네임스페이스를 잃지 않는다")
    void malformedPurlsKeepTheirCoordinates() {
        assertThat(PackageKey.of("pkg:maven/g/a@1?classifier=x&classifier=y", "java-archive", "a"))
                .isEqualTo("pkg:maven/g/a");
        assertThat(PackageKey.of("pkg:npm/bad%ZZname@1", "npm", "bad%ZZname")).isEqualTo("pkg:npm/bad%ZZname");
        assertThat(PackageKey.of("pkg:npm/%FFbroken@1", "npm", "x"))
                .as("UTF-8 이 아닌 인코딩").isEqualTo("pkg:npm/%FFbroken");
    }

    /** 칸(512자)을 넘는 정규형 — 잘라 넣으면 앞이 같은 두 패키지가 합쳐진다. */
    @Test
    @DisplayName("512자를 넘는 식별자는 앞부분과 전체의 SHA-256 — 칸에 들고, 서로 갈린다")
    void overlongKeysFitAndStayApart() {
        String a = PackageKey.of("pkg:generic/longname@1?note=" + ":".repeat(200), "binary", "longname");
        String b = PackageKey.of("pkg:generic/longname@1?note=" + ":".repeat(199) + ";", "binary", "longname");
        assertThat(a).hasSize(512).contains("~").startsWith("pkg:generic/longname?note=%3A");
        assertThat(b).hasSize(512).isNotEqualTo(a);
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
        assertThat(PackageKey.namespace("pkg:maven/io.netty/netty-transport-native-epoll?classifier=linux-x86_64"))
                .as("한정자가 붙어도 네임스페이스는 그대로").isEqualTo("io.netty");
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
