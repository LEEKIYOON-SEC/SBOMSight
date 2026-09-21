package kr.sbomsight;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 운영물에 개발·시험 것이 섞이지 않는다.
 *
 * <p><b>왜 이 시험이 있는가.</b> 점검에서 묻는 것은 "시험 코드가 있느냐" 가
 * 아니라 <b>"운영에 시험 코드·시험 값이 섞였느냐"</b> 다. 섞이는 자리는
 * 늘 같은 셋이고, 셋 다 조용히 생긴다 — 누가 열어 보기 전까지 아무도 모른다.
 *
 * <ol>
 *   <li><b>설정에 박힌 비밀번호.</b> 환경변수를 안 넣어도 일단 뜨게 해 주는
 *       기본값이 있으면, 넣은 줄 알았는데 안 넣은 설치가 그대로 남는다.
 *       그 비밀번호는 소스만 보면 누구나 안다.</li>
 *   <li><b>{@code static/} 아래의 개발 문서.</b> 그 아래는 로그인 없이 밖에서
 *       열린다. 실제로 {@code /vendor/tabler/README.md} 가 내부 빌드 절차를
 *       담은 채로 200 을 내주고 있었다.</li>
 *   <li><b>운영 jar 로 새는 시험 의존성.</b> {@code <scope>test</scope>} 를
 *       빠뜨리면 H2 와 JUnit 이 배포물에 들어간다 — 쓰지 않는 DB 엔진이
 *       운영 시스템에 실려 다니는 셈이고, 그것 자체가 취약점 목록에 뜬다.</li>
 * </ol>
 *
 * <p>시험 코드 자체는 {@code tests/} 한 폴더에 모여 있다. 운영 PC 에서는 그
 * 폴더만 지운다({@code tests/README.md}) — 저장소에는 남으므로 시험을
 * 수행했다는 증적은 잃지 않는다.
 */
class ProductionHygieneTest {

    /**
     * 설정 이름이 <b>이것으로 끝나면</b> 비밀번호다.
     *
     * <p>"포함" 으로 보면 안 된다 — {@code password-max-age-days} 는 90일
     * 이라는 정책 값이지 비밀번호가 아니다. 그것까지 잡으면 시험이 틀린
     * 자리를 가리키고, 틀린 자리를 가리키는 시험은 곧 무시된다.
     */
    private static final List<String> SECRET_SUFFIXES =
            List.of("password", "secret", "token", "credentials", "passphrase");

    /**
     * <b>비밀번호에는 기본값이 없다.</b>
     *
     * <p>{@code ${VAR:기본값}} 꼴로 적으면 환경변수가 없어도 그 값으로 뜬다.
     * 앞서 DB 비밀번호가 {@code devpass}, 키스토어 비밀번호가 {@code changeit}
     * 이었다 — 둘 다 운영 jar 안에 그대로 들어 있었다.
     */
    @Test
    @DisplayName("운영 설정에 비밀번호 기본값이 없다")
    void noFallbackSecretsInProductionConfig() throws IOException {
        Path config = Path.of("src/main/resources/application.yml");
        assertThat(config).exists();

        List<String> offenders = new ArrayList<>();
        List<String> lines = Files.readAllLines(config);
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            String trimmed = line.strip();
            if (trimmed.startsWith("#") || !trimmed.contains(":")) {
                continue;
            }
            String key = trimmed.substring(0, trimmed.indexOf(':')).strip().toLowerCase();
            if (SECRET_SUFFIXES.stream().noneMatch(key::endsWith)) {
                continue;
            }
            // `${VAR}` 는 기본값 없음, `${VAR:무엇}` 은 기본값 있음.
            String value = trimmed.substring(trimmed.indexOf(':') + 1).strip();
            if (value.startsWith("${") && value.contains(":") && !value.equals("${}")) {
                offenders.add("%s:%d — %s".formatted(config, i + 1, trimmed));
            }
        }

        assertThat(offenders)
                .as("비밀번호에 기본값을 두면 환경변수를 안 넣은 설치가 그대로 뜬다. "
                    + "`${VAR}` 로 두어 안 넣으면 멈추게 한다.")
                .isEmpty();
    }

    /**
     * <b>{@code static/} 아래에는 문서를 두지 않는다.</b>
     *
     * <p>그 아래는 {@code SecurityConfig.PUBLIC} 이라 <b>로그인 없이</b>
     * 열린다. 라이선스는 예외다 — MIT·OFL 은 라이선스가 배포물과 함께 가기를
     * 요구하고, 그것은 감추는 것이 아니라 내걸어야 하는 것이다.
     */
    @Test
    @DisplayName("공개되는 static 아래에 개발 문서가 없다")
    void noDeveloperDocsUnderStatic() throws IOException {
        Path statics = Path.of("src/main/resources/static");
        assertThat(statics).isDirectory();

        List<String> docs;
        try (Stream<Path> files = Files.walk(statics)) {
            docs = files.filter(Files::isRegularFile)
                        .map(Path::toString)
                        .filter(p -> p.endsWith(".md") || p.endsWith(".markdown"))
                        .sorted().toList();
        }

        assertThat(docs)
                .as("static 아래는 로그인 없이 열린다. 개발 문서는 docs/ 에 둔다 — "
                    + "실제로 /vendor/tabler/README.md 가 내부 빌드 절차를 담은 채 "
                    + "200 을 내주고 있었다.")
                .isEmpty();
    }

    /**
     * <b>시험 의존성은 운영 jar 에 들어가지 않는다.</b>
     *
     * <p>{@code <scope>test</scope>} 한 줄이 빠지면 H2 와 JUnit 이 배포물에
     * 실린다. 쓰지도 않는 DB 엔진이 운영 시스템에 있는 셈이고, 그 자체가
     * 이 도구가 찾아내는 종류의 항목이 된다.
     */
    @Test
    @DisplayName("시험 의존성은 test 범위다")
    void testDependenciesStayOutOfTheJar() throws IOException {
        String pom = Files.readString(Path.of("pom.xml"));

        for (String artifact : List.of("spring-boot-starter-test", "spring-security-test", "h2")) {
            int at = pom.indexOf("<artifactId>" + artifact + "</artifactId>");
            assertThat(at).as("%s 의존성이 pom.xml 에 없다", artifact).isGreaterThan(-1);

            // 그 의존성 블록이 끝나기 전에 test 범위가 나와야 한다.
            int end = pom.indexOf("</dependency>", at);
            assertThat(pom.substring(at, end))
                    .as("%s 에 <scope>test</scope> 가 없다 — 운영 jar 에 실린다", artifact)
                    .contains("<scope>test</scope>");
        }
    }

    /**
     * <b>시험은 한 폴더에 모여 있다.</b>
     *
     * <p>운영 PC 에서 {@code tests} 하나만 지우면 끝나야 한다. 새 시험
     * 스크립트를 {@code scripts/} 에 두면 그 약속이 조용히 깨진다 —
     * 지웠는데 남아 있는 것이 생기고, 그것을 알아차리는 자리는 점검뿐이다.
     */
    @Test
    @DisplayName("시험 관련 파일이 tests 밖에 흩어져 있지 않다")
    void everythingTestRelatedLivesUnderTests() throws IOException {
        assertThat(Path.of("tests")).as("tests 폴더가 없다").isDirectory();
        assertThat(Path.of("src/test"))
                .as("src/test 가 되살아났다 — 시험은 tests/ 한 곳에 둔다")
                .doesNotExist();

        List<String> strays;
        try (Stream<Path> files = Files.list(Path.of("scripts"))) {
            strays = files.map(p -> p.getFileName().toString())
                          .filter(name -> name.startsWith("test") || name.startsWith("check-"))
                          .sorted().toList();
        }

        assertThat(strays)
                .as("scripts/ 에 시험 스크립트가 있다. tests/ 로 옮긴다 — "
                    + "운영 PC 에서 tests 하나만 지우면 끝나야 한다.")
                .isEmpty();
    }
}
