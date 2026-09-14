package kr.sbomsight;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 보고서에 <b>서술형 문단이 돌아오지 않는가.</b>
 *
 * <p><b>왜 기계로 보는가.</b> 지적받은 것이 "누가 봐도 AI 가 만들어서 작성한
 * 것 같다" 였다. 기승전결 네 장에 장마다 서술형 문단이 얹혀 있었고, 그
 * 문장들은 표에 이미 있는 숫자를 한 번 더 말할 뿐이었다.
 *
 * <p>한 번 걷어 내도 다음에 표를 하나 더하면서 "이 표는 …를 보여 줍니다" 를
 * 붙이고 싶어진다. 사람이 눈으로 지키는 규칙은 화면이 늘수록 샌다.
 *
 * <p>여기서 막는 것은 셋이다.
 *
 * <ol>
 *   <li>{@code 기}·{@code 승}·{@code 전}·{@code 결} 장 표시</li>
 *   <li>{@code class="lead"} — 장마다 얹던 서술형 문단의 자리</li>
 *   <li>장(section)마다 {@code <p>} 가 둘을 넘는 것 — 각주는 한두 줄이면 족하다</li>
 * </ol>
 */
class ReportProseTest {

    private static final Path TEMPLATES = Path.of("src/main/resources/templates");

    private static final List<Path> REPORTS = List.of(
            TEMPLATES.resolve("report.html"),
            TEMPLATES.resolve("zone-report.html"));

    /**
     * 각주 규칙은 <b>보고서만의 것이 아니다.</b>
     *
     * <p>같은 지적이 화면에도 걸린다 — "설명으로 들어가는 수준 낮은 문구".
     * 보고서 둘만 지키면 {@code me.html} · {@code settings.html} ·
     * {@code vuln-detail.html} 의 각주가 서술형으로 남는다. 실제로 남아
     * 있었다.
     */
    private static List<Path> allTemplates() throws IOException {
        try (Stream<Path> files = Files.walk(TEMPLATES)) {
            return files.filter(p -> p.toString().endsWith(".html")).sorted().toList();
        }
    }

    /** 화면에 나가는 글자만 본다 — 주석은 브라우저에 글자로 뜨지 않는다. */
    private static String visible(Path file) throws IOException {
        String text = Files.readString(file);
        for (Pattern comment : List.of(Pattern.compile("(?s)<!--/\\*.*?\\*/-->"),
                                       Pattern.compile("(?s)<!--.*?-->"))) {
            text = comment.matcher(text).replaceAll("");
        }
        return text;
    }

    @Test
    @DisplayName("기승전결 장 표시가 없다")
    void noFourActStructure() throws IOException {
        for (Path file : REPORTS) {
            String text = visible(file);
            assertThat(text)
                    .as("%s 에 기승전결 표시가 남아 있다", file.getFileName())
                    .doesNotContain("class=\"ch\"");
            // 장 제목은 번호로 단다: "1. 점검 개요".
            assertThat(text)
                    .as("%s 의 장 제목이 번호가 아니다", file.getFileName())
                    .doesNotContainPattern("<h2>\\s*<span[^>]*>[기승전결]</span>");
        }
    }

    @Test
    @DisplayName("서술형 문단(class=\"lead\")이 없다")
    void noLeadParagraphs() throws IOException {
        for (Path file : REPORTS) {
            assertThat(visible(file))
                    .as("%s 에 서술형 문단이 남아 있다 — 내용은 표로 낸다", file.getFileName())
                    .doesNotContain("class=\"lead\"");
        }
    }

    /**
     * 장마다 {@code <p>} 가 둘 이하.
     *
     * <p>0 으로 막지는 않는다 — 약어를 푸는 각주 한 줄은 있어야 하고, 표가
     * 비었을 때 "없습니다" 한 줄도 필요하다. 그 이상이면 설명을 쓰기
     * 시작한 것이다.
     */
    @Test
    @DisplayName("장마다 문단이 둘을 넘지 않는다")
    void sectionsAreTablesNotProse() throws IOException {
        List<String> tooMany = new ArrayList<>();

        for (Path file : REPORTS) {
            String text = visible(file);
            Matcher sections = Pattern.compile("(?s)<section[^>]*>(.*?)</section>").matcher(text);
            int index = 0;
            while (sections.find()) {
                index++;
                String body = sections.group(1);
                long paragraphs = Pattern.compile("<p\\b").matcher(body).results().count();
                if (paragraphs > 2) {
                    tooMany.add("%s 의 %d번째 장: 문단 %d개"
                            .formatted(file.getFileName(), index, paragraphs));
                }
            }
            assertThat(index)
                    .as("%s 에서 장을 하나도 못 찾았다 — 시험이 헛돌고 있다", file.getFileName())
                    .isPositive();
        }

        assertThat(tooMany)
                .as("내용은 표로 냅니다. 설명이 필요한 약어는 각주 한 줄로 답니다.")
                .isEmpty();
    }

    /**
     * 표 안에 설명을 넣지 않는다.
     *
     * <p>앞서 노출면 표에 {@code 뜻} 이라는 열을 두고 그 칸마다 한 문장씩
     * 적었다. 표가 아니라 문단을 표 모양으로 그린 것이었다.
     */
    @Test
    @DisplayName("표에 '뜻' 열을 두지 않는다")
    void noExplanationColumn() throws IOException {
        for (Path file : REPORTS) {
            assertThat(visible(file))
                    .as("%s 의 표에 설명 열이 있다 — 각주로 내린다", file.getFileName())
                    .doesNotContain("<th>뜻</th>");
        }
    }

    // --- 각주 ----------------------------------------------------------------

    /**
     * {@code <p class="footnote">…</p>} 안에서 화면에 글자로 뜨는 것만.
     *
     * <p><b>식을 먼저 지운다.</b> {@code th:if="${a > 0}"} 처럼 속성값 안에
     * {@code >} 가 들어 있으면 여는 태그를 {@code [^>]*>} 로 집을 때 거기서
     * 끊겨, 속성 꼬리({@code 0}">})가 본문 글자로 딸려 온다 — 실제로 처음
     * 돌렸을 때 그렇게 나왔다.
     */
    private static List<String> footnotes(Path file) throws IOException {
        // 식이 내는 값(건수·날짜)은 글자 수에 넣지 않는다 — 우리가 쓴 글이
        // 아니라 데이터다. 대신 자리를 하나로 친다.
        String text = visible(file).replaceAll("(?s)\\$\\{[^}]*\\}", "0");

        List<String> out = new ArrayList<>();
        Matcher m = Pattern.compile("(?s)<p class=\"footnote\"[^>]*>(.*?)</p>").matcher(text);
        while (m.find()) {
            String body = m.group(1).replaceAll("(?s)<[^>]*>", " ");
            out.add(body.replaceAll("\\s+", " ").trim());
        }
        return out;
    }

    /**
     * 각주에 <b>서술형 종결</b>을 쓰지 않는다.
     *
     * <p>지적받은 것이 이것이다 — "수동적이고 진짜 이딴 걸 보고서? 라는 수준의
     * 내용들이 기본적으로 설명으로 들어가는 것". {@code …입니다} 를 붙이는
     * 순간 표 아래 한 줄이 설명 문단이 된다. 점검 보고서의 각주는 개조식이다:
     *
     * <pre>
     *   ✗ 업스트림에 수정 버전이 없어 업데이트로는 해소되지 않는 항목입니다.
     *   ✓ ※ 수정 버전이 하나도 없는 패키지. 일부만 해소되는 패키지는 3장 비고.
     * </pre>
     *
     * <p><b>종결을 {@code 니다} 로 잡는다.</b> 처음에 {@code 입니다} ·
     * {@code 습니다} · {@code 합니다} · {@code 됩니다} 넷만 막았더니
     * "…를 기준으로 그립니다" 가 그대로 지나갔다. 하십시오체 평서형은 전부
     * {@code 니다} 로 끝난다.
     *
     * <p>여기 걸리지 않는 것 둘.
     *
     * <ul>
     *   <li>{@code p.note.warn} — 각주가 아니라 "이 숫자를 이렇게 읽으라" 는
     *       경고 한 문장이고, 문장이어야 한다.</li>
     *   <li>{@code p.gloss} — 고르개 아래 뜨는 뜻 한 줄(§4.2~4.4). 계획이
     *       정한 문장 그대로여야 한다. 앞서 둘이 {@code footnote} 한
     *       클래스를 같이 쓰고 있었다.</li>
     * </ul>
     */
    @Test
    @DisplayName("각주가 서술형 문장이 아니다")
    void footnotesAreNotSentences() throws IOException {
        List<String> sentences = new ArrayList<>();

        for (Path file : allTemplates()) {
            for (String note : footnotes(file)) {
                if (note.contains("니다")) {
                    sentences.add("%s: %s".formatted(TEMPLATES.relativize(file), note));
                }
            }
        }

        assertThat(sentences)
                .as("각주는 개조식으로 씁니다. 서술형 종결(…니다)을 붙이면 설명 문단이 됩니다.")
                .isEmpty();
    }

    /**
     * 각주는 <b>한 줄</b>이다.
     *
     * <p>종결어미만 막으면 개조식으로 쓴 긴 설명이 들어온다. 길이로도 막는다 —
     * A4 인쇄 폭에서 두 줄이 넘어가면 그것은 각주가 아니라 문단이다.
     */
    @Test
    @DisplayName("각주가 두 줄을 넘지 않는다")
    void footnotesFitTwoLines() throws IOException {
        int budget = 90;
        List<String> tooLong = new ArrayList<>();

        for (Path file : allTemplates()) {
            for (String note : footnotes(file)) {
                if (note.length() > budget) {
                    tooLong.add("%s: %d자 — %s"
                            .formatted(TEMPLATES.relativize(file), note.length(), note));
                }
            }
        }

        assertThat(tooLong)
                .as("각주는 %d자 안에 답니다. 더 길면 설명을 쓰기 시작한 것입니다.", budget)
                .isEmpty();
    }

    // --- 숫자 (§5-9) ---------------------------------------------------------

    /**
     * 큰 수는 <b>세 자리 쉼표</b>로 찍는다.
     *
     * <p>Rocky 9 한 대의 탐지가 네 자리다. 쉼표가 없으면 {@code 1847} 과
     * {@code 18470} 이 눈으로 구분되지 않는다 — 결재 문서에서 자리 수를
     * 잘못 읽는 것이 가장 나쁜 종류의 오류다.
     *
     * <p>건수를 내는 식은 {@code #numbers.formatInteger(…, 0, 'COMMA')} 를
     * 거쳐야 한다. 실제로 여섯 자리가 그냥 찍히고 있었다.
     */
    @Test
    @DisplayName("큰 수를 세 자리 쉼표 없이 찍지 않는다")
    void bigNumbersCarryThousandsSeparators() throws IOException {
        List<String> counts = List.of(
                "findingCount", "componentCount", "matchCount", "totalFindings",
                "distinctVulnerabilities", "resolvableFindings", "blockedFindings",
                "residualFindings", "excludedByAnalysis");
        List<String> bare = new ArrayList<>();

        for (Path file : REPORTS) {
            String text = visible(file);
            Matcher m = Pattern.compile("(?s)th:text=\"([^\"]*)\"").matcher(text);
            while (m.find()) {
                String expression = m.group(1);
                if (expression.contains("formatInteger")) {
                    continue;
                }
                // 값을 찍지 않는 식(참·거짓 판정)은 자리 수와 상관이 없다.
                if (expression.contains(" > 0") || expression.contains(" == 0")) {
                    continue;
                }
                for (String count : counts) {
                    if (expression.contains(count)) {
                        bare.add("%s: %s".formatted(file.getFileName(),
                                expression.replaceAll("\\s+", " ")));
                        break;
                    }
                }
            }
        }

        assertThat(bare)
                .as("건수는 #numbers.formatInteger(…, 0, 'COMMA') 로 찍습니다 (§5-9).")
                .isEmpty();
    }

    /** 각주를 하나도 못 찾으면 위 두 시험이 헛돌고 있는 것이다. */
    @Test
    @DisplayName("각주를 실제로 찾아서 보고 있다")
    void actuallyFindsFootnotes() throws IOException {
        for (Path file : REPORTS) {
            assertThat(footnotes(file))
                    .as("%s 에서 각주를 하나도 못 찾았다", file.getFileName())
                    .isNotEmpty();
        }
        long total = 0;
        for (Path file : allTemplates()) {
            total += footnotes(file).size();
        }
        assertThat(total)
                .as("보고서 밖의 각주까지 세고 있는가 — 화면에도 같은 규칙이 걸린다")
                .isGreaterThan(REPORTS.size() * 2L);
    }
}
