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

    private static final List<Path> REPORTS = List.of(
            Path.of("src/main/resources/templates/report.html"),
            Path.of("src/main/resources/templates/zone-report.html"));

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
}
