package kr.sbomsight;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 화면에 내보내지 않기로 한 말.
 *
 * <p><b>왜 시험으로 두는가.</b> 한 번 쓸어 냈다고 보고했는데 네 화면에 그대로
 * 남아 있었다. 화면마다 눈으로 세는 방식은 화면이 늘어날수록 반드시 새고,
 * 새는 것을 아무도 모른다. 새 화면을 만들 때 옛 화면에서 표를 복사해 오면
 * 그 말도 함께 따라온다 — 실제로 {@code vulns.html} 이 그렇게 만들어졌다.
 *
 * <p>지어낸 말과 흐려진 줄임말이다. 근거는 {@code docs/rework-plan.md} §4.1.
 * 여기에 걸리면 그 표를 보고 고친다. 새 말을 만들지 않는다.
 */
class VocabularyTest {

    /** 쓰지 않기로 한 말 → 대신 쓰는 말. */
    private static final Map<String, String> BANNED = Map.of(
            "다시 볼 날", "재검토일",
            "승인한 사람", "결재 문서 번호 (승인 절차는 없다 — 있는 척하지 않는다)",
            "바로 닿음", "원격 접근",
            "한 일", "행위",
            "감춤", "(상태로 가른다)",
            "컴포넌트", "패키지");

    // '뜻' 과 '줄' 은 여기 넣지 않는다. 한 글자짜리 흔한 낱말이라 '그런 뜻이다'
    // 같은 멀쩡한 설명문에까지 걸린다. 그 둘은 열 이름이 문제였고 그 열은
    // 이미 없앴다 — 낱말 자체를 금지할 수 있는 종류가 아니다.

    /**
     * 설명이 목적인 자리까지 막으면 무엇을 왜 바꿨는지 적을 수 없게 된다.
     * 화면에 나가는 글자만 본다 — 타임리프 주석({@code <!--/* ... *&#47;-->})과
     * HTML 주석은 브라우저 화면에 글자로 뜨지 않는다.
     */
    private static List<String> visibleLines(Path file) throws IOException {
        // 줄 수를 그대로 둔다. 주석을 통째로 지우면 그 뒤 줄 번호가 전부
        // 밀려서, 시험이 가리키는 줄에 가 보면 엉뚱한 것이 있다.
        String text = Files.readString(file);
        //   타임리프 주석 — 서버가 아예 지워서 내보낸다.
        //   보통 HTML 주석 — 나가긴 하지만 사람 눈에 글자로 보이지 않는다.
        for (Pattern comment : List.of(Pattern.compile("(?s)<!--/\\*.*?\\*/-->"),
                                       Pattern.compile("(?s)<!--.*?-->"))) {
            text = comment.matcher(text).replaceAll(m -> blankKeepingLines(m.group()));
        }
        return text.lines().toList();
    }

    /** 주석을 지우되 그 안에 있던 줄바꿈은 남긴다. */
    private static String blankKeepingLines(String comment) {
        return "\n".repeat((int) comment.chars().filter(c -> c == '\n').count());
    }

    @Test
    @DisplayName("쓰지 않기로 한 말이 화면에 남아 있지 않다")
    void noBannedWordsReachTheScreen() throws IOException {
        Path templates = Path.of("src/main/resources/templates");
        List<String> hits = new ArrayList<>();

        try (Stream<Path> files = Files.walk(templates)) {
            for (Path file : files.filter(p -> p.toString().endsWith(".html")).toList()) {
                List<String> lines = visibleLines(file);
                for (int i = 0; i < lines.size(); i++) {
                    for (var banned : BANNED.entrySet()) {
                        if (lines.get(i).contains(banned.getKey())) {
                            hits.add("%s:%d  '%s' → '%s'".formatted(
                                    templates.relativize(file), i + 1,
                                    banned.getKey(), banned.getValue()));
                        }
                    }
                }
            }
        }

        assertThat(hits)
                .as("docs/rework-plan.md §4.1 의 어휘표대로 고칩니다. 새 말을 짓지 않습니다.")
                .isEmpty();
    }
}
