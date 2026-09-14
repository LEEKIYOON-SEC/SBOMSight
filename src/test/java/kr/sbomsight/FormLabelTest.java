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
 * 입력칸마다 <b>이름이 붙어 있는가</b> (§5 — 라벨).
 *
 * <p>비밀번호 변경 화면이 이랬다.
 *
 * <pre>
 *   &lt;label&gt;새 비밀번호&lt;/label&gt;
 *   &lt;input name="password" type="password"&gt;
 * </pre>
 *
 * <p>둘이 나란히 있을 뿐 묶여 있지 않아 <b>라벨을 눌러도 칸에 초점이 가지
 * 않았고</b>, 읽어 주는 도구에는 이름 없는 비밀번호 칸 셋으로 들렸다. 화면은
 * 멀쩡해 보여서 눈으로는 끝까지 안 보인다 — 그래서 기계로 본다.
 *
 * <p>세 가지 중 하나면 통과다.
 *
 * <ol>
 *   <li>{@code <label>이름 <input ...></label>} — 칸을 라벨이 감쌈</li>
 *   <li>{@code <label for="x">} + {@code <input id="x">}</li>
 *   <li>{@code aria-label="…"} — 표 안의 인라인 칸처럼 눈에 보이는 라벨을
 *       둘 자리가 없을 때</li>
 * </ol>
 */
class FormLabelTest {

    private static final Path TEMPLATES = Path.of("src/main/resources/templates");

    /** 사람이 채우는 칸만 본다. 숨은 칸과 단추는 라벨을 받을 것이 없다. */
    private static final Pattern FIELD =
            Pattern.compile("<(input|select|textarea)\\b[^>]*>");
    private static final Pattern NOT_A_FIELD =
            Pattern.compile("type=\"(hidden|submit|button|reset|image)\"");

    @Test
    @DisplayName("사람이 채우는 칸에는 전부 이름이 붙어 있다")
    void everyFieldHasALabel() throws IOException {
        List<String> unnamed = new ArrayList<>();

        try (Stream<Path> files = Files.walk(TEMPLATES)) {
            for (Path file : files.filter(p -> p.toString().endsWith(".html")).sorted().toList()) {
                // 주석 안의 예시 markup 을 세지 않는다.
                String text = Files.readString(file).replaceAll("(?s)<!--.*?-->", "");

                Matcher fields = FIELD.matcher(text);
                while (fields.find()) {
                    String tag = fields.group();
                    if (NOT_A_FIELD.matcher(tag).find() || tag.contains("aria-label=")) {
                        continue;
                    }
                    Matcher id = Pattern.compile("id=\"([^\"]+)\"").matcher(tag);
                    if (id.find() && text.contains("for=\"" + id.group(1) + "\"")) {
                        continue;
                    }
                    // 여는 <label> 이 닫힌 것보다 많으면 이 칸은 라벨 안에 있다.
                    String before = text.substring(0, fields.start());
                    if (count(before, "<label") > count(before, "</label>")) {
                        continue;
                    }
                    unnamed.add("%s:%d  %s".formatted(
                            TEMPLATES.relativize(file),
                            count(before, "\n") + 1,
                            tag.replaceAll("\\s+", " ")));
                }
            }
        }

        assertThat(unnamed)
                .as("라벨로 감싸거나, for/id 로 묶거나, aria-label 을 답니다.")
                .isEmpty();
    }

    private static int count(String text, String needle) {
        int n = 0;
        for (int i = text.indexOf(needle); i >= 0; i = text.indexOf(needle, i + needle.length())) {
            n++;
        }
        return n;
    }
}
