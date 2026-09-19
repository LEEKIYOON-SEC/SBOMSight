package kr.sbomsight;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
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
            "컴포넌트", "패키지",
            "수정본", "수정 버전",
            "재검사", "다시 검사");

    /**
     * <b>열 머리에서만</b> 쓰지 않는 말.
     *
     * <p>낱말 자체는 멀쩡한데 열 이름으로 쓰면 안 되는 것들이다.
     * {@code 서버} 는 "이 서버에서 grype 이 돈다" 처럼 본문에 쓸 자리가 있고,
     * {@code 판정} 은 주석에서 "아무도 확인하지 않은 판정" 이라고 쓸 수 있다.
     * 금지되는 것은 <b>표의 열 이름</b>이다 — 한 가지를 두 이름으로 부르는
     * 자리가 거기다.
     *
     * <p>실제로 {@code 서버 이름}/{@code 자산},
     * {@code 설치 → 수정}/{@code 현재 → 목표} 가 섞여 있었다.
     */
    private static final Map<String, String> BANNED_HEADERS = Map.of(
            "서버", "자산",
            "판정", "검토 결과 (grype 이 낸 것은 탐지)",
            "설치 → 수정", "현재 → 목표",
            "뜻", "열 자체를 없앤다 — 설명은 각주로",
            "줄", "줄 번호",
            "처리", "변경 내용");

    // '뜻' 과 '줄' 은 여기 넣지 않는다. 한 글자짜리 흔한 낱말이라 '그런 뜻이다'
    // 같은 멀쩡한 설명문에까지 걸린다. 그 둘은 열 이름이 문제였고 그 열은
    // 이미 없앴다 — 낱말 자체를 금지할 수 있는 종류가 아니다.

    /**
     * <b>말투</b> — 낱말 하나가 아니라 꼴이 문제인 것들.
     *
     * <p>낱말 목록으로는 못 잡는다. {@code grype} 은 화면에 남아야 하는
     * 자리가 있고(설정의 도구 상태 · 보고서의 <b>점검 도구</b> 줄 — 어느 판이
     * 냈는지가 곧 정확성의 근거다), {@code 올리} 도 "값을 올리면" 처럼 쓸
     * 자리가 있다. 막는 것은 <b>도구를 주어로 세운 서술</b>과 <b>지어낸
     * 빈 화면 문구</b>다.
     *
     * <p>쓰는 사람에게 이 화면은 그냥 취약점 정보다. 어느 도구가 냈는지는
     * 각주 한 줄이면 되고, 한 줄로 족한 것을 문장마다 되풀이하면 읽는 사람이
     * 도구의 사정을 알아야 하는 것처럼 읽힌다.
     */
    private static final Map<String, String> BANNED_PHRASES = Map.of(
            "grype\\s*이\\s*(준|주지|낸|돌)", "도구를 주어로 세우지 않는다 — '검사 결과 그대로' · '확인되지 않음'",
            "grype\\s*(원본|출력)", "검사 결과 그대로",
            "걸리는\\s*(것|자산|패키지|취약점)이\\s*없습니다", "조건에 맞는 … 이 없습니다",
            "SBOM\\s*을?\\s*올리", "SBOM 업로드");

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

    /**
     * 말투.
     *
     * <p><b>왜 또 시험인가.</b> "화면에서 grype 이야기를 지워 달라" 는 말을
     * 세 판에 걸쳐 들었다. 그때마다 눈에 띈 자리만 고쳤고, 다음 판에 다른
     * 화면에서 같은 말투가 나왔다 — {@code vuln-detail} 의 카드 제목,
     * {@code report} 의 각주, {@code zone-report} 의 각주가 차례로 그랬다.
     * 눈으로 세는 방식은 화면 수만큼 샌다.
     */
    @Test
    @DisplayName("쓰지 않기로 한 말투가 화면에 남아 있지 않다")
    void noBannedPhrasingsReachTheScreen() throws IOException {
        Path templates = Path.of("src/main/resources/templates");
        List<String> hits = new ArrayList<>();

        try (Stream<Path> files = Files.walk(templates)) {
            for (Path file : files.filter(p -> p.toString().endsWith(".html")).sorted().toList()) {
                List<String> lines = visibleLines(file);
                for (int i = 0; i < lines.size(); i++) {
                    for (var banned : BANNED_PHRASES.entrySet()) {
                        if (Pattern.compile(banned.getKey()).matcher(lines.get(i)).find()) {
                            hits.add("%s:%d  '%s' → %s".formatted(
                                    templates.relativize(file), i + 1,
                                    lines.get(i).strip(), banned.getValue()));
                        }
                    }
                }
            }
        }

        assertThat(hits)
                .as("도구 이름은 근거를 적는 자리(설정의 도구 상태 · 보고서의 점검 도구)에만 둡니다.")
                .isEmpty();
    }

    /**
     * 표의 열 이름.
     *
     * <p>한 가지를 두 이름으로 부르는 일은 거의 언제나 여기서 생긴다 — 새
     * 화면을 만들면서 옛 표를 베껴 오고, 베껴 온 열 이름만 손대지 않는다.
     * 실제로 {@code 설치 → 수정} 과 {@code 현재 → 목표} 가 같은 칸을
     * 가리킨 채로 둘 다 살아 있었다.
     */
    @Test
    @DisplayName("표의 열 이름이 어휘표를 따른다")
    void columnHeadersFollowTheVocabulary() throws IOException {
        Path templates = Path.of("src/main/resources/templates");
        Pattern header = Pattern.compile("<th[^>]*>\\s*([^<]*?)\\s*</th>");
        List<String> hits = new ArrayList<>();

        try (Stream<Path> files = Files.walk(templates)) {
            for (Path file : files.filter(p -> p.toString().endsWith(".html")).sorted().toList()) {
                List<String> lines = visibleLines(file);
                for (int i = 0; i < lines.size(); i++) {
                    Matcher m = header.matcher(lines.get(i));
                    while (m.find()) {
                        String name = m.group(1);
                        String replacement = BANNED_HEADERS.get(name);
                        if (replacement != null) {
                            hits.add("%s:%d  열 이름 '%s' → '%s'".formatted(
                                    templates.relativize(file), i + 1, name, replacement));
                        }
                    }
                }
            }
        }

        assertThat(hits)
                .as("docs/rework-plan.md §4.1. 같은 것을 두 이름으로 부르지 않습니다.")
                .isEmpty();
    }

    /**
     * <b>파일로 나가는 열 이름도 화면과 같아야 한다.</b>
     *
     * <p>위 시험은 템플릿의 {@code <th>} 만 본다. 그래서 N8 에서 화면의
     * {@code 서버 이름} 을 {@code 자산 이름} 으로 고쳤는데, <b>사람이 실제로
     * 채워 넣는 일괄 등록 서식</b>은 자바 문자열이라 그대로 남아 있었다 —
     * 화면과 내려받은 파일이 같은 칸을 다른 이름으로 부르고 있었다.
     *
     * <p>CSV 를 만드는 자리는 {@code CsvWriter} 와 서식 하나다. 그 두 곳의
     * 첫 줄만 본다.
     */
    @Test
    @DisplayName("내보내는 CSV 의 열 이름도 어휘표를 따른다")
    void csvHeadersFollowTheVocabulary() throws IOException {
        List<String> hits = new ArrayList<>();
        for (Path file : List.of(Path.of("src/main/java/kr/sbomsight/service/CsvWriter.java"),
                                 Path.of("src/main/java/kr/sbomsight/web/AssetImportController.java"))) {
            List<String> lines = Files.readAllLines(file);
            for (int i = 0; i < lines.size(); i++) {
                String line = lines.get(i);
                // 주석은 넘긴다 — 무엇을 왜 바꿨는지 적을 자리가 필요하다.
                if (line.stripLeading().startsWith("*") || line.stripLeading().startsWith("//")) {
                    continue;
                }
                for (var banned : BANNED_HEADERS.entrySet()) {
                    // 열 이름으로 쓰인 것만 본다: 큰따옴표로 감싼 값이거나
                    // CSV 첫 줄의 쉼표 사이 값.
                    //
                    // **그 낱말로 시작하는 것까지 잡는다.** 금지 낱말은 `서버`
                    // 인데 실제로 적혀 있던 것은 `서버 이름` 이었다. 정확히
                    // 같은 것만 찾으면 그대로 지나간다 — 처음에 그렇게 짰고,
                    // 고치기 전 코드에서 시험이 통과해 버렸다.
                    String word = Pattern.quote(banned.getKey());
                    String cell = word + "(\\s+\\S+)?";
                    if (line.matches(".*\"" + cell + "\".*")
                            || line.matches(".*(^|,)\\s*" + cell + "\\s*(,|$).*")) {
                        hits.add("%s:%d  열 이름 '%s' → '%s'".formatted(
                                file.getFileName(), i + 1, banned.getKey(), banned.getValue()));
                    }
                }
            }
        }

        assertThat(hits)
                .as("화면과 내려받은 파일이 같은 칸을 다른 이름으로 부르면 안 됩니다.")
                .isEmpty();
    }
}
