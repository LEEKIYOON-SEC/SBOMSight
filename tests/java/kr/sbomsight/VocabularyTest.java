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

import static java.util.Map.entry;
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
    private static final Map<String, String> BANNED = Map.ofEntries(
            // `Map.of` 는 짝 열 개가 한계다. 늘어나면 여기서 컴파일이 멈춘다.
            entry("다시 볼 날", "재검토일"),
            entry("승인한 사람", "결재 문서 번호 (승인 절차는 없다 — 있는 척하지 않는다)"),
            entry("바로 닿음", "원격 접근"),
            entry("한 일", "행위"),
            entry("감춤", "(상태로 가른다)"),
            entry("컴포넌트", "패키지"),
            entry("수정본", "수정 버전"),
            entry("재검사", "다시 검사"),
            // `Scan` 을 부르는 말은 `검사` 하나다. 감사 로그의 행위 이름과
            // 자산 삭제 안내에만 `스캔` 이 남아 있었다 — 같은 것을 두 말로.
            entry("스캔", "검사"),
            // 순우리말로 지어낸 말이다. 그 팀이 실제로 쓰는 말은 `필터` 다.
            // 화면 전체가 일관되게 쓰고 있었을 뿐, 아무도 그렇게 부르지 않는다.
            entry("거르개", "필터"),
            entry("묶기", "묶는 방식 또는 탭 이름(항목별 · CVE별 · 패키지별)"));

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
            "처리", "변경 내용",
            // 한 낱말이 셋을 가리켰다 — 기둥의 섹션, 자산 목록의 조치 수,
            // 검토 결과의 `AnalysisResponse`. 섹션 이름으로만 남긴다.
            "대응", "대응 방안(AnalysisResponse) 또는 조치(Remediation)",
            // 사람이 적는 자유 기술은 `설명` 하나다 (§4.1).
            "메모", "설명",
            // `비고` 는 자산이 적어 두는 칸이다. 보고서의 그 칸은 사람이 적은
            // 것이 아니라 셈해서 붙인 딱지다.
            "등록 시 건수", "등록 당시 건수",
            // **누구의 상태인지 밝힌다.** 네 가지를 가리키고 있었다 —
            // 계정(정지·잠김) · 검사(완료·실패) · 조치(대기·진행·완료) ·
            // 검토 결과(미검토·검토 중·해당됨). 뒤의 둘은 자산 상세의
            // `조치·검토 결과` 탭에 나란히 선다.
            "상태", "계정 상태 · 검사 상태 · 조치 상태 · 검토 상태 중 하나");

    /**
     * 금지 낱말로 <b>시작하지만 옳은</b> 열 이름.
     *
     * <p>CSV 쪽 검사는 `서버` 를 막으려고 `서버 이름` 까지 잡도록 앞가지로
     * 본다(아래). 그런데 {@code 대응} 을 막으면 <b>고쳐 놓은 이름</b>인
     * {@code 대응 방안} 도 함께 걸린다. 옳은 이름을 여기 적어 둔다 —
     * 앞가지 검사를 느슨하게 풀면 `서버 이름` 이 다시 새어 나간다.
     */
    private static final List<String> ALLOWED_HEADERS = List.of("대응 방안");

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
     * <b>자바에서 만드는 글도 화면에 나간다.</b>
     *
     * <p>위 시험들은 템플릿만 읽는다. 그래서 자산 삭제 안내(`스캔 3건 · 탐지 …`),
     * 검사를 지운 뒤의 안내, 404 사유(`스캔을 찾을 수 없습니다`)가 자바 문자열
     * 이라 그대로 남아 있었다 — 여덟 곳. 로그({@code log.info} 등)는 화면에
     * 나가지 않으므로 넘긴다. 주석도 넘긴다.
     */
    @Test
    @DisplayName("자바에서 만드는 안내 · 오류 글도 쓰지 않기로 한 말을 쓰지 않는다")
    void javaMessagesFollowTheVocabulary() throws IOException {
        List<String> hits = new ArrayList<>();
        for (JavaLiteral lit : javaLiterals()) {
            for (var banned : BANNED.entrySet()) {
                if (lit.text().contains(banned.getKey())) {
                    hits.add("%s  '%s' → '%s'  (%s)".formatted(
                            lit.where(), banned.getKey(), banned.getValue(), lit.text()));
                }
            }
        }
        assertThat(hits)
                .as("docs/rework-plan.md §4.1 의 어휘표대로 고칩니다. 자바 문자열도 화면에 나갑니다.")
                .isEmpty();
    }

    /**
     * <b>이름 뒤에 조사를 박아 두지 않는다.</b>
     *
     * <p>`을/를` · `이/가` · `은/는` · `으로/로` · `과/와` 는 앞말의 받침에 따라
     * 갈린다. 이름 뒤에 하나를 박아 두면 이름에 따라 틀린다 — 띄운 앱에서
     * "was-01 을 내부업무 으로 옮겼습니다". 대신 고정된 말을 사이에 둔다:
     * "was-01 자산을 내부업무 구역으로". `의` · `에` 는 받침과 상관없어 둔다.
     */
    @Test
    @DisplayName("값 뒤에 받침 따라 갈리는 조사를 붙이지 않는다")
    void noFixedParticleAfterAValue() throws IOException {
        Pattern java = Pattern.compile("\\+\\s*\"\\s?(을|를|이|가|은|는|으로|로|과|와)(\\s|\\.|$)");
        Pattern template = Pattern.compile("\\+\\s*'\\s?(을|를|이|가|은|는|으로|로|과|와)(\\s|\\.|')");
        List<String> hits = new ArrayList<>();

        for (Path file : javaFiles()) {
            List<String> lines = Files.readAllLines(file);
            for (int i = 0; i < lines.size(); i++) {
                String line = lines.get(i);
                if (isCommentOrLog(line)) {
                    continue;
                }
                if (java.matcher(line).find()) {
                    hits.add("%s:%d  %s".formatted(file.getFileName(), i + 1, line.strip()));
                }
            }
        }
        Path templates = Path.of("src/main/resources/templates");
        try (Stream<Path> files = Files.walk(templates)) {
            for (Path file : files.filter(p -> p.toString().endsWith(".html")).sorted().toList()) {
                List<String> lines = visibleLines(file);
                for (int i = 0; i < lines.size(); i++) {
                    if (template.matcher(lines.get(i)).find()) {
                        hits.add("%s:%d  %s".formatted(templates.relativize(file), i + 1,
                                                       lines.get(i).strip()));
                    }
                }
            }
        }

        assertThat(hits)
                .as("이름 뒤에는 고정된 말(자산 · 구역 · 종료 코드 …)을 두고 조사는 그 말에 붙입니다.")
                .isEmpty();
    }

    private record JavaLiteral(String where, String text) {
    }

    private static List<Path> javaFiles() throws IOException {
        try (Stream<Path> files = Files.walk(Path.of("src/main/java"))) {
            return files.filter(p -> p.toString().endsWith(".java")).sorted().toList();
        }
    }

    /** 주석 줄이거나 로그를 남기는 줄 — 화면에 나가지 않는다. */
    private static boolean isCommentOrLog(String line) {
        String s = line.stripLeading();
        return s.startsWith("*") || s.startsWith("//") || s.startsWith("/*")
                || Pattern.compile("\\blog\\.(info|warn|error|debug|trace)\\(").matcher(line).find();
    }

    /** 주석과 로그를 뺀 자바 문자열 조각. 여러 줄에 걸친 블록 주석은 통째로 넘긴다. */
    private static List<JavaLiteral> javaLiterals() throws IOException {
        Pattern literal = Pattern.compile("\"((?:[^\"\\\\]|\\\\.)*)\"");
        List<JavaLiteral> out = new ArrayList<>();
        for (Path file : javaFiles()) {
            List<String> lines = Files.readAllLines(file);
            boolean inBlock = false;
            for (int i = 0; i < lines.size(); i++) {
                String line = lines.get(i);
                String s = line.strip();
                if (inBlock) {
                    inBlock = !s.contains("*/");
                    continue;
                }
                if (s.startsWith("/*") && !s.contains("*/")) {
                    inBlock = true;
                    continue;
                }
                if (isCommentOrLog(line)) {
                    continue;
                }
                Matcher m = literal.matcher(line);
                while (m.find()) {
                    out.add(new JavaLiteral(file.getFileName() + ":" + (i + 1), m.group(1)));
                }
            }
        }
        return out;
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
                    if (ALLOWED_HEADERS.stream().anyMatch(line::contains)) {
                        continue;
                    }
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
