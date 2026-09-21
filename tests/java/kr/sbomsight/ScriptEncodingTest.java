package kr.sbomsight;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * PowerShell 스크립트의 인코딩을 고정한다.
 *
 * <p><b>왜 이 시험이 있는가.</b> Windows PowerShell 5.1 — 윈도우 기본
 * {@code powershell.exe} — 은 BOM 이 없는 파일을 시스템 ANSI 코드페이지로 읽는다.
 * 한국어 윈도우면 CP949 다. 한글이 깨지는 데서 끝나면 그나마 낫지만, 실제로는
 * <b>닫는 따옴표까지 먹혀</b> 스크립트가 통째로 파싱 실패한다:
 *
 * <pre>
 *   식에 닫는 ')' 가 없습니다.
 *   ParserError: MissingEndParenthesisInExpression
 * </pre>
 *
 * <p>실 PC 에서 이걸로 한 번 막혔다. 코드를 고친 것이 아니라 <b>파일을 저장한
 * 방식</b>이 원인이라, 편집기를 바꾸거나 스크립트를 새로 만들 때마다 조용히 다시
 * 생길 수 있다. 그래서 빌드가 확인한다.
 */
class ScriptEncodingTest {

    private static final byte[] BOM = { (byte) 0xEF, (byte) 0xBB, (byte) 0xBF };

    private static List<Path> powershellScripts() throws IOException {
        Path scripts = Path.of("scripts");
        if (!Files.isDirectory(scripts)) {
            return List.of();
        }
        try (Stream<Path> files = Files.list(scripts)) {
            return files.filter(p -> p.getFileName().toString().endsWith(".ps1")).sorted().toList();
        }
    }

    @Test
    @DisplayName("모든 .ps1 이 UTF-8 BOM 으로 저장되어 있다")
    void powershellScriptsCarryABom() throws IOException {
        List<Path> scripts = powershellScripts();
        assertThat(scripts).as("확인할 .ps1 이 하나는 있어야 한다").isNotEmpty();

        for (Path script : scripts) {
            byte[] head = new byte[3];
            try (var in = Files.newInputStream(script)) {
                int read = in.read(head);
                assertThat(read).as("%s 가 비어 있다", script).isEqualTo(3);
            }
            assertThat(head)
                    .as("%s 에 UTF-8 BOM 이 없다. PowerShell 5.1 이 CP949 로 읽어 "
                        + "파싱에 실패한다 — 편집기에서 'UTF-8 with BOM' 으로 다시 저장하라.",
                        script)
                    .isEqualTo(BOM);
        }
    }

    @Test
    @DisplayName("한글이 들어간 스크립트는 UTF-8 로 읽힌다")
    void scriptsAreValidUtf8() throws IOException {
        for (Path script : powershellScripts()) {
            // 깨진 인코딩으로 저장됐다면 여기서 대체 문자(U+FFFD)가 나온다.
            String text = Files.readString(script, StandardCharsets.UTF_8);
            assertThat(text)
                    .as("%s 에 깨진 문자가 있다 — UTF-8 이 아닌 인코딩으로 저장된 것이다", script)
                    .doesNotContain("�");
        }
    }

    /*
     * 따옴표 짝을 세는 시험도 만들어 봤지만 버렸다.
     *
     *     $major = if ($ver -match '"(\d+)') { ... }
     *
     * 처럼 작은따옴표 안에 큰따옴표가 들어간 정상적인 줄을 잡아냈다. 제대로
     * 하려면 PowerShell 토크나이저를 흉내 내야 하는데, 그것 자체가 새 버그의
     * 온상이 된다. 게다가 따옴표가 어긋나는 것은 BOM 이 없을 때 나타나는
     * **증상**이지 원인이 아니다 — 위의 두 시험이 원인을 막는다.
     */
}
