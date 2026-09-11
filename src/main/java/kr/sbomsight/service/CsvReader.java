package kr.sbomsight.service;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * CSV 읽기 — 엑셀이 저장한 파일을 사람이 준 그대로 읽는다.
 *
 * <p><b>인코딩이 이 클래스의 존재 이유다.</b> 한국어 윈도우의 엑셀에서
 * "CSV (쉼표로 분리)" 로 저장하면 <b>UTF-8 이 아니라 CP949</b> 로 나온다.
 * 그것을 UTF-8 로 읽으면 한글이 전부 깨지고, 깨진 이름으로 자산이 등록된다.
 * 이 도구는 같은 함정에 이미 한 번 걸렸다 — PowerShell 스크립트가 BOM 없이
 * 저장돼 CP949 로 읽히면서 파서가 죽었다.
 *
 * <p>읽는 순서:
 * <ol>
 *   <li>UTF-8 BOM 이 있으면 UTF-8. 엑셀의 "CSV UTF-8" 저장이 이렇게 나온다.</li>
 *   <li>없으면 <b>엄격한</b> UTF-8 로 해독해 본다. 성공하면 UTF-8 이다.</li>
 *   <li>실패하면 CP949 로 읽는다. CP949 한글 바이트열은 대개 UTF-8 로는
 *       유효하지 않아서, 이 구분이 실제로 작동한다.</li>
 * </ol>
 *
 * <p>짐작하지 않고 실패하게 두는 선택지도 있지만, 그러면 엑셀에서 저장한
 * 파일이 대부분 거절된다 — 쓰라고 만든 기능이 쓰이지 않는다.
 */
public final class CsvReader {

    private static final byte[] UTF8_BOM = { (byte) 0xEF, (byte) 0xBB, (byte) 0xBF };

    /** 한국어 윈도우 엑셀의 기본 저장 인코딩. */
    private static final Charset CP949 = Charset.forName("x-windows-949");

    private CsvReader() {
    }

    /** 어떤 인코딩으로 읽었는지 — 화면에 밝혀 준다. */
    public record Decoded(String text, String charsetName) {
    }

    public static Decoded decode(byte[] bytes) {
        if (bytes.length >= 3
                && bytes[0] == UTF8_BOM[0] && bytes[1] == UTF8_BOM[1] && bytes[2] == UTF8_BOM[2]) {
            return new Decoded(new String(bytes, 3, bytes.length - 3, StandardCharsets.UTF_8),
                               "UTF-8 (BOM)");
        }
        String utf8 = strictDecode(bytes, StandardCharsets.UTF_8);
        if (utf8 != null) {
            return new Decoded(utf8, "UTF-8");
        }
        return new Decoded(new String(bytes, CP949), "CP949");
    }

    /** 해독할 수 없으면 {@code null}. 대체 문자로 뭉개지 않는다. */
    private static String strictDecode(byte[] bytes, Charset charset) {
        try {
            return charset.newDecoder()
                          .onMalformedInput(CodingErrorAction.REPORT)
                          .onUnmappableCharacter(CodingErrorAction.REPORT)
                          .decode(ByteBuffer.wrap(bytes))
                          .toString();
        } catch (CharacterCodingException e) {
            return null;
        }
    }

    /**
     * 줄과 칸으로 나눈다.
     *
     * <p>따옴표 안의 쉼표와 줄바꿈을 지킨다 — 비고에 "DMZ, 대외" 처럼 쉼표가
     * 들어오는 일이 흔하고, 그것을 두 칸으로 쪼개면 자산 이름이 밀린다.
     * 따옴표 안의 {@code ""} 는 따옴표 한 개다.
     */
    public static List<List<String>> parse(String text) {
        List<List<String>> rows = new ArrayList<>();
        List<String> row = new ArrayList<>();
        StringBuilder cell = new StringBuilder();
        boolean quoted = false;

        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);

            if (quoted) {
                if (c == '"') {
                    if (i + 1 < text.length() && text.charAt(i + 1) == '"') {
                        cell.append('"');
                        i++;
                    } else {
                        quoted = false;
                    }
                } else {
                    cell.append(c);
                }
                continue;
            }

            switch (c) {
                case '"' -> quoted = true;
                case ',' -> {
                    row.add(cell.toString());
                    cell.setLength(0);
                }
                case '\r' -> { }   // CRLF 의 앞쪽. \n 에서 줄을 끊는다.
                case '\n' -> {
                    row.add(cell.toString());
                    cell.setLength(0);
                    rows.add(row);
                    row = new ArrayList<>();
                }
                default -> cell.append(c);
            }
        }

        // 마지막 줄에 줄바꿈이 없을 수 있다. 내용이 있으면 담는다.
        if (cell.length() > 0 || !row.isEmpty()) {
            row.add(cell.toString());
            rows.add(row);
        }

        // 빈 줄은 버린다 — 엑셀이 파일 끝에 붙이는 일이 흔하다.
        rows.removeIf(r -> r.stream().allMatch(v -> v == null || v.isBlank()));
        return rows;
    }
}
