package kr.sbomsight.domain;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;

import java.io.ByteArrayOutputStream;
import java.net.URLDecoder;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import static java.util.Map.entry;

/**
 * <b>패키지 식별자</b> — 탐지 · 인벤토리 · 검토 결과 · 조치 · 보고서 · CSV · 화면의 링크가
 * "같은 패키지인가" 를 이것 하나로 가른다(V24 · V25).
 *
 * <p><b>정의</b>: purl 을 표준 파서(packageurl-java — purl 규격 쪽의 참조 구현)로 읽어 <b>버전과
 * 하위 경로({@code #…})를 떼고, 한정자({@code ?…})는 표가 버리라는 것만 버린</b> 정규형 —
 * {@code pkg:<유형>/<네임스페이스>/<이름>[?<남은 한정자>]}. 정규형은 규격 그대로다 — 유형 · 한정자
 * 키는 소문자, 한정자는 키 순, 이름 · 값은 퍼센트 인코딩한 꼴, 유형마다 정한 이름 맞춤(pypi 는
 * 소문자 · {@code _}→{@code -}, deb · golang · github 는 소문자 …). 같은 패키지를 도구마다 다르게
 * 적어도(인코딩 · 한정자 순서 · {@code @scope} 를 인코딩하지 않고 적은 것) 같은 글자가 된다.
 * <ul>
 *   <li>버전을 넣지 않는다 — 검토 결과와 조치는 버전을 가로지른다. 넣으면 패치하는 순간
 *       검토 결과가 풀리고 같은 조치가 둘로 갈린다(FindingAnalysis · Remediation 머리말).</li>
 *   <li><b>한정자는 패키지를 가르는 것을 남긴다.</b> Maven 의 {@code classifier} · {@code type} 은 같은
 *       좌표의 다른 아티팩트다 — jdk15 빌드, linux-x86_64 네이티브, test-jar. 앞서 한정자를 통째로
 *       버려(V24) 이런 둘의 검토 결과 · 조치가 하나로 합쳐졌다. 버리는 것은 유형마다 표로 적는다
 *       ({@link #IGNORED}) — {@code arch} · {@code distro} 처럼 같은 패키지의 놓인 모양, {@code epoch} ·
 *       {@code upstream} · 빌드 해시처럼 버전에 딸린 값. 모든 유형에서 받은 곳 · 내려받은 곳 · 파일
 *       이름 · 검사합도 버린다({@link #IGNORED_ALWAYS} — 규격의 알려진 한정자). <b>표에 없는 한정자는
 *       남긴다</b> — 모르는 것을 버려 서로 다른 패키지를 합치지 않는다.</li>
 *   <li>규격이 정한 기본값은 안 적은 것과 같다 — Maven 의 {@code type=jar}({@link #DEFAULTS}).</li>
 *   <li>네임스페이스는 넣는다 — Maven 의 groupId, npm 의 scope, 배포판(rpm · deb)의 공급자.
 *       이름이 같아도 네임스페이스가 다르면 다른 패키지다.</li>
 * </ul>
 *
 * <p><b>파서는 읽고 맞추는 데 쓰고, 정규형의 글자는 규격대로 우리가 쓴다</b>({@link #format}).
 * packageurl-java 1.5.0 은 ASCII 밖 글자를 풀 때도(바이트마다 한 글자) 쓸 때도({@code %FFFFFFED})
 * 깨뜨린다 — 그 두 자리만 피한다({@link #decodeNonAscii}).
 *
 * <p><b>표준 파서가 받지 않는 purl</b>(이름이 비었거나 한정자 키가 겹친 것, UTF-8 이 아닌 인코딩 …)은
 * V24 의 규칙으로 좌표만 딴다({@link #coordinates}). 받지 않는다고 이름으로 내려가면 네임스페이스를
 * 잃어 groupId 만 다른 둘이 합쳐진다.
 *
 * <p><b>purl 이 없으면</b> {@code pkg:<유형>/<이름>} — 유형은 purl 의 이름으로 옮긴 것
 * ({@link PackageTypes#purlName}), 같은 정규형으로 쓴다(이름이 들고 온 {@code @scope/} · 경로는 그대로
 * 나눈다). 유형도 모르면 {@code pkg:/<이름>}. 네임스페이스를 지어내지 않는다 — groupId 를 모르는
 * jar 는 purl 이 있는 같은 이름과 다른 패키지로 남는다(모르는 것을 합치지 않는다).
 *
 * <p><b>이미 담긴 행은 V25 가 이 함수로 다시 만든다</b>(db.migration.V25__package_key_qualifiers).
 * 같은 입력과 기대값을 {@code tests/resources/package-key-vectors.tsv} 에 두고 PackageKeyTest 와
 * tests/check-migrations.sh 가 함께 견준다.
 */
public final class PackageKey {

    /** 식별자 칸의 길이(VARCHAR 512). */
    static final int MAX = 512;

    /**
     * 모든 유형에서 버리는 한정자 — <b>어디서 받았는가 · 어떤 파일로 왔는가</b>. 패키지가 아니라
     * 받아 온 길이다(purl 규격의 알려진 한정자 다섯).
     */
    static final Set<String> IGNORED_ALWAYS =
            Set.of("repository_url", "download_url", "vcs_url", "file_name", "checksum");

    /**
     * 유형마다 버리는 한정자. syft v1.50.0 이 purl 에 다는 것(카탈로거마다의 packageURL)과 purl 규격의
     * 유형 정의에서 왔다. <b>여기 없는 한정자는 식별자에 남는다.</b>
     */
    static final Map<String, Set<String>> IGNORED = Map.ofEntries(
            // 아키텍처 · 배포판 · 원천 패키지(upstream 에는 버전이 붙기도 한다 — glibc@2.31-13)
            entry("deb", Set.of("arch", "distro", "upstream")),
            entry("rpm", Set.of("arch", "distro", "epoch", "upstream")),
            entry("apk", Set.of("arch", "distro", "upstream")),
            entry("alpm", Set.of("arch", "distro", "upstream")),
            entry("bitnami", Set.of("arch", "distro")),
            // 빌드 문자열 · 받은 채널 · 플랫폼 · 묶음 꼴
            entry("conda", Set.of("build", "channel", "subdir", "type")),
            entry("gem", Set.of("platform")),
            entry("oci", Set.of("arch", "tag")),
            // 스토어 해시 · 파생 경로는 빌드마다 바뀐다. output(out · bin · dev …)은 남는다 — 다른 파일이다.
            entry("nix", Set.of("outputhash", "drvpath")),
            // 플랫폼 triplet · 포트 개정 · 레지스트리 기준 커밋
            entry("vcpkg", Set.of("triplet", "port_revision", "repository_revision")),
            entry("pub", Set.of("hosted_url")),
            // 레시피 · 패키지 개정. user · channel 은 레시피를 가르므로 남는다.
            entry("conan", Set.of("rrev", "prev")));

    /** purl 규격이 정한 기본값 — 적은 것과 안 적은 것이 같다. */
    static final Map<String, Map<String, String>> DEFAULTS = Map.of("maven", Map.of("type", "jar"));

    private static final String HEX = "0123456789ABCDEF";

    private PackageKey() {
    }

    /** 탐지 · 인벤토리 한 줄의 식별자. */
    public static String of(String purl, String type, String name) {
        String fromPurl = fromPurl(purl);
        return fit(fromPurl != null ? fromPurl : fallback(type, name));
    }

    /**
     * purl 의 식별자 — 정규형에서 버전 · 하위 경로와 표의 한정자를 뗀 것. 표준 파서가 받지 않으면
     * V24 의 좌표({@link #coordinates}), purl 이 아니면 {@code null}.
     */
    public static String fromPurl(String purl) {
        if (purl == null) {
            return null;
        }
        String text = purl.trim();
        if (!text.startsWith("pkg:")) {
            return null;
        }
        String canonical = canonical(text);
        return canonical != null ? canonical : coordinates(text);
    }

    /**
     * 화면에 이름 곁에 적는 네임스페이스 — {@code com.fasterxml.jackson.core} · {@code @angular} ·
     * {@code debian}. 없으면 빈 글자. 같은 이름의 다른 패키지를 화면에서 가르는 글자다.
     */
    public static String namespace(String key) {
        if (key == null || !key.startsWith("pkg:")) {
            return "";
        }
        String rest = key.substring("pkg:".length());
        int slash = rest.indexOf('/');
        if (slash < 0) {
            return "";
        }
        String path = rest.substring(slash + 1);
        int last = path.lastIndexOf('/');
        if (last <= 0) {
            return "";
        }
        try {
            return URLDecoder.decode(path.substring(0, last).replace("+", "%2B"), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return path.substring(0, last);
        }
    }

    /**
     * 검색어를 식별자 안에서 찾을 글자로 — 식별자와 같은 인코딩. 패키지 검색이 이름 말고도
     * 네임스페이스(groupId · scope · 배포판)로 찾는다(ComponentRepository).
     *
     * <p>{@code /} 로 가른 조각마다 인코딩한다 — 식별자에서 네임스페이스와 이름 사이의 {@code /} 는
     * 그대로다({@code @types/node} → {@code %40types/node}). Maven 좌표로 적은 {@code :}
     * ({@code org.apache.logging.log4j:log4j-core})도 그 자리로 읽는다.
     */
    public static String searchable(String term) {
        List<String> segments = new ArrayList<>();
        for (String segment : term.trim().replace(':', '/').split("/", -1)) {
            segments.add(encode(segment));
        }
        return String.join("/", segments);
    }

    // -----------------------------------------------------------------------

    /** 표준 파서로 읽은 정규형. 규격에 맞지 않으면 {@code null}. */
    private static String canonical(String text) {
        String decoded = decodeNonAscii(text);
        if (decoded == null) {
            return null;
        }
        try {
            PackageURL purl = new PackageURL(decoded);
            return format(purl.getType(), purl.getNamespace(), purl.getName(),
                          kept(purl.getType(), purl.getQualifiers()));
        } catch (MalformedPackageURLException | RuntimeException e) {
            // 1.5.0 은 깨진 %XX 를 숫자로 읽다 RuntimeException 을 낸다 — 받지 않는 purl 과 같다.
            return null;
        }
    }

    /**
     * 정규형의 글자 — purl 규격대로: {@code pkg:} 유형 {@code /} [네임스페이스 구획마다 인코딩 {@code /}]
     * 이름 [{@code ?} 키 순의 {@code 키=값} 을 {@code &} 로]. 인코딩은 규격의 unreserved
     * ({@code A–Z a–z 0–9 - . _ ~}) 밖의 UTF-8 바이트를 대문자 {@code %XX} 로 — packageurl-java 의
     * canonicalize 와 같은 규칙이고, 그쪽이 ASCII 밖 바이트를 {@code %FFFFFFED} 로 쓰는 것만 다르다.
     */
    static String format(String type, String namespace, String name, TreeMap<String, String> qualifiers) {
        StringBuilder out = new StringBuilder("pkg:").append(type).append('/');
        if (namespace != null && !namespace.isEmpty()) {
            for (String segment : namespace.split("/")) {
                out.append(encode(segment)).append('/');
            }
        }
        out.append(encode(name));
        char sep = '?';
        for (Map.Entry<String, String> q : qualifiers.entrySet()) {
            out.append(sep).append(q.getKey()).append('=').append(encode(q.getValue()));
            sep = '&';
        }
        return out.toString();
    }

    /** 규격의 퍼센트 인코딩 — unreserved 밖의 UTF-8 바이트를 {@code %XX}(대문자)로. */
    static String encode(String text) {
        StringBuilder out = new StringBuilder(text.length());
        for (byte b : text.getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xFF;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '.' || c == '_' || c == '~') {
                out.append((char) c);
            } else {
                out.append('%').append(HEX.charAt(c >> 4)).append(HEX.charAt(c & 0xF));
            }
        }
        return out.toString();
    }

    /** 남기는 한정자 — 표({@link #IGNORED_ALWAYS} · {@link #IGNORED})와 기본값({@link #DEFAULTS})을 뺀 것. */
    static TreeMap<String, String> kept(String type, Map<String, String> qualifiers) {
        TreeMap<String, String> kept = new TreeMap<>();
        if (qualifiers == null) {
            return kept;
        }
        Set<String> ignored = IGNORED.getOrDefault(type, Set.of());
        Map<String, String> defaults = DEFAULTS.getOrDefault(type, Map.of());
        qualifiers.forEach((key, value) -> {
            if (!IGNORED_ALWAYS.contains(key) && !ignored.contains(key) && !value.equals(defaults.get(key))) {
                kept.put(key, value);
            }
        });
        return kept;
    }

    /**
     * 표준 파서가 받지 않는 purl 의 좌표 — V24 의 규칙 그대로. 뒤에서부터 {@code #} · {@code ?} 를
     * 떼고, 첫 {@code /} 앞(한 글자 이상)을 유형으로, 그 뒤에서 뒤에서부터 {@code @}(버전)와 끝의
     * {@code /} 를 뗀다. 유형만 소문자로, 나머지는 적힌 그대로. 남은 것이 없으면 {@code null}.
     */
    private static String coordinates(String text) {
        String rest = text.substring("pkg:".length());
        int hash = rest.lastIndexOf('#');
        if (hash >= 0) {
            rest = rest.substring(0, hash);
        }
        int query = rest.lastIndexOf('?');
        if (query >= 0) {
            rest = rest.substring(0, query);
        }
        int slash = rest.indexOf('/');
        if (slash <= 0) {
            return null;
        }
        String type = rest.substring(0, slash).toLowerCase(Locale.ROOT);
        String path = rest.substring(slash + 1);
        int at = path.lastIndexOf('@');
        if (at >= 0) {
            path = path.substring(0, at);
        }
        while (path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        return path.isEmpty() ? null : "pkg:" + type + "/" + path;
    }

    /** purl 이 없을 때 — 유형(purl 의 이름으로 옮긴 것)과 이름으로. */
    private static String fallback(String type, String name) {
        String kind = PackageTypes.purlName(type);
        String trimmed = name == null ? "" : name.trim();
        if (!kind.isEmpty() && !trimmed.isEmpty()) {
            int slash = trimmed.lastIndexOf('/');
            boolean split = slash > 0 && slash < trimmed.length() - 1;
            try {
                // 파서로 맞춘다(유형 · 이름 맞춤, Maven 은 네임스페이스가 있어야 한다) — 글자는 format 이 쓴다.
                PackageURL purl = new PackageURL(kind, split ? trimmed.substring(0, slash) : null,
                                                 split ? trimmed.substring(slash + 1) : trimmed,
                                                 null, null, null);
                return format(purl.getType(), purl.getNamespace(), purl.getName(), new TreeMap<>());
            } catch (MalformedPackageURLException | RuntimeException e) {
                // 규격에 없는 유형 이름(빈칸 · 밑줄)이거나 Maven 처럼 네임스페이스가 있어야 하는 유형 — 받은 그대로.
            }
        }
        return "pkg:" + kind + "/" + trimmed;
    }

    /**
     * purl 안의 퍼센트 인코딩된 ASCII 밖 글자(UTF-8 바이트 {@code %80}–{@code %FF})를 글자로 푼다.
     *
     * <p>packageurl-java 1.5.0 은 {@code %XX} 를 한 바이트씩 한 글자로 풀어(Latin-1) 한글처럼 여러
     * 바이트인 글자를 깨뜨린다 — 같은 이름을 인코딩해 적은 purl 과 그대로 적은 purl 이 다른 식별자가
     * 됐다. 구분자({@code @ ? # & = /})는 ASCII 라 그대로 두므로 구조가 바뀌지 않는다.
     *
     * @return 푼 글자. UTF-8 로 맞지 않는 바이트열이 있으면 {@code null} — 규격에 맞지 않는 purl 이다
     */
    static String decodeNonAscii(String text) {
        if (text.indexOf('%') < 0) {
            return text;
        }
        StringBuilder out = new StringBuilder(text.length());
        ByteArrayOutputStream run = new ByteArrayOutputStream();
        int i = 0;
        while (i < text.length()) {
            int value = escapedByte(text, i);
            if (value >= 0x80) {
                run.write(value);
                i += 3;
                continue;
            }
            if (!flush(run, out)) {
                return null;
            }
            out.append(text.charAt(i));
            i++;
        }
        return flush(run, out) ? out.toString() : null;
    }

    /** {@code %XX} 가 이 자리에 있으면 그 바이트, 아니면 -1. */
    private static int escapedByte(String text, int i) {
        if (text.charAt(i) != '%' || i + 2 >= text.length()) {
            return -1;
        }
        int high = Character.digit(text.charAt(i + 1), 16);
        int low = Character.digit(text.charAt(i + 2), 16);
        return high < 0 || low < 0 ? -1 : high * 16 + low;
    }

    /** 모아 둔 바이트를 UTF-8 로 풀어 붙인다. UTF-8 이 아니면 {@code false}. */
    private static boolean flush(ByteArrayOutputStream run, StringBuilder out) {
        if (run.size() == 0) {
            return true;
        }
        try {
            out.append(StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(run.toByteArray())));
        } catch (CharacterCodingException e) {
            return false;
        }
        run.reset();
        return true;
    }

    /**
     * 칸(512자)에 들게 — 넘으면 앞부분과 전체의 SHA-256 으로. 잘라서 넣으면 앞이 같은 두 패키지가
     * 합쳐진다. purl 칸이 512자라 정규형의 퍼센트 인코딩이 글자를 늘렸을 때만 넘는다.
     */
    static String fit(String key) {
        if (key.length() <= MAX) {
            return key;
        }
        String digest = sha256(key);
        int cut = MAX - digest.length() - 1;
        if (Character.isHighSurrogate(key.charAt(cut - 1))) {
            cut--;
        }
        return key.substring(0, cut) + "~" + digest;
    }

    private static String sha256(String text) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
