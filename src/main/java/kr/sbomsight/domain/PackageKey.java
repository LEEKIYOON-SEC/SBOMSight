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
 *   <li><b>한정자는 패키지를 가르는 것을 남긴다.</b> 버전을 넘어 이어지는 다른 갈래 — Maven 의
 *       {@code classifier} · {@code type}(jdk15 빌드, linux-x86_64 네이티브, test-jar), OCI 의
 *       {@code arch}(플랫폼마다 다른 이미지), Conan 의 user · channel · 설정 · 옵션, nix 의 output. 그리고
 *       <b>같은 이름이 출처마다 다른 패키지인 유형의 출처</b>({@link #SOURCES}) — vcpkg 의 레지스트리, OCI 의
 *       저장소. 앞서 한정자를 통째로 버려(V24) classifier 만 다른 둘의 검토 결과 · 조치가 하나로 합쳐졌다.</li>
 *   <li><b>한 판을 가리키는 한정자는 버전처럼 뗀다</b>({@link #IGNORED}) — 그 버전의 개정 · 빌드(vcpkg 의
 *       port_version · git-tree, Conan 의 rrev · prev, rpm 의 epoch, nix 의 빌드 해시)와 그 판의 파일(파일
 *       이름 · 검사합 · 내려받은 곳). 남기면 올릴 때마다 식별자가 바뀌어 버전을 뗀 뜻이 없어진다. 같은
 *       패키지의 놓인 모양(배포판 패키지의 arch · distro)과 사본을 받아 온 곳(받은 곳 · 저장소 — 거울이
 *       흔하다)도 뗀다({@link #IGNORED_ALWAYS}). <b>표에 없는 한정자는 남긴다</b> — 모르는 것을 버려
 *       서로 다른 패키지를 합치지 않는다.</li>
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
     * 모든 유형에서 버리는 한정자 — <b>사본을 어디서 · 어떤 파일로 받았는가</b>(purl 규격 Annex B 의 공통
     * 한정자). 받은 곳 · 저장소는 같은 패키지의 거울이 흔하고, 내려받은 곳 · 파일 이름 · 검사합은 한 판의
     * 파일이다. 유형 정의가 이 가운데 하나로 <b>어느 패키지인가</b>를 가르면 {@link #SOURCES} 가 남긴다.
     */
    static final Set<String> IGNORED_ALWAYS =
            Set.of("repository_url", "download_url", "vcs_url", "file_name", "checksum");

    /**
     * 유형 정의가 패키지를 가르는 데 쓰는 출처 — {@link #IGNORED_ALWAYS} 에 있어도 남긴다. 같은 이름이
     * 출처마다 다른 패키지인 유형이다. 값은 맞춰 둔다({@link #source}) — 끝의 {@code /} 는 뜻이 없고,
     * vcs_url 의 {@code @개정} 은 한 판이라 뗀다.
     * <ul>
     *   <li>vcpkg — 포트를 정의한 레지스트리(파일 레지스트리 · 오버레이 포트는 file URL). 생략하면 기본
     *       레지스트리다({@link #DEFAULTS}). vcs_url 은 그 레지스트리의 저장소에 git-tree 를 붙인 것이다 —
     *       git-tree 는 (포트, 버전, port_version) 하나의 레시피라 버전처럼 떼고(vcpkg 의 버전 DB 는 한
     *       버전을 다른 git-tree 로 덮어쓰지 않는다), 저장소가 레지스트리와 같으면 더 말하는 것이 없어
     *       뗀다({@link #kept}).</li>
     *   <li>oci — 이름이 저장소 이름의 마지막 조각뿐이다({@code library/debian} → {@code debian}). 버전
     *       (digest)을 떼면 {@code docker.io/library/debian} 과 {@code ghcr.io/debian} 이 이름만 남아
     *       합쳐진다 — 네임스페이스는 repository_url 에만 있다.</li>
     *   <li>generic — 등록소가 없다. 맨 저장소를 vcs_url 로 가리킨다(규격의 정의).</li>
     *   <li>yocto — 레시피를 낸 레이어의 git URL.</li>
     *   <li>otp — 앱 소스의 정규 출처(등록소가 없다).</li>
     * </ul>
     */
    static final Map<String, Set<String>> SOURCES = Map.of(
            "vcpkg", Set.of("repository_url", "vcs_url"),
            "oci", Set.of("repository_url"),
            "generic", Set.of("vcs_url"),
            "yocto", Set.of("repository_url"),
            "otp", Set.of("repository_url"));

    /**
     * 유형마다 버리는 한정자. syft v1.50.0 이 purl 에 다는 것(카탈로거마다의 packageURL)과 purl 규격의
     * 유형 정의에서 왔다. <b>여기 없는 한정자는 식별자에 남는다.</b>
     */
    static final Map<String, Set<String>> IGNORED = Map.ofEntries(
            // 한 OS 에 깔린 같은 패키지의 놓인 모양 — 아키텍처 · 배포판 · 원천 패키지(upstream 에는 버전이
            // 붙기도 한다 — glibc@2.31-13). 취약점과 조치는 원천 패키지의 버전을 따른다. deb 의
            // arch=source 는 남는다({@link #kept}) — 원천 패키지 자체라 같은 이름의 바이너리와 다른 것이다.
            entry("deb", Set.of("arch", "distro", "upstream")),
            entry("rpm", Set.of("arch", "distro", "epoch", "upstream")),
            entry("apk", Set.of("arch", "distro", "upstream")),
            entry("alpm", Set.of("arch", "distro", "upstream")),
            entry("bitnami", Set.of("arch", "distro")),
            // 빌드 문자열 · 받은 채널 · 플랫폼 · 묶음 꼴
            entry("conda", Set.of("build", "channel", "subdir", "type")),
            entry("gem", Set.of("platform")),
            // 그때 digest 에 붙어 있던 꼬리표 — 옮겨 다닌다. arch 는 남는다 — 플랫폼마다 다른 이미지다.
            entry("oci", Set.of("tag")),
            // 스토어 해시 · 파생 경로는 빌드마다 바뀐다. output(out · bin · dev …)은 남는다 — 다른 파일이다.
            entry("nix", Set.of("outputhash", "drvpath")),
            // port_version 은 버전의 #N(syft 는 port_revision 이라 적는다), repository_revision 은 레지스트리
            // 전체의 기준 커밋 — 한 판이다. triplet 은 규격이 식별에 영향이 없다고, features 는 정보일
            // 뿐이라고 적었다.
            entry("vcpkg", Set.of("port_version", "port_revision", "repository_revision", "triplet", "features")),
            entry("pub", Set.of("hosted_url")),
            // 레시피 · 패키지 개정 — 그 버전의 내용 해시라 한 판이다(생략하면 그 버전의 최신 개정, 줄바꿈만
            // 달라도 바뀐다). user · channel 과 설정 · 옵션(os · build_type · shared …)은 남는다 — 규격이
            // 패키지를 가르는 데 쓴다.
            entry("conan", Set.of("rrev", "prev")),
            // 레이어의 커밋 · 태그 · 가지 — 한 판이다. 레이어(repository_url)는 남는다.
            entry("yocto", Set.of("layer_version")),
            // 배포본 파일의 경로 · 확장자 — 한 판의 파일이다.
            entry("cpan", Set.of("distpath", "ext")));

    /** purl 규격이 정한 기본값 — 적은 것과 안 적은 것이 같다. 값은 {@link #source} 로 맞춘 뒤 견준다. */
    static final Map<String, Map<String, String>> DEFAULTS = Map.of(
            "maven", Map.of("type", "jar"),
            "vcpkg", Map.of("repository_url", "https://github.com/microsoft/vcpkg"));

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

    /**
     * 남기는 한정자 — 표({@link #IGNORED_ALWAYS} · {@link #IGNORED})와 기본값({@link #DEFAULTS})을 뺀 것.
     * 유형의 출처({@link #SOURCES})는 맞춘 값으로 남긴다.
     */
    static TreeMap<String, String> kept(String type, Map<String, String> qualifiers) {
        TreeMap<String, String> kept = new TreeMap<>();
        if (qualifiers == null) {
            return kept;
        }
        Set<String> ignored = IGNORED.getOrDefault(type, Set.of());
        Set<String> sources = SOURCES.getOrDefault(type, Set.of());
        Map<String, String> defaults = DEFAULTS.getOrDefault(type, Map.of());
        qualifiers.forEach((key, given) -> {
            String value = sources.contains(key) ? source(key, given) : given;
            boolean dropped = IGNORED_ALWAYS.contains(key) && !sources.contains(key)
                              || ignored.contains(key) && !("deb".equals(type) && "arch".equals(key)
                                                            && "source".equals(value))
                              || value.isEmpty() || value.equals(defaults.get(key));
            if (!dropped) {
                kept.put(key, value);
            }
        });
        // vcpkg 의 vcs_url 이 레지스트리(적은 것, 없으면 기본)의 저장소면 더 말하는 것이 없다 — 남기면 같은
        // 포트를 레지스트리로만 적은 purl(syft)과 git-tree 까지 적은 purl 이 둘로 갈린다.
        String vcs = kept.get("vcs_url");
        if ("vcpkg".equals(type) && vcs != null
                && sameRepository(vcs, kept.getOrDefault("repository_url", defaults.get("repository_url")))) {
            kept.remove("vcs_url");
        }
        return kept;
    }

    /**
     * 출처 한정자의 값을 맞춘다. repository_url 은 끝의 {@code /} 를 뗀다. vcs_url 은 저장소만 남긴다 —
     * {@code <도구>+<전송>://<호스트>[/<경로>][@<개정>][#<하위 경로>]}(규격 B.3.5)에서 {@code @개정} 을
     * 떼고(한 판이다), 끝의 {@code /} 와 하위 경로 앞뒤의 {@code /} 를 뗀다(규격: 뜻이 없다). 하위 경로는
     * 남는다 — 한 저장소 안의 다른 패키지다.
     */
    static String source(String key, String value) {
        if (!"vcs_url".equals(key)) {
            return stripTrailing(value, '/');
        }
        String location = value;
        String sub = "";
        int hash = location.indexOf('#');
        if (hash >= 0) {
            sub = stripTrailing(location.substring(hash + 1).replaceFirst("^/+", ""), '/');
            location = location.substring(0, hash);
        }
        // 개정은 경로 뒤의 마지막 @ 다음 — 호스트 앞의 계정(git@)은 건드리지 않는다. 꼴을 모르면 그대로 둔다.
        int scheme = location.indexOf("://");
        int path = scheme < 0 ? -1 : location.indexOf('/', scheme + 3);
        int at = location.lastIndexOf('@');
        if (path >= 0 && at > path) {
            location = location.substring(0, at);
        }
        location = stripTrailing(location, '/');
        return sub.isEmpty() ? location : location + "#" + sub;
    }

    /**
     * vcs_url 의 저장소가 그 레지스트리인가 — 도구 접두사({@code git+})와 하위 경로를 빼고, 끝의
     * {@code .git} 은 같은 저장소로 본다(규격의 otp 예가 같은 저장소를 두 꼴로 적었다).
     */
    private static boolean sameRepository(String vcs, String registry) {
        if (registry == null) {
            return false;
        }
        String repository = vcs.replaceFirst("#.*$", "").replaceFirst("^[a-z]+\\+(?=[a-z]+://)", "");
        return withoutGit(repository).equals(withoutGit(registry));
    }

    private static String withoutGit(String url) {
        return url.endsWith(".git") ? url.substring(0, url.length() - ".git".length()) : url;
    }

    private static String stripTrailing(String text, char c) {
        int end = text.length();
        while (end > 0 && text.charAt(end - 1) == c) {
            end--;
        }
        return text.substring(0, end);
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
