package kr.sbomsight.domain;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * <b>패키지 식별자</b> — 탐지 · 인벤토리 · 검토 결과 · 조치 · 보고서 · CSV · 화면의 링크가
 * "같은 패키지인가" 를 이것 하나로 가른다(V24).
 *
 * <p><b>정의</b>: purl 에서 <b>버전 · 한정자({@code ?…}) · 하위 경로({@code #…})를 뗀 것</b> —
 * {@code pkg:<유형>/<네임스페이스>/<이름>}. 유형은 소문자로 맞추고 나머지는 purl 에 적힌 그대로
 * 둔다(인벤토리와 탐지가 같은 SBOM 의 같은 글자에서 온다).
 * <ul>
 *   <li>버전을 넣지 않는다 — 검토 결과와 조치는 버전을 가로지른다. 넣으면 패치하는 순간
 *       검토 결과가 풀리고 같은 조치가 둘로 갈린다(FindingAnalysis · Remediation 머리말).</li>
 *   <li>한정자를 넣지 않는다 — {@code arch} · {@code distro} 는 같은 패키지의 놓인 모양이다.
 *       {@code distro=rocky-9.3} 을 넣으면 OS 를 한 단계 올릴 때마다 다른 패키지가 된다.</li>
 *   <li>네임스페이스는 넣는다 — Maven 의 groupId, npm 의 scope, 배포판(rpm · deb)의 공급자.
 *       이름이 같아도 네임스페이스가 다르면 다른 패키지다.</li>
 * </ul>
 *
 * <p><b>purl 이 없으면</b> {@code pkg:<유형>/<이름>} — 유형은 purl 의 이름으로 옮긴 것
 * ({@link PackageTypes#purlName}), 유형도 모르면 {@code pkg:/<이름>}. 네임스페이스를 모르므로
 * 지어내지 않는다 — purl 이 있는 같은 패키지와 같은 글자가 된다는 보장이 없고, 다르면
 * <b>다른 패키지로 남는다</b>(모르는 것을 합치지 않는다).
 *
 * <p>purl 로 읽는 규칙은 {@link PackageTypes#fromPurl} 과 같다 — {@code pkg:} 다음에 {@code /}
 * 앞의 한 글자 이상. 같은 규칙을 V24 의 SQL 이 한 번 더 적는다(PackageKeyTest 가 견준다).
 */
public final class PackageKey {

    private PackageKey() {
    }

    /** 탐지 · 인벤토리 한 줄의 식별자. */
    public static String of(String purl, String type, String name) {
        String fromPurl = fromPurl(purl);
        if (fromPurl != null) {
            return fromPurl;
        }
        return "pkg:" + PackageTypes.purlName(type) + "/" + (name == null ? "" : name.trim());
    }

    /**
     * purl 에서 버전 · 한정자 · 하위 경로를 뗀 것. purl 이 아니면 {@code null}.
     *
     * <p>purl 규격의 순서대로 뗀다 — 뒤에서부터 {@code #} · {@code ?}, 그리고 유형 다음에서
     * 뒤에서부터 {@code @}. 네임스페이스에 인코딩되지 않은 {@code @}(npm scope)가 있어도
     * 버전만 떨어진다.
     */
    public static String fromPurl(String purl) {
        if (purl == null) {
            return null;
        }
        String text = purl.trim();
        if (!text.startsWith("pkg:")) {
            return null;
        }
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
}
