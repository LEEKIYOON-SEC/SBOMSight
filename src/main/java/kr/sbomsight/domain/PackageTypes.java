package kr.sbomsight.domain;

import java.util.Map;

import static java.util.Map.entry;

/**
 * 패키지 유형 — <b>같은 것을 두 이름으로 부른다.</b>
 *
 * <p>purl 은 {@code pkg:maven/…} · {@code pkg:pypi/…} 처럼 purl 의 유형을 쓰고, syft 와 grype 는
 * 같은 것을 {@code java-archive} · {@code python} 이라고 부른다(grype 결과의 {@code artifact.type}).
 * 패키지 화면은 SBOM 에서 딴 유형을, 탐지는 grype 의 유형을 들고 있어 — 띄운 앱에서 같은
 * jackson-databind 를 인벤토리는 {@code maven}, 탐지는 {@code java-archive} 로 적었다 — 둘을
 * 유형으로 잇자면 한쪽 이름으로 맞춰야 한다. <b>purl 의 이름으로 맞춘다</b> — 패키지 화면이
 * 이미 그 이름을 쓴다.
 *
 * <p><b>purl 이 있으면 purl 의 유형이 먼저다.</b> syft 의 유형은 purl 을 만들 때 쓰는 이름일 뿐이고,
 * 바이너리처럼 이름에 맞는 purl 유형이 없는 것({@code binary})도 purl 은 따로 달고 온다
 * ({@code pkg:generic/…}). purl 이 없을 때만 아래 표로 옮긴다.
 *
 * <p>표는 syft 의 것을 그대로 옮긴다 — syft v1.50.0 {@code syft/pkg/type.go} 의
 * {@code PackageURLType} (상수는 anchore/packageurl-go v0.2.0). 표에 없는 유형({@code binary} ·
 * {@code graalvm-native-image} …)은 받은 그대로 둔다 — 지어내지 않는다. {@code UnknownPackage}
 * 만 빈 값으로 둔다: purl 도 유형도 없는 원소를 syft 가 그렇게 부르고, 인벤토리는 같은 원소를
 * 빈 유형으로 담는다.
 */
public final class PackageTypes {

    /** syft 유형 → purl 유형. 이름이 같은 것(deb · rpm · npm …)도 적어 둔다 — 표가 syft 의 것과 한 줄씩 맞는지 볼 수 있게. */
    private static final Map<String, String> PURL_TYPE = Map.ofEntries(
            entry("alpm", "alpm"),
            entry("apk", "apk"),
            entry("bitnami", "bitnami"),
            entry("pod", "cocoapods"),
            entry("conan", "conan"),
            entry("conda", "generic"),
            entry("dart-pub", "pub"),
            entry("deb", "deb"),
            entry("dotnet", "nuget"),
            entry("erlang-otp", "otp"),
            entry("gem", "gem"),
            entry("hex", "hex"),
            entry("github-action", "github"),
            entry("github-action-workflow", "github"),
            entry("go-module", "golang"),
            entry("hackage", "hackage"),
            entry("java-archive", "maven"),
            entry("jenkins-plugin", "maven"),
            // syft 는 `generic/linux-kernel` 을 돌려준다 — purl 의 유형 칸은 generic 이다.
            entry("linux-kernel", "generic"),
            entry("linux-kernel-module", "generic"),
            entry("php-composer", "composer"),
            entry("php-pear", "pear"),
            entry("php-pecl", "pear"),
            entry("python", "pypi"),
            entry("portage", "portage"),
            entry("lua-rocks", "luarocks"),
            entry("nix", "nix"),
            entry("npm", "npm"),
            entry("opam", "opam"),
            entry("R-package", "cran"),
            entry("rpm", "rpm"),
            entry("rust-crate", "cargo"),
            entry("swift", "swift"),
            entry("swiplpack", "swiplpack"),
            entry("terraform", "terraform"),
            entry("vcpkg", "vcpkg"),
            entry("wordpress-plugin", "wordpress-plugin"),
            entry("homebrew", "homebrew"),
            entry("UnknownPackage", ""));

    private PackageTypes() {
    }

    /**
     * 화면 · 잇기에 쓰는 유형 — purl 이 있으면 purl 의 유형, 없으면 syft 의 유형을 purl 의
     * 이름으로 옮긴 것.
     */
    public static String of(String purl, String syftType) {
        String fromPurl = fromPurl(purl);
        return fromPurl != null ? fromPurl : purlName(syftType);
    }

    /**
     * {@code pkg:rpm/rocky/openssl-libs@3.0.7-24?arch=x86_64} → {@code rpm}.
     *
     * <p>purl 규격이 {@code pkg:<type>/<namespace>/<name>@<version>} 이라 첫 구획이 유형이다.
     * purl 이 아니면 {@code null}.
     */
    public static String fromPurl(String purl) {
        if (purl != null && purl.startsWith("pkg:")) {
            String rest = purl.substring("pkg:".length());
            int slash = rest.indexOf('/');
            if (slash > 0) {
                return rest.substring(0, slash);
            }
        }
        return null;
    }

    /** syft 유형을 purl 의 이름으로. 표에 없으면 받은 그대로, 없으면 빈 값. */
    public static String purlName(String syftType) {
        if (syftType == null) {
            return "";
        }
        return PURL_TYPE.getOrDefault(syftType, syftType);
    }
}
