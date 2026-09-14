package kr.sbomsight.service;

import com.fasterxml.jackson.core.TreeNode;
import com.fasterxml.jackson.databind.JsonNode;
import kr.sbomsight.service.SbomStorage.ParsedComponent;

/**
 * SBOM 원소 하나에서 이름 · 버전 · 유형 · purl · 경로를 딴다.
 *
 * <p><b>형식이 셋이고 같은 것을 다른 이름으로 부른다.</b> syft 가 무엇으로
 * 내보냈는지에 따라 세 가지가 다 들어온다.
 *
 * <pre>
 *   syft-json     artifacts[]  name  version      type          purl  locations[0].path
 *   cyclonedx     components[] name  version      (아래 참조)   purl  properties[syft:location:0:path]
 *   spdx-json     packages[]   name  versionInfo  (purl 에서)   externalRefs[purl].referenceLocator
 * </pre>
 *
 * <p><b>유형은 purl 에서 딴다.</b> {@code pkg:rpm/rocky/openssl@3.0.7} 의
 * {@code rpm} 이 우리가 화면에 쓰는 값이다. CycloneDX 의 {@code type} 은
 * {@code library}/{@code application}/{@code operating-system} 셋뿐이라
 * rpm 과 deb 를 가르지 못한다 — 그것을 유형이라고 찍으면 패키지 화면의
 * 유형 거르개가 전부 {@code library} 가 된다.
 *
 * <p>purl 이 없으면 형식이 준 값을 그대로 쓴다. <b>없는 것을 지어내지
 * 않는다</b> — 빈 칸은 SBOM 이 안 담았다는 뜻이고, 그 사실이 화면에 그대로
 * 보여야 한다.
 */
final class ComponentReader {

    private ComponentReader() {
    }

    /** 읽을 것이 없으면 {@code null}. 이름조차 없는 원소는 담지 않는다. */
    static ParsedComponent read(TreeNode tree, String field) {
        if (!(tree instanceof JsonNode node) || !node.isObject()) {
            return null;
        }

        String name = text(node, "name");
        if (name.isBlank()) {
            // 이름이 없으면 목록에서 가리킬 수 없다. 세기는 이미 셌다.
            return null;
        }

        String purl = purl(node, field);
        return new ParsedComponent(
                name,
                // SPDX 만 versionInfo 다. 나머지는 version.
                text(node, "version").isBlank() ? text(node, "versionInfo") : text(node, "version"),
                type(node, field, purl),
                purl,
                location(node, field));
    }

    // --- purl -----------------------------------------------------------------

    private static String purl(JsonNode node, String field) {
        if (!"packages".equals(field)) {
            return text(node, "purl");
        }
        // SPDX 는 purl 을 externalRefs 안에 둔다.
        JsonNode refs = node.get("externalRefs");
        if (refs == null || !refs.isArray()) {
            return "";
        }
        for (JsonNode ref : refs) {
            if ("purl".equalsIgnoreCase(text(ref, "referenceType"))) {
                return text(ref, "referenceLocator");
            }
        }
        return "";
    }

    // --- 유형 -----------------------------------------------------------------

    /**
     * {@code pkg:rpm/rocky/openssl-libs@3.0.7-24?arch=x86_64} → {@code rpm}
     *
     * <p>purl 규격이 {@code pkg:<type>/<namespace>/<name>@<version>} 이라
     * 첫 구획이 유형이다.
     */
    private static String type(JsonNode node, String field, String purl) {
        if (purl.startsWith("pkg:")) {
            String rest = purl.substring("pkg:".length());
            int slash = rest.indexOf('/');
            if (slash > 0) {
                return rest.substring(0, slash);
            }
        }
        // CycloneDX 의 type 은 library/application 뿐이라 유형으로 못 쓴다.
        return "components".equals(field) ? "" : text(node, "type");
    }

    // --- 설치 경로 -------------------------------------------------------------

    private static String location(JsonNode node, String field) {
        if ("artifacts".equals(field)) {
            JsonNode locations = node.get("locations");
            if (locations != null && locations.isArray() && !locations.isEmpty()) {
                return text(locations.get(0), "path");
            }
            return "";
        }
        if ("components".equals(field)) {
            // syft 가 CycloneDX 로 낼 때 경로를 properties 에 넣는다.
            //   { "name": "syft:location:0:path", "value": "/usr/lib64/libssl.so" }
            JsonNode properties = node.get("properties");
            if (properties == null || !properties.isArray()) {
                return "";
            }
            for (JsonNode property : properties) {
                String key = text(property, "name");
                if (key.startsWith("syft:location:") && key.endsWith(":path")) {
                    return text(property, "value");
                }
            }
        }
        // SPDX 에는 설치 경로 자리가 없다. 빈 칸으로 둔다.
        return "";
    }

    // -------------------------------------------------------------------------

    private static String text(JsonNode node, String field) {
        if (node == null) {
            return "";
        }
        JsonNode value = node.get(field);
        return value == null || !value.isTextual() ? "" : value.asText();
    }
}
