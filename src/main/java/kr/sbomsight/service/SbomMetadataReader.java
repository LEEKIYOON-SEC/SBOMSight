package kr.sbomsight.service;

import com.fasterxml.jackson.databind.JsonNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * SBOM 이 <b>제 자신에 대해 적어 온 것</b> — 생성 시각 · 생성 도구 · 대상.
 *
 * <p>{@link SbomStorage#inspect} 가 앞에서부터 흘려 읽다가 맨 윗단의 해당 칸을 만나면
 * 그 칸 하나만 트리로 읽어 넘긴다. 자리는 syft 1.52.0 으로 세 형식을 직접 떠서 확인했다.
 *
 * <pre>
 *   CycloneDX   metadata.timestamp · metadata.tools · metadata.component.name
 *   SPDX        creationInfo.created · creationInfo.creators "Tool: …" · name
 *   syft JSON   (시각 칸 없음) · descriptor.name/version · source.name
 * </pre>
 *
 * <p><b>값을 지어내지 않는다.</b> 없으면 비워 두고, 시각을 읽지 못하면 없는 것으로
 * 둔다 — 부르는 쪽이 업로드 시각으로 대신하고 그렇다고 밝힌다(SbomTime).
 */
final class SbomMetadataReader {

    private static final Logger log = LoggerFactory.getLogger(SbomMetadataReader.class);

    /** SPDX 의 생성자 줄 — {@code Tool: syft-1.52.0}. 이름과 판이 붙임표로 붙어 온다. */
    private static final Pattern NAME_DASH_VERSION = Pattern.compile("^(.+)-(\\d[\\w.+~-]*)$");

    private Instant createdAt;
    private final List<String> tools = new ArrayList<>();
    private String target = "";
    private String spdxName = "";

    /** CycloneDX {@code metadata}. */
    void cyclonedx(JsonNode metadata) {
        createdAt = time(text(metadata, "timestamp"));
        JsonNode t = metadata.get("tools");
        if (t != null && t.isArray()) {
            // 1.4 까지 — tools 가 곧 목록이다 {vendor, name, version}
            t.forEach(this::tool);
        } else if (t != null && t.isObject()) {
            // 1.5 부터 — tools.components[] · tools.services[]
            for (String kind : List.of("components", "services")) {
                JsonNode list = t.get(kind);
                if (list != null && list.isArray()) {
                    list.forEach(this::tool);
                }
            }
        }
        JsonNode component = metadata.get("component");
        if (component != null && component.isObject()) {
            target = text(component, "name");
        }
    }

    /** SPDX {@code creationInfo}. */
    void spdxCreationInfo(JsonNode info) {
        createdAt = time(text(info, "created"));
        JsonNode creators = info.get("creators");
        if (creators == null || !creators.isArray()) {
            return;
        }
        for (JsonNode creator : creators) {
            String line = creator.isTextual() ? creator.asText().trim() : "";
            if (!line.startsWith("Tool:")) {
                continue;   // Organization: · Person: 은 도구가 아니다
            }
            String tool = line.substring("Tool:".length()).trim();
            Matcher m = NAME_DASH_VERSION.matcher(tool);
            tools.add(m.matches() ? m.group(1) + " " + m.group(2) : tool);
        }
    }

    /** SPDX 문서의 맨 윗단 {@code name} — syft 는 대상 이름을 적는다. */
    void spdxName(JsonNode name) {
        spdxName = name.isTextual() ? name.asText().trim() : "";
    }

    /** syft JSON {@code source}. */
    void syftSource(JsonNode source) {
        target = text(source, "name");
    }

    /** syft JSON {@code descriptor} — syft 자신. */
    void syftDescriptor(JsonNode descriptor) {
        tool(descriptor);
    }

    /**
     * 다 읽었다 — 형식에 맞는 값만 낸다.
     *
     * <p>SPDX 의 맨 윗단 {@code name} 은 SPDX 일 때만 대상으로 쓴다. 다른 형식의 맨
     * 윗단에 같은 이름의 칸이 있어도 그것은 대상이 아니다.
     */
    SbomStorage.SbomMetadata finish(String format) {
        String t = "spdx-json".equals(format) ? spdxName : target;
        return new SbomStorage.SbomMetadata(createdAt, String.join(", ", tools), t);
    }

    // -------------------------------------------------------------------------

    private void tool(JsonNode node) {
        if (node == null || !node.isObject()) {
            return;
        }
        String name = text(node, "name");
        if (name.isBlank()) {
            return;
        }
        String version = text(node, "version");
        tools.add(version.isBlank() ? name : name + " " + version);
    }

    /**
     * ISO-8601 시각. CycloneDX 는 시간대를 붙여(Z 또는 +09:00), SPDX 는 Z 로 적는다.
     * 읽지 못하면 없는 것으로 둔다 — 0 이나 지금 시각으로 채우지 않는다.
     */
    private static Instant time(String text) {
        if (text.isBlank()) {
            return null;
        }
        try {
            return OffsetDateTime.parse(text).toInstant();
        } catch (DateTimeParseException e) {
            log.warn("SBOM 의 생성 시각을 읽지 못했습니다: {}", text);
            return null;
        }
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node == null ? null : node.get(field);
        return value == null || !value.isTextual() ? "" : value.asText().trim();
    }
}
