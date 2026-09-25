package kr.sbomsight.service;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import kr.sbomsight.config.SbomSightProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.function.Consumer;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * SBOM 원본과 grype 결과 보관.
 *
 * <p>둘 다 gzip 으로 저장한다. SBOM JSON 은 구조가 반복적이라 압축이 아주 잘
 * 먹는다(실측 약 26배). 서버 100대를 2년 보관해도 10GB 남짓이다.
 *
 * <p>업로드는 <b>스트림으로 흘려보낸다.</b> {@code getBytes()} 를 부르는 순간
 * 100MB 짜리가 통째로 힙에 올라가고, 몇 명이 동시에 올리면 서버가 죽는다.
 */
@Service
public class SbomStorage {

    private static final Logger log = LoggerFactory.getLogger(SbomStorage.class);
    private static final int BUFFER = 1 << 16;

    private final SbomSightProperties properties;

    /**
     * 코덱을 붙여 둔다 — {@code readValueAsTree()} 가 이것을 쓴다.
     *
     * <p>붙이지 않으면 원소를 하나씩 읽을 수 없고, 손으로 토큰을 걸어야 한다.
     * 그 코드는 형식이 셋(syft · CycloneDX · SPDX)이라 곧 읽을 수 없게 된다.
     */
    private final JsonFactory jsonFactory = new JsonFactory().setCodec(new ObjectMapper());

    public SbomStorage(SbomSightProperties properties) {
        this.properties = properties;
    }

    /** 업로드된 SBOM 을 gzip 으로 보관하고 그 경로를 돌려준다. */
    public Path storeSbom(long assetId, long scanId, MultipartFile file) throws IOException {
        Path dir = properties.scanDir(assetId, scanId);
        Files.createDirectories(dir);
        Path target = dir.resolve("sbom.json.gz");

        try (InputStream in = new BufferedInputStream(file.getInputStream(), BUFFER);
             OutputStream out = new GZIPOutputStream(
                     new BufferedOutputStream(Files.newOutputStream(target), BUFFER), BUFFER)) {
            in.transferTo(out);
        }
        log.info("SBOM 보관: {} ({} → {} 바이트)", target, file.getSize(), Files.size(target));
        return target;
    }

    /**
     * 보관된 SBOM 을 새 스캔 자리로 복사한다 — 재검사용.
     *
     * <p>이미 압축된 것을 그대로 복사한다. 풀었다 다시 압축하면 시간만 들고,
     * 그 과정에서 바이트가 달라지면 "같은 SBOM 을 다시 돌렸다" 는 말이
     * 정확하지 않게 된다.
     *
     * <p>경로를 함께 가리키게 하지 않는 이유: 둘 중 하나를 지우면
     * {@link #deleteScanDir} 이 디렉터리를 통째로 지우므로 나머지가 파일을
     * 잃는다.
     */
    public Path copySbom(Path storedGzip, long assetId, long newScanId) throws IOException {
        Path dir = properties.scanDir(assetId, newScanId);
        Files.createDirectories(dir);
        Path target = dir.resolve("sbom.json.gz");
        Files.copy(storedGzip, target, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        log.info("재검사용 SBOM 복사: {} → {}", storedGzip, target);
        return target;
    }

    /** grype 이 읽을 수 있도록 압축을 임시 파일로 푼다. 끝나면 지운다. */
    public Path inflate(Path gzipped, Path dir, String name) throws IOException {
        Path plain = dir.resolve(name);
        try (InputStream in = new GZIPInputStream(
                     new BufferedInputStream(Files.newInputStream(gzipped), BUFFER), BUFFER)) {
            Files.copy(in, plain, StandardCopyOption.REPLACE_EXISTING);
        }
        return plain;
    }

    /** grype JSON 을 gzip 으로 보관한다. 원본이 있어야 나중에 결과를 대조할 수 있다. */
    public Path storeGrypeReport(Path plain, Path dir) throws IOException {
        Path target = dir.resolve("grype.json.gz");
        try (InputStream in = new BufferedInputStream(Files.newInputStream(plain), BUFFER);
             OutputStream out = new GZIPOutputStream(
                     new BufferedOutputStream(Files.newOutputStream(target), BUFFER), BUFFER)) {
            in.transferTo(out);
        }
        return target;
    }

    public InputStream openGzip(Path gzipped) throws IOException {
        return new GZIPInputStream(
                new BufferedInputStream(Files.newInputStream(gzipped), BUFFER), BUFFER);
    }

    /** 스캔 폴더를 통째로 지운다. 자산이나 스캔을 지울 때 파일도 같이 없어야 한다. */
    public void deleteScanDir(long assetId, long scanId) {
        Path dir = properties.scanDir(assetId, scanId);
        if (!Files.exists(dir)) {
            return;
        }
        try (var walk = Files.walk(dir)) {
            walk.sorted((a, b) -> b.getNameCount() - a.getNameCount()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException e) {
                    log.warn("지우지 못했습니다: {} ({})", path, e.getMessage());
                }
            });
        } catch (IOException e) {
            log.warn("스캔 폴더를 지우지 못했습니다: {} ({})", dir, e.getMessage());
        }
    }

    /** 형식과 컴포넌트 수만. 담을 것이 없을 때 쓴다. */
    public SbomInfo inspect(Path plainJson) {
        return inspect(plainJson, null);
    }

    /** 받는 형식의 화면 이름. 거절할 때 이것을 그대로 말한다. */
    public static final String ACCEPTED_FORMATS = "CycloneDX JSON · SPDX JSON · syft JSON";

    /**
     * 맨 윗단의 이름 하나로 형식을 가른다 — 모르면 빈 문자열.
     *
     * <p>{@link #inspect} 와 {@link #detectFormat} 이 같은 표를 쓴다. 따로 두면
     * 올릴 때는 받았는데 읽을 때는 모르는 형식이 생긴다.
     */
    private static String formatOf(String topLevelField) {
        return switch (topLevelField) {
            case "bomFormat", "components" -> "cyclonedx-json";
            case "spdxVersion", "packages" -> "spdx-json";
            case "artifacts" -> "syft-json";
            default -> "";
        };
    }

    /**
     * 올린 파일이 <b>읽을 수 있는 SBOM 인가</b> — 형식 이름, 아니면 빈 문자열.
     *
     * <p>앞에서부터 흘려 읽다가 형식을 가르는 이름이 나오면 멈춘다. 세 형식
     * 모두 그 이름이 맨 앞에 온다(syft 가 그렇게 쓴다). 사이에 큰 객체가 있어도
     * 건너뛸 뿐 메모리에 올리지 않는다.
     *
     * <p><b>왜 올리는 자리에서 가르는가.</b> 패키지 목록은 JSON 셋에서만 읽는다.
     * XML 이나 tag-value 를 받으면 grype 은 검사하지만 패키지 탭이 비고, 받은
     * 뒤에 알면 검사 이력에 반쪽짜리 검사가 남는다.
     */
    public String detectFormat(InputStream in) {
        try (JsonParser parser = jsonFactory.createParser(new BufferedInputStream(in, BUFFER))) {
            if (parser.nextToken() != JsonToken.START_OBJECT) {
                return "";
            }
            while (parser.nextToken() == JsonToken.FIELD_NAME) {
                String format = formatOf(parser.currentName());
                if (!format.isEmpty()) {
                    return format;
                }
                parser.nextToken();
                parser.skipChildren();
            }
        } catch (IOException e) {
            // JSON 이 아니다 — XML · tag-value · 깨진 파일.
            return "";
        }
        return "";
    }

    /**
     * SBOM 의 형식과 컴포넌트 수 — <b>세는 김에 담는다.</b>
     *
     * <p>파일을 통째로 올리지 않고 앞에서부터 흘려 읽는다. 10GB 짜리라도 어느
     * 순간 메모리에 있는 것은 버퍼 하나와 컴포넌트 하나뿐이다.
     *
     * <p>{@code sink} 를 주면 컴포넌트를 하나씩 넘긴다. <b>모아서 돌려주지
     * 않는다</b> — 12만 개를 리스트에 담으면 스트리밍으로 읽은 뜻이 없어진다.
     * 받는 쪽이 배치로 흘려보내야 한다.
     *
     * <p>세는 것은 {@code sink} 가 있든 없든 같다. 담다가 sink 가 터지면
     * 그것은 그대로 올린다 — 인벤토리가 절반만 들어간 채로 "완료" 가 되면
     * 안 된다.
     */
    public SbomInfo inspect(Path plainJson, Consumer<ParsedComponent> sink) {
        String format = "";
        int components = 0;

        try (JsonParser parser = jsonFactory.createParser(
                new BufferedInputStream(Files.newInputStream(plainJson), BUFFER))) {

            int depth = 0;
            String countingField = null;

            while (parser.nextToken() != null) {
                JsonToken token = parser.currentToken();

                if (token == JsonToken.FIELD_NAME && depth == 1) {
                    String field = parser.currentName();
                    // 형식마다 컴포넌트가 담긴 이름이 다르다.
                    if (format.isBlank()) {
                        format = formatOf(field);
                    }
                    if (field.equals("components") || field.equals("packages")
                            || field.equals("artifacts")) {
                        countingField = field;
                    }
                }

                if (token == JsonToken.START_ARRAY && countingField != null) {
                    components = readArray(parser, countingField, sink);
                    countingField = null;
                    continue;
                }

                if (token == JsonToken.START_OBJECT || token == JsonToken.START_ARRAY) {
                    depth++;
                } else if (token == JsonToken.END_OBJECT || token == JsonToken.END_ARRAY) {
                    depth--;
                }
            }
        } catch (IOException e) {
            // 셀 수 없다고 업로드를 막지는 않는다. grype 이 읽을 수 있으면 그만이다.
            log.warn("SBOM 을 훑지 못했습니다: {}", e.getMessage());
        }
        return new SbomInfo(format, components);
    }

    /**
     * 배열 원소를 세고, {@code sink} 가 있으면 하나씩 넘긴다.
     *
     * <p>원소를 <b>하나씩</b> 트리로 읽는다. 컴포넌트 하나는 수백 바이트라
     * 곧바로 버려지고, 12만 개를 읽어도 동시에 살아 있는 것은 하나다.
     * {@code sink} 가 없으면 내용을 아예 건너뛴다 — 셀 수만 알면 된다.
     */
    private int readArray(JsonParser parser, String field, Consumer<ParsedComponent> sink)
            throws IOException {
        int count = 0;
        while (parser.nextToken() != JsonToken.END_ARRAY) {
            if (parser.currentToken() == null) {
                break;
            }
            count++;
            if (sink == null || parser.currentToken() != JsonToken.START_OBJECT) {
                parser.skipChildren();
                continue;
            }
            ParsedComponent parsed = ComponentReader.read(parser.readValueAsTree(), field);
            if (parsed != null) {
                sink.accept(parsed);
            }
        }
        return count;
    }

    /**
     * SBOM 이 담아 온 패키지 하나.
     *
     * <p>{@link kr.sbomsight.domain.Component} 로 가기 전의 날것이다. 엔티티를
     * 여기서 만들지 않는 이유는 자산·스캔을 이 클래스가 모르기 때문이다.
     */
    public record ParsedComponent(String name, String version, String type,
                                  String purl, String location) {
    }

    public record SbomInfo(String format, int componentCount) {
    }
}
