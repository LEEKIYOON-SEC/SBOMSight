package kr.sbomsight.service;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import kr.sbomsight.config.SbomSightProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
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
    private final JsonFactory jsonFactory = new JsonFactory();

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

    /**
     * SBOM 의 형식과 컴포넌트 수.
     *
     * <p>파일을 통째로 올리지 않고 <b>앞에서부터 흘려 읽으며</b> 필요한 것만
     * 센다. 10GB 짜리라도 어느 순간 메모리에 있는 것은 버퍼 하나뿐이다.
     */
    public SbomInfo inspect(Path plainJson) {
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
                    format = switch (field) {
                        case "bomFormat", "components" -> format.isBlank() ? "cyclonedx-json" : format;
                        case "spdxVersion", "packages" -> format.isBlank() ? "spdx-json" : format;
                        case "artifacts" -> format.isBlank() ? "syft-json" : format;
                        default -> format;
                    };
                    if (field.equals("components") || field.equals("packages")
                            || field.equals("artifacts")) {
                        countingField = field;
                    }
                }

                if (token == JsonToken.START_ARRAY && countingField != null) {
                    components = countArray(parser);
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

    /** 배열 원소 수만 센다. 원소 내용은 건너뛴다 — 셀 수만 알면 된다. */
    private int countArray(JsonParser parser) throws IOException {
        int count = 0;
        while (parser.nextToken() != JsonToken.END_ARRAY) {
            if (parser.currentToken() == null) {
                break;
            }
            count++;
            parser.skipChildren();
        }
        return count;
    }

    public record SbomInfo(String format, int componentCount) {
    }
}
