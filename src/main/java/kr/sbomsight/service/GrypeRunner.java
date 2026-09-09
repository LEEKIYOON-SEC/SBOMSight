package kr.sbomsight.service;

import kr.sbomsight.config.SbomSightProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * grype 실행.
 *
 * <p>파일 경로를 넘긴다 — SBOM 을 자바 객체로 올리지 않는다. 100MB SBOM 을
 * 파싱하면 그 몇 배가 힙에 올라가고, 10GB 는 아예 불가능하다. grype 은 Go 로
 * 짜인 도구이고 파일을 스스로 스트리밍해서 읽는다.
 *
 * <p>표준출력은 JSON 이라 파일로 곧장 흘려보낸다. 문자열로 받으면 수만 건짜리
 * 결과가 통째로 메모리에 뜬다.
 */
@Service
public class GrypeRunner {

    private static final Logger log = LoggerFactory.getLogger(GrypeRunner.class);

    /** `grype version -o json` 출력에서 판만 뽑는다. */
    private static final Pattern VERSION = Pattern.compile("\"version\"\\s*:\\s*\"([^\"]+)\"");

    private final SbomSightProperties properties;

    public GrypeRunner(SbomSightProperties properties) {
        this.properties = properties;
    }

    /** grype 이 실패했을 때. 메시지는 화면에 그대로 보여 준다 — 대개 설치·DB 문제다. */
    public static class GrypeFailedException extends RuntimeException {
        public GrypeFailedException(String message) {
            super(message);
        }
    }

    /**
     * SBOM 파일에 grype 을 돌려 JSON 을 {@code output} 에 쓴다.
     *
     * @param sbom   압축을 푼 SBOM 파일 (grype 이 직접 읽는다)
     * @param output grype JSON 을 받을 파일
     */
    public void scan(Path sbom, Path output) {
        List<String> command = List.of(
                properties.grypePath(),
                "sbom:" + sbom.toAbsolutePath(),
                "--output", "json",
                // 심각도로 거르지 않는다. 무엇을 볼지는 화면에서 정한다.
                "--file", output.toAbsolutePath().toString());

        log.info("grype 실행: {}", String.join(" ", command));
        Path errorLog = output.resolveSibling("grype-stderr.log");

        try {
            Process process = new ProcessBuilder(command)
                    .redirectErrorStream(false)
                    .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                    .redirectError(errorLog.toFile())
                    .start();

            boolean finished = process.waitFor(properties.grypeTimeoutMinutes(), TimeUnit.MINUTES);
            if (!finished) {
                process.destroyForcibly();
                throw new GrypeFailedException(
                        "grype 이 " + properties.grypeTimeoutMinutes() + "분 안에 끝나지 않았습니다.");
            }

            // grype 은 취약점을 찾으면 --fail-on 설정에 따라 0 이 아닌 값을 낼 수
            // 있다. 우리는 --fail-on 을 주지 않으므로 0 이 정상이다.
            if (process.exitValue() != 0) {
                throw new GrypeFailedException(
                        "grype 이 " + process.exitValue() + " 로 끝났습니다. " + tail(errorLog));
            }
            if (!Files.exists(output) || Files.size(output) == 0) {
                throw new GrypeFailedException("grype 이 결과를 내지 않았습니다. " + tail(errorLog));
            }

        } catch (IOException e) {
            throw new GrypeFailedException(
                    "grype 을 실행하지 못했습니다(" + properties.grypePath() + "). "
                    + "설치되어 있고 PATH 에 있는지 확인하세요. " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new GrypeFailedException("grype 실행이 중단되었습니다.");
        }
    }

    /**
     * grype 이 실제로 실행되는가, 어느 판인가.
     *
     * <p>"설치되어 있습니다"라는 말 대신 <b>실제로 불러 본다.</b> PATH 에 있는데
     * 실행 권한이 없거나, 다른 아키텍처 바이너리이거나 하는 경우를 말로는
     * 구분할 수 없다.
     *
     * @param available 실행에 성공했는가
     * @param version   판 (예: 0.87.0). 못 읽으면 빈 문자열
     * @param message   실패했을 때 화면에 그대로 보여 줄 사유
     */
    public record Status(boolean available, String version, String message) {
    }

    public Status status() {
        try {
            Process process = new ProcessBuilder(properties.grypePath(), "version", "-o", "json")
                    .redirectErrorStream(true)
                    .start();
            String out = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            boolean finished = process.waitFor(30, TimeUnit.SECONDS);
            if (!finished || process.exitValue() != 0) {
                process.destroyForcibly();
                return new Status(false, "", "grype 을 실행했지만 정상 종료하지 않았습니다.");
            }
            // JSON 전체를 화면에 쏟지 않는다 — 필요한 것은 판 하나다.
            Matcher m = VERSION.matcher(out);
            return new Status(true, m.find() ? m.group(1) : "", "");
        } catch (IOException e) {
            return new Status(false, "",
                    "grype 을 찾을 수 없습니다 (" + properties.grypePath() + "). "
                    + "설치되어 있고 PATH 에 있는지 확인하세요.");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new Status(false, "", "확인이 중단되었습니다.");
        }
    }

    /** 오류 로그의 끝부분. 전체를 화면에 쏟지 않는다. */
    private String tail(Path errorLog) {
        try {
            if (!Files.exists(errorLog)) {
                return "";
            }
            String text = Files.readString(errorLog, StandardCharsets.UTF_8).trim();
            return text.length() <= 500 ? text : "…" + text.substring(text.length() - 500);
        } catch (IOException e) {
            return "";
        }
    }
}
