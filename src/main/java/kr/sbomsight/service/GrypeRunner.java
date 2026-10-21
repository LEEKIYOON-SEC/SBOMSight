package kr.sbomsight.service;

import kr.sbomsight.config.SbomSightProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
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

    /**
     * `grype db status` 출력에서 <b>만들어진 날</b>만 뽑는다.
     *
     * <p>JSON 이면 {@code "built": "…"}, 사람이 읽는 꼴이면
     * {@code Built:  2026-03-09T00:31:20Z} 다. 판마다 어느 쪽인지 달라서 둘 다 본다.
     */
    private static final Pattern DB_BUILT = Pattern.compile(
            "\"built\"\\s*:\\s*\"([^\"]+)\"|(?im)^\\s*built\\s*:\\s*(\\S.*?)\\s*$");

    /**
     * 상태를 묻는 짧은 명령({@code version} · {@code db status}) 하나가 기다리는 시간.
     * 넘으면 끝내고 실패로 돌려준다({@link #ask}).
     */
    private static final Duration ASK_TIMEOUT = Duration.ofSeconds(30);

    /**
     * 끝난 뒤 남은 출력을 마저 받는 시간. 출력을 물려받은 자식이 남아 붙들고 있으면
     * 출력이 닫히지 않으므로, 이만큼만 기다리고 끊긴 것으로 본다.
     */
    private static final Duration DRAIN_TIMEOUT = Duration.ofSeconds(5);

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
                        "grype가 " + properties.grypeTimeoutMinutes() + "분 안에 끝나지 않았습니다.");
            }

            // grype 은 취약점을 찾으면 --fail-on 설정에 따라 0 이 아닌 값을 낼 수
            // 있다. 우리는 --fail-on 을 주지 않으므로 0 이 정상이다.
            if (process.exitValue() != 0) {
                throw new GrypeFailedException(
                        "grype가 비정상 종료했습니다(종료 코드 " + process.exitValue() + "). " + tail(errorLog));
            }
            if (!Files.exists(output) || Files.size(output) == 0) {
                throw new GrypeFailedException("grype가 결과를 내지 않았습니다. " + tail(errorLog));
            }

        } catch (IOException e) {
            throw new GrypeFailedException(
                    "grype를 실행하지 못했습니다(" + properties.grypePath() + "). "
                    + "설치되어 있고 PATH에 있는지 확인하세요. " + e.getMessage());
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
     * @param dbBuilt   취약점 DB 가 만들어진 날, grype 이 말하는 그대로.
     *                  못 읽으면 빈 문자열 — 지어내지 않는다
     * @param message   실패했을 때 화면에 그대로 보여 줄 사유
     */
    public record Status(boolean available, String version, String dbBuilt, String message) {

        /**
         * 화면에 적는 꼴 — 검사 이력 · 보고서처럼 날짜만({@code 2026-03-09}).
         * 앞서 받은 글자 그대로({@code 2026-03-09T00:31:20Z}) 찍어 이 화면만
         * 달랐다. 읽지 못하면 받은 그대로 둔다 — 지어내지 않는다.
         */
        public String dbBuiltDay() {
            java.time.Instant at = kr.sbomsight.grype.GrypeMapper.parseInstant(dbBuilt);
            return at == null ? (dbBuilt == null ? "" : dbBuilt)
                    : java.time.LocalDate.ofInstant(at, java.time.ZoneId.systemDefault()).toString();
        }
    }

    public Status status() {
        Answer answer;
        try {
            answer = ask(List.of(properties.grypePath(), "version", "-o", "json"), ASK_TIMEOUT);
        } catch (IOException e) {
            return new Status(false, "", "",
                    "grype를 찾을 수 없습니다 (" + properties.grypePath() + "). "
                    + "설치되어 있고 PATH에 있는지 확인하세요.");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new Status(false, "", "", "확인이 중단되었습니다.");
        }
        if (answer.timedOut()) {
            return new Status(false, "", "",
                    "grype가 " + ASK_TIMEOUT.toSeconds() + "초 안에 끝나지 않았습니다.");
        }
        if (answer.exitCode() != 0) {
            return new Status(false, "", "", "grype를 실행했지만 정상 종료하지 않았습니다.");
        }
        // JSON 전체를 화면에 쏟지 않는다 — 필요한 것은 판 하나다.
        Matcher m = VERSION.matcher(answer.output());
        return new Status(true, m.find() ? m.group(1) : "", dbBuilt(), "");
    }

    /**
     * 취약점 DB 가 만들어진 날 — <b>grype 에게 직접 묻는다.</b>
     *
     * <p>본래는 검사 결과 JSON 의 {@code descriptor.db} 에서 읽는다. 그런데
     * 그 자리는 판마다 옮겨 다녔고({@code db.built} → {@code db.status.built}),
     * 옮겨 간 자리를 못 찾으면 화면의 `취약점 DB` 가 <b>말없이 비었다.</b>
     * 결과 JSON 의 모양을 쫓아다니는 대신 도구에게 묻는다 — 이 물음의 답은
     * 판이 바뀌어도 {@code built} 한 낱말이다.
     *
     * <p>읽지 못하면 빈 문자열이다. 오늘 날짜 같은 것으로 채우지 않는다 —
     * 그 날 뒤에 공개된 취약점은 이 검사에 없다는 뜻을 가진 칸이라,
     * 틀린 날짜는 없는 것보다 나쁘다.
     */
    public String dbBuilt() {
        Answer answer;
        try {
            answer = ask(List.of(properties.grypePath(), "db", "status", "-o", "json"), ASK_TIMEOUT);
        } catch (IOException e) {
            log.warn("grype db status 를 실행하지 못했습니다: {}", e.getMessage());
            return "";
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return "";
        }
        if (answer.timedOut()) {
            log.warn("grype db status 가 {}초 안에 끝나지 않았습니다.", ASK_TIMEOUT.toSeconds());
            return "";
        }
        Matcher m = DB_BUILT.matcher(answer.output());
        if (!m.find()) {
            log.warn("grype db status 에서 기준일을 찾지 못했습니다.");
            return "";
        }
        return m.group(1) != null ? m.group(1).trim() : m.group(2).trim();
    }

    /**
     * 짧은 명령 하나의 답.
     *
     * @param timedOut 제한 시간 안에 끝나지 않아 끊었다 — 종료 코드와 출력은 없다
     * @param exitCode 종료 코드
     * @param output   표준출력과 표준오류를 합친 것
     */
    public record Answer(boolean timedOut, int exitCode, String output) {

        private static final Answer TIMED_OUT = new Answer(true, -1, "");
    }

    /**
     * 짧은 명령 하나를 돌려 답을 받는다 — <b>출력은 따로 읽으며, 제한 시간 안에 끝나기를
     * 먼저 기다린다.</b> 넘으면 끝낸다.
     *
     * <p>앞서는 출력을 끝까지 읽은 다음에 기다렸다(readAllBytes → waitFor 30초). 출력 읽기는
     * grype 이 출력을 닫을 때 — 대개 끝날 때 — 까지 돌아오지 않는다. grype 이 멈추면 30초
     * 제한에 닿지도 못하고 읽기에서 그대로 멈췄다: 설정 화면 요청이, 검사 뒤에 DB 기준일을
     * 묻는 자리({@link #dbBuilt})가 함께. 고치기 전 코드는 45초를 기다려도 돌아오지 않았다.
     *
     * <p>읽기를 기다림 <b>뒤로</b> 미루기만 하면 다른 데서 멈춘다 — 출력이 파이프(수십 KB)를
     * 채우면 grype 이 쓰기에서 멈추고, 끝나지 않으니 제한 시간마다 끊긴다. 그래서 따로
     * 읽는다(GrypeRunnerTest).
     *
     * @return 제한 시간을 넘기면 끝내고 {@link Answer#timedOut()}
     * @throws IOException 실행하지 못했다 — 없거나, 실행 권한이 없거나
     */
    public static Answer ask(List<String> command, Duration timeout)
            throws IOException, InterruptedException {
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        FutureTask<byte[]> output = new FutureTask<>(() -> {
            try (InputStream in = process.getInputStream()) {
                return in.readAllBytes();
            }
        });
        Thread reader = new Thread(output, "grype-output");
        reader.setDaemon(true);
        reader.start();

        boolean finished;
        try {
            finished = process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            process.destroyForcibly();
            throw e;
        }
        if (!finished) {
            process.destroyForcibly();
            return Answer.TIMED_OUT;
        }
        try {
            byte[] bytes = output.get(DRAIN_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
            return new Answer(false, process.exitValue(), new String(bytes, StandardCharsets.UTF_8));
        } catch (TimeoutException e) {
            // 끝났는데 출력이 닫히지 않는다 — 출력을 물려받은 자식이 남아 붙들고 있다.
            return Answer.TIMED_OUT;
        } catch (ExecutionException e) {
            // 출력을 읽다 실패했다. 끝은 났으니 종료 코드는 있다 — 출력은 지어내지 않는다.
            return new Answer(false, process.exitValue(), "");
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
