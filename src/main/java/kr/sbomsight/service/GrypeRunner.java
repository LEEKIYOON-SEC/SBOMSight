package kr.sbomsight.service;

import kr.sbomsight.config.SbomSightProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
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
     * 기다리는 동안 자식을 살피는 간격. 이 사이에 생긴 자식을 기억해 두었다가 끝날 때 함께
     * 끝낸다({@link #ask}) — 부모가 끝나면 자식은 고아가 되어 다시 찾을 수 없다(리눅스).
     */
    private static final Duration WATCH = Duration.ofMillis(100);

    /** 끝내라고 한 프로세스가 실제로 사라지기를 기다리는 시간. */
    private static final Duration KILL_WAIT = Duration.ofSeconds(5);

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
     * 짧은 명령 하나를 돌려 답을 받는다 — <b>제한 시간 안에 끝나기를 기다리고, 넘으면 끝낸다.
     * 무엇으로 끝나든 이 명령이 낳은 프로세스는 남기지 않는다.</b>
     *
     * <p>출력은 <b>파이프가 아니라 임시 파일</b>로 받는다. 앞서는 파이프를 따로 읽는 작업을
     * 두었다(그 전에는 출력을 끝까지 읽은 다음에 기다려, 멈춘 grype 에 30초 제한이 닿지
     * 않았다). 그런데 출력을 물려받은 자식이 남아 파이프를 붙들면 읽는 작업이 끝나지 않는다 —
     * 자바는 막힌 파이프 읽기를 깨우지 못한다. 시간을 넘길 때마다 그 작업과 자식이 하나씩
     * 쌓였다(GrypeRunnerTest). 파일이면 읽는 작업이 없고, 출력이 파이프를 채워 grype 이 쓰기에서
     * 멈추는 일도 없다. 표준입력은 쓰지 않으므로 바로 닫는다.
     *
     * <p>기다리는 동안 자식을 살펴 기억해 두고({@link #WATCH}), 끝날 때 <b>자식부터</b> 끝낸
     * 뒤 그 명령을 끝내고 사라지기를 기다린다 — 제한 시간을 넘겼을 때 · 기다리다 끊겼을 때 ·
     * 끝났는데 자식이 남았을 때 모두. 자식을 낳자마자 끝난 명령의 자식은 살피는 사이에 보이지
     * 않고, 리눅스는 그 자식을 1번 프로세스에 넘겨 자식으로 다시 찾을 수 없다 — 출력을
     * 물려받았으니 <b>출력 파일을 붙든 프로세스</b>로 찾는다({@link #holding}).
     *
     * @return 제한 시간을 넘기면 끝내고 {@link Answer#timedOut()}
     * @throws IOException 실행하지 못했다 — 없거나, 실행 권한이 없거나
     */
    public static Answer ask(List<String> command, Duration timeout)
            throws IOException, InterruptedException {
        Path out = Files.createTempFile("sbomsight-grype-", ".out");
        try {
            Process process = new ProcessBuilder(command)
                    .redirectErrorStream(true)
                    .redirectOutput(out.toFile())
                    .start();
            process.getOutputStream().close();
            Set<ProcessHandle> seen = new LinkedHashSet<>();
            boolean finished;
            try {
                finished = await(process, timeout, seen);
            } finally {
                end(process, seen, out);
            }
            if (!finished) {
                return Answer.TIMED_OUT;
            }
            return new Answer(false, process.exitValue(),
                              new String(Files.readAllBytes(out), StandardCharsets.UTF_8));
        } finally {
            discard(out);
        }
    }

    /** 제한 시간 안에 끝나기를 기다린다. 그동안 보인 자식을 {@code seen} 에 모은다. */
    private static boolean await(Process process, Duration timeout, Set<ProcessHandle> seen)
            throws InterruptedException {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (true) {
            process.descendants().forEach(seen::add);
            long left = deadline - System.nanoTime();
            if (left <= 0) {
                return !process.isAlive();
            }
            if (process.waitFor(Math.min(left, WATCH.toNanos()), TimeUnit.NANOSECONDS)) {
                return true;
            }
        }
    }

    /**
     * 이 명령과 그것이 낳은 것을 끝내고 사라지기를 기다린다 — <b>자식부터.</b> 부모를 먼저
     * 끝내면 자식은 고아가 되어 다시 찾을 수 없다. 그다음 출력 파일을 아직 붙든 것(살피는
     * 사이에 보이지 않은 고아)과 그 자식을 끝낸다. 이미 끝난 것은 그대로 지나간다.
     */
    private static void end(Process process, Set<ProcessHandle> seen, Path out) {
        process.descendants().forEach(seen::add);
        seen.forEach(ProcessHandle::destroyForcibly);
        process.destroyForcibly();
        for (ProcessHandle holder : holding(out)) {
            holder.descendants().forEach(seen::add);
            seen.add(holder);
        }
        seen.forEach(ProcessHandle::destroyForcibly);
        long deadline = System.nanoTime() + KILL_WAIT.toNanos();
        for (ProcessHandle p : seen) {
            gone(p, deadline);
        }
        gone(process.toHandle(), deadline);
    }

    /**
     * 출력 파일을 연 프로세스 — 이 명령이 출력을 물려준 것이다. 리눅스의 {@code /proc} 에서
     * 찾는다. {@code /proc} 이 없는 곳(윈도우)은 부모가 끝나도 자식이 부모 번호를 그대로 들고
     * 있어 {@code descendants()} 가 찾는다. 남의 프로세스라 읽지 못하는 것 · 그사이 끝난 것은
     * 지나간다 — 출력 파일은 이 물음만의 임시 파일이라 다른 것이 열 일은 없다.
     */
    private static List<ProcessHandle> holding(Path out) {
        Path proc = Path.of("/proc");
        List<ProcessHandle> holders = new ArrayList<>();
        if (!Files.isDirectory(proc)) {
            return holders;
        }
        Path target;
        try {
            target = out.toRealPath();
        } catch (IOException e) {
            return holders;
        }
        long self = ProcessHandle.current().pid();
        try (var pids = Files.list(proc)) {
            for (Path dir : (Iterable<Path>) pids::iterator) {
                String name = dir.getFileName().toString();
                if (name.isEmpty() || !name.chars().allMatch(Character::isDigit)
                        || Long.parseLong(name) == self) {
                    continue;
                }
                try (var fds = Files.list(dir.resolve("fd"))) {
                    if (fds.anyMatch(fd -> opens(fd, target))) {
                        ProcessHandle.of(Long.parseLong(name)).ifPresent(holders::add);
                    }
                } catch (IOException | SecurityException e) {
                    // 남의 것 · 그사이 끝난 것
                }
            }
        } catch (IOException | SecurityException e) {
            log.warn("출력 파일을 붙든 프로세스를 찾지 못했습니다: {}", e.getMessage());
        }
        return holders;
    }

    private static boolean opens(Path fd, Path target) {
        try {
            return Files.readSymbolicLink(fd).equals(target);
        } catch (IOException | SecurityException e) {
            return false;
        }
    }

    private static void gone(ProcessHandle p, long deadline) {
        long left = deadline - System.nanoTime();
        try {
            p.onExit().get(Math.max(left, 0), TimeUnit.NANOSECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (ExecutionException | TimeoutException e) {
            log.warn("끝내라고 한 프로세스 {} 가 {}초 안에 사라지지 않았습니다", p.pid(), KILL_WAIT.toSeconds());
        }
    }

    /** 출력을 받은 임시 파일을 지운다. 지우지 못하면 끝날 때 지우게 해 둔다 — 답을 막지 않는다. */
    private static void discard(Path out) {
        try {
            Files.deleteIfExists(out);
        } catch (IOException e) {
            log.warn("grype 출력 임시 파일을 지우지 못했습니다({}): {}", out, e.getMessage());
            out.toFile().deleteOnExit();
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
