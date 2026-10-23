package kr.sbomsight;

import kr.sbomsight.service.GrypeRunner;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

/**
 * grype 에게 짧게 묻는 자리({@link GrypeRunner#ask}) — 설정의 도구 상태와 검사 뒤의
 * DB 기준일이 이것으로 묻는다.
 *
 * <p><b>진짜 프로세스를 띄운다.</b> 멈춘 grype 을 흉내 내려면 끝나지 않는 프로세스가
 * 있어야 한다. 셸 스크립트로 두지 않는다 — 윈도우에서 돌지 않는다(FakeGrype 와 같은
 * 까닭). 시험을 돌리는 그 자바로 아래의 작은 프로그램을 띄운다.
 */
class GrypeRunnerTest {

    /** 덜 쓴 출력을 내고 끝나지 않는다 — 멈춘 grype 의 꼴. */
    public static final class Hang {
        public static void main(String[] args) throws InterruptedException {
            System.out.println("{\"version\": \"0.87.0\"");
            System.out.flush();
            Thread.sleep(TimeUnit.MINUTES.toMillis(10));
        }
    }

    /** 답하고 바로 끝난다. */
    public static final class Quick {
        public static void main(String[] args) {
            System.out.println("{\"version\": \"0.87.0\"}");
        }
    }

    /** 파이프(수십 KB)를 한참 넘는 출력을 내고 끝난다. */
    public static final class Loud {
        public static void main(String[] args) {
            String line = "x".repeat(63);
            for (int i = 0; i < 16_384; i++) {      // 1 MiB
                System.out.println(line);
            }
            System.out.println("END");
        }
    }

    /** 오래 잔다 — 부모가 낳고 남긴 자식의 꼴. */
    public static final class Sleeper {
        public static void main(String[] args) throws InterruptedException {
            Thread.sleep(TimeUnit.MINUTES.toMillis(10));
        }
    }

    /**
     * 자식(Sleeper)을 낳아 출력을 물려준다 — 자식이 출력을 붙든다. 자식의 번호를 {@code args[0]}
     * 파일에 적는다. {@code args[1]} 이 {@code hang} 이면 저도 멈추고, {@code exit} 이면 조금 뒤
     * 답하고 끝난다(자식은 남긴 채).
     */
    public static final class Spawner {
        public static void main(String[] args) throws Exception {
            Process child = new ProcessBuilder(java(Sleeper.class))
                    .redirectOutput(ProcessBuilder.Redirect.INHERIT)
                    .redirectError(ProcessBuilder.Redirect.INHERIT)
                    .start();
            Files.writeString(Path.of(args[0]), Long.toString(child.pid()));
            System.out.println("{\"version\": \"0.87.0\"}");
            System.out.flush();
            Thread.sleep("hang".equals(args[1]) ? TimeUnit.MINUTES.toMillis(10) : 1_000);
        }
    }

    private static List<String> java(Class<?> main, String... args) {
        List<String> command = new ArrayList<>(List.of(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-cp", System.getProperty("java.class.path"), main.getName()));
        command.addAll(List.of(args));
        return command;
    }

    /** 아직 살아 있는 grype 출력 읽기 작업(고치기 전 코드가 띄우던 것). */
    private static long readers() {
        return Thread.getAllStackTraces().keySet().stream()
                     .filter(t -> t.isAlive() && t.getName().startsWith("grype-output")).count();
    }

    private static boolean alive(long pid) {
        return ProcessHandle.of(pid).map(ProcessHandle::isAlive).orElse(false);
    }

    /** 시험이 실패해도 기계에 남기지 않는다 — 고치기 전 코드로 돌리면 자식이 10분씩 남는다. */
    private static void sweep(List<Long> pids) {
        for (long pid : pids) {
            ProcessHandle.of(pid).ifPresent(ProcessHandle::destroyForcibly);
        }
    }

    private static Set<Long> children() {
        return ProcessHandle.current().children().map(ProcessHandle::pid).collect(Collectors.toSet());
    }

    /**
     * 앞서는 출력을 끝까지 읽은 다음에 기다려, 여기서 10분(이 프로그램이 자는 시간)을
     * 멈춰 있었다. 시험이 그만큼 매달리지 않게 20초에서 끊어 실패로 본다.
     */
    @Test
    @DisplayName("멈춘 grype 은 제한 시간에 끊는다 — 출력을 기다리느라 함께 멈추지 않는다")
    void aHungToolIsCutOffAtTheTimeout() throws Exception {
        Set<Long> before = children();

        GrypeRunner.Answer answer = assertTimeoutPreemptively(Duration.ofSeconds(20),
                () -> GrypeRunner.ask(java(Hang.class), Duration.ofSeconds(3)),
                "제한 시간이 3초인데 20초를 기다려도 돌아오지 않았다");

        assertThat(answer.timedOut()).as("끝나지 않는 도구를 끝난 것으로 읽었다").isTrue();

        // 끊은 grype 이 뒤에 남아 돌지 않는다 — 남으면 설정 화면을 열 때마다 하나씩 쌓인다.
        for (ProcessHandle left : ProcessHandle.current().children()
                                               .filter(p -> !before.contains(p.pid())).toList()) {
            left.onExit().get(10, TimeUnit.SECONDS);
        }
    }

    /**
     * <b>제한 시간을 넘기면 그 명령이 낳은 것까지 끝낸다.</b> 앞서는 그 명령만 끝내, 출력을
     * 물려받은 자식이 남았다 — 그 자식이 출력 파이프를 붙들어 읽는 작업도 끝나지 않았다.
     * 설정 화면을 열 때마다 자식 하나와 작업 하나가 쌓인다. 세 번 되풀이해 쌓이지 않음을 본다.
     */
    @Test
    @DisplayName("제한 시간을 넘기면 자식까지 끝내고, 되풀이해도 읽는 작업이 쌓이지 않는다")
    void aTimeoutEndsTheWholeTreeEveryTime() throws Exception {
        long readersBefore = readers();
        Set<Long> before = children();
        List<Long> spawned = new ArrayList<>();
        try {
            for (int i = 0; i < 3; i++) {
                Path pidFile = Files.createTempFile("grype-child-", ".pid");
                GrypeRunner.Answer answer = assertTimeoutPreemptively(Duration.ofSeconds(30),
                        () -> GrypeRunner.ask(java(Spawner.class, pidFile.toString(), "hang"),
                                              Duration.ofSeconds(2)));
                long grandchild = Long.parseLong(Files.readString(pidFile).trim());
                spawned.add(grandchild);
                Files.deleteIfExists(pidFile);

                assertThat(answer.timedOut()).isTrue();
                assertThat(alive(grandchild))
                        .as("끊은 명령이 낳은 자식(%d)이 남았다", grandchild).isFalse();
                assertThat(ProcessHandle.current().children()
                                        .filter(p -> !before.contains(p.pid())).toList())
                        .as("끊은 명령이 남았다").isEmpty();
            }
            assertThat(readers())
                    .as("출력을 읽는 작업이 끝나지 않고 쌓였다 — 자식이 출력을 붙들고 있다")
                    .isEqualTo(readersBefore);
        } finally {
            sweep(spawned);
        }
    }

    /**
     * <b>끝났는데 자식이 출력을 붙든 경우.</b> 앞서는 출력이 닫히기를 5초 기다린 뒤 끊긴 것으로
     * 보았다 — 답을 받고도 버렸고, 자식은 남았다. 이제 답을 그대로 받고 자식은 끝낸다.
     */

    /**
     * <b>자식을 낳자마자 끝나는 경우</b> — 띄운 앱에서 가짜 grype(`sleep &` 뒤 곧바로 끝남)로
     * 재현했다. 자식이 부모 곁에 있는 시간이 몇 ms 라 기다리며 살피는 사이에 보이지 않고, 부모가
     * 끝나면 리눅스는 자식을 1번 프로세스에 넘겨 자식으로 다시 찾을 수 없다. 자바로 띄운 부모는
     * 끝나는 데 시간이 걸려 이 틈을 만들지 못한다 — 셸로만 만들 수 있어 셸이 있는 곳에서만
     * 돈다(윈도우는 부모가 끝나도 자식이 부모 번호를 그대로 들고 있어 이 틈이 없다).
     */
    @Test
    @DisplayName("자식을 낳자마자 끝나도 — 남은 자식을 찾아 끝낸다 (셸이 있는 곳)")
    void aChildLeftBehindAtOnceIsEnded() throws Exception {
        org.junit.jupiter.api.Assumptions.assumeTrue(Files.isExecutable(Path.of("/bin/sh")),
                                                     "셸이 없다 — 리눅스 · 유닉스에서만 생기는 틈");
        long readersBefore = readers();
        Path pidFile = Files.createTempFile("grype-child-", ".pid");
        List<Long> spawned = new ArrayList<>();
        try {
            // ( … & ) — 자식을 낳은 하위 셸이 곧바로 끝나 자식이 처음부터 고아가 된다.
            GrypeRunner.Answer answer = assertTimeoutPreemptively(Duration.ofSeconds(30),
                    () -> GrypeRunner.ask(List.of("/bin/sh", "-c",
                            "( sleep 604 & echo $! > '" + pidFile + "' ); echo '{\"version\": \"0.87.0\"}'"),
                            Duration.ofSeconds(20)));
            long grandchild = Long.parseLong(Files.readString(pidFile).trim());
            spawned.add(grandchild);

            assertThat(answer.timedOut()).as("끝난 명령의 답을 버렸다").isFalse();
            assertThat(answer.output()).contains("{\"version\": \"0.87.0\"}");
            assertThat(alive(grandchild)).as("남은 자식(%d)을 끝내지 않았다", grandchild).isFalse();
            assertThat(readers()).isEqualTo(readersBefore);
        } finally {
            sweep(spawned);
            Files.deleteIfExists(pidFile);
        }
    }

    @Test
    @DisplayName("답하고 끝났는데 자식이 남았으면 — 답은 받고 자식은 끝낸다")
    void aChildLeftBehindIsEnded() throws Exception {
        long readersBefore = readers();
        Path pidFile = Files.createTempFile("grype-child-", ".pid");
        List<Long> spawned = new ArrayList<>();
        try {
            GrypeRunner.Answer answer = assertTimeoutPreemptively(Duration.ofSeconds(30),
                    () -> GrypeRunner.ask(java(Spawner.class, pidFile.toString(), "exit"),
                                          Duration.ofSeconds(20)));
            long grandchild = Long.parseLong(Files.readString(pidFile).trim());
            spawned.add(grandchild);

            assertThat(answer.timedOut()).as("끝난 명령의 답을 버렸다").isFalse();
            assertThat(answer.exitCode()).isZero();
            assertThat(answer.output()).contains("{\"version\": \"0.87.0\"}");
            assertThat(alive(grandchild)).as("남은 자식(%d)을 끝내지 않았다", grandchild).isFalse();
            assertThat(readers()).isEqualTo(readersBefore);
        } finally {
            sweep(spawned);
            Files.deleteIfExists(pidFile);
        }
    }

    @Test
    @DisplayName("바로 끝나면 출력과 종료 코드를 그대로 받는다")
    void aQuickAnswerIsReadWhole() throws Exception {
        GrypeRunner.Answer answer = GrypeRunner.ask(java(Quick.class), Duration.ofSeconds(30));

        assertThat(answer.timedOut()).isFalse();
        assertThat(answer.exitCode()).isZero();
        assertThat(answer.output()).contains("{\"version\": \"0.87.0\"}");
    }

    /**
     * 읽기를 기다림 <b>뒤로</b> 미루기만 하면 여기서 멈춘다 — 아무도 읽지 않는 출력이
     * 파이프를 채우면 도구가 쓰기에서 멈추고, 끝나지 않으니 제한 시간에 끊긴다.
     */
    @Test
    @DisplayName("출력이 파이프를 넘을 만큼 커도 멈추지 않는다 — 기다리는 동안 쓰기가 막히지 않는다")
    void aLongAnswerDoesNotStallTheTool() throws Exception {
        GrypeRunner.Answer answer = GrypeRunner.ask(java(Loud.class), Duration.ofSeconds(30));

        assertThat(answer.timedOut()).as("기다리는 동안 출력을 읽지 않아 도구가 쓰기에서 멈췄다")
                                     .isFalse();
        assertThat(answer.exitCode()).isZero();
        assertThat(answer.output()).hasSizeGreaterThan(1_000_000).contains("END");
    }

    @Test
    @DisplayName("실행하지 못하면 그렇다고 알린다 — 빈 답으로 바꾸지 않는다")
    void aMissingToolIsAnError() {
        assertThatThrownBy(() -> GrypeRunner.ask(List.of("sbomsight-no-such-grype"),
                                                 Duration.ofSeconds(5)))
                .isInstanceOf(IOException.class);
    }
}
