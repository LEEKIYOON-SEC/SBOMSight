package kr.sbomsight;

import kr.sbomsight.service.GrypeRunner;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
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

    private static List<String> java(Class<?> main) {
        return List.of(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                       "-cp", System.getProperty("java.class.path"), main.getName());
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
    @DisplayName("출력이 파이프를 넘어도 멈추지 않는다 — 기다리는 동안 따로 읽는다")
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
