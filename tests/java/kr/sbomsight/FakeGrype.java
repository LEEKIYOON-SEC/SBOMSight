package kr.sbomsight;

import kr.sbomsight.domain.Scan;
import kr.sbomsight.repo.ScanRepository;
import kr.sbomsight.service.GrypeRunner;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;

/**
 * grype 대신 — <b>미리 만든 검사 결과를 쓴다.</b>
 *
 * <p>업로드 → 뒤에서 검사 → 저장 → 화면 · 보고서까지 앱의 코드가 그대로 돌고,
 * grype 을 부르는 자리만 바뀐다. 셸 스크립트로 가짜 grype 을 두지 않는다 —
 * 윈도우에서 시험이 돌지 않는다.
 *
 * <p>어느 결과를 쓸지는 <b>SBOM 이 정한다</b> — SBOM 의 {@code "marker"} 값이
 * {@code fake-grype/<marker>.json} 을 고른다. 진짜 grype 처럼 같은 SBOM 은 같은
 * 결과를 낸다.
 *
 * <pre>
 *   &#64;MockBean GrypeRunner grype;
 *   &#64;BeforeEach void fake() { fakeGrype = FakeGrype.on(grype); }
 * </pre>
 *
 * <p>{@code @MockBean} 은 시험마다 다시 비워지므로 {@code @BeforeEach} 에서 매번 건다.
 */
final class FakeGrype {

    private static final Pattern MARKER = Pattern.compile("\"marker\"\\s*:\\s*\"([^\"]+)\"");

    /** 결과 JSON 의 {@code descriptor.db.built} 가 없을 때 도구에게 묻는 값. */
    static final String DB_BUILT = "2026-09-30T00:00:00Z";

    private volatile CountDownLatch gate;

    private FakeGrype() {
    }

    static FakeGrype on(GrypeRunner mock) {
        FakeGrype fake = new FakeGrype();
        doAnswer(invocation -> {
            fake.run(invocation.getArgument(0), invocation.getArgument(1));
            return null;
        }).when(mock).scan(any(Path.class), any(Path.class));
        when(mock.dbBuilt()).thenReturn(DB_BUILT);
        return fake;
    }

    /**
     * 이제부터 시작하는 검사를 <b>grype 단계에 붙잡아 둔다</b> — {@link #release()}
     * 할 때까지. "검사가 도는 동안" 을 시간에 기대지 않고 만든다.
     */
    void hold() {
        gate = new CountDownLatch(1);
    }

    void release() {
        CountDownLatch g = gate;
        gate = null;
        if (g != null) {
            g.countDown();
        }
    }

    /**
     * 검사가 끝날 때까지 기다린다 — 완료든 실패든.
     *
     * <p>완료 표시와 인벤토리 교체는 한 트랜잭션이라(ScanService.run) 상태만 보면
     * 된다. <b>실패는 다르다</b> — 상태를 먼저 적고 담다 만 인벤토리를 나중에
     * 버린다. 실패 뒤의 인벤토리를 재는 시험은 남은 행을 직접 기다려야 한다.
     */
    static Scan awaitFinished(ScanRepository scans, Long scanId) throws InterruptedException {
        for (int i = 0; i < 400; i++) {
            Scan scan = scans.findById(scanId).orElseThrow();
            if (!scan.isInFlight()) {
                return scan;
            }
            Thread.sleep(25);
        }
        throw new AssertionError("검사 " + scanId + " 이 10초 안에 끝나지 않았습니다");
    }

    private void run(Path sbom, Path output) throws IOException, InterruptedException {
        CountDownLatch g = gate;
        if (g != null && !g.await(30, TimeUnit.SECONDS)) {
            throw new GrypeRunner.GrypeFailedException("시험이 붙잡은 검사를 30초 안에 놓지 않았습니다.");
        }
        Matcher m = MARKER.matcher(Files.readString(sbom));
        if (!m.find()) {
            throw new GrypeRunner.GrypeFailedException("SBOM 에 marker 가 없습니다: " + sbom);
        }
        String resource = "/fake-grype/" + m.group(1) + ".json";
        try (InputStream in = FakeGrype.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new GrypeRunner.GrypeFailedException("미리 만든 결과가 없습니다: " + resource);
            }
            Files.copy(in, output, StandardCopyOption.REPLACE_EXISTING);
        }
    }
}
