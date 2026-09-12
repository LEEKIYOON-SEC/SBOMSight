package kr.sbomsight.web;

import kr.sbomsight.domain.Scan;
import kr.sbomsight.domain.ScanStage;
import kr.sbomsight.domain.ScanStatus;
import kr.sbomsight.repo.ScanRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * 검사가 지금 어디까지 왔는가 — 화면이 물어보는 자리.
 *
 * <p>서버 한 대짜리 SBOM 에 grype 이 몇 분씩 걸린다. 그 동안 화면에 "검사 중"
 * 한 마디만 떠 있으면 돌고 있는지 멈춘 것인지 알 수 없어 사람이 새로고침만
 * 반복하게 된다. 자산 상세 화면이 이 주소를 주기적으로 물어 단계를 갱신한다.
 *
 * <p><b>화면을 밀어 주지 않고 물어보게 두는 이유.</b> SSE 나 WebSocket 을
 * 쓰면 연결이 하나 더 생기고, 세션 만료·프록시·역방향 프록시 설정이 전부
 * 변수가 된다. 몇 분에 한 번 도는 작업의 진행을 보여 주는 데에 그만한 것을
 * 들일 이유가 없다.
 */
@RestController
public class ScanStatusController {

    private final ScanRepository scans;

    public ScanStatusController(ScanRepository scans) {
        this.scans = scans;
    }

    /** 눈금 하나. */
    public record Step(String name, String label, String detail, String state) {
    }

    public record Progress(long scanId, String status, String statusLabel,
                           String stage, String stageLabel, String stageDetail,
                           boolean running, boolean done, boolean failed,
                           String error, long elapsedSeconds,
                           int componentCount, int findingCount,
                           List<Step> steps) {
    }

    @GetMapping("/scans/{id}/status")
    public ResponseEntity<Progress> status(@PathVariable Long id) {
        return scans.findById(id)
                    .map(scan -> ResponseEntity.ok(progress(scan)))
                    .orElseGet(() -> ResponseEntity.notFound().build());
    }

    private Progress progress(Scan scan) {
        boolean failed = scan.getStatus() == ScanStatus.FAILED;
        boolean done = scan.getStatus() == ScanStatus.DONE;

        // 끝난 검사는 걸린 시간을, 도는 검사는 지금까지를 센다.
        Instant until = scan.getFinishedAt() != null ? scan.getFinishedAt() : Instant.now();
        long elapsed = Math.max(0, Duration.between(scan.getCreatedAt(), until).toSeconds());

        return new Progress(
                scan.getId(),
                scan.getStatus().name(),
                scan.getStatus().label(),
                scan.getStage().name(),
                scan.getStage().label(),
                scan.getStage().detail(),
                scan.isInFlight(),
                done,
                failed,
                scan.getErrorMessage(),
                elapsed,
                scan.getComponentCount(),
                scan.getFindingCount(),
                steps(scan));
    }

    /**
     * 눈금의 상태 — 끝남 / 도는 중 / 아직 / 멈춤.
     *
     * <p>실패하면 <b>그 자리에서 멈춘 것으로</b> 둔다. 실패한 검사의 남은
     * 눈금을 회색으로 흘려 보내면 아직 진행 중인 것처럼 읽힌다.
     */
    private List<Step> steps(Scan scan) {
        ScanStage current = scan.getStage();
        boolean failed = scan.getStatus() == ScanStatus.FAILED;
        boolean done = scan.getStatus() == ScanStatus.DONE;

        List<Step> out = new ArrayList<>();
        for (ScanStage stage : ScanStage.steps()) {
            String state;
            if (done || current.isAfter(stage)) {
                state = "done";
            } else if (stage == current) {
                state = failed ? "failed" : "running";
            } else {
                state = failed ? "skipped" : "todo";
            }
            out.add(new Step(stage.name(), stage.label(), detail(scan, stage), state));
        }
        return out;
    }

    /** 눈금 아래 한 줄. 이미 알게 된 값이 있으면 그것을 보여 준다. */
    private String detail(Scan scan, ScanStage stage) {
        return switch (stage) {
            case UPLOADED -> scan.getSbomFilename();
            case READING -> scan.getComponentCount() > 0
                    ? String.format("컴포넌트 %,d개", scan.getComponentCount())
                    : stage.detail();
            case SAVING -> scan.getStatus() == ScanStatus.DONE
                    ? String.format("탐지 %,d건", scan.getFindingCount())
                    : stage.detail();
            default -> stage.detail();
        };
    }
}
