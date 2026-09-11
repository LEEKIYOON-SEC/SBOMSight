package kr.sbomsight.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import kr.sbomsight.config.SbomSightProperties;
import kr.sbomsight.domain.*;
import kr.sbomsight.grype.GrypeMapper;
import kr.sbomsight.grype.GrypeReport;
import kr.sbomsight.repo.FindingRepository;
import kr.sbomsight.repo.ScanRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

/**
 * SBOM 업로드 → grype 실행 → 저장.
 *
 * <p>업로드는 즉시 끝내고 grype 은 뒤에서 돌린다. 5만 건짜리 스캔이 몇 분씩
 * 걸리는데 그동안 브라우저를 붙잡아 두면 화면이 멈춘 것처럼 보이고, 프록시나
 * 브라우저가 먼저 연결을 끊는다.
 */
@Service
public class ScanService {

    private static final Logger log = LoggerFactory.getLogger(ScanService.class);

    private final ScanRepository scans;
    private final FindingRepository findings;
    private final SbomStorage storage;
    private final GrypeRunner grype;
    private final GrypeMapper mapper;
    private final ObjectMapper json;
    private final SbomSightProperties properties;

    public ScanService(ScanRepository scans, FindingRepository findings, SbomStorage storage,
                       GrypeRunner grype, GrypeMapper mapper, ObjectMapper json,
                       SbomSightProperties properties) {
        this.scans = scans;
        this.findings = findings;
        this.storage = storage;
        this.grype = grype;
        this.mapper = mapper;
        this.json = json;
        this.properties = properties;
    }

    /**
     * 업로드를 받아 스캔을 만들고 큐에 넣는다. 파일 저장까지만 하고 곧장 돌아온다.
     *
     * @return 만들어진 스캔. 상태는 QUEUED 다.
     */
    @Transactional
    public Scan submit(Asset asset, MultipartFile file, String actor) throws IOException {
        Scan scan = new Scan(asset, actor);
        scan.setSbomFilename(originalName(file));
        scan.setSbomBytes(file.getSize());
        scans.saveAndFlush(scan);   // 파일 경로에 스캔 번호가 필요하다

        Path stored = storage.storeSbom(asset.getId(), scan.getId(), file);
        scan.setSbomPath(stored.toString());
        return scans.save(scan);
    }

    /**
     * 보관된 SBOM 을 갱신된 grype DB 로 다시 돌린다.
     *
     * <p><b>왜 필요한가.</b> 어제 없던 취약점이 오늘 생긴다 — SBOM 이 아니라
     * 취약점 DB 가 바뀌기 때문이다. syft 와 grype 을 나눠 둔 구조의 가장 큰
     * 이점이 여기에 있는데 지금까지 쓰지 않고 있었다. 대상 서버에 다시 갈
     * 필요가 없다.
     *
     * <p><b>덮어쓰지 않고 새 스캔으로 쌓는다.</b> 원래 스캔의 결과를 갈아
     * 끼우면 "그때 무엇을 봤는지" 가 사라진다 — 그 결과로 이미 결재가
     * 올라갔을 수도 있다. 새 스캔으로 쌓으면 이력 비교가 그대로 돌아가
     * "같은 SBOM 인데 무엇이 늘었나" 를 바로 읽을 수 있다.
     *
     * @return 새로 만들어진 스캔. 상태는 QUEUED 다.
     */
    @Transactional
    public Scan rescan(Scan source, String actor) throws IOException {
        if (source.getSbomPath() == null || source.getSbomPath().isBlank()) {
            throw new IllegalStateException("이 스캔에는 보관된 SBOM 이 없어 다시 돌릴 수 없습니다.");
        }
        Path stored = Path.of(source.getSbomPath());
        if (!Files.exists(stored)) {
            throw new IllegalStateException("보관된 SBOM 파일을 찾을 수 없습니다: " + stored);
        }

        Scan copy = new Scan(source.getAsset(), actor);
        copy.setSbomFilename(source.getSbomFilename());
        copy.setSbomBytes(source.getSbomBytes());
        copy.setSbomFormat(source.getSbomFormat());
        copy.setRescanOf(source.getId());
        scans.saveAndFlush(copy);   // 파일 경로에 스캔 번호가 필요하다

        // 원본을 복사한다. 경로를 함께 가리키게 하면 둘 중 하나를 지울 때
        // 나머지가 파일을 잃는다.
        Path target = storage.copySbom(stored, source.getAsset().getId(), copy.getId());
        copy.setSbomPath(target.toString());
        return scans.save(copy);
    }

    /**
     * grype 을 돌리고 결과를 저장한다. 별도 스레드에서 실행된다.
     *
     * <p>실패해도 스캔 자체는 남긴다. 실패한 스캔이 사라지면 "안 돌렸다"와
     * "돌렸는데 실패했다"를 구분할 수 없다.
     */
    @Async
    public void runAsync(Long scanId) {
        try {
            run(scanId);
        } catch (Exception e) {
            log.error("스캔 {} 실패", scanId, e);
            markFailed(scanId, e.getMessage());
        }
    }

    @Transactional
    public void run(Long scanId) throws IOException {
        Scan scan = scans.findById(scanId).orElseThrow();
        scan.setStatus(ScanStatus.RUNNING);
        scans.saveAndFlush(scan);

        Path dir = properties.scanDir(scan.getAsset().getId(), scan.getId());
        Path plainSbom = null;
        Path plainReport = dir.resolve("grype.json");

        try {
            // grype 은 파일을 직접 읽는다. 압축본을 잠깐 풀어 준다.
            plainSbom = storage.inflate(Path.of(scan.getSbomPath()), dir, "sbom.json");

            SbomStorage.SbomInfo info = storage.inspect(plainSbom);
            scan.setSbomFormat(info.format());
            scan.setComponentCount(info.componentCount());

            grype.scan(plainSbom, plainReport);

            GrypeReport report;
            try (InputStream in = Files.newInputStream(plainReport)) {
                report = json.readValue(in, GrypeReport.class);
            }

            mapper.applyMetadata(scan, report);
            GrypeMapper.Result result = mapper.map(scan, report);

            findings.deleteByScanId(scan.getId());   // 다시 돌린 경우
            findings.saveAll(result.findings());

            scan.setMatchCount(result.matches());
            scan.setFindingCount(result.findings().size());
            scan.setMergedCount(result.merged());
            scan.setDroppedCount(result.dropped());
            if (!scan.accountsBalance()) {
                // 회계가 안 맞으면 그 사실을 남긴다. 조용히 넘어가면 사라진
                // 건수를 아무도 눈치채지 못한다.
                log.warn("스캔 {} 회계 불일치: match={} finding={} merged={} dropped={}",
                        scan.getId(), result.matches(), result.findings().size(),
                        result.merged(), result.dropped());
            }

            scan.setGrypePath(storage.storeGrypeReport(plainReport, dir).toString());
            scan.setStatus(ScanStatus.DONE);
            scan.setFinishedAt(Instant.now());
            scans.save(scan);

            log.info("스캔 {} 완료: {}건 (match {} · 병합 {} · 제외 {})",
                    scan.getId(), result.findings().size(), result.matches(),
                    result.merged(), result.dropped());

        } finally {
            // 푼 파일은 지운다. 압축본과 grype 원본만 남기면 된다.
            deleteQuietly(plainSbom);
            deleteQuietly(plainReport);
        }
    }

    @Transactional
    public void markFailed(Long scanId, String message) {
        scans.findById(scanId).ifPresent(scan -> {
            scan.setStatus(ScanStatus.FAILED);
            scan.setErrorMessage(message == null ? "알 수 없는 오류" : message);
            scan.setFinishedAt(Instant.now());
            scans.save(scan);
        });
    }

    /**
     * 스캔을 지운다. <b>보관 파일도 함께 지운다.</b>
     *
     * <p>DB 행만 지우면 디스크에 SBOM 이 남아 용량은 그대로이고, 그 안에는
     * 설치 패키지 목록이라는 내부 정보가 들어 있다.
     */
    @Transactional
    public void delete(Scan scan) {
        long assetId = scan.getAsset().getId();
        long scanId = scan.getId();
        scans.delete(scan);      // findings 는 FK ON DELETE CASCADE
        storage.deleteScanDir(assetId, scanId);
    }

    /** 서버가 죽었다 살아났을 때 남아 있는 진행 중 스캔을 정리한다. */
    @Transactional
    public int reapStale() {
        List<Scan> stuck = scans.findByStatusIn(List.of(ScanStatus.QUEUED, ScanStatus.RUNNING));
        stuck.forEach(scan -> {
            scan.setStatus(ScanStatus.FAILED);
            scan.setErrorMessage("서버가 다시 시작되어 중단되었습니다. 다시 올려 주세요.");
            scan.setFinishedAt(Instant.now());
        });
        scans.saveAll(stuck);
        return stuck.size();
    }

    private String originalName(MultipartFile file) {
        String name = file.getOriginalFilename();
        if (name == null || name.isBlank()) {
            return "sbom.json";
        }
        // 경로가 섞여 들어오면 파일 이름만 취한다.
        return Path.of(name).getFileName().toString();
    }

    private void deleteQuietly(Path path) {
        if (path == null) {
            return;
        }
        try {
            Files.deleteIfExists(path);
        } catch (IOException e) {
            log.warn("임시 파일을 지우지 못했습니다: {}", path);
        }
    }
}
