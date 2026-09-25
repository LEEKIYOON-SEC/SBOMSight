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
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
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
    private final ComponentInventoryService inventory;
    private final TransactionTemplate transactions;

    public ScanService(ScanRepository scans, FindingRepository findings, SbomStorage storage,
                       GrypeRunner grype, GrypeMapper mapper, ObjectMapper json,
                       SbomSightProperties properties, ComponentInventoryService inventory,
                       PlatformTransactionManager transactionManager) {
        this.scans = scans;
        this.findings = findings;
        this.storage = storage;
        this.grype = grype;
        this.mapper = mapper;
        this.json = json;
        this.properties = properties;
        this.inventory = inventory;
        this.transactions = new TransactionTemplate(transactionManager);
    }

    /** 읽을 수 없는 SBOM — 올리는 자리에서 돌려보낸다. 메시지는 화면에 그대로 나간다. */
    public static class UnsupportedSbomException extends IllegalArgumentException {
        public UnsupportedSbomException() {
            super("JSON 형식의 SBOM 이 아닙니다. " + SbomStorage.ACCEPTED_FORMATS + " 만 받습니다.");
        }
    }

    /**
     * 업로드를 받아 스캔을 만들고 큐에 넣는다. 파일 저장까지만 하고 곧장 돌아온다.
     *
     * <p><b>형식부터 본다.</b> 패키지 목록을 읽지 못하는 SBOM 은 스캔을 만들기
     * 전에 돌려보낸다({@link SbomStorage#detectFormat}).
     *
     * @return 만들어진 스캔. 상태는 QUEUED 다.
     * @throws UnsupportedSbomException 받는 형식(JSON 셋)이 아닐 때
     */
    @Transactional
    public Scan submit(Asset asset, MultipartFile file, String actor) throws IOException {
        try (InputStream head = file.getInputStream()) {
            if (storage.detectFormat(head).isEmpty()) {
                throw new UnsupportedSbomException();
            }
        }
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
            throw new IllegalStateException("이 검사에는 보관된 SBOM 이 없어 다시 검사할 수 없습니다.");
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
            // **담다가 실패한 인벤토리를 버린다.** 담기는 쓰는 대로 커밋되고
            // `makeCurrent` 는 검사가 끝난 뒤에 부르므로, 중간에 터지면 새 검사
            // 것이 이전 검사 것 옆에 남는다. 화면은 완료된 검사의 행만 읽어
            // 보이지는 않지만, 쌓아 둘 까닭이 없다.
            //
            // 앞서 여기서 버리는 것이 없어 READING 에서 실패한 뒤 79행이 화면에
            // 떠 있었고, 손으로 지웠다.
            inventory.discard(scanId);
        }
    }

    /**
     * <b>여기에는 트랜잭션이 없다. 일부러 없다.</b>
     *
     * <p>앞서 {@code @Transactional} 이 붙어 있었는데 <b>적용되지 않았다</b> —
     * {@link #runAsync} 가 같은 빈의 이 메서드를 부르므로 프록시를 지나지
     * 않는다. 즉 표시만 있고 효력이 없었고, 그 표시를 믿고 짠 자리가 생겼다
     * ({@link #reapStale} 의 주석이 그랬다). 그래서 지웠다.
     *
     * <p><b>살려도 안 된다.</b> 이 메서드의 대부분은 grype 이 도는 시간이고,
     * 서버 한 대치 SBOM 이면 몇 분이다. 그 시간 내내 DB 트랜잭션을 붙잡으면
     * 진행 상태를 묻는 다른 요청이 커밋 전 값을 못 보고, 단계가 하나씩 뜨는
     * 것이 아니라 끝나는 순간 한꺼번에 뜬다 — {@code ScanRepository.updateStage}
     * 가 {@code REQUIRES_NEW} 인 이유가 그것이다.
     *
     * <p>그래서 <b>쓰기마다 제 트랜잭션으로 끝낸다.</b> 그 결과 중간에
     * 실패하면 거기까지 쓴 것이 남는다. 남아도 되는 이유는 셋이다.
     *
     * <ul>
     *   <li>그 검사는 {@code FAILED} 로 남고, 화면·보고서는 <b>자산마다 최신
     *       완료 검사만</b> 본다 — 실패한 검사의 숫자가 어디에도 섞이지 않는다.</li>
     *   <li>탐지 저장은 {@code saveAll} 한 번이라 그 안에서는 전부 들어가거나
     *       전부 안 들어간다.</li>
     *   <li>패키지 인벤토리는 실패 시 {@link ComponentInventoryService#discard}
     *       로 버린다 ({@link #reapStale} 과 {@link #runAsync} 양쪽에서).</li>
     * </ul>
     */
    public void run(Long scanId) throws IOException {
        Scan scan = scans.findById(scanId).orElseThrow();
        scan.setStatus(ScanStatus.RUNNING);
        scan.setStage(ScanStage.READING);
        scans.saveAndFlush(scan);
        scans.updateStage(scanId, ScanStage.READING);

        Path dir = properties.scanDir(scan.getAsset().getId(), scan.getId());
        Path plainSbom = null;
        Path plainReport = dir.resolve("grype.json");

        try {
            // grype 은 파일을 직접 읽는다. 압축본을 잠깐 풀어 준다.
            plainSbom = storage.inflate(Path.of(scan.getSbomPath()), dir, "sbom.json");

            // 세는 김에 담는다. 앞서는 컴포넌트 수만 세고 버렸는데, 그래서
            // 취약점이 붙은 패키지만 알 수 있었다 — log4j 가 어디 깔려 있는지는
            // CVE 가 터진 다음에야 찾게 됐다.
            //
            // **이전 것은 검사가 끝난 뒤에 지운다**(아래). 앞서는 담자마자
            // 지웠고, 그 뒤 grype 이 실패하면 담은 것도 버려져 그 자산의 패키지
            // 목록이 통째로 사라졌다. 담은 행은 검사가 끝날 때까지 보이지 않는다
            // (ComponentRepository 가 완료된 검사의 행만 읽는다).
            SbomStorage.SbomInfo info;
            try (ComponentInventoryService.Sink sink =
                         inventory.open(scan.getAsset().getId(), scan.getId())) {
                info = storage.inspect(plainSbom, sink);
            }

            scan.setSbomFormat(info.format());
            scan.setComponentCount(info.componentCount());

            // 여기가 대개 가장 길다. 단계를 먼저 커밋해야 도는 동안 화면에 뜬다.
            scan.setStage(ScanStage.SCANNING);
            scans.updateStage(scanId, ScanStage.SCANNING);

            grype.scan(plainSbom, plainReport);

            scan.setStage(ScanStage.SAVING);
            scans.updateStage(scanId, ScanStage.SAVING);

            GrypeReport report;
            try (InputStream in = Files.newInputStream(plainReport)) {
                report = json.readValue(in, GrypeReport.class);
            }

            // 기준일이 결과 JSON 에 없으면 도구에게 직접 묻는다 — 그 자리는
            // grype 판마다 옮겨 다녔고, 놓치면 화면에서 말없이 빈 칸이 된다.
            mapper.applyMetadata(scan, report, grype.dbBuilt());
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
            scan.setStage(ScanStage.DONE);
            scan.setFinishedAt(Instant.now());
            // 끝났다고 적는 것과 인벤토리를 새 검사 것으로 바꾸는 것을 **한 번에**
            // 한다. 따로 하면 그 사이에 두 검사의 패키지가 함께 보이거나(끝낸
            // 뒤 지우기 전) 아무것도 안 보인다(지운 뒤 끝내기 전).
            transactions.executeWithoutResult(tx -> {
                scans.save(scan);
                inventory.makeCurrent(scan.getAsset().getId(), scan.getId());
            });

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

    /**
     * 서버가 죽었다 살아났을 때 남아 있는 진행 중 스캔을 정리한다.
     *
     * <p>그 스캔에서 온 <b>인벤토리도 버린다.</b> {@link #run} 은 쓰기마다 제
     * 트랜잭션으로 끝내므로, 프로세스가 죽으면 <b>거기까지 담긴 것이 그대로
     * 남는다</b> — 실패한 검사의 패키지 목록을 "지금 깔려 있는 것" 으로 보여
     * 주면 안 된다.
     *
     * <p>앞서 이 주석은 "{@code run} 이 한 트랜잭션이라 대개 함께 되돌려진다"
     * 고 적고 있었다. <b>그 전제가 틀렸다</b> — {@code @Transactional} 은
     * 자기 호출이라 적용되지 않았고, 되돌려지는 일은 처음부터 없었다.
     */
    @Transactional
    public int reapStale() {
        List<Scan> stuck = scans.findByStatusIn(List.of(ScanStatus.QUEUED, ScanStatus.RUNNING));
        stuck.forEach(scan -> {
            scan.setStatus(ScanStatus.FAILED);
            scan.setErrorMessage("서버가 다시 시작되어 중단되었습니다. 다시 올려 주세요.");
            scan.setFinishedAt(Instant.now());
            inventory.discard(scan.getId());
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
