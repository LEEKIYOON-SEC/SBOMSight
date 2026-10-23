package kr.sbomsight.service;

import kr.sbomsight.domain.*;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.ReportPublicationRepository;
import kr.sbomsight.repo.ScanRepository;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * 보고서 발행 — 그 순간의 문서를 굳혀 저장한다(R11, D6, V20).
 *
 * <p><b>한 번의 발행이 하는 일</b> — 한 트랜잭션 안에서:
 * <ol>
 *   <li>보고서를 계산한다(초안과 같은 계산)</li>
 *   <li>근거가 된 검사의 자산 행을 잠그고, 그 검사가 아직 있는지 잠그며 읽는다 — 그 사이에
 *       지워졌으면 발행하지 않는다. 검사 삭제도 같은 자산 행을 잠그고 발행본이 가리키는지를
 *       보므로(ScanService.delete), 둘이 겹치면 어느 한쪽이 먼저 끝난 것을 본다</li>
 *   <li>발행 번호를 매긴다 — 그해의 마지막 번호 + 1</li>
 *   <li>발행 정보(번호 · 시각 · 발행자)를 넣어 문서를 그린다 — 화면 쪽이 그린다({@link Renderer})</li>
 *   <li>문서의 SHA-256 · 계산 결과(JSON) · 가리키는 검사와 함께 저장하고 감사 로그에 남긴다</li>
 * </ol>
 *
 * <p><b>번호가 겹치면 다시 한다.</b> 동시에 눌린 둘은 같은 마지막 번호를 보고 같은 번호를
 * 매긴다. 유일 키(uk_report_publication_number)가 뒤의 것을 막고, 막힌 쪽은 새 트랜잭션에서
 * 처음부터 다시 한다 — 문서에 번호가 들어가므로 다시 그려야 한다. 사람에게 "다시 눌러
 * 주세요" 를 돌려주지 않는다. {@value #ATTEMPTS}번 막히면 그때 돌려준다.
 */
@Service
public class PublicationService {

    /** 번호가 겹쳐 다시 하는 횟수까지 친 시도 수. */
    static final int ATTEMPTS = 3;

    /** 발행 번호의 연도 — 화면이 시각을 찍는 시간대와 같다(서버 시간대). */
    private static final ZoneId WALL_CLOCK = ZoneId.systemDefault();

    /** 결재 문서 번호의 너비 — 검토 결과의 같은 칸과 같다(V11 · V20). */
    static final int APPROVAL_DOC_MAX = 128;

    private final ReportPublicationRepository publications;
    private final ScanRepository scans;
    private final AssetRepository assets;
    private final ReportService reports;
    private final ZoneReportService zoneReports;
    private final AuditService audit;
    private final TransactionTemplate transactions;

    public PublicationService(ReportPublicationRepository publications, ScanRepository scans,
                              AssetRepository assets, ReportService reports,
                              ZoneReportService zoneReports,
                              AuditService audit, PlatformTransactionManager transactionManager) {
        this.publications = publications;
        this.scans = scans;
        this.assets = assets;
        this.reports = reports;
        this.zoneReports = zoneReports;
        this.audit = audit;
        this.transactions = new TransactionTemplate(transactionManager);
    }

    /** 발행 정보 — 문서 정보에 찍혀 해시가 함께 묶는다. */
    public record Head(String number, Instant publishedAt, String publisher) {
    }

    /** 계산한 보고서를 발행 정보와 함께 문서(HTML)로 그린다 — 화면 쪽이 맡는다. */
    @FunctionalInterface
    public interface Renderer<R> {
        String render(R report, Head head);
    }

    /** 발행 · 결재 문서 번호를 하지 못했다 — 메시지는 화면에 그대로 나간다. */
    public static class PublicationException extends IllegalStateException {
        public PublicationException(String message) {
            super(message);
        }
    }

    // --- 발행 -----------------------------------------------------------------

    /** 점검 결과 보고서 — 검사 하나. */
    public ReportPublication publishScan(Long scanId, String actor,
                                        Renderer<ReportService.Report> renderer) {
        return publish(() -> {
            Scan scan = scans.findWithAsset(scanId)
                    .orElseThrow(() -> new PublicationException("검사를 찾을 수 없습니다."));
            // 끝나지 않았거나 실패한 검사의 보고서는 0건으로 그려진다 — 깨끗한 서버로 읽힌다.
            if (scan.getStatus() != ScanStatus.DONE) {
                throw new PublicationException("완료된 검사의 보고서만 발행할 수 있습니다.");
            }
            ReportService.Report report = reports.build(scan);
            Asset asset = scan.getAsset();
            return new Prepared<>(PublicationKind.SCAN, asset.getName(),
                                  p -> p.targetScan(asset.getId(), scan.getId()),
                                  report, report.basisScans(), renderer);
        }, actor);
    }

    /** 구역 현황 보고서 — 구역(전체면 {@code null}) · 기간. */
    public ReportPublication publishZone(Long zoneId, LocalDate from, LocalDate to, String actor,
                                        Renderer<ZoneReportService.ZoneReport> renderer) {
        return publish(() -> {
            ZoneReportService.ZoneReport report = zoneReports.build(zoneId, from, to);
            return new Prepared<>(PublicationKind.ZONE, report.scope().zoneName(),
                                  p -> p.targetZone(zoneId, from, to),
                                  report, report.basisScans(), renderer);
        }, actor);
    }

    /**
     * 한 번의 시도에 필요한 것 — 무엇을(종류 · 대상), 계산한 보고서와 그 근거, 그리는 쪽.
     * 번호 · 시각 · 발행자는 저장하는 트랜잭션에서 정한다.
     *
     * @param target 발행본에 대상(자산 · 검사 또는 구역 · 기간)을 적는다
     */
    private record Prepared<R>(PublicationKind kind, String targetName,
                               Consumer<ReportPublication> target,
                               R report, List<Scan> basis, Renderer<R> renderer) {

        String render(Head head) {
            return renderer.render(report, head);
        }
    }

    private ReportPublication publish(Supplier<Prepared<?>> prepare, String actor) {
        for (int attempt = 1; ; attempt++) {
            try {
                return transactions.execute(status -> once(prepare.get(), actor));
            } catch (DataIntegrityViolationException e) {
                if (!numberClash(e)) {
                    throw e;
                }
                if (attempt >= ATTEMPTS) {
                    throw new PublicationException("동시에 발행한 것과 번호가 겹쳤습니다. 다시 발행하십시오.");
                }
            }
        }
    }

    private ReportPublication once(Prepared<?> prepared, String actor) {
        List<Long> basis = prepared.basis().stream().map(Scan::getId).toList();
        lockBasis(prepared.basis());

        // DB 는 마이크로초까지 담는다 — 문서 · 계산 결과의 시각과 저장한 시각이 같게.
        Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);
        int year = LocalDate.ofInstant(now, WALL_CLOCK).getYear();
        int seq = Objects.requireNonNullElse(publications.maxSeq(year), 0) + 1;
        Head head = new Head(ReportPublication.number(year, seq), now, actor);

        String html = prepared.render(head);
        ReportPublication p = new ReportPublication(prepared.kind(), year, seq, now, actor,
                                                    prepared.targetName());
        prepared.target().accept(p);
        p.document(html, PublicationJson.write(p.getKind(), head, basis, prepared.report()),
                   sha256(html));
        p.getScanIds().addAll(basis);
        publications.saveAndFlush(p);   // 번호가 겹치면 여기서 막힌다

        audit.record(AuditEvent.REPORT_PUBLISHED, p.getNumber() + " · " + target(p),
                     p.getKind().label() + " · 가리키는 검사 " + basis.size() + "개 · sha256:"
                     + p.getDocumentSha256());
        return p;
    }

    /**
     * 근거가 된 검사의 자산 행을 잠그고(번호 차례로 — 엇갈리면 서로 기다린다), 검사가 아직
     * 있는지 잠그며 읽는다. 보고서를 계산하는 사이에 지워졌으면 발행하지 않는다.
     */
    private void lockBasis(List<Scan> basis) {
        if (basis.isEmpty()) {
            return;
        }
        basis.stream().map(s -> s.getAsset().getId()).distinct().sorted()
             .forEach(assets::lockById);
        List<Long> ids = basis.stream().map(Scan::getId).toList();
        if (scans.lockExisting(ids).size() != ids.size()) {
            throw new PublicationException(
                    "보고서의 근거가 된 검사가 그 사이에 지워졌습니다. 보고서를 다시 열어 확인한 뒤 발행하십시오.");
        }
    }

    private static boolean numberClash(DataIntegrityViolationException e) {
        Throwable cause = e.getMostSpecificCause();
        String message = cause.getMessage() == null ? "" : cause.getMessage();
        return message.toLowerCase(Locale.ROOT).contains("uk_report_publication_number");
    }

    /** 목록 · 감사 로그에 적는 대상 — 자산 이름, 또는 구역 이름과 기간. */
    public static String target(ReportPublication p) {
        return p.getKind() == PublicationKind.SCAN ? p.getTargetName()
                : p.getTargetName() + " " + p.getPeriodFrom() + " ~ " + p.getPeriodTo();
    }

    static String sha256(String html) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                                                         .digest(html.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);   // 자바가 늘 갖추는 알고리즘이다
        }
    }

    // --- 보기 -----------------------------------------------------------------

    /** 발행본과 그 문서가 해시와 맞는가. */
    public record Viewed(ReportPublication publication, boolean verified) {
    }

    /**
     * 발행본을 연다 — <b>볼 때마다 해시를 다시 대조한다.</b> 저장한 문서가 고쳐졌으면
     * 화면이 그 문서를 보이지 않는다. 고친 문서를 발행본인 척 보이면 해시를 찍은 뜻이 없다.
     */
    @Transactional(readOnly = true)
    public java.util.Optional<Viewed> view(Long id) {
        return publications.findById(id).map(p -> {
            p.getEvents().size();   // 화면이 이력을 그린다 — 트랜잭션 안에서 읽어 둔다
            return new Viewed(p, sha256(p.getDocumentHtml()).equals(p.getDocumentSha256()));
        });
    }

    // --- 결재 문서 번호 --------------------------------------------------------

    /**
     * 결재 문서 번호를 적는다. 바뀌었으면 발행본의 이력과 감사 로그에 남기고 참을 돌려준다
     * — 같은 값을 다시 적은 것은 남기지 않는다. 문서(해시)는 건드리지 않는다.
     */
    @Transactional
    public boolean changeApprovalDoc(Long id, String value, String actor) {
        String next = value == null ? "" : value.trim();
        if (next.length() > APPROVAL_DOC_MAX) {
            throw new PublicationException("결재 문서 번호는 " + APPROVAL_DOC_MAX + "자까지 적을 수 있습니다.");
        }
        ReportPublication p = publications.findById(id)
                .orElseThrow(() -> new PublicationException("발행본을 찾을 수 없습니다."));
        String before = p.getApprovalDoc();
        if (!p.changeApprovalDoc(next, actor)) {
            return false;
        }
        audit.record(AuditEvent.PUBLICATION_APPROVAL_DOC_CHANGED, p.getNumber() + " · " + target(p),
                     (before.isEmpty() ? "—" : before) + " → " + (next.isEmpty() ? "—" : next));
        return true;
    }
}
