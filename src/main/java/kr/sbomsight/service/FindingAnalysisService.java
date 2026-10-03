package kr.sbomsight.service;

import kr.sbomsight.domain.*;
import kr.sbomsight.repo.FindingAnalysisRepository;
import kr.sbomsight.repo.FindingRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * 검토 결과 기록.
 *
 * <p><b>검토 결과는 grype 의 판정을 바꾸지 않는다.</b> {@code 해당 없음} 을
 * 적어도 그 건이 탐지에서 빠지거나 심각도가 내려가지 않는다. 기본 목록에서
 * 빠질 뿐이고, 보고서는 <b>몇 건이 빠졌는지를 반드시 찍는다.</b> 검토가
 * 건수를 줄이면 그 순간 보고서는 실제보다 안전해 보이는 숫자를 말하게
 * 된다 — 그것이 이 기능을 잘못 만드는 가장 쉬운 길이다.
 */
@Service
public class FindingAnalysisService {

    /** 볼 일이 끝나지 않은 상태들. 목록 질의에 넘긴다. */
    public static final List<AnalysisState> OPEN_STATES =
            Arrays.stream(AnalysisState.values()).filter(AnalysisState::isOpen).toList();

    private final FindingAnalysisRepository analyses;
    private final FindingRepository findings;
    private final AuditService audit;

    public FindingAnalysisService(FindingAnalysisRepository analyses, FindingRepository findings,
                                  AuditService audit) {
        this.analyses = analyses;
        this.findings = findings;
        this.audit = audit;
    }

    /**
     * 탐지 한 줄에서 적는다 — 표 · CVE 상세의 `작성` · `수정`.
     *
     * <p><b>그 탐지의 두 번호로 있던 행을 먼저 찾는다</b>(R6). 앞서는 화면이 보낸 번호
     * (화면에 찍는 번호) 하나로만 찾아, GHSA 로 적어 둔 건에 나중에 CVE 가 붙은 뒤 표에서
     * 고치면 새 행이 생겼다 — 같은 취약점의 결정이 둘로 갈렸다(재현 시험 P3). 찾는 규칙은
     * 읽을 때({@link #analysisOf})와 같다. 그런 행이 둘이면 나중에 고친 것을 고친다.
     * 없으면 화면에 찍는 번호(있으면 CVE)로 새로 만든다 — 결재 · 보고가 그 번호로 돈다.
     *
     * <p>탐지는 이 자산 · 이 패키지의 것이어야 한다. 화면은 언제나 맞는 짝을 보낸다 —
     * 어긋나면 손으로 만든 요청이라 적지 않고 알린다.
     */
    @Transactional
    public FindingAnalysis recordForFinding(Asset asset, Long findingId, String packageName,
                                            AnalysisState state, AnalysisJustification justification,
                                            AnalysisResponse response, String note, String otherControl,
                                            String approvalDoc, LocalDate reviewBy, String actor) {
        Finding finding = findings.findById(findingId)
                .orElseThrow(() -> new IllegalArgumentException("탐지를 찾을 수 없습니다."));
        if (!finding.getScan().getAsset().getId().equals(asset.getId())
                || !finding.getPackageName().equals(packageName)) {
            throw new IllegalArgumentException("다른 자산 · 패키지의 탐지입니다.");
        }
        FindingAnalysis existing = later(
                analyses.findOne(asset.getId(), finding.getCve(), packageName).orElse(null),
                hasRelated(finding.getCve(), finding.getRelatedCve())
                        ? analyses.findOne(asset.getId(), finding.getRelatedCve(), packageName).orElse(null)
                        : null);
        String cve = existing != null ? existing.getCve() : finding.getDisplayId();
        return record(asset, cve, packageName, state, justification, response,
                      note, otherControl, approvalDoc, reviewBy, actor);
    }

    /**
     * 검토 결과를 적는다. 없으면 만들고, 있으면 바꾼 칸만 이력에 남긴다.
     *
     * <p>고르는 값과 적는 값을 가른다 — <b>근거</b>는 표준값 아홉 중 하나를
     * <b>고르는</b> 것이고, <b>설명</b>은 사람이 <b>적는</b> 것이다. 같은
     * 말로 부르면 "근거를 골라야 합니다" 가 무엇을 하라는 말인지 흐려진다.
     */
    @Transactional
    public FindingAnalysis record(Asset asset, String cve, String packageName,
                                  AnalysisState state, AnalysisJustification justification,
                                  AnalysisResponse response, String note, String otherControl,
                                  String approvalDoc, LocalDate reviewBy, String actor) {
        AnalysisState newState = state == null ? AnalysisState.NOT_SET : state;

        // 해당 없다고만 적고 끝내면 점검에서 답할 것이 없다. 아홉 가지 중
        // 하나를 고를 수 없다면 아직 해당 없다고 말할 단계가 아니다.
        if (newState.needsJustification() && justification == null) {
            throw new IllegalArgumentException("해당 없음으로 두려면 근거를 골라야 합니다.");
        }
        // 나머지 상태에서 근거가 남아 있으면 앞서 고른 것이 조용히 따라온다.
        AnalysisJustification newJustification =
                newState.needsJustification() ? justification : null;

        // 고치지 않고 두기로 한 것에 기한이 없으면 방치와 구분되지 않는다.
        if (response != null && response.needsReviewDate()) {
            if (reviewBy == null) {
                throw new IllegalArgumentException(
                        "대응 방안이 " + response.label() + "일 때는 재검토일을 정해야 합니다.");
            }
            if (reviewBy.isBefore(LocalDate.now())) {
                throw new IllegalArgumentException("재검토일은 오늘 이후여야 합니다.");
            }
        }
        // 기한을 받지 않는 대응으로 바꾸면 앞서 잡아 둔 날짜는 뜻이 없어진다.
        LocalDate newReviewBy =
                response != null && response.needsReviewDate() ? reviewBy : null;

        FindingAnalysis analysis = analyses.findOne(asset.getId(), cve, packageName)
                .orElseGet(() -> new FindingAnalysis(asset, cve, packageName));

        boolean isNew = analysis.getId() == null;
        // 바뀐 칸만 남긴다. 손대지 않은 칸까지 쌓으면 이력이 읽히지 않는다.
        note(analysis, actor, "상태", label(analysis.getState()), label(newState));
        note(analysis, actor, "근거",
             label(analysis.getJustification()), label(newJustification));
        note(analysis, actor, "대응", label(analysis.getResponse()), label(response));
        note(analysis, actor, "재검토일",
             String.valueOf(analysis.getReviewBy() == null ? "" : analysis.getReviewBy()),
             String.valueOf(newReviewBy == null ? "" : newReviewBy));
        // 적는 칸도 남긴다(R8, V19). 앞서는 고르는 칸만 남겨 "결재 문서 번호는 언제
        // 바뀌었나" 에 답할 것이 없었다. 저장하는 꼴(앞뒤 빈칸을 뗀 값)으로 견준다 —
        // 빈칸만 다른 것은 바뀐 것이 아니다.
        note(analysis, actor, "설명", analysis.getNote(), trimmed(note));
        note(analysis, actor, "추가 보안 통제", analysis.getOtherControl(), trimmed(otherControl));
        note(analysis, actor, "결재 문서 번호", analysis.getApprovalDoc(), trimmed(approvalDoc));

        analysis.setState(newState);
        analysis.setJustification(newJustification);
        analysis.setResponse(response);
        analysis.setNote(note);
        analysis.setOtherControl(otherControl);
        analysis.setApprovalDoc(approvalDoc);
        analysis.setReviewBy(newReviewBy);
        analysis.setUpdatedAt(Instant.now());
        analysis.setUpdatedBy(actor);
        analyses.save(analysis);

        audit.record(AuditEvent.ANALYSIS_RECORDED,
                     asset.getName() + " · " + cve,
                     packageName + " · " + newState.label()
                     + (response == null ? "" : " · " + response.label())
                     + (newReviewBy == null ? "" : " · 재검토 " + newReviewBy)
                     + (isNew ? "" : " (변경)"));
        return analysis;
    }

    private void note(FindingAnalysis analysis, String actor,
                      String field, String before, String after) {
        if (!Objects.equals(before, after)) {
            analysis.record(actor, field, before, after);
        }
    }

    private static String trimmed(String text) {
        return text == null ? "" : text.trim();
    }

    /** 이력에 남기는 말은 화면에 찍는 말과 같아야 한다 — 사람이 읽는 것이다. */
    private static String label(Object value) {
        if (value == null) {
            return "";
        }
        return switch (value) {
            case AnalysisState s -> s.label();
            case AnalysisJustification j -> j.label();
            case AnalysisResponse r -> r.label();
            default -> String.valueOf(value);
        };
    }

    /** 한 건 — 상세 화면. 자산 · 구역 · 이력까지 한 번에 읽는다. */
    @Transactional(readOnly = true)
    public java.util.Optional<FindingAnalysis> detail(Long id) {
        return analyses.findDetail(id);
    }

    /**
     * 한 자산치를 {@code (CVE, 패키지명)} 키로 준다.
     *
     * <p>목록이 행마다 표시를 붙이는 데 쓴다. 건마다 물으면 한 장에 수백 번
     * 왕복한다.
     */
    @Transactional(readOnly = true)
    public Map<String, FindingAnalysis> byKey(Long assetId) {
        return index(analyses.findByAsset(assetId), FindingAnalysis::key);
    }

    /**
     * 여러 자산치를 {@code (자산id, CVE, 패키지명)} 키로 준다.
     *
     * <p>구역·전체 범위의 목록은 자산이 섞여 있어 자산 id 까지 키에 넣어야
     * 한다. 넣지 않으면 web-01 의 검토 결과가 api-01 행에 붙는다.
     */
    @Transactional(readOnly = true)
    public Map<String, FindingAnalysis> byAssetKey(Collection<Long> assetIds) {
        return assetIds.isEmpty() ? Map.of()
                : index(analyses.findByAssets(assetIds),
                        a -> a.getAsset().getId() + "|" + a.key());
    }

    private Map<String, FindingAnalysis> index(List<FindingAnalysis> rows,
                                               Function<FindingAnalysis, String> key) {
        return rows.stream().collect(Collectors.toMap(key, Function.identity(), (a, b) -> a));
    }

    /**
     * 대응 화면의 검토 결과 탭 — 보고서도 이것으로 모은다.
     *
     * @param includeArchived 운영 종료한 자산의 것도 넣는가. 대응 화면은
     *                        {@code 운영 종료 자산 포함} 을 켰을 때만 넣는다.
     *                        보고서는 <b>넣고</b> 제 범위로 거른다 — 운영 종료한
     *                        자산의 제 보고서가 제 검토 결과를 잃으면 안 된다
     */
    @Transactional(readOnly = true)
    public List<FindingAnalysis> list(boolean includeDone, Long zoneId, boolean includeArchived) {
        return analyses.findForList(includeDone, OPEN_STATES, zoneId, LocalDate.now(), includeArchived);
    }

    /**
     * 한 자산치 — 자산 상세의 조치·검토 결과 탭.
     *
     * <p>아무도 손대지 않은 행은 내지 않는다. 목록 화면과 같은 규칙이다 —
     * 그 자산의 탐지 전부가 쏟아지면 목록이 되지 못한다.
     */
    @Transactional(readOnly = true)
    public List<FindingAnalysis> forAsset(Long assetId) {
        return analyses.findByAsset(assetId).stream()
                       .filter(a -> !a.isUntouched())
                       .sorted(java.util.Comparator
                               .comparing(FindingAnalysis::isReviewOverdue).reversed()
                               .thenComparing(FindingAnalysis::getCve))
                       .toList();
    }

    /** 재검토일이 지난 것. 운영 종료한 자산의 것은 {@code includeArchived} 일 때만. */
    @Transactional(readOnly = true)
    public List<FindingAnalysis> reviewOverdue(boolean includeArchived) {
        return analyses.findReviewOverdue(LocalDate.now(), includeArchived);
    }

    /**
     * 탐지 한 줄이 <b>어떤 검토 상태인가.</b>
     *
     * <p>적어 둔 것이 없으면 {@link AnalysisState#NOT_SET}(미검토)다. 없는
     * 것을 "괜찮다" 로 읽지 않는다 — 아무도 보지 않았다는 뜻이다.
     *
     * <p>맞추는 규칙은 {@link #analysisOf} 한 곳에 있다. 보고서 1장의 `제외` 집계와
     * 2.4 의 검토 결과 분포가 <b>같아야 하므로.</b>
     *
     * @param byKey {@code "CVE|패키지명"} → 적어 둔 것
     */
    public static AnalysisState stateOf(Map<String, FindingAnalysis> byKey,
                                        String cve, String relatedCve, String packageName) {
        FindingAnalysis found = analysisOf(byKey, cve, relatedCve, packageName);
        return found == null ? AnalysisState.NOT_SET : found.getState();
    }

    /**
     * 탐지 한 줄에 <b>적어 둔 검토 결과</b> — 없으면 {@code null}.
     *
     * <p><b>규칙은 하나다</b>(R6). 같은 자산 · 같은 패키지에서 번호가 탐지의 주
     * 식별자 또는 함께 온 CVE 와 같은 행이고, 그런 행이 둘이면 <b>나중에 고친 것</b>
     * 이다(D4 — {@link #later}). 앞서 여기와 SQL 은 주 식별자 쪽을 먼저, 표는 CVE
     * 쪽을 먼저 찾았다. 둘로 갈린 건(재현 시험 P3)에서 표는 고친 결정(해당됨)을,
     * 목록 · 보고서는 옛 결정(해당 없음)을 말했다. 저장({@link #recordForFinding}) ·
     * 표 · 묶어 보는 화면 · SQL(FindingRepository)이 이 규칙 하나를 쓴다.
     *
     * <p>보고서 4장이 그 줄의 대응 방안과 재검토일을 모을 때도 쓴다 — 상태만으로는
     * 모자라다.
     */
    public static FindingAnalysis analysisOf(Map<String, FindingAnalysis> byKey,
                                             String cve, String relatedCve, String packageName) {
        return later(byKey.get(cve + "|" + packageName),
                     hasRelated(cve, relatedCve) ? byKey.get(relatedCve + "|" + packageName) : null);
    }

    /**
     * 위와 같은 것을 <b>자산 id 를 키에 넣은 지도</b>({@link #byAssetKey})로 — 구역 ·
     * 전체 범위의 목록, CVE 상세, 묶어 보는 화면.
     */
    public static FindingAnalysis analysisOf(Map<String, FindingAnalysis> byAssetKey, Long assetId,
                                             String cve, String relatedCve, String packageName) {
        String prefix = assetId + "|";
        return later(byAssetKey.get(prefix + cve + "|" + packageName),
                     hasRelated(cve, relatedCve)
                             ? byAssetKey.get(prefix + relatedCve + "|" + packageName) : null);
    }

    /** 표 · CVE 상세가 줄마다 부른다(finding-table · vuln-detail). */
    public static FindingAnalysis analysisOf(Map<String, FindingAnalysis> byAssetKey, Finding finding) {
        return analysisOf(byAssetKey, finding.getScan().getAsset().getId(),
                          finding.getCve(), finding.getRelatedCve(), finding.getPackageName());
    }

    /**
     * 둘 중 <b>나중에 고친 것</b> — 고친 시각, 같으면 나중에 만든 행(id). 하나가 없으면
     * 다른 하나.
     *
     * <p>시각은 <b>마이크로초까지만</b> 견준다. DB 의 칸(DATETIME(6))이 거기까지라
     * SQL(FindingRepository)은 그 값으로 견주는데, 막 저장한 행은 메모리에 나노초가
     * 남아 있다. 자르지 않으면 같은 두 행을 두 규칙이 다르게 고를 수 있다.
     */
    static FindingAnalysis later(FindingAnalysis a, FindingAnalysis b) {
        if (a == null || b == null) {
            return a == null ? b : a;
        }
        int byTime = a.getUpdatedAt().truncatedTo(java.time.temporal.ChronoUnit.MICROS)
                      .compareTo(b.getUpdatedAt().truncatedTo(java.time.temporal.ChronoUnit.MICROS));
        if (byTime != 0) {
            return byTime > 0 ? a : b;
        }
        return a.getId() > b.getId() ? a : b;
    }

    /** 함께 온 CVE 가 주 식별자와 다른 번호인가 — 같으면 한 번만 찾는다. */
    private static boolean hasRelated(String cve, String relatedCve) {
        return relatedCve != null && !relatedCve.isBlank() && !relatedCve.equals(cve);
    }

    /** 상태마다 0 부터 시작하는 빈 표. 없는 줄이 빠지면 표가 판마다 달라진다. */
    public static Map<AnalysisState, Long> emptyStateCounts() {
        Map<AnalysisState, Long> counts = new LinkedHashMap<>();
        for (AnalysisState state : AnalysisState.values()) {
            counts.put(state, 0L);
        }
        return counts;
    }
}
