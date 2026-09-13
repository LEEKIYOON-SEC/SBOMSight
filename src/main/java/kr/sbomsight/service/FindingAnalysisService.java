package kr.sbomsight.service;

import kr.sbomsight.domain.*;
import kr.sbomsight.repo.FindingAnalysisRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.Collection;
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
    private final AuditService audit;

    public FindingAnalysisService(FindingAnalysisRepository analyses, AuditService audit) {
        this.analyses = analyses;
        this.audit = audit;
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
                        response.label() + " 으로 두려면 재검토일을 정해야 합니다.");
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

    @Transactional(readOnly = true)
    public List<FindingAnalysis> list(boolean includeDone, Long zoneId) {
        return analyses.findForList(includeDone, OPEN_STATES, zoneId);
    }

    @Transactional(readOnly = true)
    public List<FindingAnalysis> reviewOverdue() {
        return analyses.findReviewOverdue(LocalDate.now());
    }

    @Transactional(readOnly = true)
    public long countForAsset(Long assetId) {
        return analyses.countByAsset(assetId);
    }
}
