package kr.sbomsight.domain;

/**
 * 대응 — <b>어떻게 할 것인가.</b>
 *
 * <p>앞서 표준 이름을 그대로 직역해 {@code 업데이트 · 되돌리기 · 우회책 있음 ·
 * 고칠 수 없음 · 고치지 않음} 으로 썼다. 뜻이 안 통했다. 저장값은 표준 그대로
 * 두고 화면 말만 우리가 쓰는 말로 바꾼다.
 *
 * <p><b>{@code 조치 불가} 와 {@code 조치 안 함} 을 합치지 않는다.</b> 할 수
 * 없는 것과 안 하기로 한 것은 다르고, 점검에서 묻는 것이 정확히 그 차이다.
 * {@code 조치 안 함(위험 수용)} 이 앞서의 "위험 수용" 에 해당한다.
 *
 * @see <a href="https://cyclonedx.org/docs/1.6/json/#vulnerabilities_items_analysis_response">
 *      CycloneDX 1.6 — analysis.response</a>
 */
public enum AnalysisResponse {

    UPDATE("update", "버전 올려 조치",
           "수정 버전이 나온 판으로 올립니다.", false),

    ROLLBACK("rollback", "이전 버전으로 내림",
             "올릴 수 없어, 취약하지 않은 예전 판으로 내립니다.", false),

    WORKAROUND_AVAILABLE("workaround_available", "우회 조치 (패치 없이)",
                         "설정 변경·접근 제한 등으로 막습니다. 패키지는 그대로 둡니다.", false),

    CAN_NOT_FIX("can_not_fix", "조치 불가",
                "수정 버전이 없고 우회도 되지 않습니다.", true),

    /** 고칠 수 있지만 안 하기로 한 것. 기한이 없으면 방치와 구분되지 않는다. */
    WILL_NOT_FIX("will_not_fix", "조치 안 함 (위험 수용)",
                 "고칠 수 있지만 하지 않기로 하고 위험을 감수합니다.", true);

    private final String standard;
    private final String label;
    private final String gloss;
    private final boolean needsReviewDate;

    AnalysisResponse(String standard, String label, String gloss, boolean needsReviewDate) {
        this.standard = standard;
        this.label = label;
        this.gloss = gloss;
        this.needsReviewDate = needsReviewDate;
    }

    public String standard() {
        return standard;
    }

    public String label() {
        return label;
    }

    /** 고르면 아래에 뜨는 한 줄. */
    public String gloss() {
        return gloss;
    }

    /**
     * 재검토일을 받아야 하는가.
     *
     * <p>고치지 않고 두기로 한 것({@code 조치 불가}·{@code 조치 안 함})에는
     * <b>반드시 기한이 있어야 한다.</b> 기한 없이 남겨 둔 것은 방치와 구분되지
     * 않는다 — 점검에서 묻는 것이 그것이다. 고치기로 한 것(올림·내림·우회)은
     * 조치 자체에 기한이 있으므로 여기서 또 묻지 않는다.
     */
    public boolean needsReviewDate() {
        return needsReviewDate;
    }
}
