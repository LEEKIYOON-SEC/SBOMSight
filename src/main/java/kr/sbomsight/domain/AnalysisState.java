package kr.sbomsight.domain;

/**
 * 검토 결과 — <b>우리가</b> 그 탐지를 어떻게 판단했는가.
 *
 * <p><b>grype 이 낸 것은 탐지, 우리가 적는 것은 검토 결과다.</b> 둘을 같은
 * 말로 부르지 않는다. 여기에 무엇을 적든 grype 이 "이 패키지에 이 CVE 가
 * 있다" 고 한 말은 그대로 남는다. 탐지에서 빠지지도, 심각도가 내려가지도
 * 않는다 — 우리가 기록하는 것은 <b>그 말에 대한 우리의 결정</b>이다.
 *
 * <p><b>저장값은 CycloneDX VEX 표준 그대로, 화면은 우리가 쓰는 말.</b>
 * 내보내기와 점검에서는 표준 이름으로 답하고, 쓰는 사람은 한국어를 읽는다.
 * 둘을 한 곳에 묶어 두어야 화면 말만 바꾸다 저장값이 함께 바뀌는 일이 없다.
 *
 * @see <a href="https://cyclonedx.org/docs/1.6/json/#vulnerabilities_items_analysis_state">
 *      CycloneDX 1.6 — analysis.state</a>
 */
public enum AnalysisState {

    /** 아직 아무도 보지 않았다. 값이 없는 것이지 "괜찮다" 가 아니다. */
    NOT_SET("미검토", "아직 보지 않았습니다.", true),

    IN_TRIAGE("검토 중", "우리 환경에 해당되는지 확인하고 있습니다.", true),

    EXPLOITABLE("해당됨", "우리 환경에 영향이 있습니다. 고쳐야 합니다.", true),

    /** 탐지 자체는 맞다. 다만 우리 환경에 영향이 없다 — 근거를 골라야 한다. */
    NOT_AFFECTED("해당 없음", "탐지는 맞지만 우리 환경에는 영향이 없습니다.", false),

    /** 탐지가 틀렸다. 패키지를 잘못 짚었거나 버전을 잘못 읽은 경우다. */
    FALSE_POSITIVE("오탐", "탐지 자체가 틀렸습니다(패키지 오인 등).", false);

    private final String label;
    private final String gloss;
    private final boolean open;

    AnalysisState(String label, String gloss, boolean open) {
        this.label = label;
        this.gloss = gloss;
        this.open = open;
    }

    /** 화면에 찍는 말. */
    public String label() {
        return label;
    }

    /** 고르면 아래에 뜨는 한 줄. 고르는 사람이 무엇을 고르는지 알아야 한다. */
    public String gloss() {
        return gloss;
    }

    /**
     * 아직 할 일이 남아 있는가 — <b>기본 목록에 보이는가.</b>
     *
     * <p>앞서 {@code 목록에서 감추기} 체크박스를 두려 했다. 없앴다. 사람이
     * 켜고 끄게 두면 같은 상태인데 어떤 건 보이고 어떤 건 안 보인다. 상태가
     * 정한다 — 볼 일이 끝난 것(해당 없음·오탐)만 빠진다.
     *
     * <p><b>{@code 해당됨 + 조치 안 함(위험 수용)} 은 계속 보인다.</b> 안
     * 고치기로 한 것은 눈앞에 남아 있어야 한다. 그래서 감추는 축을 대응이
     * 아니라 상태에 둔다.
     */
    public boolean isOpen() {
        return open;
    }

    /** {@code 해당 없음} 일 때만 근거를 고른다. 나머지 상태에서는 묻지 않는다. */
    public boolean needsJustification() {
        return this == NOT_AFFECTED;
    }
}
