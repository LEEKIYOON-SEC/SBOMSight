package kr.sbomsight.domain;

/**
 * 근거 — <b>왜 해당 없는가.</b> {@link AnalysisState#NOT_AFFECTED} 일 때만 고른다.
 *
 * <p>"해당 없음" 만 적고 끝내면 점검에서 답할 것이 없다. 아홉 가지 중 하나를
 * 고르게 하는 이유가 그것이다 — 고를 수 없으면 아직 해당 없다고 말할 단계가
 * 아니다.
 *
 * <p>저장값은 CycloneDX VEX 표준 그대로다. 이름을 우리 식으로 바꾸면
 * 내보낸 파일을 다른 도구가 읽지 못한다.
 *
 * @see <a href="https://cyclonedx.org/docs/1.6/json/#vulnerabilities_items_analysis_justification">
 *      CycloneDX 1.6 — analysis.justification</a>
 */
public enum AnalysisJustification {

    CODE_NOT_PRESENT("code_not_present", "취약한 코드가 들어 있지 않음"),
    CODE_NOT_REACHABLE("code_not_reachable", "취약한 코드를 실행하지 않음"),
    REQUIRES_CONFIGURATION("requires_configuration", "특정 설정을 켜야 하는데 안 켜 둠"),
    REQUIRES_DEPENDENCY("requires_dependency", "함께 있어야 할 다른 패키지가 없음"),
    REQUIRES_ENVIRONMENT("requires_environment", "특정 환경에서만 되는데 그 환경이 아님"),
    PROTECTED_BY_COMPILER("protected_by_compiler", "컴파일 옵션이 막고 있음"),
    PROTECTED_AT_RUNTIME("protected_at_runtime", "실행 환경이 막고 있음"),
    PROTECTED_AT_PERIMETER("protected_at_perimeter", "방화벽·WAF 가 막고 있음"),
    PROTECTED_BY_MITIGATING_CONTROL("protected_by_mitigating_control", "다른 통제가 막고 있음");

    private final String standard;
    private final String label;

    AnalysisJustification(String standard, String label) {
        this.standard = standard;
        this.label = label;
    }

    /** 내보내기에 쓰는 표준 이름. */
    public String standard() {
        return standard;
    }

    public String label() {
        return label;
    }
}
