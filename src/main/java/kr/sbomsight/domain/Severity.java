package kr.sbomsight.domain;

import java.util.List;

/**
 * grype 이 내는 심각도 — <b>순서와 우리말 이름이 한곳에 있다.</b>
 *
 * <p>앞서 {@code List.of("critical", "high", "medium", "low", "negligible",
 * "unknown")} 이 {@code ReportService} 와 {@code ZoneReportService} 에 각각
 * 복사돼 있었고, 우리말 이름은 템플릿마다 {@code th:switch} 로 또 적혀
 * 있었다. 패키지 화면이 세 번째 복사본이 될 자리였다.
 *
 * <p><b>순서는 알파벳이 아니다.</b> {@code critical} 이 {@code high} 보다
 * 앞이고 {@code low} 는 {@code medium} 뒤다 — 뜻으로 줄을 세운다. DB 정렬은
 * 알파벳이라 이 순서를 SQL 에 맡길 수 없다.
 *
 * <p><b>값을 다시 매기지 않는다.</b> grype 이 준 글자를 그대로 받아 어느 칸에
 * 놓을지만 정한다. 모르는 글자는 {@link #UNKNOWN} 으로 두고 버리지 않는다 —
 * 버리면 건수가 조용히 줄어든다.
 */
public enum Severity {

    CRITICAL("critical", "심각"),
    HIGH("high", "높음"),
    MEDIUM("medium", "보통"),
    LOW("low", "낮음"),
    NEGLIGIBLE("negligible", "무시 가능"),
    /** grype 이 안 주거나 우리가 모르는 글자. 0 이 아니라 "모른다" 다. */
    UNKNOWN("unknown", "미확인");

    private final String key;
    private final String label;

    Severity(String key, String label) {
        this.key = key;
        this.label = label;
    }

    /** DB 에 들어 있는 소문자 글자. */
    public String key() {
        return key;
    }

    public String label() {
        return label;
    }

    /** 취약점이 있다고 볼 수 있는 등급인가 — {@link #UNKNOWN} 도 있는 것이다. */
    public boolean known() {
        return this != UNKNOWN;
    }

    /** 심각한 순서. 표와 집계가 이 순서를 쓴다. */
    public static final List<Severity> RANKED = List.of(values());

    /** 집계 맵의 열쇠 순서. */
    public static final List<String> KEYS = RANKED.stream().map(Severity::key).toList();

    /**
     * grype 이 준 글자를 칸에 놓는다. 비어 있거나 모르면 {@link #UNKNOWN}.
     *
     * <p>{@code Critical} · {@code CRITICAL} · {@code critical} 이 다 온다.
     */
    public static Severity of(String raw) {
        if (raw == null || raw.isBlank()) {
            return UNKNOWN;
        }
        String lower = raw.trim().toLowerCase();
        for (Severity severity : RANKED) {
            if (severity.key.equals(lower)) {
                return severity;
            }
        }
        return UNKNOWN;
    }
}
