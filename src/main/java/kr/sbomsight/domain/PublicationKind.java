package kr.sbomsight.domain;

/**
 * 무엇을 발행했는가. 이름 그대로 DB 에 넣는다({@code report_publications.kind}) —
 * <b>이름은 바꾸지 않는다.</b>
 *
 * <p>화면 이름은 두 보고서의 머리 제목 그대로다(report.html · zone-report.html).
 */
public enum PublicationKind {
    /** 자산 한 대 — 검사 하나의 보고서. */
    SCAN("점검 결과 보고서"),
    /** 구역 · 기간 보고서. */
    ZONE("구역 현황 보고서");

    private final String label;

    PublicationKind(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }
}
