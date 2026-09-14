package kr.sbomsight.domain;

/**
 * 조치 상태 — 올리기로 한 일이 어디까지 왔는가.
 *
 * <p><b>셋뿐이다.</b> 일감은 아직 안 했거나, 하는 중이거나, 했다.
 *
 * <p><b>{@code ACCEPTED}(하지 않고 닫음) 를 없앴다.</b> 같은 결정이 두 곳에
 * 적힐 수 있었다 — 여기의 {@code ACCEPTED} 와 검토 결과의
 * {@link AnalysisResponse#WILL_NOT_FIX}(조치 안 함 · 위험 수용). 그러면 보고서는
 * 한쪽만 읽고, 두 쪽이 다르게 적혀 있어도 아무도 모른다.
 *
 * <p><b>남길 쪽은 검토 결과다.</b> 통제가 그쪽에만 있다.
 *
 * <table>
 *   <caption>같은 결정을 두 곳에 적을 때 무엇이 다른가</caption>
 *   <tr><th></th><th>{@code ACCEPTED} (없앴다)</th><th>{@code WILL_NOT_FIX}</th></tr>
 *   <tr><td>근거</td><td>없음</td><td>아홉 가지 중 하나 (§4.3)</td></tr>
 *   <tr><td>재검토일</td><td>없음</td><td><b>반드시 받는다</b></td></tr>
 *   <tr><td>결재 문서 번호</td><td>없음</td><td>적는 칸이 있다</td></tr>
 * </table>
 *
 * <p>근거도 재검토일도 없이 아무나 눌러 닫을 수 있는 상태는 <b>통제가 있는
 * 것처럼 보이는 만큼 없느니만 못하다.</b> 이 클래스에 앞서 적혀 있던 것과
 * 같은 이유다 — 화면 이름이 {@code 예외 승인} 이었고, 이 도구에 승인 절차는
 * 없으므로 고쳤다. 이번에는 이름이 아니라 <b>그 상태 자체</b>를 없앤다.
 *
 * <p>이미 {@code ACCEPTED} 로 닫아 둔 행은 {@code V14} 가 <b>대기로 되돌리고
 * 그 사실을 메모와 이력에 남긴다.</b> 완료로 바꾸면 하지 않은 일을 했다고
 * 적는 셈이고, 조용히 지우면 누가 언제 닫았는지가 사라진다.
 */
public enum RemediationStatus {
    OPEN("대기"),
    IN_PROGRESS("진행"),
    DONE("완료");

    private final String label;

    RemediationStatus(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }

    public boolean isClosed() {
        return this == DONE;
    }
}
