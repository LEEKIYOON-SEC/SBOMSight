package kr.sbomsight.domain;

/**
 * 조치 상태 — 올리기로 한 일이 어디까지 왔는가.
 *
 * <p>{@link #ACCEPTED} 는 "이 조치는 결국 하지 않고 닫는다" 는 뜻이다.
 *
 * <p><b>화면 이름이 {@code 예외 승인} 이었다. 고쳤다.</b> 이 도구에 승인
 * 절차는 없다 — 아무나 눌러 닫을 수 있는 상태에 '승인' 이라는 이름을 붙이면
 * 통제가 있는 것처럼 보이는데 실제로는 없다. 점검에서 없느니만 못하다.
 *
 * <p><b>겹치는 자리가 남아 있다.</b> "안 고치기로 했다" 는 판단은 이제
 * {@link AnalysisResponse#WILL_NOT_FIX}(검토 결과의 대응)가 담는다. 여기
 * {@code ACCEPTED} 는 <b>그 판단이 아니라 조치 하나가 닫힌 상태</b>이고,
 * 둘이 같은 말로 읽히면 어느 쪽을 봐야 할지 모르게 된다. 이 상태를 아예
 * 없애고 검토 결과 쪽으로 모을지는 값이 DB 에 글자로 들어 있어 마이그레이션이
 * 필요하다 — 화면을 합치는 이 단계에서 함께 하지 않는다.
 */
public enum RemediationStatus {
    OPEN("대기"),
    IN_PROGRESS("진행"),
    DONE("완료"),
    ACCEPTED("하지 않고 닫음");

    private final String label;

    RemediationStatus(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }

    public boolean isClosed() {
        return this == DONE || this == ACCEPTED;
    }
}
