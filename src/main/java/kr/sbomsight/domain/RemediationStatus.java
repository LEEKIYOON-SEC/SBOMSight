package kr.sbomsight.domain;

/**
 * 조치 상태.
 *
 * <p>{@link #ACCEPTED} 는 "고치지 않기로 하고 그 사실을 남긴다"는 뜻이다.
 * 수정본이 없는 취약점은 지우거나 무시하는 대신 여기로 옮겨 둔다 — 조용히
 * 사라지면 다음 사람이 같은 판단을 처음부터 다시 해야 한다.
 */
public enum RemediationStatus {
    OPEN("대기"),
    IN_PROGRESS("진행"),
    DONE("완료"),
    ACCEPTED("예외 승인");

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
