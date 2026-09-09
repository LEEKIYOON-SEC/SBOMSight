package kr.sbomsight.domain;

/** 스캔 진행 상태. 실패도 남긴다 — 실패한 스캔이 사라지면 "안 돌았다"와 구분이 안 된다. */
public enum ScanStatus {
    QUEUED("대기"),
    RUNNING("검사 중"),
    DONE("완료"),
    FAILED("실패");

    private final String label;

    ScanStatus(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }
}
