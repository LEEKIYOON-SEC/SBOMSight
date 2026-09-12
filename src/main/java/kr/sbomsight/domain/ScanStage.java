package kr.sbomsight.domain;

/**
 * 검사가 지금 어디까지 왔는가.
 *
 * <p><b>왜 상태만으로는 부족한가.</b> {@link ScanStatus} 는 대기·검사 중·
 * 완료·실패 넷뿐이다. 서버 한 대짜리 SBOM 에 grype 이 몇 분씩 걸리는데 그
 * 동안 화면에는 "검사 중" 한 마디만 떠 있으면, 돌고 있는 것인지 멈춘 것인지
 * 알 수 없어 사람이 새로고침만 반복하게 된다.
 *
 * <p>단계는 <b>실제로 하는 일</b>과 하나씩 맞물린다. 보여 주기 위해 지어낸
 * 눈금이 아니라 {@code ScanService.run()} 이 실제로 지나가는 자리다.
 */
public enum ScanStage {

    /** 파일을 받아 보관했다. grype 을 부르기 전. */
    UPLOADED("올리기", "SBOM 을 받았습니다"),

    /** 압축을 풀고 형식과 컴포넌트 수를 센다. */
    READING("SBOM 읽기", "형식과 컴포넌트를 셉니다"),

    /** grype 이 도는 중. 대개 여기가 가장 길다. */
    SCANNING("grype 검사", "취약점을 맞춰 봅니다"),

    /** grype 출력을 읽어 저장한다. */
    SAVING("결과 정리", "탐지를 저장합니다"),

    /** 끝. */
    DONE("완료", "");

    private final String label;
    private final String detail;

    ScanStage(String label, String detail) {
        this.label = label;
        this.detail = detail;
    }

    public String label() {
        return label;
    }

    public String detail() {
        return detail;
    }

    /** 화면의 눈금. {@link #DONE} 은 눈금이 아니라 끝난 상태라 빠진다. */
    public static ScanStage[] steps() {
        return new ScanStage[] { UPLOADED, READING, SCANNING, SAVING };
    }

    /** 이 단계가 {@code other} 보다 뒤인가. 눈금을 채울 때 쓴다. */
    public boolean isAfter(ScanStage other) {
        return ordinal() > other.ordinal();
    }
}
