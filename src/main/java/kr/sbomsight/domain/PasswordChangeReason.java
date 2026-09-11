package kr.sbomsight.domain;

/**
 * 비밀번호 변경 화면에 온 이유.
 *
 * <p>경우마다 할 말이 다르고, 첫 칸에 넣어야 할 것도 다르다. 하나의 문구로
 * 뭉쳐 두면 임시 비밀번호를 받아 온 사람에게 "현재 비밀번호" 를 물어
 * 무엇을 넣으라는 건지 한 번 더 생각하게 만든다.
 */
public enum PasswordChangeReason {

    /** 처음 로그인했다. 아직 한 번도 로그인한 적이 없는 계정. */
    FIRST_LOGIN("비밀번호 설정",
                "최초 로그인입니다. 사용하실 비밀번호를 설정해 주세요.",
                "임시 비밀번호"),

    /** 관리자가 초기화했다. 지금 비밀번호는 임시값이다. */
    TEMPORARY("비밀번호 변경",
              "임시 비밀번호로 로그인하셨습니다. 새 비밀번호로 변경해 주세요.",
              "임시 비밀번호"),

    /** 변경 주기가 지났다. */
    EXPIRED("비밀번호 변경",
            "비밀번호를 변경하신 지 오래되었습니다. 새 비밀번호로 변경해 주세요.",
            "현재 비밀번호"),

    /** 본인이 스스로 바꾸러 왔다. 강제가 아니다. */
    VOLUNTARY("비밀번호 변경",
              "",
              "현재 비밀번호");

    private final String title;
    private final String lede;
    private final String currentLabel;

    PasswordChangeReason(String title, String lede, String currentLabel) {
        this.title = title;
        this.lede = lede;
        this.currentLabel = currentLabel;
    }

    public String title() {
        return title;
    }

    public String lede() {
        return lede;
    }

    /** 첫 칸의 이름. 임시 비밀번호를 받아 온 사람에게는 그렇게 묻는다. */
    public String currentLabel() {
        return currentLabel;
    }

    /** 바꾸지 않으면 다른 화면이 열리지 않는가. */
    public boolean isForced() {
        return this != VOLUNTARY;
    }
}
