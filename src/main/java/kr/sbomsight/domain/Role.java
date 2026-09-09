package kr.sbomsight.domain;

/** 권한은 둘뿐이다. 관리자는 전부, 조회는 읽기만. */
public enum Role {
    ADMIN("관리자"),
    VIEWER("조회");

    private final String label;

    Role(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }

    /** 스프링 시큐리티는 {@code ROLE_} 접두어를 기대한다. */
    public String authority() {
        return "ROLE_" + name();
    }
}
