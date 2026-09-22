package kr.sbomsight.domain;

/**
 * 감사 로그에 남기는 일.
 *
 * <p>이름을 그대로 DB 에 넣는다. 숫자 코드를 쓰면 로그를 눈으로 볼 수 없고,
 * 순서를 바꾸는 순간 옛 기록의 뜻이 달라진다. <b>이름은 바꾸지 않는다</b> —
 * 바꾸면 이미 쌓인 기록이 무엇이었는지 알 수 없다.
 */
public enum AuditEvent {

    // --- 로그인 ---
    LOGIN_SUCCESS("로그인"),
    LOGIN_FAILURE("로그인 실패"),
    LOGIN_BLOCKED("로그인 차단"),
    LOGOUT("로그아웃"),

    // --- 계정 ---
    PASSWORD_CHANGED("비밀번호 변경"),
    USER_CREATED("계정 생성"),
    USER_DELETED("계정 삭제"),
    USER_UPDATED("계정 수정"),
    /**
     * 옛 이름. <b>지우지 않는다.</b>
     *
     * <p>권한을 드롭다운으로 즉시 저장하던 시절에 이 이름으로 남겼다. 지금은
     * `수정` 팝업이 한 번에 저장하고 {@code USER_UPDATED} 로 남지만, 이미
     * 쌓인 감사 로그에는 이 이름이 들어 있다 — 지우면 그 행을 읽다 터진다
     * ({@code @Enumerated(STRING)}).
     */
    USER_ROLE_CHANGED("권한 변경"),
    USER_PASSWORD_RESET("비밀번호 초기화"),
    USER_UNLOCKED("계정 잠금 해제"),

    // --- 구역 ---
    ZONE_CREATED("구역 생성"),
    ZONE_RENAMED("구역 이름 변경"),
    ZONE_RECOLORED("구역 색 변경"),
    ZONE_DELETED("구역 삭제"),

    // --- 자산 · 스캔 ---
    ASSET_CREATED("자산 등록"),
    ASSET_DELETED("자산 삭제"),
    ASSET_ZONE_CHANGED("자산 구역 변경"),
    // 저장값(이름)은 그대로 두고 화면 말만 바꿨다 — 이미 쌓인 감사 기록이
    // 있고, 그 기록의 뜻은 달라지지 않았다.
    ASSET_ARCHIVED("자산 운영 종료"),
    ASSET_UNARCHIVED("자산 운영 재개"),
    SBOM_UPLOADED("SBOM 업로드"),
    SCAN_DELETED("검사 삭제"),
    SCAN_RESCANNED("다시 검사"),

    // --- 조치 · 검토 결과 ---
    /**
     * 지운 조치는 <b>이력까지 함께</b> 사라진다({@code cascade = ALL}).
     * 그래서 지운 뒤에 남는 자취는 이 줄 하나뿐이다 — 반드시 남긴다.
     */
    REMEDIATION_DELETED("조치 삭제"),
    ANALYSIS_RECORDED("검토 결과 기록"),

    /**
     * 옛 이름 둘. <b>지우지 않는다.</b>
     *
     * <p>위험 수용은 검토 결과({@code 해당됨 · 조치 안 함})로 합쳐졌고 표도
     * 옮겼지만, 이미 쌓인 감사 로그에는 이 이름이 그대로 들어 있다. 여기서
     * 지우면 그 행을 읽을 때 무슨 일이었는지 알 수 없게 된다. 새로 쌓이지는
     * 않는다.
     */
    RISK_ACCEPTED("위험 수용"),
    RISK_ACCEPTANCE_REVOKED("위험 수용 철회"),

    // --- 설정 ---
    // `SETTING_CHANGED` 를 뺐다. 선언만 있고 어디서도 기록하지 않았는데
    // 화면의 `행위` 고르개는 `values()` 로 만들어진다 — 고르면 언제나 0건인
    // 선택지였다. 실제로 남는 설정 변경은 접근 IP 하나뿐이고 그것은 제
    // 이름이 있다.
    IP_ALLOWLIST_CHANGED("접근 IP 변경");

    private final String label;

    AuditEvent(String label) {
        this.label = label;
    }

    /** 화면에 찍는 한글 이름. */
    public String label() {
        return label;
    }
}
