package kr.sbomsight.domain;

/**
 * 검사의 <b>SBOM 생성 시각</b>을 어디서 가져왔는가.
 *
 * <p>앞서 화면과 보고서의 시각은 전부 검사가 돈 시각이었다. 40일 전에 뜬 SBOM 을
 * 오늘 다시 검사하면 그 자산을 오늘 점검한 것처럼 읽혔다. SBOM 은 그 자체로 생성
 * 시각을 적어 온다(CycloneDX {@code metadata.timestamp} · SPDX
 * {@code creationInfo.created}). 그것을 쓰되, 한 칸에 성격이 다른 시각이 섞이므로
 * <b>대신 넣은 것이면 그렇다고 밝힌다</b> — 밝히지 않으면 업로드 시각을 SBOM 의
 * 시각으로 읽게 된다.
 *
 * <p>화면 말은 D11 에서 정했다. SBOM 에 적힌 시각을 쓴 보통의 경우에는 열 이름이
 * 이미 말하므로 아무것도 붙이지 않는다.
 */
public enum SbomTime {

    /**
     * 아직 SBOM 을 읽지 않았다 — 업로드 직후 · 검사 전에 실패. 그 자리에는 업로드
     * 시각이 들어 있고, 검사가 SBOM 을 읽으면 아래 셋 중 하나로 바뀐다. 화면은
     * 값을 적지 않는다({@code —}).
     */
    PENDING(""),

    /** SBOM 에 적힌 시각. */
    SBOM(""),

    /** SBOM 에 생성 시각이 없다 — syft JSON 이 그렇다. 업로드 시각을 쓴다. */
    NO_TIMESTAMP("업로드 시각으로 대체 (SBOM에 생성 시각 없음)"),

    /** SBOM 의 시각이 업로드보다 늦다 — 대상 서버의 시계가 틀렸다. 업로드 시각을 쓴다. */
    CLOCK_AHEAD("업로드 시각으로 대체 (SBOM 생성 시각이 업로드보다 늦음)"),

    /**
     * V17 이전에 올린 검사 — 그때는 SBOM 의 시각을 읽지 않았다. 업로드 시각을
     * 쓴다(다시 검사는 원본의 업로드 시각). 이관이 SBOM 을 다시 읽어 채우지
     * 않는다 — 없는 기록을 지어내 채우면 어디까지가 기록이고 어디부터가 추정인지
     * 가를 수 없다(V10 · V13 과 같은 까닭).
     */
    UNCONFIRMED("업로드 시각으로 대체 (SBOM 생성 시각 확인되지 않음)");

    private final String label;

    SbomTime(String label) {
        this.label = label;
    }

    /** 시각 옆에 붙이는 말. 붙일 것이 없으면 빈 글자. */
    public String label() {
        return label;
    }

    /** 화면이 시각을 적을 수 있는가 — 아직 읽지 않았으면 적지 않는다. */
    public boolean known() {
        return this != PENDING;
    }
}
