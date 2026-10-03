package kr.sbomsight.service;

/**
 * <b>완료 뒤</b> — 완료한 조치의 패키지에 해소 건수가 남았을 때, 그것이 무엇인가(R10 · D11).
 *
 * <p>앞서는 셋을 가르지 못해 모두 `완료 · 탐지 남음` 이었다. 조치는 했는데 SBOM 을 아직
 * 못 뜬 자산이 "조치가 안 됐다" 로 읽혔고(재현 시험 P10), 조치는 됐는데 같은 패키지에 새
 * 취약점이 나온 것도 같은 말이었다. 조치 화면 · 취약점 표 · 보고서 · CSV 가 이 하나로
 * 가른다({@link RemediationService#afterDone}).
 *
 * <p>둘 이상에 해당하면 <b>앞의 것</b>이다 — 검증 대기 › 탐지 남음 › 신규 탐지. SBOM 이
 * 완료보다 앞이면 남은 것이 대상인지 아닌지를 따질 근거가 아직 없다. 대상이 남았으면
 * 새 탐지가 함께 있어도 조치가 덜 된 것이 먼저다.
 *
 * @param kind    어느 갈래인가
 * @param fixable 남은 해소 건수 — 수정 버전이 있는 탐지, 해당 없음 · 오탐 제외
 *                (보고서 3 · 5장과 같은 축)
 */
public record AfterDone(Kind kind, long fixable) {

    public enum Kind {
        /** 지금 SBOM 이 조치 완료보다 앞이다 — 고치기 전의 서버를 보고 있다. 새 SBOM 을 올리면 풀린다. */
        PENDING("완료 · 검증 대기"),
        /** 고친 뒤의 SBOM 에 조치 대상이 남았다 — 조치가 덜 됐다. 대상을 모르는 옛 조치도 여기. */
        REMAINING("완료 · 탐지 남음"),
        /**
         * 고친 뒤의 SBOM 에 남은 것이 조치 대상이 아니다 — 조치는 됐고 새 조치(다음 회차)가
         * 필요하다. 등록할 때 탐지가 없던 조치(대상이 없다고 알려짐)도 여기.
         */
        NEW_FINDINGS("완료 · 신규 탐지");

        private final String label;

        Kind(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }

    public String label() {
        return kind.label();
    }

    public boolean isPending() {
        return kind == Kind.PENDING;
    }

    public boolean isRemaining() {
        return kind == Kind.REMAINING;
    }

    /** 새 조치(다음 회차)를 열 자리 — 그 옆에 `조치 등록` 을 둔다(D11). */
    public boolean isNew() {
        return kind == Kind.NEW_FINDINGS;
    }
}
