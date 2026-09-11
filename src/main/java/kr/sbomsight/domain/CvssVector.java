package kr.sbomsight.domain;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * CVSS 벡터를 그 구성 요소로 풀어 읽는다.
 *
 * <p><b>이것은 grype 의 판정을 다시 계산하는 것이 아니다.</b> 점수도 심각도도
 * 여기서 산출하지 않는다. grype 이 함께 준 문자열
 *
 * <pre>
 *   CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
 * </pre>
 *
 * 안에 이미 적혀 있는 항목을 꺼내 읽을 뿐이다. 같은 응답 안의 값을 옮기는
 * 것이므로 CVE 번호를 앞으로 꺼내는 것과 같은 성격이다.
 *
 * <p><b>왜 필요한가.</b> "심각 21건"은 어디부터 손대야 하는지 말해 주지 않는다.
 * 같은 심각도라도 <i>밖에서 인증 없이 바로 닿는 것</i>과 <i>서버에 이미
 * 들어와야 쓸 수 있는 것</i>은 대응 순서가 다르다. 그 구분이 벡터에 이미
 * 들어 있는데 지금까지 저장만 하고 쓰지 않았다.
 *
 * <p><b>3.x 만 읽는다.</b> CVSS 2.0 은 {@code Au}(인증)를 쓰고 {@code UI}·{@code S}
 * 가 아예 없다. 2.0 을 3.x 인 척 읽으면 없는 항목을 "해당 없음"으로 채우게
 * 되는데, 그것은 확인하지 않은 판정을 만드는 일이다. 읽을 수 없으면
 * {@link Optional#empty()} 를 돌려주고 호출부가 <b>판단 불가</b>로 센다.
 */
public record CvssVector(String attackVector,
                         String attackComplexity,
                         String privilegesRequired,
                         String userInteraction,
                         String scope) {

    /**
     * 읽을 수 있으면 풀어서, 아니면 비어서 돌아온다.
     *
     * <p>3.x 벡터이면서 우리가 보는 다섯 항목이 모두 있을 때만 성공으로 본다.
     * 일부만 있는 벡터를 반쯤 읽어 두면 그 빈칸이 나중에 조용히 false 로
     * 굳는다.
     */
    public static Optional<CvssVector> parse(String raw) {
        if (raw == null || raw.isBlank()) {
            return Optional.empty();
        }
        String text = raw.trim();
        if (!text.startsWith("CVSS:3")) {
            return Optional.empty();
        }

        Map<String, String> parts = new HashMap<>();
        for (String segment : text.split("/")) {
            int colon = segment.indexOf(':');
            if (colon > 0) {
                parts.put(segment.substring(0, colon), segment.substring(colon + 1));
            }
        }

        String av = parts.get("AV");
        String ac = parts.get("AC");
        String pr = parts.get("PR");
        String ui = parts.get("UI");
        String s  = parts.get("S");
        if (av == null || ac == null || pr == null || ui == null || s == null) {
            return Optional.empty();
        }
        return Optional.of(new CvssVector(av, ac, pr, ui, s));
    }

    /** AV:N — 네트워크에서 닿는다. */
    public boolean networkAttackable() {
        return "N".equals(attackVector);
    }

    /** PR:N — 아무 권한 없이 쓸 수 있다. */
    public boolean noPrivileges() {
        return "N".equals(privilegesRequired);
    }

    /** UI:N — 누가 링크를 누르거나 파일을 열어 줄 필요가 없다. */
    public boolean noUserInteraction() {
        return "N".equals(userInteraction);
    }

    /** S:C — 취약한 구성 요소 너머로 영향이 번진다(컨테이너·샌드박스 경계 등). */
    public boolean scopeChanged() {
        return "C".equals(scope);
    }

    /**
     * 셋이 동시에 성립하는 것 — <b>밖에서, 인증 없이, 아무 도움 없이.</b>
     *
     * <p>서버 취약점 대응에서 먼저 손대야 하는 것이 이것이다. 사용자 개입이
     * 필요한 건(UI:R)은 사람이 쓰는 PC 에서는 현실적인 경로지만 서버에서는
     * 그렇지 않다.
     */
    public boolean directlyReachable() {
        return networkAttackable() && noPrivileges() && noUserInteraction();
    }
}
