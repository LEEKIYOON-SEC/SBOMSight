package kr.sbomsight.domain;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.TreeSet;
import java.util.stream.Collectors;

/**
 * 수정 버전 — <b>하나로 고르지 않는다.</b>
 *
 * <p>패키지 하나에 걸린 탐지는 저마다 수정 버전을 가진다. web-01 의 curl
 * 한 벌에 deb10u2 부터 deb10u9 까지 여덟 가지였다. 앞서 화면마다 그중
 * 하나를 제각각 골랐다 — 조치는 CVSS 가 가장 높은 건의 것(deb10u4; 그리로
 * 올려도 10건이 남는다), 보고서는 글자로 가장 큰 것(`9.0.90` 을 `9.0.107`
 * 보다 크다고 본다). 같은 조치의 목표가 조치 화면과 보고서에서 달랐다.
 *
 * <p>버전끼리 견주려면 배포판·언어마다 다른 규칙을 짜 넣어야 하고, 그것은
 * 검사 결과가 준 것을 다시 판정하는 일이다(CLAUDE.md 11). <b>여럿이면 여럿을
 * 적는다</b> — `수정 버전 N가지` 와 그 목록(사용자 결정). 조치 화면 · 보고서 ·
 * CSV 가 이 한 곳의 규칙을 쓴다. 화면은 {@code fragments/ui :: fixversions}
 * 가 같은 규칙으로 그린다.
 *
 * <p><b>목록은 글자 순이다 — 버전 순이 아니다.</b> 마지막 것이 가장 높은
 * 버전이라는 뜻이 아니다.
 */
public final class FixVersions {

    /** 조치에 저장하는 꼴의 구분자. 버전 문자열에는 빈칸이 없다. */
    private static final String STORED = " ";

    private FixVersions() {
    }

    /** 모은다 — 빈 것을 빼고, 겹친 것을 하나로, 글자 순으로. 버전끼리 견주지 않는다. */
    public static List<String> collect(Collection<String> raw) {
        return raw.stream()
                  .filter(Objects::nonNull)
                  .map(String::trim)
                  .filter(v -> !v.isEmpty())
                  .collect(Collectors.toCollection(TreeSet::new))
                  .stream().toList();
    }

    /** 조치의 {@code to_version} 에 저장하는 꼴. */
    public static String join(List<String> versions) {
        return String.join(STORED, versions);
    }

    /** 저장된 꼴을 목록으로. 버전 하나만 적혀 있던 옛 행도 그대로 읽힌다. */
    public static List<String> split(String stored) {
        if (stored == null || stored.isBlank()) {
            return List.of();
        }
        return collect(List.of(stored.trim().split("\\s+")));
    }

    /**
     * 글로 적는 꼴 — CSV · 감사 로그.
     *
     * @return 없으면 빈 문자열, 하나면 그 버전, 여럿이면 `수정 버전 3가지: a · b · c`
     */
    public static String describe(List<String> versions) {
        return switch (versions.size()) {
            case 0 -> "";
            case 1 -> versions.get(0);
            default -> "수정 버전 " + versions.size() + "가지: " + String.join(" · ", versions);
        };
    }
}
