package kr.sbomsight.service;

import kr.sbomsight.domain.Finding;

import java.math.BigDecimal;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 보고서 부록 — <b>실제 악용 · 심각 취약점과 그 설명의 첫 문장.</b>
 *
 * <p>앞서 보고서 어디에도 "무엇이 위험한가" 가 없었다 — 번호와 건수뿐이라,
 * 받는 사람이 번호를 하나씩 찾아봐야 했다. 설명은 검사 결과에 이미 있다
 * (grype 이 준 원문, 대개 영문). <b>옮기거나 요약하지 않고 첫 문장만</b>
 * 싣는다 — 우리가 다시 쓰면 아무도 확인하지 않은 설명이 된다. 전문은 화면의
 * CVE 상세에 있다.
 *
 * <p>한 줄은 <b>취약점 하나</b>다. 여러 패키지 · 자산에 걸린 것을 한 줄로
 * 모은다. 번호는 화면에 찍는 번호(Finding.displayId)로 묶는다 — 목록과 같다.
 */
public final class Appendix {

    /** 첫 문장이 이보다 길면 자르고 {@code …} 로 끝낸다 — 한 줄이 한 쪽을 차지하지 않게. */
    static final int MAX_SUMMARY = 240;

    private Appendix() {
    }

    /**
     * 부록 한 줄.
     *
     * @param kev        한 건이라도 실제 악용 확인(KEV)
     * @param critical   한 건이라도 심각
     * @param packages   걸린 패키지 이름 — 글자 순, 겹침 없이
     * @param assetCount 걸린 자산 수 — 구역 보고서가 찍는다
     * @param maxCvss    가장 높은 CVSS. 없으면 {@code null}
     * @param summary    설명의 첫 문장. 설명이 없으면 빈 글자(표는 {@code —})
     */
    public record Row(String cve, boolean kev, boolean critical, List<String> packages,
                      long assetCount, BigDecimal maxCvss, String summary) {
    }

    /** 실제 악용 먼저(확인된 사실) → 최고 CVSS → 번호. */
    private static final Comparator<Row> ORDER =
            Comparator.comparing(Row::kev).reversed()
                      .thenComparing(Row::maxCvss, Comparator.nullsLast(Comparator.reverseOrder()))
                      .thenComparing(Row::cve);

    /** @param urgent 실제 악용이거나 심각인 탐지(FindingRepository.findUrgentIn) */
    static List<Row> of(List<Finding> urgent) {
        Map<String, List<Finding>> byCve = urgent.stream()
                .collect(Collectors.groupingBy(Finding::getDisplayId, LinkedHashMap::new,
                                               Collectors.toList()));
        return byCve.entrySet().stream()
                .map(e -> row(e.getKey(), e.getValue()))
                .sorted(ORDER)
                .toList();
    }

    private static Row row(String cve, List<Finding> rows) {
        return new Row(cve,
                rows.stream().anyMatch(f -> Boolean.TRUE.equals(f.getKev())),
                rows.stream().anyMatch(f -> "critical".equalsIgnoreCase(f.getSeverity())),
                rows.stream().map(Finding::getPackageName).distinct().sorted().toList(),
                rows.stream().map(f -> f.getScan().getAsset().getId()).distinct().count(),
                rows.stream().map(Finding::getCvssScore).filter(Objects::nonNull)
                    .max(Comparator.naturalOrder()).orElse(null),
                rows.stream().map(Finding::getDescription)
                    .filter(d -> d != null && !d.isBlank())
                    .findFirst().map(Appendix::firstSentence).orElse(""));
    }

    /** 문장 끝으로 보지 않는 줄임말 — 마침표 앞 낱말(소문자). */
    private static final Set<String> ABBREVIATIONS = Set.of(
            "e.g", "i.e", "etc", "vs", "cf", "al", "approx", "inc", "ltd", "co", "corp",
            "no", "mr", "ms", "dr", "jr", "sr", "st", "fig", "ver", "v");

    /**
     * 설명의 첫 문장. 줄바꿈 · 겹친 빈칸을 하나로 편다.
     *
     * <p>문장 끝은 {@code .} {@code ?} {@code !} 뒤에 빈칸이 오는 자리다.
     * {@code e.g.} 같은 줄임말과 이니셜({@code J. Smith})에서는 끊지 않는다.
     * 버전 번호({@code 1.2.3})는 마침표 뒤에 빈칸이 없어 걸리지 않는다. 너무
     * 길면 자르고 {@code …} 로 끝낸다(서로게이트 쌍을 가르지 않는다).
     */
    static String firstSentence(String text) {
        if (text == null) {
            return "";
        }
        String flat = text.replaceAll("\\s+", " ").trim();
        String sentence = flat;
        for (int i = 0; i < flat.length() - 1; i++) {
            char c = flat.charAt(i);
            if ((c == '.' || c == '?' || c == '!') && flat.charAt(i + 1) == ' '
                    && !(c == '.' && abbreviation(flat, i))) {
                sentence = flat.substring(0, i + 1);
                break;
            }
        }
        if (sentence.length() > MAX_SUMMARY) {
            int cut = MAX_SUMMARY - 1;
            if (Character.isHighSurrogate(sentence.charAt(cut - 1))) {
                cut--;
            }
            sentence = sentence.substring(0, cut).stripTrailing() + "…";
        }
        return sentence;
    }

    /** 마침표 앞 낱말이 줄임말이거나 영문 한 글자(이니셜)인가. 숫자 하나(`version 2.`)는 문장 끝이다. */
    private static boolean abbreviation(String text, int dot) {
        int start = dot;
        while (start > 0 && text.charAt(start - 1) != ' ') {
            start--;
        }
        String word = text.substring(start, dot).toLowerCase(Locale.ROOT)
                          .replaceAll("^[(\\[\"']+", "");
        return (word.length() == 1 && Character.isLetter(word.charAt(0)))
                || ABBREVIATIONS.contains(word);
    }
}
