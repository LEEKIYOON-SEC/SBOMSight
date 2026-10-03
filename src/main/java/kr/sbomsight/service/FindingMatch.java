package kr.sbomsight.service;

import kr.sbomsight.repo.FindingRepository;

import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 두 검사의 탐지를 맞댄다 — 신규 · 해소 · 유지(보고서 6장 · 구역 보고서 7장).
 *
 * <p><b>같은 취약점인가는 검토 결과를 맞추는 규칙과 같다</b>(R6 —
 * {@link FindingAnalysisService#analysisOf}): 같은 자산 · 같은 패키지에서 번호(주
 * 식별자 · 함께 온 CVE)가 하나라도 같으면 같은 것이다. 앞서는 주 식별자 하나로 맞대어,
 * grype 의 DB 가 바뀌어 같은 취약점의 주 식별자가 CVE 에서 GHSA 로 옮겨 가면
 * "해소 1 + 신규 1" 로 갈렸다 — 아무것도 고치지 않았는데 보고서가 고친 것처럼 말했다.
 *
 * <p>버전은 보지 않는다. 버전을 넣으면 패치했을 때 키가 바뀌어 같은 것이 해소 ·
 * 신규로 갈린다. 한 검사 안에서 같은 (자산, 패키지, 주 식별자)는 한 건으로 센다 —
 * 앞서 (CVE, 패키지명) 짝의 집합으로 세던 것과 같다.
 */
public final class FindingMatch {

    private FindingMatch() {
    }

    /**
     * 탐지 한 줄의 대조 축.
     *
     * @param assetId 자산 — 한 자산만 맞대면 {@code null} 이어도 된다
     */
    public record Key(Long assetId, String cve, String relatedCve, String packageName) {
    }

    /** 맞댄 결과. */
    public record Counts(long added, long resolved, long kept) {
    }

    public static Counts compare(Collection<Key> now, Collection<Key> before) {
        Map<String, Set<String>> nowEntries = entries(now);
        Map<String, Set<String>> beforeEntries = entries(before);
        Set<String> nowIds = ids(nowEntries);
        Set<String> beforeIds = ids(beforeEntries);

        long kept = nowEntries.entrySet().stream()
                .filter(e -> e.getValue().stream().anyMatch(beforeIds::contains)).count();
        long resolved = beforeEntries.entrySet().stream()
                .filter(e -> e.getValue().stream().noneMatch(nowIds::contains)).count();
        return new Counts(nowEntries.size() - kept, resolved, kept);
    }

    /**
     * (자산, 패키지, 주 식별자) 한 건 → 그 건의 대조 번호들({@code 자산|패키지|번호}).
     * 같은 건이 버전 · 경로마다 여러 줄이면 함께 온 CVE 를 모은다.
     */
    private static Map<String, Set<String>> entries(Collection<Key> keys) {
        Map<String, Set<String>> out = new LinkedHashMap<>();
        for (Key k : keys) {
            String scope = k.assetId() + "|" + k.packageName() + "|";
            Set<String> ids = out.computeIfAbsent(scope + k.cve(), x -> new HashSet<>());
            ids.add(scope + k.cve());
            if (k.relatedCve() != null && !k.relatedCve().isBlank()) {
                ids.add(scope + k.relatedCve());
            }
        }
        return out;
    }

    private static Set<String> ids(Map<String, Set<String>> entries) {
        Set<String> out = new HashSet<>();
        entries.values().forEach(out::addAll);
        return out;
    }

    /** 자산 하나짜리 키 목록으로 — 보고서 6장. */
    static List<Key> of(Collection<FindingRepository.FindingKey> rows) {
        return rows.stream()
                   .map(r -> new Key(null, r.getCve(), r.getRelatedCve(), r.getPackageName()))
                   .toList();
    }
}
