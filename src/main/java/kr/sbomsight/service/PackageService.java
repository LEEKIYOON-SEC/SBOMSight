package kr.sbomsight.service;

import kr.sbomsight.domain.Component;
import kr.sbomsight.domain.PackageKey;
import kr.sbomsight.domain.Severity;
import kr.sbomsight.repo.ComponentRepository;
import kr.sbomsight.repo.FindingRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 무엇이 어디에 몇 버전으로 깔려 있나 — <b>취약점이 붙기 전에도.</b>
 *
 * <p>취약점 화면은 grype 이 매치를 낸 것만 보여 준다. 그래서 {@code log4j} 가
 * 어디 깔려 있는지는 CVE 가 터진 다음에야, 그것도 매치가 난 자산에서만 알 수
 * 있었다. SBOM 에는 처음부터 전부 들어 있었다.
 *
 * <p><b>이 화면의 가장 중요한 신호는 일부 자산만 업그레이드한 패키지다.</b>
 * 같은 패키지에 걸린 것이 있는 버전과 없는 버전이 함께 깔려 있으면 "이미 올린
 * 자산이 있는데 안 올린 자산이 남았다" 는 뜻이다.
 *
 * <p>심각도는 grype 이 낸 것을 그대로 옮긴다. 버전마다 <b>어느 등급이 가장
 * 높은가</b>만 골라 표시에 쓴다 — 다시 매기지 않는다.
 */
@Service
public class PackageService {

    private final ComponentRepository components;
    private final FindingRepository findings;
    private final VulnQuery vulns;

    public PackageService(ComponentRepository components, FindingRepository findings,
                          VulnQuery vulns) {
        this.components = components;
        this.findings = findings;
        this.vulns = vulns;
    }

    /**
     * 화면의 표 한 쪽.
     *
     * <p><b>거른 뒤에 자른다.</b> 앞서는 앞 200개를 자른 뒤에 거르개를
     * 걸었다. 그래서 `취약점 있는 것만` 은 3,908개 이름 중 <b>앞 200개
     * 안에서만</b> 찾았고, 201번째 이후에 있는 취약한 패키지는 화면에도
     * 수에도 나오지 않았다. 잘렸다는 각주가 있었지만, 각주는 "거르개가
     * 전부를 보지 못한다" 는 말까지 하지는 않는다.
     *
     * <p>버전 분포({@link #assemble})는 <b>이 쪽에 실리는 이름만</b> 물어
     * 본다. 전부 물으면 자산 백 대의 인벤토리에서 수백만 행이 된다.
     *
     * <p><b>한 줄은 패키지 식별자다</b>(PackageKey · V24) — 탐지 · 검토 결과 · 조치와 같은 키.
     * 앞서 이름으로만 묶어 npm 과 pypi 의 같은 이름이, 그다음 (이름, 유형)으로 묶어 groupId 만
     * 다른 Maven 의 같은 artifactId 가 한 줄에 섞였다.
     */
    @Transactional(readOnly = true)
    public Listing list(Long zoneId, String type, String q, boolean vulnerableOnly,
                        boolean mixedOnly, int page, Integer size) {
        String kind = blankToNull(type);
        String term = blankToNull(q);
        List<ComponentRepository.PackageRow> grouped =
                components.groupByPackage(zoneId, kind, term);

        if (vulnerableOnly || mixedOnly) {
            Set<String> keep = rowsMatching(zoneId, kind, term, vulnerableOnly, mixedOnly);
            grouped = grouped.stream().filter(r -> keep.contains(r.getPackageKey())).toList();
        }

        Page<ComponentRepository.PackageRow> slice = Paging.slice(grouped, page, size);
        List<PackageRow> rows = slice.getContent().isEmpty()
                ? List.of()
                : assemble(slice.getContent(), zoneId);

        return new Listing(new PageImpl<>(rows, slice.getPageable(), slice.getTotalElements()),
                           components.types());
    }

    /**
     * 거르개 둘에 걸리는 <b>줄(패키지 식별자) 전부.</b>
     *
     * <p>`취약점 있는 것만` 과 `일부 자산만 업그레이드` 는 패키지 단위
     * 성질이라 버전 분포를 다 세어 봐야 판단이 선다. 자르기 전에 세야
     * 하므로 전부를 훑는다 — 행 수는 {@code (식별자, 버전)} 만큼이라
     * 인벤토리 전체보다 작고, 내보내기가 이미 같은 질의를 쓰고 있다.
     */
    private Set<String> rowsMatching(Long zoneId, String type, String q,
                                     boolean vulnerableOnly, boolean mixedOnly) {
        List<ComponentRepository.VersionRow> spread = components.versionSpreadAll(zoneId, type, q);
        Severities severities = severities(null, zoneId, spread);
        // 줄 → [걸린 버전이 있다, 안 걸린 버전이 있다]
        Map<String, boolean[]> flags = new LinkedHashMap<>();
        for (ComponentRepository.VersionRow version : spread) {
            boolean[] seen = flags.computeIfAbsent(version.getPackageKey(), k -> new boolean[2]);
            long total = severities.of(version).values().stream().mapToLong(Long::longValue).sum();
            seen[total > 0 ? 0 : 1] = true;
        }
        Set<String> keep = new LinkedHashSet<>();
        flags.forEach((key, seen) -> {
            if (vulnerableOnly && !seen[0]) {
                return;
            }
            if (mixedOnly && !(seen[0] && seen[1])) {
                return;
            }
            keep.add(key);
        });
        return keep;
    }

    /**
     * 펼쳤을 때 — 이 패키지가 어느 자산에 어느 버전으로 깔려 있나.
     *
     * <p>{@code open} 이 식별자({@code pkg:…})면 그 패키지 하나. 아니면 식별자가 붙기 전의
     * 주소다 — 그 이름(과 {@code type} 이 있으면 그 유형)의 줄 전부. 적어 둔 주소가 죽지 않게.
     */
    @Transactional(readOnly = true)
    public List<Component> assetsOf(String open, String type, Long zoneId) {
        return isKey(open) ? components.findByPackageKey(open, zoneId)
                           : components.findByNameAndType(open, type, zoneId);
    }

    /** 펼친 줄을 가리키는 값이 식별자인가 — 아니면 이름(식별자가 붙기 전의 주소)이다. */
    public static boolean isKey(String open) {
        return open != null && open.startsWith("pkg:");
    }

    /**
     * CSV 내보내기 — <b>거른 것 전부.</b>
     *
     * <p>한 줄이 {@code (패키지, 유형, 버전)} 하나다. 화면의 버전 조각 하나가 한
     * 줄이 된다 — 버전 분포를 한 칸에 몰아 넣으면 엑셀에서 쓸 수 없다.
     *
     * <p><b>보고 있던 쪽이 아니라 거른 것 전부다.</b> 화면에 한 쪽만
     * 보이는데 파일도 그 쪽뿐이면 그 파일로 대조를 할 수 없다.
     */
    @Transactional(readOnly = true)
    public List<ExportRow> export(Long zoneId, String type, String q, boolean vulnerableOnly,
                                  boolean mixedOnly) {
        List<ComponentRepository.VersionRow> spread =
                components.versionSpreadAll(zoneId, blankToNull(type), blankToNull(q));
        if (spread.isEmpty()) {
            return List.of();
        }

        Severities severities = severities(null, zoneId, spread);

        // 거르개 둘은 패키지 단위 성질이라 줄(패키지 식별자)로 모아 봐야 판단이 선다.
        Map<String, List<ExportRow>> byRow = new LinkedHashMap<>();
        for (ComponentRepository.VersionRow version : spread) {
            byRow.computeIfAbsent(version.getPackageKey(), k -> new ArrayList<>())
                 .add(new ExportRow(version.getName(), version.getType(), version.getPackageKey(),
                                    new VersionSlice(version.getVersion(), version.getAssetCount(),
                                                     severities.of(version))));
        }

        List<ExportRow> out = new ArrayList<>();
        for (List<ExportRow> versions : byRow.values()) {
            boolean vulnerable = versions.stream().anyMatch(r -> r.version().vulnerable());
            boolean clean = versions.stream().anyMatch(r -> !r.version().vulnerable());
            if (vulnerableOnly && !vulnerable) {
                continue;
            }
            if (mixedOnly && !(vulnerable && clean)) {
                continue;
            }
            out.addAll(versions);
        }
        return out;
    }

    /** 자산 상세의 `패키지` 탭. 그 자산 것만, 설치 경로까지 — 한 쪽씩. */
    @Transactional(readOnly = true)
    public Page<Component> ofAsset(Long assetId, String q, int page, Integer size) {
        return components.findByAsset(assetId, blankToNull(q), Paging.request(page, size));
    }

    // -----------------------------------------------------------------------

    private List<PackageRow> assemble(List<ComponentRepository.PackageRow> page, Long zoneId) {
        // 버전 분포: (식별자, 버전) → 자산 수. 이 쪽에 선 줄의 식별자만 묻는다.
        List<String> keys = page.stream().map(ComponentRepository.PackageRow::getPackageKey).toList();
        List<ComponentRepository.VersionRow> versions = components.versionSpread(keys, zoneId);
        Map<String, List<ComponentRepository.VersionRow>> spread = new LinkedHashMap<>();
        for (ComponentRepository.VersionRow version : versions) {
            spread.computeIfAbsent(version.getPackageKey(), k -> new ArrayList<>()).add(version);
        }

        // 탐지는 이름으로 물어 온다 — 유형을 모르는 줄이 받을 것까지(Severities).
        List<String> names = versions.stream().map(ComponentRepository.VersionRow::getName)
                                     .distinct().toList();
        Severities severities = severities(names, zoneId, versions);

        List<PackageRow> rows = new ArrayList<>();
        for (ComponentRepository.PackageRow row : page) {
            List<VersionSlice> slices = new ArrayList<>();
            for (ComponentRepository.VersionRow version
                    : spread.getOrDefault(row.getPackageKey(), List.of())) {
                slices.add(new VersionSlice(version.getVersion(), version.getAssetCount(),
                                            severities.of(version)));
            }
            rows.add(new PackageRow(row.getPackageKey(), row.getName(), row.getType(),
                                    row.getAssetCount(), slices));
        }
        return rows;
    }

    /**
     * 탐지의 등급별 건수를 인벤토리의 버전 조각에 잇는다.
     *
     * <p><b>취약점 화면과 같은 범위로 센다</b> — 운영 중인 자산의 최신 완료
     * 검사, 구역을 골랐으면 그 구역만({@link VulnQuery#latestScanIds}). 앞서는
     * 모든 자산의 최신 검사를 따로 불러 셌다. 같은 버전이 두 구역에 깔려 있으면
     * DMZ 를 골라도 내부업무 자산의 탐지가 합쳐졌고(libc6 — 패키지 화면 58건,
     * 취약점 화면 29건), 운영 종료한 자산의 탐지도 남았다.
     *
     * <p><b>(식별자, 버전)으로 잇는다.</b> 인벤토리와 탐지가 같은 규칙으로 만든 식별자다
     * ({@link PackageKey}) — 앞서는 유형을 purl 과 함께 맞춰 (이름, 버전, 유형)으로 이었다.
     *
     * @param names    물어 볼 이름. {@code null} 이면 전부 (CSV 내보내기)
     * @param versions 이을 인벤토리 조각 — 유형을 모르는 줄이 무엇을 받을지 가를 때 쓴다
     */
    private Severities severities(List<String> names, Long zoneId,
                                  List<ComponentRepository.VersionRow> versions) {
        // (이름, 버전) → 인벤토리에 있는 식별자
        Map<String, Set<String>> inventory = new LinkedHashMap<>();
        for (ComponentRepository.VersionRow version : versions) {
            inventory.computeIfAbsent(key(version.getName(), version.getVersion()),
                                      k -> new LinkedHashSet<>())
                     .add(version.getPackageKey());
        }
        // (이름, 버전) → 식별자 → 등급 → 건수
        Map<String, Map<String, Map<String, Long>>> found = new LinkedHashMap<>();
        List<Long> scanIds = vulns.latestScanIds(zoneId);
        if (!scanIds.isEmpty()) {
            List<FindingRepository.PackageVersionSeverity> rows = names == null
                    ? findings.severityByPackageVersion(scanIds)
                    : findings.severityByPackageVersion(scanIds, names);
            for (FindingRepository.PackageVersionSeverity row : rows) {
                found.computeIfAbsent(key(row.getPackageName(), row.getPackageVersion()),
                                      k -> new LinkedHashMap<>())
                     .computeIfAbsent(row.getPackageKey(), k -> new LinkedHashMap<>())
                     .merge(Severity.of(row.getSeverity()).key(), row.getTotal(), Long::sum);
            }
        }
        return new Severities(inventory, found);
    }

    /**
     * 버전 조각마다의 등급별 건수.
     *
     * <p><b>유형을 모르는 줄</b>(SBOM 이 purl 도 유형도 안 담은 원소 — 식별자가
     * {@code pkg:/이름})은 제 식별자의 탐지와, 같은 이름 · 버전의 <b>어느 줄의 식별자와도 맞지
     * 않는</b> 탐지를 받는다. 받을 줄이 없다고 버리면 그 수가 화면에서 조용히 사라진다 —
     * 실제보다 안전해 보이는 숫자다. 식별자가 맞는 줄이 있는 탐지는 그 줄에만 붙는다. 이것은
     * 이 화면의 수를 세는 일이다 — 검토 결과 · 조치는 식별자로만 붙는다.
     */
    private record Severities(Map<String, Set<String>> inventory,
                              Map<String, Map<String, Map<String, Long>>> found) {

        Map<String, Long> of(ComponentRepository.VersionRow version) {
            String at = key(version.getName(), version.getVersion());
            Map<String, Map<String, Long>> byKey = found.getOrDefault(at, Map.of());
            String own = version.getPackageKey();
            if (!untyped(own)) {
                return byKey.getOrDefault(own, Map.of());
            }
            Set<String> listed = inventory.getOrDefault(at, Set.of());
            Map<String, Long> merged = new LinkedHashMap<>();
            byKey.forEach((findingKey, counts) -> {
                if (findingKey.equals(own) || !listed.contains(findingKey)) {
                    counts.forEach((severity, n) -> merged.merge(severity, n, Long::sum));
                }
            });
            return merged;
        }

        /** 유형을 모르는 줄의 식별자 — {@code pkg:/이름}. */
        private static boolean untyped(String packageKey) {
            return packageKey == null || packageKey.startsWith("pkg:/");
        }
    }

    /**
     * {@code (이름, 버전)} 하나를 가리키는 키.
     *
     * <p>구분자는 <b>NUL</b> 이다. 이름과 버전은 SBOM 이 담아 온 글자라 빈칸도
     * 하이픈도 콜론도 그 안에 들어 있을 수 있다. 그런 글자를 구분자로 쓰면
     * 서로 다른 두 패키지가 한 키로 붙고, 그 순간 건수가 남의 것과 합쳐진다.
     */
    private static String key(String name, String version) {
        return name + "\0" + (version == null ? "" : version);
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    // -----------------------------------------------------------------------
    // 화면에 넘기는 모양
    // -----------------------------------------------------------------------

    /**
     * 화면에 넘기는 한 쪽.
     *
     * <p><b>잘림 각주가 없어졌다.</b> 앞서는 앞 200개만 싣고 "이름 3,908개
     * 중 앞 200개만 화면에" 라고 적어 두었다. 이제 쪽으로 넘기므로 잘리는
     * 것이 없다 — 화면 머리의 수와 쪽 넘김이 같은 것을 말한다.
     */
    public record Listing(Page<PackageRow> rows, List<String> types) {

        /** 화면 머리에 찍는 수 — 거르개를 건 뒤의 줄(패키지 식별자) 수. */
        public String label() {
            return String.format("%,d", rows.getTotalElements()) + "개";
        }
    }

    /**
     * CSV 한 줄 — {@code (패키지 식별자, 버전)} 하나.
     *
     * <p>화면의 버전 조각 하나가 한 줄이 된다. 버전 분포를 한 칸에 몰아 넣으면
     * 엑셀에서 거르지도 정렬하지도 못한다.
     */
    public record ExportRow(String name, String type, String packageKey, VersionSlice version) {
    }

    /** 패키지 한 줄 — 식별자 하나. 이름 · 유형은 화면에 찍을 값. */
    public record PackageRow(String packageKey, String name, String type, long assetCount,
                             List<VersionSlice> versions) {

        /** 이름 곁에 적는 네임스페이스 — groupId · scope · 배포판. 없으면 빈 글자. */
        public String namespace() {
            return PackageKey.namespace(packageKey);
        }

        public long findingCount() {
            return versions.stream().mapToLong(VersionSlice::total).sum();
        }

        /**
         * <b>걸린 것이 있는 버전과 없는 버전이 함께 깔려 있는가</b> — 화면의
         * `일부 자산만 업그레이드`.
         *
         * <p>이 화면에서 가장 중요한 신호다: "이미 올린 자산이 있는데 안 올린
         * 자산이 남았다" 는 뜻이다. 화면 말은 그 뜻으로 적는다 — 앞서
         * `버전 갈림` 이라고 불렀는데 무엇이 왜 갈렸는지 말해 주지 않아,
         * 쓰는 사람이 무엇을 거르는 단추인지 몰랐다.
         *
         * <p>이름({@code mixed})은 그대로 둔다 — 주소에 남는 값이라 적어 둔
         * 주소와 즐겨찾기가 죽는다.
         */
        public boolean mixed() {
            boolean vulnerable = false;
            boolean clean = false;
            for (VersionSlice slice : versions) {
                if (slice.vulnerable()) {
                    vulnerable = true;
                } else {
                    clean = true;
                }
            }
            return vulnerable && clean;
        }

        /** 이 패키지에 걸린 것 중 가장 높은 등급. 없으면 {@code null}. */
        public Severity worst() {
            Severity worst = null;
            for (VersionSlice slice : versions) {
                Severity slices = slice.worst();
                if (slices != null && (worst == null || slices.ordinal() < worst.ordinal())) {
                    worst = slices;
                }
            }
            return worst;
        }
    }

    /**
     * 한 버전 조각 — 이 버전이 몇 대에 깔려 있고 무엇이 걸렸나.
     *
     * @param severities 등급 → 건수. 비어 있으면 이 버전에는 걸린 것이 없다
     */
    public record VersionSlice(String version, long assetCount, Map<String, Long> severities) {

        /** 버전을 SBOM 이 안 담았으면 그렇다고 말한다. */
        public String label() {
            return version == null || version.isBlank() ? "—" : version;
        }

        public long total() {
            return severities.values().stream().mapToLong(Long::longValue).sum();
        }

        public boolean vulnerable() {
            return total() > 0;
        }

        /** 이 버전에 걸린 것 중 가장 높은 등급. 표시 색이 이것을 따른다. */
        public Severity worst() {
            for (Severity severity : Severity.RANKED) {
                if (severities.getOrDefault(severity.key(), 0L) > 0) {
                    return severity;
                }
            }
            return null;
        }

        /**
         * 표시에 올렸을 때 뜨는 줄 — {@code 심각 1 · 높음 6 · 보통 9}.
         *
         * <p>색만으로 가르지 않는다(§5-15). 걸린 것이 없으면 그렇게 말한다.
         */
        public String title() {
            if (!vulnerable()) {
                return label() + " — 걸린 것 없음 · " + assetCount + "대";
            }
            StringBuilder out = new StringBuilder(label()).append(" — ");
            boolean first = true;
            for (Severity severity : Severity.RANKED) {
                long count = severities.getOrDefault(severity.key(), 0L);
                if (count == 0) {
                    continue;
                }
                if (!first) {
                    out.append(" · ");
                }
                out.append(severity.label()).append(' ').append(count);
                first = false;
            }
            return out.append(" · ").append(assetCount).append("대").toString();
        }
    }
}
