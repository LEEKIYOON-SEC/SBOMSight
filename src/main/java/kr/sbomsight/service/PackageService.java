package kr.sbomsight.service;

import kr.sbomsight.domain.Component;
import kr.sbomsight.domain.Scan;
import kr.sbomsight.domain.Severity;
import kr.sbomsight.repo.ComponentRepository;
import kr.sbomsight.repo.FindingRepository;
import kr.sbomsight.repo.ScanRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 무엇이 어디에 몇 버전으로 깔려 있나 — <b>취약점이 붙기 전에도.</b>
 *
 * <p>취약점 화면은 grype 이 매치를 낸 것만 보여 준다. 그래서 {@code log4j} 가
 * 어디 깔려 있는지는 CVE 가 터진 다음에야, 그것도 매치가 난 자산에서만 알 수
 * 있었다. SBOM 에는 처음부터 전부 들어 있었다.
 *
 * <p><b>이 화면의 가장 중요한 신호는 버전이 갈린 패키지다.</b> 같은 패키지에
 * 취약한 버전과 안전한 버전이 섞여 있으면 "이미 올린 자산이 있는데 안 올린
 * 자산이 남았다" 는 뜻이다.
 *
 * <p>심각도는 grype 이 낸 것을 그대로 옮긴다. 버전마다 <b>어느 등급이 가장
 * 높은가</b>만 골라 표시에 쓴다 — 다시 매기지 않는다.
 */
@Service
public class PackageService {

    /** 한 번에 보여 줄 패키지 수. 버전 분포를 물어 볼 이름 수이기도 하다. */
    private static final int PAGE = 200;

    private final ComponentRepository components;
    private final FindingRepository findings;
    private final ScanRepository scans;

    public PackageService(ComponentRepository components, FindingRepository findings,
                          ScanRepository scans) {
        this.components = components;
        this.findings = findings;
        this.scans = scans;
    }

    @Transactional(readOnly = true)
    public Listing list(Long zoneId, String type, String q, boolean vulnerableOnly,
                        boolean mixedOnly) {
        List<ComponentRepository.PackageRow> grouped =
                components.groupByName(zoneId, blankToNull(type), blankToNull(q));

        boolean more = grouped.size() > PAGE;
        List<ComponentRepository.PackageRow> page =
                more ? grouped.subList(0, PAGE) : grouped;

        List<String> names = page.stream().map(ComponentRepository.PackageRow::getName).toList();
        List<PackageRow> rows = names.isEmpty()
                ? List.of()
                : assemble(page, names, zoneId);

        // 거르개는 조립 뒤에 걸린다 — "취약점 있는 것만" 과 "버전이 갈린
        // 것만" 은 버전 분포를 다 세어 봐야 알 수 있다.
        List<PackageRow> filtered = rows.stream()
                .filter(r -> !vulnerableOnly || r.findingCount() > 0)
                .filter(r -> !mixedOnly || r.mixed())
                .toList();

        return new Listing(filtered, grouped.size(), more, components.types());
    }

    /** 펼쳤을 때 — 이 패키지가 어느 자산에 어느 버전으로 깔려 있나. */
    @Transactional(readOnly = true)
    public List<Component> assetsOf(String name, Long zoneId) {
        return components.findByName(name, zoneId);
    }

    /**
     * CSV 내보내기 — <b>거른 것 전부.</b>
     *
     * <p>한 줄이 {@code (패키지, 버전)} 하나다. 화면의 버전 조각 하나가 한
     * 줄이 된다 — 버전 분포를 한 칸에 몰아 넣으면 엑셀에서 쓸 수 없다.
     *
     * <p><b>{@link #PAGE} 에서 자르지 않는다.</b> 화면은 앞 200개만 싣지만,
     * 잘린 파일은 그것이 잘렸다는 사실을 들고 다니지 않는다.
     */
    @Transactional(readOnly = true)
    public List<ExportRow> export(Long zoneId, String type, String q, boolean vulnerableOnly,
                                  boolean mixedOnly) {
        List<ComponentRepository.TypedVersionRow> spread =
                components.versionSpreadAll(zoneId, blankToNull(type), blankToNull(q));
        if (spread.isEmpty()) {
            return List.of();
        }

        Map<String, Map<String, Long>> severities = severities(null);

        // 거르개 둘은 패키지 단위 성질이라 이름으로 모아 봐야 판단이 선다.
        Map<String, List<ExportRow>> byName = new LinkedHashMap<>();
        for (ComponentRepository.TypedVersionRow row : spread) {
            byName.computeIfAbsent(row.getName(), k -> new ArrayList<>())
                  .add(new ExportRow(row.getName(), row.getType(),
                                     new VersionSlice(row.getVersion(), row.getAssetCount(),
                                                      severities.getOrDefault(
                                                              key(row.getName(), row.getVersion()),
                                                              Map.of()))));
        }

        List<ExportRow> out = new ArrayList<>();
        for (List<ExportRow> versions : byName.values()) {
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

    /** 자산 상세의 `패키지` 탭. 그 자산 것만, 설치 경로까지. */
    @Transactional(readOnly = true)
    public List<Component> ofAsset(Long assetId, String q) {
        return components.findByAsset(assetId, blankToNull(q));
    }

    // -----------------------------------------------------------------------

    private List<PackageRow> assemble(List<ComponentRepository.PackageRow> page,
                                      List<String> names, Long zoneId) {
        // 버전 분포: (이름, 버전) → 자산 수
        Map<String, List<ComponentRepository.VersionRow>> spread = new LinkedHashMap<>();
        for (ComponentRepository.VersionRow row : components.versionSpread(names, zoneId)) {
            spread.computeIfAbsent(row.getName(), k -> new ArrayList<>()).add(row);
        }

        Map<String, Map<String, Long>> severities = severities(names);

        List<PackageRow> rows = new ArrayList<>();
        for (ComponentRepository.PackageRow row : page) {
            List<VersionSlice> slices = new ArrayList<>();
            for (ComponentRepository.VersionRow version
                    : spread.getOrDefault(row.getName(), List.of())) {
                slices.add(new VersionSlice(
                        version.getVersion(),
                        version.getAssetCount(),
                        severities.getOrDefault(key(row.getName(), version.getVersion()), Map.of())));
            }
            rows.add(new PackageRow(row.getName(), row.getType(), row.getAssetCount(), slices));
        }
        return rows;
    }

    /**
     * {@code (이름, 버전)} → 등급별 건수.
     *
     * <p>취약점은 자산마다 <b>최신 완료 검사 것만</b> 본다 — 취약점 화면과 같은
     * 범위여야 두 화면의 숫자가 맞는다.
     *
     * @param names 물어 볼 이름. {@code null} 이면 전부 (CSV 내보내기)
     */
    private Map<String, Map<String, Long>> severities(List<String> names) {
        List<Long> scanIds = scans.findLatestDonePerAsset().stream().map(Scan::getId).toList();
        Map<String, Map<String, Long>> out = new LinkedHashMap<>();
        if (scanIds.isEmpty()) {
            return out;
        }
        List<FindingRepository.PackageVersionSeverity> rows = names == null
                ? findings.severityByPackageVersion(scanIds)
                : findings.severityByPackageVersion(scanIds, names);
        for (FindingRepository.PackageVersionSeverity row : rows) {
            out.computeIfAbsent(key(row.getPackageName(), row.getPackageVersion()),
                                k -> new LinkedHashMap<>())
               .merge(Severity.of(row.getSeverity()).key(), row.getTotal(), Long::sum);
        }
        return out;
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
     * @param total 거르개 전 전체 이름 수
     * @param more  {@link #PAGE} 를 넘어 잘렸는가 — 잘린 것을 숨기지 않는다
     */
    public record Listing(List<PackageRow> rows, int total, boolean more, List<String> types) {

        /**
         * 화면 머리에 찍는 수. <b>표에 실린 줄 수와 어긋나지 않게 한다.</b>
         *
         * <p>{@link #total} 은 거르개 전 이름 수다. 그것만 찍으면 `버전이 갈린
         * 것만` 을 켜서 한 줄만 남은 화면 머리에 {@code 6개} 가 적힌다. 어느
         * 숫자가 맞는지 물어볼 자리가 없으므로 <b>둘을 같이 적는다.</b>
         *
         * <p>{@link #PAGE} 에서 잘린 것도 같은 모양으로 드러난다 — 왜 잘렸는지는
         * 표 아래 각주가 말한다.
         */
        public String label() {
            String shown = comma(rows.size());
            return rows.size() == total ? shown + "개" : comma(total) + "개 중 " + shown + "개";
        }

        private static String comma(int value) {
            return String.format("%,d", value);
        }
    }

    /**
     * CSV 한 줄 — {@code (패키지, 버전)} 하나.
     *
     * <p>화면의 버전 조각 하나가 한 줄이 된다. 버전 분포를 한 칸에 몰아 넣으면
     * 엑셀에서 거르지도 정렬하지도 못한다.
     */
    public record ExportRow(String name, String type, VersionSlice version) {
    }

    /** 패키지 한 줄. */
    public record PackageRow(String name, String type, long assetCount,
                             List<VersionSlice> versions) {

        public long findingCount() {
            return versions.stream().mapToLong(VersionSlice::total).sum();
        }

        /**
         * <b>취약한 버전과 안전한 버전이 섞여 있는가.</b>
         *
         * <p>이 화면에서 가장 중요한 신호다 — "이미 올린 자산이 있는데 안 올린
         * 자산이 남았다" 는 뜻이다.
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
