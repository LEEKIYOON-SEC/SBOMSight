package kr.sbomsight.service;

import kr.sbomsight.domain.Finding;
import kr.sbomsight.domain.Scan;
import kr.sbomsight.domain.ScanStatus;
import kr.sbomsight.repo.FindingRepository;
import kr.sbomsight.repo.ScanRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.JpaSort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.web.server.ResponseStatusException;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;

import static org.springframework.http.HttpStatus.NOT_FOUND;

/**
 * 취약점 목록을 채우는 한 벌.
 *
 * <p><b>왜 서비스로 빼는가.</b> 전체 취약점 화면과 자산 상세의 취약점 탭이
 * 같은 표를 그린다. 각자 자기 질의를 부르게 두면 한쪽만 고치는 날이 오고,
 * 그때부터 같은 데이터가 화면마다 다르게 보인다.
 */
@Service
public class VulnQuery {

    public static final int PAGE_SIZE = 100;

    /**
     * 한 쪽에 몇 건. 화면에서 고른다.
     *
     * <p>고를 수 있는 값만 받는다 — 주소에 손으로 적은 {@code size=50000} 이
     * 그대로 질의로 들어가면 한 사람이 화면 한 장으로 DB 를 붙잡는다.
     */
    public static final List<Integer> PAGE_SIZES = List.of(10, 30, 50, 100);

    /** 목록에 없는 값은 기본값으로 되돌린다. {@code null} 도 기본값이다. */
    public static int sizeOf(Integer size) {
        return size != null && PAGE_SIZES.contains(size) ? size : PAGE_SIZE;
    }

    private final FindingRepository findings;
    private final ScanRepository scans;
    private final ZoneService zones;
    private final FindingAnalysisService analyses;

    public VulnQuery(FindingRepository findings, ScanRepository scans, ZoneService zones,
                     FindingAnalysisService analyses) {
        this.findings = findings;
        this.scans = scans;
        this.zones = zones;
        this.analyses = analyses;
    }

    /**
     * 무엇을 보고 있는가.
     *
     * @param label       화면 머리에 그대로 찍는다. 범위를 모르는 목록은 숫자를 잘못 읽게 한다.
     * @param scanIds     이 범위에 해당하는 검사들
     * @param singleAsset 자산 하나로 좁혀졌으면 그 id — 화면 머리와 링크에 쓴다
     * @param assetIds    이 범위에 걸린 자산 전부 — 검토 결과를 한 번에 끌어온다
     */
    public record Scope(String label, List<Long> scanIds, Long singleAsset,
                        List<Long> assetIds) {
    }

    /**
     * 화면 안의 링크를 만든다 — <b>고른 것은 이어 가고, 안 고른 것은 안 붙인다.</b>
     *
     * <p>왜 자바에서 만드는가. 타임리프의 {@code @{/vulns(zone=${zone}, q=${q}, …)}}
     * 는 값이 없어도 이름을 적는다. 그래서 아무것도 고르지 않은 채 묶기 단추
     * 하나만 눌러도 주소가
     * {@code /vulns?zone=&scan=&group=cve&q=&severity=&fixable=&kev=} 가 된다.
     * 동작은 하지만 그 주소가 결재 문서에 붙고 옆자리에 전달된다. 읽을 수
     * 있어야 한다.
     *
     * @param path   앞에 붙는 경로 — {@code /vulns} 또는 {@code /assets/3}
     * @param fixed  그 화면이 언제나 달고 다니는 것 — 자산 상세의 {@code tab=vulns}
     */
    public static final class Links {

        private final String path;
        private final String fixed;
        private final LinkedHashMap<String, Object> current = new LinkedHashMap<>();

        public Links(String path, String fixed) {
            this.path = path;
            this.fixed = fixed;
        }

        public Links with(String name, Object value) {
            current.put(name, value);
            return this;
        }

        /**
         * 같은 것을 들고 있는 새 벌. <b>원본을 건드리지 않는다.</b>
         *
         * <p>화면 하나에 링크가 여럿이고 각자 한두 가지만 다를 때 쓴다 —
         * 목록의 정렬 머리, 구역 고르개, 보기 바꾸개가 그렇다.
         * {@link #with} 는 제 자리에서 값을 바꾸므로 한 벌을 돌려 쓰면
         * 앞 링크가 뒤 링크에 새어 들어간다.
         *
         * <pre>
         * ${links.copy().with('sort','name').with('dir','desc').here()}
         * </pre>
         */
        public Links copy() {
            return copy(path);
        }

        /**
         * 고른 것을 그대로 들고 <b>다른 경로로</b> 가는 새 벌.
         *
         * <p>내려받기 주소가 그렇다 — 화면에 걸어 둔 거르개를 그대로 들고
         * {@code /export.csv} 로 간다. 보던 것과 다른 파일이 떨어지면 어느
         * 쪽이 맞는지 물어볼 자리가 없다.
         */
        public Links copy(String otherPath) {
            Links clone = new Links(otherPath, fixed);
            clone.current.putAll(current);
            return clone;
        }

        /** 지금 고른 것 그대로. 거르개를 지우는 '처음으로' 링크는 {@link #clear()}. */
        public String here() {
            return build(null, null);
        }

        public String group(String group) {
            // 묶기를 바꾸면 페이지는 처음으로 — 3쪽에 있다가 CVE별로 가면
            // 3쪽이 없을 수 있고, 그러면 빈 화면이 뜬다.
            return build("group", group);
        }

        public String sort(String sort) {
            return build("sort", sort);
        }

        public String page(int page) {
            return build("page", page);
        }

        /** 이 화면의 경로. 쪽 이동 form 의 {@code action} 이 쓴다. */
        public String path() {
            return path;
        }

        /**
         * 지금 고른 것을 form 의 숨은 칸으로.
         *
         * <p>쪽 이동은 링크가 아니라 <b>form</b> 이다 — 몇 번째로 갈지는
         * 사람이 적는 값이라 주소를 미리 만들어 둘 수 없다. 그 form 이
         * 지금의 범위·거르개·정렬을 잃지 않게 그대로 실어 보낸다. 손으로
         * 적으면 거르개를 하나 더할 때 이 목록에 넣는 것을 잊는다.
         *
         * <p>{@code page} 는 뺀다 — 넣으면 숨은 칸과 사람이 적은 값이 같은
         * 이름으로 두 번 실려 서버가 앞의 것을 읽는다.
         */
        public java.util.Map<String, String> fields() {
            LinkedHashMap<String, String> out = new LinkedHashMap<>();
            for (var e : merged().entrySet()) {
                if (!"page".equals(e.getKey())) {
                    out.put(e.getKey(), String.valueOf(e.getValue()));
                }
            }
            return out;
        }

        /**
         * 지금 고른 것에서 <b>한 가지만 바꾼 주소.</b> {@code null} 을 주면
         * 그 값을 뺀다 — 펼친 것을 접는 링크가 그렇게 만들어진다.
         *
         * <p>패키지 화면의 `자산 보기`/`접기` 와 `취약점` 링크가 쓴다. 같은
         * 일을 하는 링크 만들기를 두 벌로 두면 한쪽만 고치는 날이 온다.
         */
        public String change(String name, Object value) {
            return build(name, value);
        }

        /** 거르개를 전부 지운다. 범위와 묶기는 남긴다 — 지금 보던 자리는 그대로다. */
        public String clear() {
            Links bare = new Links(path, fixed);
            bare.with("zone", current.get("zone"))
                .with("scan", current.get("scan"))
                .with("group", current.get("group"));
            return bare.here();
        }

        public String csv() {
            Links download = new Links(path + "/export.csv", null);
            download.with("zone", current.get("zone"))
                    .with("scan", current.get("scan"))
                    .with("q", current.get("q"))
                    .with("severity", current.get("severity"))
                    .with("fixable", current.get("fixable"))
                    .with("kev", current.get("kev"));
            return download.here();
        }

        /** 언제나 달고 다니는 것 + 지금 고른 것. 빈 값은 빼고 돌려준다. */
        private LinkedHashMap<String, Object> merged() {
            LinkedHashMap<String, Object> all = new LinkedHashMap<>();
            if (fixed != null) {
                for (String pair : fixed.split("&")) {
                    int eq = pair.indexOf('=');
                    all.put(pair.substring(0, eq), pair.substring(eq + 1));
                }
            }
            current.forEach((name, value) -> {
                if (value != null && !String.valueOf(value).isBlank()) {
                    all.put(name, value);
                }
            });
            return all;
        }

        private String build(String overrideName, Object overrideValue) {
            LinkedHashMap<String, Object> all = merged();
            if (overrideName != null) {
                all.put(overrideName, overrideValue);
                // 목록이 바뀌면 몇 쪽을 보고 있었는지는 뜻이 없어진다.
                if (!"page".equals(overrideName)) {
                    all.remove("page");
                }
            }

            StringBuilder url = new StringBuilder(path);
            char sep = '?';
            for (var e : all.entrySet()) {
                String text = e.getValue() == null ? "" : String.valueOf(e.getValue());
                if (text.isBlank()) {
                    continue;
                }
                url.append(sep).append(e.getKey()).append('=')
                   .append(URLEncoder.encode(text, StandardCharsets.UTF_8));
                sep = '&';
            }
            return url.toString();
        }
    }

    /** 검사 하나. 검사 이력의 '열기' 가 여기로 온다. */
    @Transactional(readOnly = true)
    public Scope ofScan(Long scanId) {
        Scan s = scans.findWithAsset(scanId)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "검사를 찾을 수 없습니다."));
        String when = s.getCreatedAt().atZone(java.time.ZoneId.systemDefault())
                       .toLocalDateTime().toString().replace('T', ' ').substring(0, 16);
        return new Scope(s.getAsset().getName() + " · " + when + " 검사",
                         List.of(s.getId()), s.getAsset().getId(),
                         List.of(s.getAsset().getId()));
    }

    /**
     * 전체 또는 한 구역.
     *
     * <p>각 자산의 <b>최신 완료 검사만</b> 본다. 이력 전체를 훑으면 이미 조치가
     * 끝난 옛 검사가 섞여 나와 "아직 있다" 고 말하게 된다 — 그 답을 믿고
     * 서버에 들어가면 없다.
     */
    @Transactional(readOnly = true)
    public Scope ofZone(Long zoneId) {
        List<Scan> latest = scans.findLatestDonePerAsset().stream()
                .filter(s -> s.getStatus() == ScanStatus.DONE)
                .filter(s -> s.getAsset().getArchivedAt() == null)
                .filter(s -> zoneId == null || s.getAsset().getZone().getId().equals(zoneId))
                .toList();

        // **`전체 5대` 라고만 쓰면 자산이 다섯 대인 줄 읽힌다.** 여섯 대 중
        // 검사된 것이 다섯일 뿐이다 — 검사 안 한 자산이 빠졌다는 사실이
        // 부제에 없으면 이 화면의 건수가 전부인 것으로 읽힌다.
        String label = (zoneId == null ? "전체" : zones.require(zoneId).getName())
                + " · 검사된 " + latest.size() + "대의 최신 검사";
        return new Scope(label, latest.stream().map(Scan::getId).toList(),
                         latest.size() == 1 ? latest.get(0).getAsset().getId() : null,
                         latest.stream().map(s -> s.getAsset().getId()).toList());
    }

    /** 목록을 모델에 담는다. 묶는 방식에 따라 담기는 값이 다르다. */
    @Transactional(readOnly = true)
    public void fill(Model model, Scope scope, String group, String q, String severity,
                     Boolean fixable, Boolean kev, int page, Integer size,
                     String sort, String dir) {
        String term = blankToNull(q);
        String sev = blankToNull(severity);

        model.addAttribute("cveGroups", List.of());
        model.addAttribute("packageGroups", List.of());
        model.addAttribute("page", Page.<Finding>empty());

        if (scope.scanIds().isEmpty()) {
            model.addAttribute("analyses", java.util.Map.of());
            return;
        }

        switch (group == null ? "item" : group) {
            case "cve" -> model.addAttribute("cveGroups",
                    findings.groupByCveIn(scope.scanIds(), term, sev, fixable, kev));
            // 거르개를 **넷 다** 넘긴다. 앞서는 `scanIds` 만 넘겼고, 화면에는
            // 고른 값이 그대로 남아 있는데 목록이 한 줄도 바뀌지 않았다.
            case "package" -> model.addAttribute("packageGroups",
                    findings.groupByPackageIn(scope.scanIds(), term, sev, fixable, kev));
            default -> {
                int p = Math.max(page, 0);
                int rows = sizeOf(size);
                boolean asc = "asc".equals(dir);
                model.addAttribute("page", "severity".equals(sort) || sort == null
                        // 심각도는 글자다. Critical 이 High 보다 앞이라는 것은
                        // 알파벳 순서가 아니라 뜻이고, ORDER BY CASE 로만 낸다.
                        ? findings.findInBySeverity(scope.scanIds(), term, sev, fixable, kev,
                                                    asc, PageRequest.of(p, rows))
                        : findings.findIn(scope.scanIds(), term, sev, fixable, kev,
                                          PageRequest.of(p, rows, order(sort, dir))));
            }
        }

        // 행마다 검토 결과 표시를 붙이기 위한 것. 건마다 물으면 목록 한 장에
        // 수백 번 왕복한다.
        //
        // 키에 **자산 id 를 넣는다.** 구역·전체 범위는 자산이 섞여 있어서,
        // (CVE, 패키지명) 으로만 맞추면 web-01 의 검토 결과가 api-01 행에
        // 붙는다. 자산 하나짜리 범위에서는 눈에 띄지 않다가 범위를 넓히는
        // 순간 틀리는 종류의 버그다.
        model.addAttribute("analyses", analyses.byAssetKey(scope.assetIds()));
    }

    /**
     * 정렬 기준.
     *
     * <p>어느 축으로 정렬하든 <b>값이 없는 건은 항상 뒤로</b> 보낸다. CVSS 가
     * 없는 건을 0 점으로 줄 세우면 "안전하다"는, 아무도 내리지 않은 판정이 된다.
     * 방향을 뒤집어도 따라 올라오지 않는다.
     *
     * <p><b>{@code dir} 은 곧이곧대로 읽는다</b> — {@code asc} 면 오름차순,
     * 아니면 내림차순. 칸마다 "처음 눌렀을 때의 방향" 이 다른 것은
     * ({@code CVSS} 는 큰 것부터, {@code 패키지} 는 사전 순) 화면이 링크를
     * 만들 때 정하고, 여기서 다시 뒤집지 않는다. 뒤집으면 화면에 찍힌
     * 화살표와 실제 순서가 어긋난다.
     *
     * <p><b>{@code Sort.Order#nullsLast()} 로는 안 된다.</b> 그 지시는 SQL 에
     * 도달하지 않는다 — 띄워서 재 보고 찾았다. Hibernate 가 내보낸 것은
     * {@code order by f1_0.cvss_score, f1_0.package_name} 이고 {@code nulls
     * last} 는 어디에도 없었다. 내림차순에서는 MySQL·H2 가 NULL 을 알아서
     * 뒤로 보내 주어 지금까지 맞아 보였을 뿐이고, 오름차순을 열자 <b>CVSS 가
     * 없는 34건이 "가장 안 위험한 것" 자리에 줄줄이 섰다.</b>
     *
     * <p>그래서 정렬 축 앞에 <b>"값이 없는가" 한 칸을 직접 붙인다.</b>
     * 이것만이 두 방향·두 DB 에서 같게 돈다.
     */
    public static Sort order(String sort, String dir) {
        Sort.Direction d = "asc".equals(dir) ? Sort.Direction.ASC : Sort.Direction.DESC;
        return switch (sort == null ? "" : sort) {
            case "epss" -> nullsLast("f.epss")
                    .and(Sort.by(Sort.Order.by("epss").with(d)))
                    .and(nullsLast("f.cvssScore"))
                    .and(Sort.by(Sort.Order.by("cvssScore").with(d)));
            // 이름은 비지 않는다(NOT NULL). 값 검사를 붙일 것이 없다.
            case "package" -> Sort.by(Sort.Order.by("packageName").with(d),
                                      Sort.Order.asc("cve"));
            case "cve" -> Sort.by(Sort.Order.by("cve").with(d));
            default -> nullsLast("f.cvssScore")
                    .and(Sort.by(Sort.Order.by("cvssScore").with(d),
                                 Sort.Order.asc("packageName")));
        };
    }

    /**
     * "값이 없는가" 를 맨 앞 정렬 칸으로.
     *
     * <p>{@code 0}(있음) → {@code 1}(없음) 오름차순이므로, 뒤에 오는 축의
     * 방향과 무관하게 값 없는 건이 <b>언제나 뒤로</b> 간다.
     *
     * <p>{@code JpaSort.unsafe} 는 식을 그대로 JPQL 의 {@code ORDER BY} 에
     * 넣는다. 그래서 <b>여기 적는 별칭은 질의의 별칭과 같아야 한다</b> —
     * {@link kr.sbomsight.repo.FindingRepository#findIn} 의 {@code f} 다.
     * 질의의 별칭을 바꾸면 여기도 바꿔야 하고, 안 바꾸면 그 화면이 500 이 된다.
     */
    private static Sort nullsLast(String path) {
        // 괄호로 감싼다. Spring Data 는 괄호가 없는 식을 속성 이름으로 보고
        // 질의의 별칭을 앞에 붙여서(`f.CASE WHEN …`) 질의가 구문 오류로 터진다.
        return JpaSort.unsafe(Sort.Direction.ASC,
                              "(CASE WHEN " + path + " IS NULL THEN 1 ELSE 0 END)");
    }

    private String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
