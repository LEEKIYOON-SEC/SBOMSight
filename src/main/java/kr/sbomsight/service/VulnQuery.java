package kr.sbomsight.service;

import kr.sbomsight.domain.Finding;
import kr.sbomsight.domain.Scan;
import kr.sbomsight.domain.ScanStatus;
import kr.sbomsight.repo.FindingRepository;
import kr.sbomsight.repo.ScanRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
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

    private final FindingRepository findings;
    private final ScanRepository scans;
    private final ZoneService zones;
    private final RiskAcceptanceService acceptances;

    public VulnQuery(FindingRepository findings, ScanRepository scans, ZoneService zones,
                     RiskAcceptanceService acceptances) {
        this.findings = findings;
        this.scans = scans;
        this.zones = zones;
        this.acceptances = acceptances;
    }

    /**
     * 무엇을 보고 있는가.
     *
     * @param label       화면 머리에 그대로 찍는다. 범위를 모르는 목록은 숫자를 잘못 읽게 한다.
     * @param scanIds     이 범위에 해당하는 검사들
     * @param singleAsset 자산 하나로 좁혀졌으면 그 id — 검토 결과 표시에 쓴다
     */
    public record Scope(String label, List<Long> scanIds, Long singleAsset) {
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

        private String build(String overrideName, Object overrideValue) {
            LinkedHashMap<String, Object> all = new LinkedHashMap<>();
            if (fixed != null) {
                for (String pair : fixed.split("&")) {
                    int eq = pair.indexOf('=');
                    all.put(pair.substring(0, eq), pair.substring(eq + 1));
                }
            }
            all.putAll(current);
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
                         List.of(s.getId()), s.getAsset().getId());
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

        String label = (zoneId == null ? "전체 " : zones.require(zoneId).getName() + " ")
                + latest.size() + "대 · 최신 검사 기준";
        return new Scope(label, latest.stream().map(Scan::getId).toList(),
                         latest.size() == 1 ? latest.get(0).getAsset().getId() : null);
    }

    /** 목록을 모델에 담는다. 묶는 방식에 따라 담기는 값이 다르다. */
    @Transactional(readOnly = true)
    public void fill(Model model, Scope scope, String group, String q, String severity,
                     Boolean fixable, Boolean kev, int page, String sort) {
        String term = blankToNull(q);
        String sev = blankToNull(severity);

        model.addAttribute("cveGroups", List.of());
        model.addAttribute("packageGroups", List.of());
        model.addAttribute("page", Page.<Finding>empty());

        if (scope.scanIds().isEmpty()) {
            model.addAttribute("acceptedKeys", java.util.Set.of());
            return;
        }

        switch (group == null ? "item" : group) {
            case "cve" -> model.addAttribute("cveGroups",
                    findings.groupByCveIn(scope.scanIds(), term, sev, fixable, kev));
            case "package" -> model.addAttribute("packageGroups",
                    findings.groupByPackageIn(scope.scanIds()));
            default -> {
                int p = Math.max(page, 0);
                model.addAttribute("page", "severity".equals(sort) || sort == null
                        // 심각도는 글자다. Critical 이 High 보다 앞이라는 것은
                        // 알파벳 순서가 아니라 뜻이고, ORDER BY CASE 로만 낸다.
                        ? findings.findInBySeverity(scope.scanIds(), term, sev, fixable, kev,
                                                    PageRequest.of(p, PAGE_SIZE))
                        : findings.findIn(scope.scanIds(), term, sev, fixable, kev,
                                          PageRequest.of(p, PAGE_SIZE, order(sort))));
            }
        }

        // 검토 결과가 붙은 건에 표시를 달기 위한 키 집합. 건마다 물으면
        // 목록 한 장에 수백 번 왕복한다.
        model.addAttribute("acceptedKeys", scope.singleAsset() == null
                ? java.util.Set.of()
                : acceptances.activeKeys(scope.singleAsset()));
    }

    /**
     * 정렬 기준.
     *
     * <p>어느 축으로 정렬하든 <b>값이 없는 건은 항상 뒤로</b> 보낸다. CVSS 가
     * 없는 건을 0 점으로 줄 세우면 "안전하다"는, 아무도 내리지 않은 판정이 된다.
     */
    public static Sort order(String sort) {
        return switch (sort == null ? "" : sort) {
            case "epss" -> Sort.by(Sort.Order.desc("epss").nullsLast(),
                                   Sort.Order.desc("cvssScore").nullsLast());
            case "package" -> Sort.by(Sort.Order.asc("packageName"), Sort.Order.asc("cve"));
            case "cve" -> Sort.by(Sort.Order.asc("cve"));
            default -> Sort.by(Sort.Order.desc("cvssScore").nullsLast(),
                               Sort.Order.asc("packageName"));
        };
    }

    private String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
