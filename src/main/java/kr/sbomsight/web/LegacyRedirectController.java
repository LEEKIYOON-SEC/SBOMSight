package kr.sbomsight.web;

import org.springframework.stereotype.Controller;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.UriUtils;

import java.nio.charset.StandardCharsets;

/**
 * 옛 주소를 새 화면으로 이어 준다.
 *
 * <p>화면이 자리를 옮겼다. 적어 둔 주소 · 즐겨찾기가 죽지 않게 계속 남긴다.
 *
 * <p><b>개편 중에는 반대 방향의 임시 다리도 여기 있었다.</b> 새 주소를 기둥에
 * 먼저 걸어 두고 그 화면이 아직 없을 때 <b>새 주소 → 옛 화면</b> 으로
 * 보냈다 — 개편 계획(§6)의 302 를 한꺼번에 넣으면
 * {@code /lookup → /vulns} 가 되는데 {@code /vulns} 는 몇 단계 뒤에나 생기고,
 * 그 사이 앱이 깨진 채로 있게 되기 때문이다. 마지막 다리였던
 * {@code /reports} 는 N7 에서 진짜 화면이 생기면서 지웠다.
 */
@Controller
public class LegacyRedirectController {

    /** 감사 로그는 관리자만 보는 것이라 설정 안으로 들어갔다 (N2). */
    @GetMapping("/audit")
    public String audit() {
        return "redirect:/settings/audit";
    }

    /**
     * 전사 조회는 취약점 화면에 흡수됐다 (N4).
     *
     * <p>검색어를 넣어야만 답하던 화면이었고, 같은 질의를 {@code /scans/{id}}
     * 와 나눠 가지고 있었다. 범위를 고르는 한 화면으로 합쳤다.
     */
    @GetMapping("/lookup")
    public String lookup(@RequestParam(required = false) String q,
                         @RequestParam(required = false) Long zone) {
        return "redirect:/vulns" + carry(q, zone);
    }

    /** 내려받기 주소도 함께 옮겼다. 결재 서류에 붙여 둔 링크가 죽지 않게 남긴다. */
    @GetMapping("/lookup/export.csv")
    public String lookupExport(@RequestParam(required = false) String q,
                               @RequestParam(required = false) Long zone) {
        return "redirect:/vulns/export.csv" + carry(q, zone);
    }

    private String carry(String q, Long zone) {
        StringBuilder to = new StringBuilder();
        String sep = "?";
        if (q != null && !q.isBlank()) {
            to.append(sep).append("q=").append(UriUtils.encodeQueryParam(q, StandardCharsets.UTF_8));
            sep = "&";
        }
        if (zone != null) {
            to.append(sep).append("zone=").append(zone);
        }
        return to.toString();
    }

    /**
     * 조치와 검토 결과는 대응 화면의 두 탭이 됐다 (N5).
     *
     * <p>둘 다 "이 건을 어떻게 할 것인가" 에 대한 답인데 화면이 갈라져 있어,
     * 어느 쪽이 급한지 알려면 두 번 봐야 했다. 위험 수용은 그중에서도
     * 다섯 상태 중 하나({@code 해당됨})와 다섯 대응 중 하나({@code 조치 안 함})의
     * 조합일 뿐이었고, 표를 따로 두니 나머지 조합("해당 없음"·"오탐")을
     * 적을 자리가 아예 없었다.
     */
    @GetMapping({ "/remediations", "/analyses", "/acceptances" })
    public String actions(HttpServletRequest request) {
        // 검토 결과 쪽에서 온 것은 그 탭으로 연다. 조치 탭으로 떨어뜨리면
        // 즐겨찾기를 눌렀는데 다른 목록이 뜬다.
        String from = request.getRequestURI();
        return from.endsWith("/remediations")
                ? "redirect:/actions"
                : "redirect:/actions?tab=analyses";
    }

    /** 조치 상세도 대응 아래로 옮겼다. 한 영역의 주소가 두 갈래이면 기억하지 못한다. */
    @GetMapping("/remediations/{id}")
    public String remediationDetail(@PathVariable Long id) {
        return "redirect:/actions/" + id;
    }

    @GetMapping("/remediations/export.csv")
    public String remediationExport() {
        return "redirect:/actions/export.csv";
    }

    /**
     * 보고서 주소가 {@code /reports/} 아래로 모였다 (N7).
     *
     * <p>앞서 자산 보고서는 {@code /report/{scanId}}, 구역 보고서는
     * {@code /report/zone}, 고르는 화면은 {@code /reports} 였다. 한 글자
     * 차이로 갈라진 두 접두사를 아무도 기억하지 못한다.
     *
     * <p><b>구역 쪽을 먼저 적는다.</b> {@code /report/zone} 을
     * {@code /report/{scanId}} 가 먼저 집으면 {@code "zone"} 을 숫자로
     * 바꾸려다 400 이 난다. 스프링은 고정 경로를 먼저 맞추지만, 순서를
     * 눈으로도 맞춰 둔다.
     */
    @GetMapping("/report/zone")
    public String zoneReport(HttpServletRequest request) {
        String query = request.getQueryString();
        return "redirect:/reports/zone" + (query == null || query.isBlank() ? "" : "?" + query);
    }

    @GetMapping("/report/{scanId}")
    public String scanReport(@PathVariable Long scanId) {
        return "redirect:/reports/scan/" + scanId;
    }

}
