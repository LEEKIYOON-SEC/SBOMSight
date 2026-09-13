package kr.sbomsight.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.UriUtils;

import java.nio.charset.StandardCharsets;

/**
 * 옛 주소와 아직 안 만든 주소를 이어 준다.
 *
 * <p><b>두 가지가 섞여 있다. 섞인 채로 두지 않는다 — 아래 표시로 갈라 둔다.</b>
 *
 * <p><b>① 영구</b> — 화면이 자리를 옮겼다. 적어 둔 주소·즐겨찾기가 죽지 않게
 * 계속 남긴다.
 *
 * <p><b>② 임시 다리</b> — 새 주소를 기둥에 먼저 걸어 두고, 그 화면은 아직
 * 안 만들었다. 지금은 <b>새 주소 → 옛 화면</b> 으로 보낸다. 해당 단계에서
 * 진짜 화면이 생기면 <b>이 줄을 지우고</b> 반대 방향(옛 주소 → 새 주소)을
 * 영구로 남긴다.
 *
 * <p>왜 이렇게 하는가. 개편 계획(§6)의 302 를 한꺼번에 넣으면
 * {@code /lookup → /vulns} 가 되는데 {@code /vulns} 는 몇 단계 뒤에나 생긴다.
 * 그 사이 앱이 깨진 채로 있게 된다. 반대로 걸어 두면 <b>커밋마다 앱이
 * 살아 있고</b>, 주소는 지금부터 최종 모양이라 더 이상 움직이지 않는다.
 */
@Controller
public class LegacyRedirectController {

    // --- ① 영구 ------------------------------------------------------------

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

    // --- ② 임시 다리 — 진짜 화면이 생기면 지운다 ----------------------------

    /** N5 에서 {@code /actions} 가 생기면 지우고 두 옛 화면을 이리로 보낸다. */
    @GetMapping("/actions")
    public String actions() {
        return "redirect:/remediations";
    }

    /** N7 에서 {@code /reports} 고르기 화면이 생기면 지운다. */
    @GetMapping("/reports")
    public String reports() {
        return "redirect:/report/zone";
    }

    /** N6 에서 {@code /me} 가 생기면 지운다. */
    @GetMapping("/me")
    public String me() {
        return "redirect:/password";
    }
}
