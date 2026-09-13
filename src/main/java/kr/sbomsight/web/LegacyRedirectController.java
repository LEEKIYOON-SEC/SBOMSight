package kr.sbomsight.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

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

    // --- ② 임시 다리 — 진짜 화면이 생기면 지운다 ----------------------------

    /** N4 에서 {@code /vulns} 가 생기면 지우고 {@code /lookup} 을 이리로 보낸다. */
    @GetMapping("/vulns")
    public String vulns() {
        return "redirect:/lookup";
    }

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
