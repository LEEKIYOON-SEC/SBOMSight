package kr.sbomsight.web;

import kr.sbomsight.domain.RemediationStatus;
import kr.sbomsight.repo.AppUserRepository;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.RemediationRepository;
import kr.sbomsight.repo.FindingAnalysisRepository;
import kr.sbomsight.service.PasswordPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

import java.time.LocalDate;
import java.util.List;

/**
 * 모든 화면의 왼쪽 기둥이 쓰는 값.
 *
 * <p><b>숫자를 메뉴에 붙이는 이유.</b> 누르기 전에 거기 무엇이 있는지 알아야
 * 한다. "조치" 만 적혀 있으면 매번 눌러서 확인하게 되고, 기한이 지난 것이
 * 생겨도 그 화면을 열기 전까지는 아무 데서도 보이지 않는다.
 *
 * <p>화면마다 같은 질의를 다시 짜지 않도록 여기 한 곳에서 담는다. 전부
 * 집계 질의라 한 화면에 다섯 번 왕복한다 — 목록을 끌어와 세는 것이 아니다.
 */
@ControllerAdvice
public class LayoutAdvice {

    private static final List<RemediationStatus> OPEN =
            List.of(RemediationStatus.OPEN, RemediationStatus.IN_PROGRESS);

    private final AppUserRepository users;
    private final PasswordPolicy policy;
    private final AssetRepository assets;
    private final RemediationRepository remediations;
    private final FindingAnalysisRepository analyses;

    public LayoutAdvice(AppUserRepository users, PasswordPolicy policy,
                        AssetRepository assets, RemediationRepository remediations,
                        FindingAnalysisRepository analyses) {
        this.users = users;
        this.policy = policy;
        this.assets = assets;
        this.remediations = remediations;
        this.analyses = analyses;
    }

    @ModelAttribute
    @Transactional(readOnly = true)
    public void layout(Authentication auth, Model model) {
        boolean signedIn = auth != null
                && auth.isAuthenticated()
                && !auth.getPrincipal().equals("anonymousUser");

        boolean locked = signedIn
                && users.findByUsername(auth.getName()).map(policy::mustChange).orElse(false);
        model.addAttribute("passwordLocked", locked);

        // 로그인 전이거나 초기 비밀번호에 붙잡혀 있으면 기둥 자체를 그리지
        // 않는다. 값을 담아 봐야 화면에 쓰이지 않고, 질의만 늘어난다.
        if (!signedIn || locked) {
            return;
        }

        LocalDate today = LocalDate.now();

        model.addAttribute("navAssetCount", assets.findLiveWithZone().size());

        // 대응 배지는 하나다. 앞서는 '조치' 와 '위험 수용' 이 기둥에서 갈라져
        // 있어 어느 쪽이 급한지 두 번 봐야 했고, 두 화면을 하나로 합치면서
        // 숫자도 합친다. 기한이 지난 것 = 조치 기한 + 재검토일.
        model.addAttribute("navActionOverdue",
                remediations.countOverdue(today) + analyses.countReviewOverdue(today));
        model.addAttribute("navActionOpen", remediations.countByStatusIn(OPEN));
        model.addAttribute("navInitials", initials(auth.getName()));
    }

    /**
     * 이름표에 넣을 머리글자.
     *
     * <p>한글 이름이면 첫 글자 하나다 — "이기윤" 을 "이기" 로 자르면 성씨도
     * 이름도 아닌 것이 된다. 영문 아이디는 점·밑줄로 나눠 두 글자를 쓴다.
     */
    static String initials(String username) {
        if (username == null || username.isBlank()) {
            return "?";
        }
        String name = username.trim();
        if (name.codePointAt(0) >= 0xAC00 && name.codePointAt(0) <= 0xD7A3) {
            return name.substring(0, 1);
        }
        String[] parts = name.split("[._\\-\\s]+");
        if (parts.length >= 2 && !parts[0].isEmpty() && !parts[1].isEmpty()) {
            return (parts[0].charAt(0) + "" + parts[1].charAt(0)).toUpperCase();
        }
        return name.substring(0, Math.min(2, name.length())).toUpperCase();
    }
}
