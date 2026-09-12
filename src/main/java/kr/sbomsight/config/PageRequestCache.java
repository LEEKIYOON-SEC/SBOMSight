package kr.sbomsight.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * 로그인한 뒤 <b>돌아갈 만한 자리</b>만 기억한다.
 *
 * <p><b>왜 필요한가.</b> 스프링 시큐리티는 로그인 없이 닿은 요청을 기억해
 * 두었다가 로그인에 성공하면 그리로 보낸다. 사람이 주소를 치고 들어왔다가
 * 로그인 화면으로 튕겼을 때 원래 가려던 화면으로 데려다 주는 기능이다.
 *
 * <p>그런데 <b>기억하는 것이 화면이 아닐 수 있다.</b> 로그인 화면이 글꼴을
 * 불러오는데 그 글꼴 경로가 열려 있지 않으면, 브라우저의 글꼴 요청이
 * "로그인 없이 닿은 요청" 으로 기억된다. 그 뒤 로그인에 성공하면 스프링은
 * 약속대로 그리로 보내고 — 브라우저는 <b>글꼴 파일을 내려받는다.</b>
 * 로그인은 성공했는데 화면은 열리지 않고 아무 반응이 없다.
 *
 * <p>실제로 그렇게 만들었다. 글꼴을 저장소에 담으면서 {@code /fonts/**} 를
 * 열어 두지 않았고, 로그아웃한 뒤 다시 로그인하면 woff2 파일이 떨어졌다.
 *
 * <p>경로를 여는 것만으로는 부족하다. 그것은 이번 한 건을 막을 뿐이고, 화면이
 * 아닌 요청이 하나 더 생기면 같은 일이 다시 난다. 그래서 <b>기억할 자격</b>을
 * 여기서 못 박는다 — 사람이 브라우저 주소창으로 갈 수 있는 자리만 기억한다.
 */
public class PageRequestCache extends HttpSessionRequestCache {

    public PageRequestCache() {
        setRequestMatcher(new PageMatcher());
    }

    /**
     * 사람이 볼 화면을 요청한 것인가.
     *
     * <ul>
     *   <li>GET 이어야 한다 — POST 를 기억해 두었다 다시 보내면 같은 동작이
     *       두 번 실행된다.</li>
     *   <li>브라우저가 HTML 을 원한다고 말해야 한다. 글꼴·CSS·이미지·JSON 은
     *       {@code Accept} 가 다르다.</li>
     *   <li>자바스크립트가 뒤에서 부른 것이면 안 된다 — 진행 상태를 묻는
     *       요청 같은 것이 기억되면 로그인 후 JSON 한 덩이가 뜬다.</li>
     * </ul>
     */
    static final class PageMatcher implements RequestMatcher {

        @Override
        public boolean matches(HttpServletRequest request) {
            if (!"GET".equalsIgnoreCase(request.getMethod())) {
                return false;
            }
            if ("XMLHttpRequest".equals(request.getHeader("X-Requested-With"))) {
                return false;
            }
            String accept = request.getHeader("Accept");
            if (accept == null || !accept.contains("text/html")) {
                return false;
            }
            // 로그인 화면 자신과 로그아웃은 기억해도 갈 곳이 못 된다.
            String path = request.getRequestURI();
            if (request.getContextPath() != null && !request.getContextPath().isEmpty()) {
                path = path.substring(request.getContextPath().length());
            }
            return !path.startsWith("/login") && !path.startsWith("/logout");
        }
    }
}
