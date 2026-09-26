package kr.sbomsight.web;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.autoconfigure.web.servlet.error.ErrorViewResolver;
import org.springframework.boot.web.servlet.error.ErrorAttributes;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.csrf.CsrfException;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.ModelAndView;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * 오류 화면 — <b>한국어로, 무엇을 하면 되는지까지.</b>
 *
 * <p>앞서 404 · 400 · 405 · 403 · 500 이 전부 스프링 부트의 영문 기본 화면
 * ({@code Whitelabel Error Page})이었다. 옛 주소를 걷은 뒤로는 옛 즐겨찾기도
 * 그 화면을 봤다(ErrorPageTest).
 *
 * <p>스프링의 오류 처리는 그대로 둔다 — 화면이 아닌 요청(JSON)에는 지금처럼
 * JSON 이 나간다. 여기서는 <b>화면으로 나갈 때의 말</b>만 정한다. 화면은
 * {@code error.html} 이다.
 *
 * <p><b>안의 사정은 내보내지 않는다</b>(application.yml 의 {@code server.error.*}).
 * 예외 문구에는 테이블 이름과 질의가 들어 있을 수 있다. 사유를 보여 주는 것은
 * <b>우리가 적은 {@link ResponseStatusException} 사유</b>뿐이다 — "자산을 찾을
 * 수 없습니다." 처럼 화면에 내려고 적은 글이다.
 */
@Component
public class ErrorPages implements ErrorViewResolver {

    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final ErrorAttributes errors;

    public ErrorPages(ErrorAttributes errors) {
        this.errors = errors;
    }

    /** 화면에 찍는 것 — 제목 한 줄, 설명 한 줄. */
    record Page(String title, String detail) {
    }

    @Override
    public ModelAndView resolveErrorView(HttpServletRequest request, HttpStatus status,
                                         Map<String, Object> model) {
        Page page = page(request, status);
        Map<String, Object> out = new HashMap<>();
        out.put("status", status.value());
        out.put("title", page.title());
        out.put("detail", page.detail());
        // 서버 쪽 오류에만 시각을 찍는다 — 기록(로그)에서 그 줄을 찾는 열쇠다.
        // 서버 기록과 같은 시계(이 PC 의 시간대)로 찍는다.
        out.put("time", status.is5xxServerError() ? LocalDateTime.now().format(TIME) : null);
        return new ModelAndView("error", out, status);
    }

    private Page page(HttpServletRequest request, HttpStatus status) {
        return switch (status.value()) {
            case 400 -> new Page("요청을 처리할 수 없습니다",
                    "주소에 든 값이 올바르지 않습니다. 화면의 링크로 다시 열어 주세요.");
            // 403 은 둘이다. 관리자만 하는 일을 조회 계정이 했거나(주소 규칙 ·
            // @PreAuthorize), 폼의 보안 확인 값이 세션과 맞지 않거나(CSRF).
            // 뒤의 것을 "관리자만" 이라고 하면 관리자가 자기 권한을 의심한다.
            case 403 -> staleForm(request)
                    ? new Page("요청을 받지 못했습니다",
                            "이 화면을 연 뒤에 다시 로그인했으면 이렇게 됩니다. 화면을 새로 고친 뒤 다시 해 주세요.")
                    : new Page("권한이 없습니다", "이 작업은 관리자 계정만 할 수 있습니다.");
            case 404 -> new Page("찾을 수 없습니다", reason(request)
                    .orElse("주소가 바뀌었거나, 가리키던 자산 · 검사 · 조치가 지워졌을 수 있습니다."));
            // 이 도구에서 405 는 거의 언제나 단추(POST)의 주소를 주소창(GET)으로
            // 연 것이다 — 폼이 남긴 주소를 복사해 두었거나 즐겨찾기에 넣은 경우.
            case 405 -> new Page("주소창으로 열 수 없는 주소입니다",
                    "화면의 단추로 하는 작업(다시 검사 · 삭제 등)의 주소입니다.");
            default -> status.is5xxServerError()
                    ? new Page("처리하지 못했습니다",
                            "되풀이되면 아래 시각을 관리자에게 알려 주세요. 서버 기록에 그 시각의 자세한 내용이 남습니다.")
                    : new Page("요청을 처리할 수 없습니다", "");
        };
    }

    /**
     * 폼의 보안 확인 값(CSRF)이 맞지 않아 막힌 것인가. 스프링 시큐리티가 막을 때
     * 그 예외를 요청에 얹어 두고 오류 화면으로 넘긴다.
     */
    private static boolean staleForm(HttpServletRequest request) {
        return request.getAttribute(WebAttributes.ACCESS_DENIED_403) instanceof CsrfException;
    }

    /**
     * 우리가 적은 사유 — {@link ResponseStatusException} 의 사유, 또는 예외 종류에
     * {@link ResponseStatus} 로 박아 둔 사유({@code ZoneService.NoSuchZoneException}).
     * 다른 예외의 문구는 내보내지 않는다.
     */
    private Optional<String> reason(HttpServletRequest request) {
        Throwable error = errors.getError(new ServletWebRequest(request));
        if (error instanceof ResponseStatusException rse
                && rse.getReason() != null && !rse.getReason().isBlank()) {
            return Optional.of(rse.getReason());
        }
        ResponseStatus declared = error == null ? null
                : AnnotatedElementUtils.findMergedAnnotation(error.getClass(), ResponseStatus.class);
        if (declared != null && !declared.reason().isBlank()) {
            return Optional.of(declared.reason());
        }
        return Optional.empty();
    }
}
