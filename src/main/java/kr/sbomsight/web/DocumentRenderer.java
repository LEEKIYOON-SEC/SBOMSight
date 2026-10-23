package kr.sbomsight.web;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.View;
import org.thymeleaf.spring6.view.ThymeleafViewResolver;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Locale;
import java.util.Map;

/**
 * 보고서의 <b>문서 부분</b>을 글자로 그린다 — 발행본에 저장할 것(R11).
 *
 * <p>초안과 <b>같은 화면</b>(report.html · zone-report.html)의 {@code document} 조각을 그린다.
 * 발행본만을 위한 화면을 따로 두면 두 벌이 갈라지는 날이 온다 — 장 하나를 고치며 한쪽만
 * 고친다. 조각 밖의 머리 단추 · 고르개는 그리지 않고, 조각 안에서는 {@code publication}
 * (발행 정보)이 있으면 폼과 관리자 칸을 빼고 문서 정보에 발행 정보를 찍는다.
 *
 * <p>요청을 처리하는 화면과 같은 길(ThymeleafViewResolver)로 그린다 — 링크 · 권한 표시가
 * 그 요청 그대로 풀린다. 응답에는 쓰지 않는다: 쓰는 곳만 가로채고, 머리 · 상태는 손대지
 * 않는다.
 */
@Component
public class DocumentRenderer {

    private final ThymeleafViewResolver views;

    public DocumentRenderer(ThymeleafViewResolver views) {
        this.views = views;
    }

    public String render(String template, Map<String, ?> model,
                         HttpServletRequest request, HttpServletResponse response) {
        try {
            View view = views.resolveViewName(template + " :: document", Locale.KOREAN);
            if (view == null) {
                throw new IllegalStateException("화면을 찾지 못했습니다: " + template);
            }
            Capture capture = new Capture(response);
            view.render(model, request, capture);
            return capture.text();
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("문서를 그리지 못했습니다: " + template, e);
        }
    }

    /** 쓰는 곳만 가로챈다. 머리 · 상태 · 버퍼는 진짜 응답에 닿지 않는다. */
    private static final class Capture extends HttpServletResponseWrapper {

        private final StringWriter out = new StringWriter();
        private final PrintWriter writer = new PrintWriter(out);

        Capture(HttpServletResponse response) {
            super(response);
        }

        String text() {
            writer.flush();
            return out.toString();
        }

        @Override
        public PrintWriter getWriter() {
            return writer;
        }

        @Override
        public ServletOutputStream getOutputStream() {
            throw new IllegalStateException("문서는 글자로만 그린다");
        }

        @Override
        public void flushBuffer() {
            writer.flush();
        }

        @Override
        public boolean isCommitted() {
            return false;
        }

        @Override
        public void reset() {
        }

        @Override
        public void resetBuffer() {
        }

        @Override
        public void setContentType(String type) {
        }

        @Override
        public void setCharacterEncoding(String charset) {
        }

        @Override
        public void setContentLength(int len) {
        }

        @Override
        public void setContentLengthLong(long len) {
        }

        @Override
        public void setLocale(Locale locale) {
        }

        @Override
        public void setStatus(int sc) {
        }

        @Override
        public void setHeader(String name, String value) {
        }

        @Override
        public void addHeader(String name, String value) {
        }

        @Override
        public void setDateHeader(String name, long date) {
        }

        @Override
        public void addDateHeader(String name, long date) {
        }

        @Override
        public void setIntHeader(String name, int value) {
        }

        @Override
        public void addIntHeader(String name, int value) {
        }
    }
}
