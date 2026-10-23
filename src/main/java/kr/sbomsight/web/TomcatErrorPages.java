package kr.sbomsight.web;

import org.apache.catalina.Context;
import org.apache.catalina.Pipeline;
import org.apache.catalina.Valve;
import org.apache.catalina.valves.ErrorReportValve;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.stereotype.Component;
import org.thymeleaf.ITemplateEngine;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * <b>스프링까지 오지 못한 요청의 오류 화면도 한국어로.</b>
 *
 * <p>주소에 쓸 수 없는 글자가 든 요청({@code /%} · {@code /a%00b} 처럼 복사하다
 * 잘린 주소)은 톰캣이 스프링 앞에서 끊는다. 그래서 {@link ErrorPages} 를 거치지
 * 않고 톰캣의 영문 화면({@code HTTP Status 400 – Bad Request})이 떴다. 톰캣에는
 * 이 화면의 한국어 판도 없다 — 브라우저가 한국어를 청해도 영문이다.
 *
 * <p>톰캣의 오류 보고 밸브는 상태마다 <b>디스크의 HTML 파일</b>을 내보낼 수
 * 있다({@code errorCode.nnn}, 톰캣 문서에 있는 설정이다). 그 파일을 기동할 때
 * 앱의 오류 화면({@code error.html})으로 그려 톰캣 작업 폴더에 둔다 — 모양과
 * 말이 앱 안의 오류 화면과 같다. 400 은 400 의 말로, 그 밖은 상태를 모르는
 * 판으로 그린다.
 *
 * <p>앱이 이미 그린 오류(404 · 403 · 500 …)는 건드리지 않는다. 밸브는 응답에
 * 아무것도 쓰이지 않았을 때만 나선다.
 */
@Component
class TomcatErrorPages implements WebServerFactoryCustomizer<TomcatServletWebServerFactory> {

    private static final Logger log = LoggerFactory.getLogger(TomcatErrorPages.class);

    private final ObjectProvider<ITemplateEngine> templates;

    TomcatErrorPages(ObjectProvider<ITemplateEngine> templates) {
        this.templates = templates;
    }

    @Override
    public void customize(TomcatServletWebServerFactory factory) {
        factory.addContextCustomizers(this::install);
    }

    /**
     * 스프링 부트가 호스트에 달아 둔 오류 보고 밸브(서버 정보 · 보고 끔)에 파일을
     * 건다. 이 조정은 부트의 것보다 뒤에 돈다(순서를 적지 않은 조정은 맨 뒤).
     * 밸브가 없으면 같은 설정으로 하나 단다 — 없으면 톰캣이 보고를 켠 기본
     * 밸브를 단다.
     */
    private void install(Context context) {
        Map<String, String> pages = new LinkedHashMap<>();
        try {
            pages.put("errorCode.400", write(context, "sbomsight-error-400.html", 400));
            pages.put("errorCode.0", write(context, "sbomsight-error.html", null));
        } catch (IOException | RuntimeException e) {
            // 화면을 못 그렸다고 기동을 멈추지 않는다 — 톰캣의 영문 화면이 뜰 뿐이다.
            log.warn("톰캣 앞단 오류 화면을 만들지 못했습니다. 톰캣 기본 화면을 씁니다.", e);
            return;
        }

        Pipeline host = context.getParent().getPipeline();
        boolean found = false;
        for (Valve valve : host.getValves()) {
            if (valve instanceof ErrorReportValve report) {
                pages.forEach(report::setProperty);
                found = true;
            }
        }
        if (!found) {
            ErrorReportValve report = new ErrorReportValve();
            report.setShowServerInfo(false);
            report.setShowReport(false);
            pages.forEach(report::setProperty);
            host.addValve(report);
        }
    }

    /** @return 밸브에 걸 절대 경로 */
    private String write(Context context, String name, Integer status) throws IOException {
        String html = templates.getObject().process("error",
                new org.thymeleaf.context.Context(Locale.KOREAN, ErrorPages.beforeSpring(status)));
        File file = new File(context.getCatalinaBase(), name);
        Files.writeString(file.toPath(), html, StandardCharsets.UTF_8);
        file.deleteOnExit();
        return file.getAbsolutePath();
    }
}
