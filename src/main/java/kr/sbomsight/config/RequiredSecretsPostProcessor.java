package kr.sbomsight.config;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 비밀번호가 없으면 <b>읽을 수 있는 말로</b> 멈춘다.
 *
 * <p><b>왜 있는가.</b> {@code application.yml} 에서 DB·키스토어 비밀번호의
 * 기본값을 뺐다. 기본값이 있으면 환경변수를 안 넣어도 일단 뜨고, 그래서
 * "넣은 줄 알았는데 안 넣은" 설치가 {@code devpass} 로 돌아간다 — 그
 * 비밀번호는 소스만 보면 누구나 안다.
 *
 * <p>그런데 <b>기본값만 빼면 멈추는 말이 엉뚱하다.</b> 실제로 이렇게 멈췄다.
 *
 * <pre>
 *   java.io.IOException: keystore password was incorrect
 *   Caused by: javax.crypto.BadPaddingException: Given final block not properly padded
 * </pre>
 *
 * <p>인증서 파일이 깨진 것으로 읽힌다. 실제로는 환경변수 한 줄이 빠진
 * 것뿐이다. 새벽에 이것을 받아 든 사람은 인증서를 다시 만들기 시작한다.
 *
 * <p>그래서 <b>컨텍스트가 뜨기 전에</b> 본다. {@code EnvironmentPostProcessor}
 * 는 톰캣이 SSL 을 세우기 전에 돌므로, 빠진 이름을 그대로 적어 줄 수 있다.
 *
 * <p>값이 <b>비어 있는 것</b>은 통과시킨다 — 비밀번호 없는 DB 계정은 드물지만
 * 있고, 그것은 우리가 판단할 일이 아니다. 여기서 막는 것은 "정하지 않았다" 이지
 * "짧다" 가 아니다.
 */
public class RequiredSecretsPostProcessor implements EnvironmentPostProcessor, Ordered {

    /** 설정 이름 → 그 자리에 넣는 환경변수 이름. */
    private static final Map<String, String> REQUIRED = new LinkedHashMap<>();

    static {
        REQUIRED.put("spring.datasource.password", "SBOMSIGHT_DB_PASSWORD");
        REQUIRED.put("server.ssl.key-store-password", "SBOMSIGHT_KEYSTORE_PASSWORD");
    }

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment,
                                       SpringApplication application) {
        List<String> missing = new ArrayList<>();
        REQUIRED.forEach((property, variable) -> {
            if (!resolved(environment, property, variable)) {
                missing.add(variable);
            }
        });
        if (missing.isEmpty()) {
            return;
        }
        throw new IllegalStateException("""

                ┌──────────────────────────────────────────────────────────┐
                │  설정하지 않은 값이 있어 기동하지 않았습니다.            │
                └──────────────────────────────────────────────────────────┘

                  없는 것   %s

                이 값들에는 기본값을 두지 않습니다. 기본값이 있으면 넣지 않은
                설치가 그대로 떠 버리고, 소스에 적힌 비밀번호로 돌게 됩니다.

                윈도우   config\\env.ps1 에 적습니다 (보기: scripts\\env.example.ps1)

                    $env:SBOMSIGHT_DB_PASSWORD       = '...'
                    $env:SBOMSIGHT_KEYSTORE_PASSWORD = '...'

                리눅스   띄울 때 환경변수로 줍니다

                    SBOMSIGHT_DB_PASSWORD=... SBOMSIGHT_KEYSTORE_PASSWORD=... \\
                      ./scripts/run-server.sh

                비밀번호가 없는 DB 계정이라면 빈 값으로 두면 됩니다 — 없는 것과
                비운 것은 다릅니다.
                """.formatted(String.join(" · ", missing)));
    }

    /**
     * 그 값이 실제로 정해졌는가.
     *
     * <p>환경변수를 직접 보지 않고 <b>스프링이 읽은 값</b>을 본다 —
     * {@code SPRING_DATASOURCE_PASSWORD} 로 주거나 {@code --spring.datasource
     * .password=} 로 주는 길도 있고, 그것들도 정한 것이다.
     *
     * <p><b>못 푼 자리표시자만 잡는다.</b> 스프링은 풀리지 않은
     * {@code ${…}} 를 글자 그대로 흘려보내는 자리가 있어서, 그대로 두면 그
     * 글자가 비밀번호로 쓰인다 — 실제로 키스토어가 그 글자를 받아
     * {@code keystore password was incorrect} 로 멈췄다.
     *
     * <p>값이 <b>없는 것</b>({@code null})은 잡지 않는다. 시험은 자기
     * {@code application.yml} 로 이 자리를 아예 덮어쓰기 때문이다 — 거기까지
     * 막으면 시험이 한 줄도 못 돈다. 운영 설정에서 이 줄이 통째로 사라지는
     * 쪽은 {@code ProductionHygieneTest} 가 본다.
     */
    private static boolean resolved(ConfigurableEnvironment environment,
                                    String property, String variable) {
        String value;
        try {
            value = environment.getProperty(property);
        } catch (IllegalArgumentException notResolvable) {
            // `Could not resolve placeholder 'SBOMSIGHT_DB_PASSWORD'` — 이 길로
            // 오는 것이 바로 우리가 잡으려는 경우다. 여기서 터지게 두면 이
            // 클래스의 이름이 박힌 스택 트레이스가 나가고, 읽는 사람은 우리
            // 코드가 깨진 것으로 본다.
            return false;
        }
        return value == null || !value.contains("${" + variable + "}");
    }

    /**
     * 설정 파일을 다 읽은 <b>뒤에</b> 본다.
     *
     * <p>{@code ConfigDataEnvironmentPostProcessor} 가 {@code application.yml}
     * 을 올리기 전에 돌면 무엇을 봐도 비어 있다.
     */
    @Override
    public int getOrder() {
        return Ordered.LOWEST_PRECEDENCE;
    }
}
