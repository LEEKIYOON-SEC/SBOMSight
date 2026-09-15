package kr.sbomsight.config;

import org.springframework.boot.diagnostics.AbstractFailureAnalyzer;
import org.springframework.boot.diagnostics.FailureAnalysis;

import java.sql.SQLException;

/**
 * DB 접속이 막혔을 때, 무엇을 고쳐야 하는지 한국어로 말한다.
 *
 * <p><b>왜 있는가.</b> MySQL 8 의 기본 인증(<code>caching_sha2_password</code>)은
 * 서버가 <b>메모리에 캐시해 둔 계정</b>에 대해서만 빠른 경로로 인증한다. 그
 * 캐시는 <b>서버가 다시 뜨면 비워진다.</b> 그러면 다음 접속은 전체 인증을 해야
 * 하고, 전체 인증은 TLS 이거나 서버의 RSA 공개키가 있어야 한다. 둘 다 없으면
 * 드라이버가 이렇게 말하고 멈춘다.
 *
 * <pre>
 *   RSA public key is not available client side (option serverRsaPublicKeyFile not set)
 * </pre>
 *
 * <p>겉으로는 <b>몇 달을 잘 돌다가 PC 를 재부팅한 다음 날 아침에 안 뜨는</b>
 * 것으로 나타난다. DB 는 멀쩡히 살아 있고 비밀번호도 맞으므로, 이 문구를 모르면
 * 어디를 봐야 하는지 알 수 없다. 실제로 그렇게 하루를 잃었다.
 *
 * <p>고치는 법은 접속 주소에 옵션 하나를 더하는 것이다. 되풀이되지 않도록
 * 기본값과 예시 파일에도 넣었지만, <b>이미 설치된 곳의
 * <code>config\env.ps1</code> 은 각자 고쳐야 한다</b> — 그 파일이
 * <code>SBOMSIGHT_DB_URL</code> 로 기본값을 덮기 때문이다.
 */
public class DataSourceFailureAnalyzer extends AbstractFailureAnalyzer<SQLException> {

    /** 드라이버가 내는 문구. mariadb-java-client 3.3.4 의 CachingSha2PasswordPlugin. */
    private static final String RSA_KEY_MISSING = "RSA public key is not available";

    @Override
    protected FailureAnalysis analyze(Throwable rootFailure, SQLException cause) {
        String message = cause.getMessage();
        if (message == null || !message.contains(RSA_KEY_MISSING)) {
            return null;
        }
        return new FailureAnalysis("""
                데이터베이스에 로그인하지 못했습니다 — MySQL 8 의 인증 방식 때문입니다.

                MySQL 8 은 한 번 인증한 계정을 서버 메모리에 캐시해 두고, 그 캐시가
                있는 동안에는 간단한 경로로 접속을 받아 줍니다. 그 캐시는 DB 서버가
                다시 뜰 때 비워집니다. 비워진 뒤 첫 접속은 전체 인증을 해야 하는데,
                전체 인증에는 TLS 연결이거나 서버의 RSA 공개키가 필요합니다.

                DB 는 정상입니다. 비밀번호도 맞습니다. 접속 주소에 옵션이 하나
                빠져 있을 뿐입니다.""",
                """
                config\\env.ps1 의 접속 주소 끝에 allowPublicKeyRetrieval=true 를 더하세요.

                  $env:SBOMSIGHT_DB_URL = 'jdbc:mariadb://localhost:3306/sbomsight?\
                sslMode=disable&rewriteBatchedStatements=true&allowPublicKeyRetrieval=true'

                그리고 다시 띄우면 됩니다. 같은 PC 안의 접속(127.0.0.1)이라 공개키를
                받아 오는 경로가 밖으로 나가지 않습니다.

                DB 를 다른 PC 에 두었다면 이 옵션 대신 TLS 로 붙으세요 —
                sslMode=disable 을 sslMode=trust 로 바꾸면 전체 인증이 암호화된
                연결 위에서 이루어지므로 공개키를 따로 받지 않습니다.""",
                cause);
    }
}
