package kr.sbomsight;

import kr.sbomsight.config.DataSourceFailureAnalyzer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.boot.diagnostics.FailureAnalysis;
import org.springframework.boot.diagnostics.FailureAnalyzer;
import org.springframework.core.io.support.SpringFactoriesLoader;

import java.sql.SQLException;
import java.sql.SQLInvalidAuthorizationSpecException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 기동이 막혔을 때 무엇을 고쳐야 하는지 화면에 뜨는가.
 *
 * <p>실 PC 에서 하루를 잃은 자리다. DB 는 살아 있고 비밀번호도 맞는데
 * <b>DB 서버가 재부팅된 다음 날부터</b> 기동이 안 됐다. 원인은 MySQL 8 의
 * 인증 캐시가 비워져 전체 인증이 필요해진 것이고, 드라이버가 낸 문구는
 * 영어 한 줄("RSA public key is not available...")뿐이었다.
 */
class DataSourceFailureAnalyzerTest {

    /** 드라이버가 실제로 내는 모양 — 바깥은 접속 실패, 안에 진짜 이유가 있다. */
    private static Throwable realFailure() {
        SQLException inner = new SQLException(
                "RSA public key is not available client side (option serverRsaPublicKeyFile not set)");
        SQLException outer = new SQLInvalidAuthorizationSpecException(
                "Could not connect to address=(host=localhost)(port=3306)(type=master) : "
                + "RSA public key is not available client side (option serverRsaPublicKeyFile not set)",
                "S1009", inner);
        return new BeanCreationException("dataSource", "DB 를 열지 못했습니다", outer);
    }

    @Test
    @DisplayName("RSA 공개키 오류에 무엇을 고칠지 한국어로 답한다")
    void explainsTheRsaFailure() {
        FailureAnalysis analysis = new DataSourceFailureAnalyzer().analyze(realFailure());

        assertThat(analysis).as("이 오류를 아무도 설명하지 않으면 영어 한 줄만 남는다").isNotNull();
        assertThat(analysis.getDescription())
                .contains("데이터베이스에 로그인하지 못했습니다")
                .contains("다시 뜰 때 비워집니다");
        // 고치는 한 줄이 그 자리에 있어야 한다. "설정을 확인하세요" 는 답이 아니다.
        assertThat(analysis.getAction())
                .contains("allowPublicKeyRetrieval=true")
                .contains("config\\env.ps1");
    }

    @Test
    @DisplayName("다른 DB 오류는 가로채지 않는다")
    void leavesOtherFailuresAlone() {
        Throwable other = new BeanCreationException("dataSource", "x",
                new SQLException("Access denied for user 'sbomsight'@'localhost'"));

        assertThat(new DataSourceFailureAnalyzer().analyze(other))
                .as("비밀번호가 틀린 것까지 이 문구로 답하면 엉뚱한 곳을 고치게 된다")
                .isNull();
    }

    @Test
    @DisplayName("spring.factories 에 등록되어 실제로 불린다")
    void isRegistered() {
        // 스프링 부트가 등록해 둔 분석기 중에는 생성자에 BeanFactory 를 요구하는
        // 것이 있어, 여기서 전부 만들려 들면 그쪽에서 먼저 터진다. 만들지 못한
        // 것은 넘기고, 우리 것이 그 목록에 있는지만 본다.
        List<FailureAnalyzer> loaded = SpringFactoriesLoader
                .forDefaultResourceLocation(getClass().getClassLoader())
                .load(FailureAnalyzer.class, (type, name, failure) -> { });

        assertThat(loaded)
                .as("등록되지 않으면 이 클래스는 아무 때도 불리지 않는다")
                .anyMatch(DataSourceFailureAnalyzer.class::isInstance);
    }
}
