package kr.sbomsight;

import kr.sbomsight.domain.CvssVector;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * CVSS 벡터 해석.
 *
 * <p>여기서 고정하는 것은 <b>읽을 수 없는 것을 읽은 척하지 않는다</b>는 것이다.
 * 벡터가 없거나 2.0 이면 빈 값이 나와야 하고, 호출부는 그것을 "해당 없음"이
 * 아니라 "판단 불가"로 세야 한다. 없는 것을 아니오로 채우면 보고서가
 * "원격에서 닿지 않습니다" 라는, 아무도 확인하지 않은 말을 하게 된다.
 */
class CvssVectorTest {

    @Test
    @DisplayName("3.1 벡터를 항목별로 읽는다")
    void readsAThreeOneVector() {
        // 실제 grype 0.87 이 CVE-2021-44228 에 준 벡터.
        CvssVector v = CvssVector.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H").orElseThrow();

        assertThat(v.attackVector()).isEqualTo("N");
        assertThat(v.attackComplexity()).isEqualTo("L");
        assertThat(v.privilegesRequired()).isEqualTo("N");
        assertThat(v.userInteraction()).isEqualTo("N");
        assertThat(v.scope()).isEqualTo("C");

        assertThat(v.networkAttackable()).isTrue();
        assertThat(v.noPrivileges()).isTrue();
        assertThat(v.noUserInteraction()).isTrue();
        assertThat(v.scopeChanged()).isTrue();
        assertThat(v.directlyReachable()).isTrue();
    }

    @Test
    @DisplayName("3.0 도 읽는다")
    void readsAThreeZeroVector() {
        CvssVector v = CvssVector.parse("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N").orElseThrow();
        assertThat(v.directlyReachable()).isTrue();
        assertThat(v.scopeChanged()).isFalse();
    }

    @Test
    @DisplayName("사용자 개입이 필요하면 '바로 닿는 것'이 아니다")
    void userInteractionBreaksDirectReach() {
        CvssVector v = CvssVector.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H").orElseThrow();
        assertThat(v.networkAttackable()).isTrue();
        assertThat(v.noUserInteraction()).isFalse();
        assertThat(v.directlyReachable()).isFalse();
    }

    @Test
    @DisplayName("권한이 필요하면 '바로 닿는 것'이 아니다")
    void privilegesBreakDirectReach() {
        CvssVector v = CvssVector.parse("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H").orElseThrow();
        assertThat(v.noPrivileges()).isFalse();
        assertThat(v.directlyReachable()).isFalse();
    }

    @Test
    @DisplayName("로컬 공격은 원격이 아니다")
    void localIsNotNetwork() {
        CvssVector v = CvssVector.parse("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H").orElseThrow();
        assertThat(v.networkAttackable()).isFalse();
        assertThat(v.directlyReachable()).isFalse();
    }

    /**
     * 2.0 은 Au(인증)를 쓰고 UI·S 가 없다. 3.x 인 척 읽으면 없는 항목을
     * 채우게 되므로 아예 읽지 않는다.
     */
    @Test
    @DisplayName("CVSS 2.0 은 읽지 않는다")
    void refusesCvss2() {
        assertThat(CvssVector.parse("AV:N/AC:L/Au:N/C:P/I:P/A:P")).isEmpty();
        assertThat(CvssVector.parse("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P")).isEmpty();
    }

    @Test
    @DisplayName("항목이 빠진 3.x 벡터도 읽지 않는다")
    void refusesAnIncompleteVector() {
        // S 가 없다. 반쯤 읽어 두면 그 빈칸이 나중에 조용히 굳는다.
        assertThat(CvssVector.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N")).isEmpty();
    }

    @Test
    @DisplayName("없거나 빈 값은 빈 결과다")
    void handlesMissing() {
        assertThat(CvssVector.parse(null)).isEmpty();
        assertThat(CvssVector.parse("")).isEmpty();
        assertThat(CvssVector.parse("   ")).isEmpty();
        assertThat(CvssVector.parse("말이 안 되는 값")).isEmpty();
    }

    /**
     * 실제 98건짜리 스캔에서 확인한 수. 이 시험이 깨지면 해석이 바뀐 것이다.
     */
    @Test
    @DisplayName("실제 grype 출력의 벡터 분포와 맞는다")
    void matchesTheRealScan() {
        String[] real = {
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",   // log4j-core, 바로 닿음
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",   // commons-text, 바로 닿음
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",   // 개입 필요
            "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"    // 로컬
        };
        long reachable = 0;
        for (String raw : real) {
            Optional<CvssVector> v = CvssVector.parse(raw);
            assertThat(v).as("%s 를 읽지 못했다", raw).isPresent();
            if (v.get().directlyReachable()) {
                reachable++;
            }
        }
        assertThat(reachable).isEqualTo(2);
    }
}
