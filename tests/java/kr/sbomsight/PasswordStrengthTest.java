package kr.sbomsight;

import kr.sbomsight.service.PasswordStrength;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 비밀번호로 쓸 수 있는 글자인가.
 *
 * <p>앞서 규칙은 <b>길이 8자</b> 하나였고, 그 규칙은 <b>두 군데에 따로</b>
 * 적혀 있었다({@code AuthController.MIN_LENGTH} · {@code
 * AccountService.MIN_PASSWORD_LENGTH}). 길이만 보면 {@code password} 가
 * 통과한다 — 금융권 점검이 요구하는 것은 문자 종류의 조합이다.
 */
class PasswordStrengthTest {

    @Test
    @DisplayName("세 가지를 섞으면 8자부터 받는다")
    void threeKindsFromEight() {
        assertThat(PasswordStrength.rejection("Ab!12345", "alice")).isNull();
        assertThat(PasswordStrength.rejection("Ab!1234", "alice"))
                .as("한 자 모자라면 받지 않는다").contains("8자 이상");
    }

    @Test
    @DisplayName("두 가지만 섞으면 10자부터 받는다")
    void twoKindsFromTen() {
        assertThat(PasswordStrength.rejection("abcd123456", "alice")).isNull();
        assertThat(PasswordStrength.rejection("abcd12345", "alice"))
                .as("두 가지는 9자로 모자라다").contains("10자 이상");
    }

    /** 길이로 대신할 수 없다 — 이것이 길이 규칙만 두었을 때 새던 자리다. */
    @Test
    @DisplayName("한 가지만 쓰면 길어도 받지 않는다")
    void oneKindIsNeverEnough() {
        assertThat(PasswordStrength.rejection("password", "alice"))
                .contains("두 가지 이상");
        assertThat(PasswordStrength.rejection("passwordpasswordpassword", "alice"))
                .as("24자여도 영문 하나뿐이면 받지 않는다")
                .contains("두 가지 이상");
        assertThat(PasswordStrength.rejection("1234567890123", "alice"))
                .as("숫자만도 같다")
                .contains("두 가지 이상");
    }

    /**
     * 계정 이름을 담지 않는다.
     *
     * <p>이 도구의 계정 이름은 사번이나 이름이고, 설정 화면과 감사 로그에
     * 그대로 보인다. 아는 사람이 가장 먼저 넣어 보는 것이다.
     */
    @Test
    @DisplayName("계정 이름이 들어 있으면 받지 않는다 — 대소문자를 가리지 않고")
    void theUsernameIsNotAllowedInside() {
        assertThat(PasswordStrength.rejection("alice!2026pw", "alice")).contains("계정 이름");
        assertThat(PasswordStrength.rejection("xxALICExx!12", "alice"))
                .as("대문자로 적어도 같다").contains("계정 이름");
        assertThat(PasswordStrength.rejection("Sbom!2026-pw", "alice"))
                .as("다른 계정 이름은 걸리지 않는다").isNull();
        assertThat(PasswordStrength.rejection("Sbom!2026-pw", null))
                .as("계정 이름을 모르는 자리에서도 판단할 수 있어야 한다").isNull();
    }

    @Test
    @DisplayName("같은 글자를 세 번 이어 쓰면 받지 않는다")
    void noRunOfThree() {
        assertThat(PasswordStrength.rejection("Sbom!2026aaa", "alice")).contains("세 번");
        assertThat(PasswordStrength.rejection("Ab!111234", "alice")).contains("세 번");
        assertThat(PasswordStrength.rejection("Ab!112234", "alice"))
                .as("두 번은 받는다 — 세 번을 허용하면 길이를 채우는 수단이 된다")
                .isNull();
    }

    @Test
    @DisplayName("빈 값은 사유를 말한다")
    void blankSaysWhy() {
        assertThat(PasswordStrength.rejection(null, "alice")).isNotNull();
        assertThat(PasswordStrength.rejection("", "alice")).isNotNull();
        assertThat(PasswordStrength.rejection("   ", "alice")).isNotNull();
    }

    /**
     * 임시 비밀번호는 <b>제 규칙을 지킨다.</b>
     *
     * <p>지키지 않으면 본인이 그것으로 로그인한 뒤 변경 화면에서 막히는
     * 것이 아니라, 애초에 로그인이 되지 않는다.
     */
    @Test
    @DisplayName("임시 비밀번호는 규칙을 지키고 매번 다르다")
    void theTemporaryPasswordObeysTheRules() {
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 200; i++) {
            String temporary = PasswordStrength.temporary();
            assertThat(PasswordStrength.rejection(temporary, "alice"))
                    .as("임시 비밀번호가 규칙을 어기면 본인이 못 들어옵니다: " + temporary)
                    .isNull();
            seen.add(temporary);
        }
        assertThat(seen).as("200번에 겹치는 것이 있으면 난수가 아닙니다").hasSize(200);
    }

    /**
     * <b>규칙이 한 곳에만 있다.</b>
     *
     * <p>앞서 두 군데에 8 이 적혀 있었다. 같은 규칙을 두 벌 두면 한쪽만
     * 고치는 날이 오고, 그때부터 스스로 바꾸는 길과 관리자가 넣어 주는
     * 길의 기준이 달라진다.
     */
    @Test
    @DisplayName("길이 기준이 PasswordStrength 밖에 적혀 있지 않다")
    void theRuleLivesInOnePlace() throws IOException {
        for (String name : new String[] {
                "src/main/java/kr/sbomsight/web/AuthController.java",
                "src/main/java/kr/sbomsight/service/AccountService.java" }) {
            assertThat(Files.readString(Path.of(name)))
                    .as("%s 가 길이 기준을 따로 들고 있습니다", name)
                    .doesNotContain("MIN_LENGTH")
                    .doesNotContain("MIN_PASSWORD_LENGTH");
        }
    }
}
