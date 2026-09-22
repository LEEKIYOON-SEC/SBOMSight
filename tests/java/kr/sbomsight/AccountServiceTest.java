package kr.sbomsight;

import kr.sbomsight.domain.AppUser;
import kr.sbomsight.domain.Role;
import kr.sbomsight.repo.AppUserRepository;
import kr.sbomsight.service.AccountService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import kr.sbomsight.service.PasswordStrength;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 계정 관리.
 *
 * <p>여기서 지키는 것은 <b>관리자를 잃지 않는 것</b>이다. 마지막 관리자를
 * 지우거나 강등하면 웹으로는 되돌릴 방법이 없다.
 */
@SpringBootTest
@Transactional
class AccountServiceTest {

    @Autowired AccountService accounts;
    @Autowired AppUserRepository users;
    @Autowired PasswordEncoder encoder;

    /**
     * 규칙을 통과하는 비밀번호 하나.
     *
     * <p>앞서 씨앗을 {@code "alice-password"} 처럼 <b>계정 이름을 담아</b>
     * 만들고 있었다. `계정 이름이 들어 있으면 받지 않는다` 는 규칙이 생기면서
     * 시험 열넷이 한꺼번에 막혔다 — 규칙이 제 일을 한 것이다.
     */
    private static final String GOOD = "Sbom!2026-pw";

    @BeforeEach
    void clean() {
        users.deleteAll();
        users.save(new AppUser("root", encoder.encode(GOOD), Role.ADMIN));
    }

    @Test
    @DisplayName("계정을 만들면 비밀번호가 해시로만 남는다")
    void createsWithHashedPassword() {
        AppUser user = accounts.create("alice", GOOD, Role.VIEWER, "앨리스");

        assertThat(user.getPasswordHash()).doesNotContain(GOOD);
        assertThat(encoder.matches(GOOD, user.getPasswordHash())).isTrue();
        assertThat(user.getRole()).isEqualTo(Role.VIEWER);
    }

    @Test
    @DisplayName("같은 이름은 두 번 만들 수 없다")
    void rejectsDuplicateName() {
        accounts.create("alice", GOOD, Role.VIEWER, "");
        assertThatThrownBy(() -> accounts.create("alice", GOOD, Role.ADMIN, ""))
                .isInstanceOf(AccountService.AccountException.class)
                .hasMessageContaining("이미 있는");
    }

    /**
     * 약한 비밀번호를 <b>사유별로</b> 막는다.
     *
     * <p>앞서 규칙은 `8자 이상` 하나였고, 그래서 {@code password} 가 통과했다.
     * 지금은 조합을 센다 — 영문·숫자·특수 가운데 셋을 섞으면 8자, 둘이면
     * 10자, 하나면 길어도 받지 않는다.
     */
    @Test
    @DisplayName("약한 비밀번호를 사유별로 막는다")
    void rejectsWeakPasswords() {
        assertThatThrownBy(() -> accounts.create("alice", "short", Role.VIEWER, ""))
                .as("영문만 — 길이와 무관하게 받지 않는다")
                .isInstanceOf(AccountService.AccountException.class)
                .hasMessageContaining("두 가지 이상");
        assertThatThrownBy(() -> accounts.create("alice", "passwordonly", Role.VIEWER, ""))
                .as("길어도 한 가지만 쓰면 받지 않는다")
                .hasMessageContaining("두 가지 이상");
        assertThatThrownBy(() -> accounts.create("alice", "abcd12345", Role.VIEWER, ""))
                .as("두 가지는 10자부터")
                .hasMessageContaining("10자 이상");
        assertThatThrownBy(() -> accounts.create("alice", "Ab!12", Role.VIEWER, ""))
                .as("세 가지도 8자부터")
                .hasMessageContaining("8자 이상");
        assertThatThrownBy(() -> accounts.create("alice", "alice!2026pw", Role.VIEWER, ""))
                .as("계정 이름은 아는 사람이 가장 먼저 넣어 본다")
                .hasMessageContaining("계정 이름");
        assertThatThrownBy(() -> accounts.create("alice", "Sbom!2026aaa", Role.VIEWER, ""))
                .as("같은 글자를 세 번 이어 길이를 채우는 것을 막는다")
                .hasMessageContaining("세 번");

        // 통과하는 것도 함께 못 박는다 — 막는 시험만 있으면 전부 막아도 통과한다.
        assertThat(accounts.create("alice", "Sbom!2026-pw", Role.VIEWER, "").getUsername())
                .isEqualTo("alice");
    }

    @Test
    @DisplayName("이상한 계정 이름은 받지 않는다")
    void rejectsBadName() {
        assertThatThrownBy(() -> accounts.create("../etc/passwd", GOOD, Role.VIEWER, ""))
                .isInstanceOf(AccountService.AccountException.class);
        assertThatThrownBy(() -> accounts.create("", GOOD, Role.VIEWER, ""))
                .isInstanceOf(AccountService.AccountException.class);
    }

    // --- 관리자를 잃지 않는다 ------------------------------------------------

    // --- 수정 ---------------------------------------------------------------

    /**
     * <b>칸마다 따로 바뀐다.</b> 이름만 고치려다 권한이 함께 바뀌거나,
     * 비밀번호 칸을 비워 뒀는데 비밀번호가 지워지면 안 된다.
     */
    @Test
    @DisplayName("이름만 바꾸면 이름만 바뀐다")
    void renamingTouchesNothingElse() {
        accounts.create("bob", GOOD, Role.VIEWER, "옛 이름");
        AppUser before = users.findByUsername("bob").orElseThrow();
        String hash = before.getPasswordHash();

        String changed = accounts.update("bob", "새 이름", Role.VIEWER, true, null, "root");

        AppUser after = users.findByUsername("bob").orElseThrow();
        assertThat(changed).isEqualTo("이름");
        assertThat(after.getDisplayName()).isEqualTo("새 이름");
        assertThat(after.getRole()).isEqualTo(Role.VIEWER);
        assertThat(after.getPasswordHash())
                .as("비밀번호 칸을 비웠는데 비밀번호가 바뀌었다")
                .isEqualTo(hash);
        assertThat(after.isMustChange())
                .as("건드리지도 않았는데 변경을 강제하게 됐다")
                .isFalse();
    }

    @Test
    @DisplayName("권한만 바꾸면 권한만 바뀐다")
    void changingTheRoleTouchesNothingElse() {
        accounts.create("carol", GOOD, Role.VIEWER, "캐롤");
        String changed = accounts.update("carol", "캐롤", Role.ADMIN, true, null, "root");

        AppUser after = users.findByUsername("carol").orElseThrow();
        assertThat(changed).isEqualTo("권한 관리자");
        assertThat(after.getRole()).isEqualTo(Role.ADMIN);
        assertThat(after.getDisplayName()).isEqualTo("캐롤");
    }

    /**
     * 관리자가 정해 준 비밀번호는 <b>본인이 받아서 곧바로 바꾸게</b> 한다.
     * 관리자가 아는 비밀번호를 그대로 쓰게 두지 않는다.
     */
    @Test
    @DisplayName("새 비밀번호를 주면 본인이 다시 바꾸게 된다")
    void anAdminSetPasswordMustBeChangedAgain() {
        accounts.create("dave", GOOD, Role.VIEWER, "");
        String changed = accounts.update("dave", "", Role.VIEWER, true, "새비밀번호!1234", "root");

        AppUser after = users.findByUsername("dave").orElseThrow();
        assertThat(changed).isEqualTo("비밀번호");
        assertThat(encoder.matches("새비밀번호!1234", after.getPasswordHash())).isTrue();
        assertThat(after.isMustChange()).isTrue();
    }

    /** 관리자가 넣어 주는 비밀번호도 <b>같은 규칙</b>을 지난다. */
    @Test
    @DisplayName("관리자가 넣는 비밀번호도 약하면 거절한다")
    void refusesAWeakPassword() {
        accounts.create("erin", GOOD, Role.VIEWER, "");
        assertThatThrownBy(() -> accounts.update("erin", "", Role.VIEWER, true, "1234567", "root"))
                .isInstanceOf(AccountService.AccountException.class)
                .hasMessageContaining("두 가지 이상");
        assertThatThrownBy(() -> accounts.update("erin", "", Role.VIEWER, true, "erin!2026pw", "root"))
                .hasMessageContaining("계정 이름");
    }

    /** 잠긴 계정에 새 비밀번호를 줬는데 잠긴 채면 아무 효과가 없다. */
    @Test
    @DisplayName("새 비밀번호를 주면 잠금도 함께 풀린다")
    void aNewPasswordAlsoUnlocks() {
        accounts.create("frank", GOOD, Role.VIEWER, "");
        AppUser locked = users.findByUsername("frank").orElseThrow();
        locked.setFailedAttempts(5);
        locked.setLockedAt(java.time.Instant.now());
        users.saveAndFlush(locked);

        accounts.update("frank", "", Role.VIEWER, true, "새비밀번호!1234", "root");

        AppUser after = users.findByUsername("frank").orElseThrow();
        assertThat(after.getLockedAt()).isNull();
        assertThat(after.getFailedAttempts()).isZero();
    }

    @Test
    @DisplayName("바뀐 것이 없으면 빈 문자열을 준다")
    void nothingChangedSaysSo() {
        accounts.create("grace", GOOD, Role.VIEWER, "그레이스");
        assertThat(accounts.update("grace", "그레이스", Role.VIEWER, true, null, "root")).isEmpty();
    }

    @Test
    @DisplayName("자기 계정은 정지할 수 없다")
    void cannotDisableYourself() {
        accounts.create("heidi", GOOD, Role.ADMIN, "");
        assertThatThrownBy(() -> accounts.update("heidi", "", Role.ADMIN, false, null, "heidi"))
                .isInstanceOf(AccountService.AccountException.class)
                .hasMessageContaining("자기 계정");
    }

    @Test
    @DisplayName("마지막 관리자는 지울 수 없다")
    void keepsTheLastAdmin() {
        accounts.create("alice", GOOD, Role.VIEWER, "");
        assertThatThrownBy(() -> accounts.delete("root", "alice"))
                .isInstanceOf(AccountService.AccountException.class)
                .hasMessageContaining("마지막 관리자");
    }

    @Test
    @DisplayName("마지막 관리자는 강등할 수 없다")
    void cannotDemoteTheLastAdmin() {
        assertThatThrownBy(() -> accounts.update("root", "", Role.VIEWER, true, null, "root"))
                .isInstanceOf(AccountService.AccountException.class)
                .hasMessageContaining("마지막 관리자");
    }

    @Test
    @DisplayName("마지막 관리자는 정지할 수 없다")
    void cannotDisableTheLastAdmin() {
        assertThatThrownBy(() -> accounts.update("root", "", Role.ADMIN, false, null, "admin2"))
                .isInstanceOf(AccountService.AccountException.class)
                .hasMessageContaining("마지막 관리자");
    }

    @Test
    @DisplayName("관리자가 둘이면 하나는 지울 수 있다")
    void secondAdminFreesTheFirst() {
        accounts.create("other", GOOD, Role.ADMIN, "");
        accounts.delete("root", "other");
        assertThat(users.findByUsername("root")).isEmpty();
    }

    @Test
    @DisplayName("자기 계정은 지울 수 없다 — 실수로 자기를 내보내지 않게")
    void cannotDeleteSelf() {
        accounts.create("other", GOOD, Role.ADMIN, "");
        assertThatThrownBy(() -> accounts.delete("root", "root"))
                .isInstanceOf(AccountService.AccountException.class)
                .hasMessageContaining("자기 계정");
    }

    // --- 비밀번호 초기화 ------------------------------------------------------

    /**
     * 초기화는 <b>임시 비밀번호</b>를 낸다.
     *
     * <p>앞서 <b>계정 이름과 같게</b> 만들고 있었다. 계정 이름은 설정 화면과
     * 감사 로그에 그대로 보이고 대개 사번이다 — 이름을 아는 사람이라면
     * 누구든, 본인이 로그인하기 전에 그 계정으로 들어갈 수 있었다.
     * `반드시 바꾸게` 하는 것도 도움이 되지 않는다: 먼저 들어간 사람이 새
     * 비밀번호를 정하고, 그러면 본인은 못 들어온다.
     */
    @Test
    @DisplayName("초기화하면 임시 비밀번호가 나온다 — 계정 이름이 아니다")
    void resetIssuesAOneTimePassword() {
        accounts.create("alice", GOOD, Role.VIEWER, "");
        String temporary = accounts.resetPassword("alice", "root");

        AppUser user = users.findByUsername("alice").orElseThrow();
        assertThat(encoder.matches("alice", user.getPasswordHash()))
                .as("계정 이름으로 들어갈 수 있으면 이름을 아는 사람이 먼저 들어간다")
                .isFalse();
        assertThat(encoder.matches(temporary, user.getPasswordHash()))
                .as("돌려준 임시 비밀번호로는 들어갈 수 있어야 한다")
                .isTrue();
        assertThat(PasswordStrength.rejection(temporary, "alice"))
                .as("임시 비밀번호가 제 규칙을 어기면 본인이 못 들어온다")
                .isNull();
        // 두 번 초기화하면 서로 다른 것이 나온다.
        assertThat(accounts.resetPassword("alice", "root")).isNotEqualTo(temporary);
        assertThat(user.isMustChange()).isTrue();
    }
}
