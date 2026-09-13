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

    @BeforeEach
    void clean() {
        users.deleteAll();
        users.save(new AppUser("root", encoder.encode("root-password"), Role.ADMIN));
    }

    @Test
    @DisplayName("계정을 만들면 비밀번호가 해시로만 남는다")
    void createsWithHashedPassword() {
        AppUser user = accounts.create("alice", "alice-password", Role.VIEWER, "앨리스");

        assertThat(user.getPasswordHash()).doesNotContain("alice-password");
        assertThat(encoder.matches("alice-password", user.getPasswordHash())).isTrue();
        assertThat(user.getRole()).isEqualTo(Role.VIEWER);
    }

    @Test
    @DisplayName("같은 이름은 두 번 만들 수 없다")
    void rejectsDuplicateName() {
        accounts.create("alice", "alice-password", Role.VIEWER, "");
        assertThatThrownBy(() -> accounts.create("alice", "other-password", Role.ADMIN, ""))
                .isInstanceOf(AccountService.AccountException.class)
                .hasMessageContaining("이미 있는");
    }

    @Test
    @DisplayName("짧은 비밀번호는 받지 않는다")
    void rejectsShortPassword() {
        assertThatThrownBy(() -> accounts.create("alice", "short", Role.VIEWER, ""))
                .isInstanceOf(AccountService.AccountException.class)
                .hasMessageContaining("8자 이상");
    }

    @Test
    @DisplayName("이상한 계정 이름은 받지 않는다")
    void rejectsBadName() {
        assertThatThrownBy(() -> accounts.create("../etc/passwd", "a-password", Role.VIEWER, ""))
                .isInstanceOf(AccountService.AccountException.class);
        assertThatThrownBy(() -> accounts.create("", "a-password", Role.VIEWER, ""))
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
        accounts.create("bob", "bob-password", Role.VIEWER, "옛 이름");
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
        accounts.create("carol", "carol-password", Role.VIEWER, "캐롤");
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
        accounts.create("dave", "dave-password", Role.VIEWER, "");
        String changed = accounts.update("dave", "", Role.VIEWER, true, "새비밀번호1234", "root");

        AppUser after = users.findByUsername("dave").orElseThrow();
        assertThat(changed).isEqualTo("비밀번호");
        assertThat(encoder.matches("새비밀번호1234", after.getPasswordHash())).isTrue();
        assertThat(after.isMustChange()).isTrue();
    }

    @Test
    @DisplayName("8자 미만 비밀번호는 거절한다")
    void refusesAShortPassword() {
        accounts.create("erin", "erin-password", Role.VIEWER, "");
        assertThatThrownBy(() -> accounts.update("erin", "", Role.VIEWER, true, "1234567", "root"))
                .isInstanceOf(AccountService.AccountException.class)
                .hasMessageContaining("8자 이상");
    }

    /** 잠긴 계정에 새 비밀번호를 줬는데 잠긴 채면 아무 효과가 없다. */
    @Test
    @DisplayName("새 비밀번호를 주면 잠금도 함께 풀린다")
    void aNewPasswordAlsoUnlocks() {
        accounts.create("frank", "frank-password", Role.VIEWER, "");
        AppUser locked = users.findByUsername("frank").orElseThrow();
        locked.setFailedAttempts(5);
        locked.setLockedAt(java.time.Instant.now());
        users.saveAndFlush(locked);

        accounts.update("frank", "", Role.VIEWER, true, "새비밀번호1234", "root");

        AppUser after = users.findByUsername("frank").orElseThrow();
        assertThat(after.getLockedAt()).isNull();
        assertThat(after.getFailedAttempts()).isZero();
    }

    @Test
    @DisplayName("바뀐 것이 없으면 빈 문자열을 준다")
    void nothingChangedSaysSo() {
        accounts.create("grace", "grace-password", Role.VIEWER, "그레이스");
        assertThat(accounts.update("grace", "그레이스", Role.VIEWER, true, null, "root")).isEmpty();
    }

    @Test
    @DisplayName("자기 계정은 정지할 수 없다")
    void cannotDisableYourself() {
        accounts.create("heidi", "heidi-password", Role.ADMIN, "");
        assertThatThrownBy(() -> accounts.update("heidi", "", Role.ADMIN, false, null, "heidi"))
                .isInstanceOf(AccountService.AccountException.class)
                .hasMessageContaining("자기 계정");
    }

    @Test
    @DisplayName("마지막 관리자는 지울 수 없다")
    void keepsTheLastAdmin() {
        accounts.create("alice", "alice-password", Role.VIEWER, "");
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
        accounts.create("other", "other-password", Role.ADMIN, "");
        accounts.delete("root", "other");
        assertThat(users.findByUsername("root")).isEmpty();
    }

    @Test
    @DisplayName("자기 계정은 지울 수 없다 — 실수로 자기를 내보내지 않게")
    void cannotDeleteSelf() {
        accounts.create("other", "other-password", Role.ADMIN, "");
        assertThatThrownBy(() -> accounts.delete("root", "root"))
                .isInstanceOf(AccountService.AccountException.class)
                .hasMessageContaining("자기 계정");
    }

    // --- 비밀번호 초기화 ------------------------------------------------------

    @Test
    @DisplayName("초기화하면 계정 이름과 같아지고 반드시 바꿔야 한다")
    void resetForcesAChange() {
        accounts.create("alice", "alice-password", Role.VIEWER, "");
        accounts.resetPassword("alice", "root");

        AppUser user = users.findByUsername("alice").orElseThrow();
        // 관리자가 새 비밀번호를 지어내지 않는다 — 지어내면 그것을 전달하는
        // 경로가 또 필요하고 대개 메신저로 흘러간다.
        assertThat(encoder.matches("alice", user.getPasswordHash())).isTrue();
        assertThat(user.isMustChange()).isTrue();
    }
}
