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
        assertThatThrownBy(() -> accounts.changeRole("root", Role.VIEWER, "root"))
                .isInstanceOf(AccountService.AccountException.class)
                .hasMessageContaining("마지막 관리자");
    }

    @Test
    @DisplayName("마지막 관리자는 정지할 수 없다")
    void cannotDisableTheLastAdmin() {
        assertThatThrownBy(() -> accounts.setEnabled("root", false, "root"))
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
