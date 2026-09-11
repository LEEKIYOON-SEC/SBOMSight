package kr.sbomsight;

import kr.sbomsight.config.SbomSightProperties;
import kr.sbomsight.domain.AppUser;
import kr.sbomsight.domain.PasswordChangeReason;
import kr.sbomsight.domain.Role;
import kr.sbomsight.repo.AppUserRepository;
import kr.sbomsight.service.AccountService;
import kr.sbomsight.service.PasswordPolicy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 비밀번호 변경 주기.
 *
 * <p>여기서 고정하는 것:
 * <ol>
 *   <li>주기가 지나면 실제로 붙잡힌다.</li>
 *   <li><b>바꾸면 풀린다.</b> 변경 시각을 옮기지 않으면 바꿔도 계속 만료
 *       상태라 그 화면에서 나올 수 없다 — 도구를 아예 못 쓰게 만드는 버그다.</li>
 *   <li>이유가 경우에 맞다. 관리자가 방금 초기화한 계정에게 "주기가
 *       지났습니다" 라고 말하면 사실과 다르다.</li>
 * </ol>
 */
@SpringBootTest
@AutoConfigureMockMvc
class PasswordPolicyTest {

    private static final String NAME = "policy.test";
    private static final String PASSWORD = "정상-비밀번호-2026";

    @Autowired MockMvc mvc;
    @Autowired AppUserRepository users;
    @Autowired PasswordEncoder encoder;
    @Autowired PasswordPolicy policy;
    @Autowired AccountService accounts;
    @Autowired SbomSightProperties properties;

    /**
     * 지우고 다시 만드는 대신 있으면 되쓴다.
     *
     * <p>이 시험들은 트랜잭션 밖에서 돌기 때문에(진짜 로그인·리다이렉트
     * 흐름을 태우려면 커밋되어야 한다) 삭제가 flush 되기 전에 삽입이 일어나
     * 유니크 제약에 걸렸다. 되쓰는 쪽이 멱등하고 경합이 없다.
     */
    @BeforeEach
    void setUp() {
        AppUser user = users.findByUsername(NAME)
                .orElseGet(() -> new AppUser(NAME, encoder.encode(PASSWORD), Role.ADMIN));
        user.setPasswordHash(encoder.encode(PASSWORD));
        user.setRole(Role.ADMIN);
        user.setEnabled(true);
        user.setMustChange(false);
        user.setFailedAttempts(0);
        user.setLockedAt(null);
        user.setLastLoginAt(Instant.now());
        user.setPasswordChangedAt(Instant.now());
        users.saveAndFlush(user);
    }

    private AppUser reload() {
        return users.findByUsername(NAME).orElseThrow();
    }

    private void agePassword(long days) {
        AppUser user = reload();
        user.setPasswordChangedAt(Instant.now().minus(days, ChronoUnit.DAYS));
        users.save(user);
    }

    // --- 이유 판정 ----------------------------------------------------------

    @Test
    @DisplayName("갓 바꾼 비밀번호는 붙잡히지 않는다")
    void freshPasswordIsFine() {
        assertThat(policy.mustChange(reload())).isFalse();
        assertThat(policy.reasonFor(reload())).isEqualTo(PasswordChangeReason.VOLUNTARY);
    }

    @Test
    @DisplayName("주기가 지나면 만료로 붙잡힌다")
    void expiresAfterTheWindow() {
        agePassword(properties.passwordMaxAgeDays() + 1);

        assertThat(policy.mustChange(reload())).isTrue();
        assertThat(policy.forcedReason(reload())).isEqualTo(PasswordChangeReason.EXPIRED);
    }

    @Test
    @DisplayName("주기 하루 전에는 아직 괜찮다")
    void notYetExpiredTheDayBefore() {
        agePassword(properties.passwordMaxAgeDays() - 1);
        assertThat(policy.mustChange(reload())).isFalse();
    }

    @Test
    @DisplayName("한 번도 로그인한 적 없으면 '최초 로그인' 이다")
    void firstLoginIsItsOwnCase() {
        AppUser user = reload();
        user.setMustChange(true);
        user.setLastLoginAt(null);
        users.save(user);

        assertThat(policy.forcedReason(reload())).isEqualTo(PasswordChangeReason.FIRST_LOGIN);
    }

    @Test
    @DisplayName("쓰던 계정을 초기화한 것은 '임시 비밀번호' 다")
    void resetIsTemporary() {
        AppUser user = reload();
        user.setMustChange(true);
        user.setLastLoginAt(Instant.now());
        users.save(user);

        assertThat(policy.forcedReason(reload())).isEqualTo(PasswordChangeReason.TEMPORARY);
    }

    /**
     * 관리자가 방금 초기화한 계정에게 "주기가 지났습니다" 라고 말하면 사실과
     * 다르다. mustChange 가 만료보다 앞선다.
     */
    @Test
    @DisplayName("초기화와 만료가 겹치면 초기화가 먼저다")
    void resetWinsOverExpiry() {
        agePassword(properties.passwordMaxAgeDays() + 10);
        AppUser user = reload();
        user.setMustChange(true);
        users.save(user);

        assertThat(policy.forcedReason(reload())).isEqualTo(PasswordChangeReason.TEMPORARY);
    }

    /**
     * 마이그레이션이 모든 계정에 값을 채워 두므로 이 값이 없다는 것은 무언가
     * 어긋난 상태다. "아직 괜찮다" 로 읽으면 통제가 조용히 꺼지고 아무도
     * 그것을 모른다.
     */
    @Test
    @DisplayName("변경 시각이 없으면 지난 것으로 본다")
    void missingTimestampCountsAsExpired() {
        AppUser user = reload();
        user.setPasswordChangedAt(null);
        users.save(user);

        assertThat(policy.isExpired(reload())).isTrue();
    }

    // --- 실제 흐름 ----------------------------------------------------------

    @Test
    @DisplayName("만료된 계정은 다른 화면을 열 수 없다")
    void expiredUserIsHeldAtThePasswordScreen() throws Exception {
        agePassword(properties.passwordMaxAgeDays() + 1);

        mvc.perform(get("/").with(user(NAME).roles("ADMIN")))
           .andExpect(redirectedUrl("/password"));
        mvc.perform(get("/password").with(user(NAME).roles("ADMIN")))
           .andExpect(status().isOk());
    }

    /**
     * 이 시험이 가장 중요하다. 변경 시각을 옮기지 않으면 바꿔도 계속 만료
     * 상태라 변경 화면에서 나올 수 없다 — 도구를 아예 못 쓰게 된다.
     */
    @Test
    @DisplayName("바꾸면 풀려서 다른 화면이 열린다")
    void changingThePasswordReleasesTheHold() throws Exception {
        agePassword(properties.passwordMaxAgeDays() + 1);

        mvc.perform(post("/password").with(user(NAME).roles("ADMIN")).with(csrf())
                        .param("current", PASSWORD)
                        .param("password", "새-비밀번호-2026")
                        .param("confirm", "새-비밀번호-2026"))
           .andExpect(redirectedUrl("/"));

        assertThat(policy.isExpired(reload())).as("바꿨는데도 만료 상태다").isFalse();
        assertThat(policy.mustChange(reload())).isFalse();

        mvc.perform(get("/").with(user(NAME).roles("ADMIN")))
           .andExpect(status().isOk());
    }

    @Test
    @DisplayName("만료 화면에 경우에 맞는 문구가 나온다")
    void showsTheRightCopy() throws Exception {
        agePassword(properties.passwordMaxAgeDays() + 5);

        String html = mvc.perform(get("/password").with(user(NAME).roles("ADMIN")))
                         .andReturn().getResponse().getContentAsString();

        assertThat(html).contains("비밀번호를 변경하신 지 오래되었습니다");
        assertThat(html).contains("현재 비밀번호");
        // 구현 동작을 옮겨 적은 옛 문구가 남아 있지 않아야 한다.
        assertThat(html).doesNotContain("다른 화면이 열리지 않습니다");
    }

    @Test
    @DisplayName("임시 비밀번호 화면은 첫 칸을 '임시 비밀번호' 로 묻는다")
    void temporaryCaseLabelsTheFirstField() throws Exception {
        AppUser user = reload();
        user.setMustChange(true);
        users.save(user);

        String html = mvc.perform(get("/password").with(user(NAME).roles("ADMIN")))
                         .andReturn().getResponse().getContentAsString();

        assertThat(html).contains("임시 비밀번호로 로그인하셨습니다");
        assertThat(html).contains("임시 비밀번호");
    }

    @Test
    @Transactional
    @DisplayName("초기화하면 잠금도 함께 풀린다")
    void resetAlsoClearsTheLock() {
        AppUser user = reload();
        user.setLockedAt(Instant.now());
        user.setFailedAttempts(9);
        users.save(user);

        accounts.resetPassword(NAME, "admin");

        // 초기화의 목적은 들어오게 해 주는 것인데, 잠금이 남아 있으면
        // 아무 효과가 없다.
        assertThat(reload().getLockedAt()).isNull();
        assertThat(reload().getFailedAttempts()).isZero();
    }
}
