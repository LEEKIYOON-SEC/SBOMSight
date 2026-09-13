package kr.sbomsight.service;

import kr.sbomsight.domain.AppUser;
import kr.sbomsight.domain.Role;
import kr.sbomsight.repo.AppUserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.regex.Pattern;

/**
 * 계정 관리 — 관리자가 웹에서 한다.
 *
 * <p>CLI 는 최초 관리자 한 명을 만드는 부트스트랩 용도로만 쓴다. 계정을 늘리고
 * 줄이는 일은 운영 중에 계속 생기는데, 그때마다 서버에 붙어야 하면 결국 계정을
 * 돌려 쓰게 된다.
 */
@Service
public class AccountService {

    private static final Logger log = LoggerFactory.getLogger(AccountService.class);

    public static final int MIN_PASSWORD_LENGTH = 8;
    private static final Pattern NAME = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$");

    private final AppUserRepository users;
    private final PasswordEncoder encoder;

    public AccountService(AppUserRepository users, PasswordEncoder encoder) {
        this.users = users;
        this.encoder = encoder;
    }

    /** 운영자에게 그대로 보여 줄 수 있는 실패 사유. */
    public static class AccountException extends RuntimeException {
        public AccountException(String message) {
            super(message);
        }
    }

    @Transactional(readOnly = true)
    public List<AppUser> list() {
        return users.findAllByOrderByUsernameAsc();
    }

    @Transactional
    public AppUser create(String username, String password, Role role, String displayName) {
        String name = username == null ? "" : username.trim();
        if (!NAME.matcher(name).matches()) {
            throw new AccountException(
                    "계정 이름은 영문·숫자로 시작하고 2자 이상이어야 하며 . _ - 만 쓸 수 있습니다.");
        }
        if (users.existsByUsername(name)) {
            throw new AccountException("이미 있는 계정 이름입니다.");
        }
        if (password == null || password.length() < MIN_PASSWORD_LENGTH) {
            throw new AccountException(MIN_PASSWORD_LENGTH + "자 이상으로 정해 주세요.");
        }

        AppUser user = new AppUser(name, encoder.encode(password), role);
        user.setDisplayName(displayName);
        log.info("계정을 만들었습니다: {} ({})", name, role);
        return users.save(user);
    }

    /**
     * 계정 하나를 고친다 — 이름 · 권한 · 사용 여부 · (원하면) 새 비밀번호.
     *
     * <p><b>왜 한 번에 받는가.</b> 앞서는 권한만 드롭다운으로 <b>고르는 즉시
     * 저장</b>됐고, 이름과 비밀번호는 아예 바꿀 길이 없었다. 즉시 저장은
     * 실수로 스친 것과 정말 바꾼 것을 가르지 못한다 — 되돌릴 자리도 없다.
     *
     * @param newPassword 비우면 <b>비밀번호를 건드리지 않는다.</b> 빈 칸을
     *                    "빈 비밀번호로 바꾸라" 로 읽으면 안 된다.
     * @return 무엇이 바뀌었는지 사람이 읽을 한 줄. 아무것도 안 바뀌면 빈 문자열.
     */
    @Transactional
    public String update(String username, String displayName, Role role, boolean enabled,
                         String newPassword, String actor) {
        AppUser user = require(username);
        List<String> changed = new java.util.ArrayList<>();

        String name = displayName == null ? "" : displayName.trim();
        if (!name.equals(user.getDisplayName())) {
            user.setDisplayName(name);
            changed.add("이름");
        }

        if (role != null && role != user.getRole()) {
            // 마지막 관리자를 잃으면 웹으로는 되돌릴 수 없다.
            if (user.getRole() == Role.ADMIN) {
                requireAnotherAdmin(username);
            }
            user.setRole(role);
            changed.add("권한 " + role.label());
        }

        if (enabled != user.isEnabled()) {
            if (!enabled) {
                if (username.equals(actor)) {
                    throw new AccountException("자기 계정은 정지할 수 없습니다.");
                }
                if (user.getRole() == Role.ADMIN) {
                    requireAnotherAdmin(username);
                }
            }
            user.setEnabled(enabled);
            changed.add(enabled ? "사용" : "정지");
        }

        if (newPassword != null && !newPassword.isBlank()) {
            if (newPassword.length() < MIN_PASSWORD_LENGTH) {
                throw new AccountException(MIN_PASSWORD_LENGTH + "자 이상으로 정해 주세요.");
            }
            user.setPasswordHash(encoder.encode(newPassword));
            // 관리자가 정해 준 비밀번호다. 본인이 받아서 곧바로 바꾸게 한다 —
            // 관리자가 아는 비밀번호를 그대로 쓰게 두지 않는다.
            user.setMustChange(true);
            user.setPasswordChangedAt(java.time.Instant.now());
            // 잠겨 있었다면 함께 푼다. 비밀번호를 새로 줬는데 잠긴 채면
            // 아무 효과가 없다.
            user.setFailedAttempts(0);
            user.setLockedAt(null);
            changed.add("비밀번호");
        }

        if (changed.isEmpty()) {
            return "";
        }
        users.save(user);
        String summary = String.join(" · ", changed);
        log.info("{} 계정을 고쳤습니다: {} ({})", username, summary, actor);
        return summary;
    }

    @Transactional
    public void delete(String username, String actor) {
        AppUser user = require(username);
        if (username.equals(actor)) {
            throw new AccountException("자기 계정은 지울 수 없습니다.");
        }
        if (user.getRole() == Role.ADMIN) {
            requireAnotherAdmin(username);
        }
        users.delete(user);
        log.info("계정을 지웠습니다: {} ({})", username, actor);
    }

    /**
     * 비밀번호를 계정 이름과 같게 되돌린다.
     *
     * <p>관리자가 새 비밀번호를 지어내지 않는다 — 지어내면 그것을 본인에게
     * 전달하는 경로가 또 필요하고, 대개 메신저로 흘러간다. 대신 <b>다음 로그인에서
     * 반드시 바꾸게</b> 하고, 바꾸기 전에는 다른 화면이 열리지 않는다.
     */
    @Transactional
    public void resetPassword(String username, String actor) {
        AppUser user = require(username);
        user.setPasswordHash(encoder.encode(username));
        user.setMustChange(true);
        // 주기 기준도 지금으로 옮긴다. 옛 시각을 남겨 두면 mustChange 와
        // 만료가 동시에 참이 되어, 바꾼 직후에도 "주기가 지났습니다" 로
        // 다시 붙잡힐 수 있다.
        user.setPasswordChangedAt(java.time.Instant.now());
        // 잠긴 계정을 초기화하면 잠금도 함께 풀린다 — 초기화의 목적이
        // 들어오게 해 주는 것인데 잠금이 남아 있으면 아무 효과가 없다.
        user.setFailedAttempts(0);
        user.setLockedAt(null);
        users.save(user);
        log.info("{} 의 비밀번호를 초기화했습니다 ({})", username, actor);
    }

    // changeRole · setEnabled 는 update 로 합쳤다. 권한을 바꾸는 길이 둘이면
    // 한쪽에만 '마지막 관리자' 보호가 걸린 채로 남는 날이 온다.

    private AppUser require(String username) {
        return users.findByUsername(username)
                .orElseThrow(() -> new AccountException("계정을 찾을 수 없습니다."));
    }

    /** 마지막 관리자를 잃지 않게 막는다. 잃으면 웹으로는 되돌릴 수 없다. */
    private void requireAnotherAdmin(String username) {
        boolean another = users.findAllByOrderByUsernameAsc().stream()
                .anyMatch(u -> u.getRole() == Role.ADMIN
                            && u.isEnabled()
                            && !u.getUsername().equals(username));
        if (!another) {
            throw new AccountException(
                    "마지막 관리자입니다. 다른 관리자를 먼저 만든 뒤에 하세요.");
        }
    }
}
