package kr.sbomsight.domain;

import jakarta.persistence.*;

import java.time.Instant;

@Entity
@Table(name = "users")
public class AppUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 64)
    private String username;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private Role role = Role.VIEWER;

    @Column(name = "display_name", nullable = false, length = 64)
    private String displayName = "";

    @Column(nullable = false)
    private boolean enabled = true;

    /** 초기화된 계정. 새 비밀번호를 정하기 전에는 다른 화면이 열리지 않는다. */
    @Column(name = "must_change", nullable = false)
    private boolean mustChange = false;

    /** 연속 로그인 실패 횟수. 성공하면 0 으로 돌아간다. */
    @Column(name = "failed_attempts", nullable = false)
    private int failedAttempts = 0;

    /** 잠긴 시각. NULL 이면 잠겨 있지 않다. */
    @Column(name = "locked_at")
    private Instant lockedAt;

    /**
     * 비밀번호를 마지막으로 바꾼 시각 — 변경 주기의 기준.
     *
     * <p>NULL 은 "모른다" 다. 그것을 "아주 오래됐다" 로 읽으면 판을 올린
     * 직후 전원이 변경 화면에 걸리고, "방금 바꿨다" 로 읽으면 주기가 한 번
     * 통째로 건너뛰어진다. 마이그레이션이 기존 계정에 값을 채워 둔다.
     */
    @Column(name = "password_changed_at")
    private Instant passwordChangedAt = Instant.now();

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    /**
     * 이번에 들어온 시각. 설정의 '마지막 로그인' 이 이것이다.
     *
     * <p>V1 부터 열은 있었지만 <b>한 번도 채워지지 않았다</b> —
     * {@code setLastLoginAt} 을 부르는 곳이 없었다. 이제
     * {@link kr.sbomsight.service.LoginAttemptService#onSuccess} 가 채운다.
     */
    @Column(name = "last_login_at")
    private Instant lastLoginAt;

    /**
     * 그 전에 들어온 시각. <b>{@code null} 이면 이번이 처음이다.</b>
     *
     * <p>왜 칸을 하나 더 두는가. 비밀번호 변경 화면은 "최초 로그인" 과
     * "관리자가 초기화함" 을 갈라 말해야 하는데, 그 화면은 로그인 <b>다음
     * 요청</b>에서 뜬다. 그래서 {@code lastLoginAt} 하나만 보면 이미 이번
     * 로그인 시각이 박혀 있어 둘을 가를 수 없다 — 순서로는 풀리지 않는다.
     *
     * <p>날짜 하나로 눈치껏 가르려 하면(만든 시각과 비교한다든지) 언젠가
     * 틀리고, 틀린 줄도 모른다. 사실 두 개를 두 칸에 나눠 적는다.
     */
    @Column(name = "previous_login_at")
    private Instant previousLoginAt;

    protected AppUser() {
    }

    public AppUser(String username, String passwordHash, Role role) {
        this.username = username;
        this.passwordHash = passwordHash;
        this.role = role;
    }

    public Long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName == null ? "" : displayName;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isMustChange() {
        return mustChange;
    }

    public void setMustChange(boolean mustChange) {
        this.mustChange = mustChange;
    }

    public int getFailedAttempts() {
        return failedAttempts;
    }

    public void setFailedAttempts(int failedAttempts) {
        this.failedAttempts = failedAttempts;
    }

    public Instant getLockedAt() {
        return lockedAt;
    }

    public void setLockedAt(Instant lockedAt) {
        this.lockedAt = lockedAt;
    }

    public Instant getPasswordChangedAt() {
        return passwordChangedAt;
    }

    public void setPasswordChangedAt(Instant passwordChangedAt) {
        this.passwordChangedAt = passwordChangedAt;
    }

    /**
     * 지금 잠겨 있는가.
     *
     * @param autoUnlockAfter 이만큼 지나면 스스로 풀린다. {@code null} 이면
     *                        관리자가 풀어 줄 때까지 잠긴 채로 있다.
     */
    public boolean isLocked(java.time.Duration autoUnlockAfter) {
        if (lockedAt == null) {
            return false;
        }
        if (autoUnlockAfter == null) {
            return true;
        }
        return lockedAt.plus(autoUnlockAfter).isAfter(Instant.now());
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getLastLoginAt() {
        return lastLoginAt;
    }

    public Instant getPreviousLoginAt() {
        return previousLoginAt;
    }

    /**
     * 로그인 한 번을 기록한다 — 이번 시각을 넣고 앞의 것을 한 칸 밀어 둔다.
     *
     * <p>두 칸을 따로 세팅하게 두지 않는다. 한쪽만 건드리면 "그 전 로그인"
     * 이 이번 로그인과 같아지거나 영영 비어 있게 된다.
     */
    public void recordLogin(Instant at) {
        this.previousLoginAt = this.lastLoginAt;
        this.lastLoginAt = at;
    }

    /** 이번이 첫 로그인인가 — 앞선 로그인이 없다. */
    public boolean isFirstLogin() {
        return previousLoginAt == null;
    }
}
