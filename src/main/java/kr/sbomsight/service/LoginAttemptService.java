package kr.sbomsight.service;

import kr.sbomsight.config.SbomSightProperties;
import kr.sbomsight.domain.AppUser;
import kr.sbomsight.domain.AuditEvent;
import kr.sbomsight.repo.AppUserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

/**
 * 로그인 실패 횟수와 계정 잠금.
 *
 * <p><b>없는 계정으로는 아무것도 만들지 않는다.</b> 시도한 이름마다 행을
 * 만들어 두면 표가 남의 추측으로 채워지고, 더 나쁘게는 "이 이름은 실패
 * 횟수가 쌓인다" 는 사실 자체가 계정의 존재를 알려 준다. 로그인 화면의
 * 응답은 계정이 있든 없든, 잠겼든 아니든 <b>언제나 같다</b> — 감사 로그에만
 * 사유를 남긴다.
 *
 * <p>잠금은 기본 30분 뒤 스스로 풀린다. 관리자가 즉시 풀 수도 있다.
 * 영구 잠금(설정에서 0)이 점검 기준에는 더 맞지만, 이름만 알면 누구든 남의
 * 계정을 잠글 수 있고 새벽에 본인이 잠기면 손쓸 데가 없다.
 */
@Service
public class LoginAttemptService {

    private static final Logger log = LoggerFactory.getLogger(LoginAttemptService.class);

    private final AppUserRepository users;
    private final SbomSightProperties properties;
    private final AuditService audit;

    public LoginAttemptService(AppUserRepository users, SbomSightProperties properties,
                               AuditService audit) {
        this.users = users;
        this.properties = properties;
        this.audit = audit;
    }

    /**
     * 실패 한 번.
     *
     * <p>증가는 <b>SQL 한 문장으로</b> 한다. 읽어서 더해 저장하면 동시에 들어온
     * 두 시도가 같은 값을 읽고 같은 값을 써서 한 번으로 세어진다.
     */
    @Transactional
    public void onFailure(String username) {
        if (!properties.lockoutEnabled() || username == null || username.isBlank()) {
            return;
        }
        // 없는 계정은 여기서 끝. 행을 만들지 않는다.
        int updated = users.incrementFailedAttempts(username);
        if (updated == 0) {
            return;
        }

        Optional<AppUser> found = users.findByUsername(username);
        if (found.isEmpty()) {
            return;
        }
        AppUser user = found.get();
        if (user.getLockedAt() == null
                && user.getFailedAttempts() >= properties.maxLoginFailures()) {
            user.setLockedAt(Instant.now());
            users.save(user);
            audit.recordAs(username, AuditEvent.LOGIN_BLOCKED, username,
                           "연속 실패 " + user.getFailedAttempts() + "회로 잠겼습니다");
            log.warn("계정을 잠갔습니다: {} (연속 실패 {}회)", username, user.getFailedAttempts());
        }
    }

    /**
     * 성공 한 번 — 횟수를 되돌린다.
     *
     * <p>자동 해제 시간이 지나 통과한 경우 잠금 표시도 함께 지운다. 남겨 두면
     * 다음 실패 한 번에 곧바로 다시 잠긴 것으로 보인다.
     */
    @Transactional
    public void onSuccess(String username) {
        users.findByUsername(username).ifPresent(user -> {
            if (user.getFailedAttempts() != 0 || user.getLockedAt() != null) {
                user.setFailedAttempts(0);
                user.setLockedAt(null);
                users.save(user);
            }
        });
    }

    /** 관리자가 푼다. */
    @Transactional
    public void unlock(String username) {
        users.findByUsername(username).ifPresent(user -> {
            user.setFailedAttempts(0);
            user.setLockedAt(null);
            users.save(user);
            audit.record(AuditEvent.USER_UNLOCKED, username, "");
        });
    }

    /** 지금 잠겨 있는가 — 설정 화면과 인증 양쪽이 이 판단을 쓴다. */
    public boolean isLocked(AppUser user) {
        return properties.lockoutEnabled() && user.isLocked(properties.autoUnlockAfter());
    }

    /** 남은 잠금 시간(분). 자동 해제를 쓰지 않으면 -1. */
    public long minutesRemaining(AppUser user) {
        var window = properties.autoUnlockAfter();
        if (window == null || user.getLockedAt() == null) {
            return -1;
        }
        long left = java.time.Duration.between(Instant.now(), user.getLockedAt().plus(window))
                                      .toMinutes();
        return Math.max(left, 0);
    }
}
