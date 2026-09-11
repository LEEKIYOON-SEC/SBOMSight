package kr.sbomsight.service;

import kr.sbomsight.config.SbomSightProperties;
import kr.sbomsight.domain.AppUser;
import kr.sbomsight.domain.PasswordChangeReason;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;

/**
 * 비밀번호를 지금 바꿔야 하는가, 그렇다면 왜인가.
 *
 * <p>세 가지를 한자리에서 판단한다 — 최초 로그인, 관리자 초기화, 변경 주기
 * 도래. 화면과 인터셉터가 각자 판단하면 둘이 어긋나 "바꾸라는데 다른 화면이
 * 열린다" 거나 반대로 "바꿀 것이 없는데 갇힌다" 가 된다.
 */
@Service
public class PasswordPolicy {

    private static final Logger log = LoggerFactory.getLogger(PasswordPolicy.class);

    private final SbomSightProperties properties;

    public PasswordPolicy(SbomSightProperties properties) {
        this.properties = properties;
    }

    /**
     * 이 계정이 지금 변경 화면에 붙잡혀야 하는 이유. 없으면 {@code null}.
     *
     * <p>{@code mustChange} 가 먼저다. 관리자가 방금 초기화한 계정에게
     * "주기가 지났습니다" 라고 말하면 사실과 다르다.
     */
    public PasswordChangeReason forcedReason(AppUser user) {
        if (user.isMustChange()) {
            // 한 번도 로그인한 적이 없으면 처음 받은 계정이고, 있으면
            // 관리자가 쓰던 계정을 초기화한 것이다.
            return user.getLastLoginAt() == null
                    ? PasswordChangeReason.FIRST_LOGIN
                    : PasswordChangeReason.TEMPORARY;
        }
        if (isExpired(user)) {
            return PasswordChangeReason.EXPIRED;
        }
        return null;
    }

    /** 스스로 바꾸러 온 경우까지 포함한 이유 — 화면이 문구를 고르는 데 쓴다. */
    public PasswordChangeReason reasonFor(AppUser user) {
        PasswordChangeReason forced = forcedReason(user);
        return forced == null ? PasswordChangeReason.VOLUNTARY : forced;
    }

    public boolean mustChange(AppUser user) {
        return forcedReason(user) != null;
    }

    /**
     * 변경 주기가 지났는가.
     *
     * <p>{@code passwordChangedAt} 이 비어 있으면 <b>지난 것으로 본다.</b>
     * 마이그레이션이 모든 계정에 값을 채워 두므로 이 값이 없다는 것은 무언가
     * 어긋난 상태다. 그때 "아직 괜찮다" 로 읽으면 통제가 조용히 꺼지고,
     * 아무도 그것을 모른다 — 한 번 더 바꾸게 하는 쪽이 덜 위험하다.
     */
    public boolean isExpired(AppUser user) {
        if (!properties.passwordExpiryEnabled()) {
            return false;
        }
        Instant changed = user.getPasswordChangedAt();
        if (changed == null) {
            log.warn("{} 의 비밀번호 변경 시각이 없습니다 — 변경을 요구합니다.", user.getUsername());
            return true;
        }
        return changed.plus(maxAge()).isBefore(Instant.now());
    }

    /** 바꾼 지 며칠 됐는가. 값이 없으면 -1. */
    public long daysSinceChange(AppUser user) {
        Instant changed = user.getPasswordChangedAt();
        return changed == null ? -1 : Duration.between(changed, Instant.now()).toDays();
    }

    /** 주기까지 며칠 남았는가. 주기를 쓰지 않으면 -1. */
    public long daysUntilExpiry(AppUser user) {
        if (!properties.passwordExpiryEnabled() || user.getPasswordChangedAt() == null) {
            return -1;
        }
        return Duration.between(Instant.now(), user.getPasswordChangedAt().plus(maxAge())).toDays();
    }

    public int maxAgeDays() {
        return properties.passwordMaxAgeDays();
    }

    private Duration maxAge() {
        return Duration.ofDays(properties.passwordMaxAgeDays());
    }
}
