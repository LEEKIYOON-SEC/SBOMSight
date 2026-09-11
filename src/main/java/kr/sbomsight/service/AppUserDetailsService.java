package kr.sbomsight.service;

import kr.sbomsight.domain.AppUser;
import kr.sbomsight.repo.AppUserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/** 스프링 시큐리티가 로그인할 때 쓰는 계정 조회. */
@Service
public class AppUserDetailsService implements UserDetailsService {

    private final AppUserRepository users;
    private final LoginAttemptService attempts;

    public AppUserDetailsService(AppUserRepository users, LoginAttemptService attempts) {
        this.users = users;
        this.attempts = attempts;
    }

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser user = users.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("계정을 찾을 수 없습니다."));
        return User.withUsername(user.getUsername())
                .password(user.getPasswordHash())
                .authorities(List.of(new SimpleGrantedAuthority(user.getRole().authority())))
                .disabled(!user.isEnabled())
                // 잠금은 여기서 알려 준다. 스프링 시큐리티가 비밀번호를
                // 대조하기 **전에** 막아 주므로, 잠긴 계정에 대해서는 맞는
                // 비밀번호를 넣어도 통과하지 않는다.
                .accountLocked(attempts.isLocked(user))
                .build();
    }
}
