package kr.sbomsight.service;

import kr.sbomsight.config.SbomSightProperties;
import kr.sbomsight.domain.AppUser;
import kr.sbomsight.domain.Role;
import kr.sbomsight.repo.AppUserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * 첫 기동 준비 — 보관 폴더와 최초 관리자.
 *
 * <p>최초 비밀번호는 <b>임의로 만들어 콘솔에 한 번만 찍는다.</b> 고정 문자열을
 * 두면 그것을 바꾸지 않은 설치가 그대로 남고, 소스만 보면 누구나 안다.
 */
@Component
public class BootstrapService implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(BootstrapService.class);

    private final AppUserRepository users;
    private final PasswordEncoder encoder;
    private final SbomSightProperties properties;
    private final ScanService scans;

    public BootstrapService(AppUserRepository users, PasswordEncoder encoder,
                            SbomSightProperties properties, ScanService scans) {
        this.users = users;
        this.encoder = encoder;
        this.properties = properties;
        this.scans = scans;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) throws Exception {
        Files.createDirectories(properties.dataDir());

        if (users.count() == 0) {
            String password = randomPassword();
            AppUser admin = new AppUser(properties.bootstrapAdmin(),
                                        encoder.encode(password), Role.ADMIN);
            admin.setDisplayName("최초 관리자");
            // 첫 로그인에서 반드시 바꾸게 한다. 콘솔에 찍힌 비밀번호가 그대로
            // 남으면 그 로그를 본 사람은 누구나 들어올 수 있다.
            admin.setMustChange(true);
            users.save(admin);

            log.warn("""

                    ┌──────────────────────────────────────────────────────────┐
                    │  계정이 없어 최초 관리자를 만들었습니다.                 │
                    │                                                          │
                    │    계정   {}
                    │    비밀번호  {}
                    │                                                          │
                    │  이 비밀번호는 지금 한 번만 표시됩니다.                  │
                    │  로그인하면 곧바로 새 비밀번호를 정해야 합니다.          │
                    └──────────────────────────────────────────────────────────┘
                    """, properties.bootstrapAdmin(), password);
        }

        int reaped = scans.reapStale();
        if (reaped > 0) {
            log.info("서버가 다시 시작되어 진행 중이던 스캔 {}건을 실패로 정리했습니다.", reaped);
        }
    }

    private String randomPassword() {
        byte[] bytes = new byte[18];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
