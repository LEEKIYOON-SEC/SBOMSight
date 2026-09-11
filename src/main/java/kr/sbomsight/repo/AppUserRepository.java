package kr.sbomsight.repo;

import kr.sbomsight.domain.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {

    Optional<AppUser> findByUsername(String username);

    boolean existsByUsername(String username);

    List<AppUser> findAllByOrderByUsernameAsc();

    /**
     * 실패 횟수를 하나 올린다.
     *
     * <p><b>SQL 한 문장으로</b> 한다. 읽어서 더해 저장하면 동시에 들어온 두
     * 시도가 같은 값을 읽고 같은 값을 써서 한 번으로 세어진다 — 잠금을
     * 우회하는 길이 된다.
     *
     * <p>없는 계정이면 0 을 돌려준다. 그런 이름으로 행을 만들지는 않는다.
     *
     * @return 바뀐 행 수 (0 또는 1)
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE AppUser u SET u.failedAttempts = u.failedAttempts + 1 WHERE u.username = :username")
    int incrementFailedAttempts(@Param("username") String username);

    /** 잠긴 계정. 설정 화면에서 해제 대상을 찾는다. */
    List<AppUser> findByLockedAtIsNotNull();
}
