package kr.sbomsight.repo;

import kr.sbomsight.domain.Zone;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ZoneRepository extends JpaRepository<Zone, Long> {

    /** 화면에 세우는 순서. 정한 순서가 같으면 이름으로 가른다. */
    List<Zone> findAllByOrderBySortOrderAscNameAsc();

    Optional<Zone> findByName(String name);

    boolean existsByName(String name);
}
