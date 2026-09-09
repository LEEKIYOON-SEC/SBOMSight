package kr.sbomsight.repo;

import kr.sbomsight.domain.Asset;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface AssetRepository extends JpaRepository<Asset, Long> {

    /** 그룹 먼저, 그 안에서 이름 순. 목록에서 같은 그룹이 붙어 보여야 읽힌다. */
    List<Asset> findByArchivedAtIsNullOrderByGroupNameAscNameAsc();

    Optional<Asset> findByName(String name);

    boolean existsByName(String name);
}
