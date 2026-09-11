package kr.sbomsight;

import kr.sbomsight.domain.Asset;
import kr.sbomsight.domain.Zone;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.ZoneRepository;
import kr.sbomsight.service.ZoneService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 구역 관리.
 *
 * <p>여기서 고정하는 것은 하나다: <b>자산이 갈 곳을 잃지 않는다.</b> 구역을
 * 지우거나 이름을 바꾸는 일이 자산을 미아로 만들면 구역별 합계와 전체가
 * 어긋나고, 그때 어느 쪽이 맞는지 아무도 모른다.
 */
@SpringBootTest
@Transactional
class ZoneServiceTest {

    @Autowired ZoneService service;
    @Autowired ZoneRepository zones;
    @Autowired AssetRepository assets;

    private Asset assetIn(Zone zone) {
        Asset a = new Asset();
        a.setName("srv-" + System.nanoTime());
        a.setZone(zone);
        return assets.save(a);
    }

    @Test
    @DisplayName("미분류는 없으면 만들어진다")
    void unassignedAlwaysExists() {
        Zone z = service.unassigned();
        assertThat(z.getName()).isEqualTo(Zone.UNASSIGNED);
        assertThat(z.isUnassigned()).isTrue();
        // 두 번 불러도 하나다.
        assertThat(service.unassigned().getId()).isEqualTo(z.getId());
    }

    @Test
    @DisplayName("앞뒤 공백은 버린다 — 'DMZ ' 와 'DMZ' 가 갈라지면 안 된다")
    void trimsTheName() {
        Zone z = service.create("  DMZ-" + System.nanoTime() + "  ", "#a71922", "");
        assertThat(z.getName()).doesNotStartWith(" ").doesNotEndWith(" ");
    }

    @Test
    @DisplayName("같은 이름은 두 번 만들 수 없다")
    void refusesDuplicates() {
        String name = "DMZ-" + System.nanoTime();
        service.create(name, "", "");
        assertThatThrownBy(() -> service.create(name, "", ""))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("이미 있는 구역");
    }

    @Test
    @DisplayName("빈 이름은 받지 않는다")
    void refusesBlank() {
        assertThatThrownBy(() -> service.create("   ", "", ""))
                .isInstanceOf(IllegalArgumentException.class);
    }

    /**
     * 이 시험이 핵심이다. 자산이 남아 있는 구역을 지우면 그 자산은 갈 곳이
     * 없어진다. 남은 자산을 조용히 미분류로 옮기는 쪽이 친절해 보이지만,
     * 그러면 삭제 한 번에 구역 배치가 소리 없이 바뀐다.
     */
    @Test
    @DisplayName("자산이 남은 구역은 지울 수 없다")
    void refusesToDeleteANonEmptyZone() {
        Zone zone = service.create("DMZ-" + System.nanoTime(), "", "");
        assetIn(zone);

        assertThatThrownBy(() -> service.delete(zone.getId()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("먼저 다른 구역으로 옮기세요");

        assertThat(zones.findById(zone.getId())).isPresent();
    }

    @Test
    @DisplayName("빈 구역은 지울 수 있다")
    void deletesAnEmptyZone() {
        Zone zone = service.create("빈-" + System.nanoTime(), "", "");
        service.delete(zone.getId());
        assertThat(zones.findById(zone.getId())).isEmpty();
    }

    @Test
    @DisplayName("미분류는 지우거나 이름을 바꿀 수 없다")
    void protectsTheUnassignedZone() {
        Zone z = service.unassigned();

        assertThatThrownBy(() -> service.delete(z.getId()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.rename(z.getId(), "아무거나"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("자산이 갈 곳을 잃습니다");
    }

    @Test
    @DisplayName("이름을 바꿔도 그 구역의 자산은 그대로 붙어 있다")
    void renameKeepsAssets() {
        Zone zone = service.create("옛이름-" + System.nanoTime(), "", "");
        Asset asset = assetIn(zone);

        service.rename(zone.getId(), "새이름-" + System.nanoTime());

        assertThat(assets.findWithZone(asset.getId()).orElseThrow().getZone().getId())
                .isEqualTo(zone.getId());
    }

    @Test
    @DisplayName("목록은 정한 순서대로 서고 미분류는 뒤에 남는다")
    void ordersZones() {
        service.unassigned();
        Zone a = service.create("A-" + System.nanoTime(), "", "");
        Zone b = service.create("B-" + System.nanoTime(), "", "");

        service.reorder(java.util.List.of(b.getId(), a.getId()));

        var ordered = service.all().stream().map(Zone::getName).toList();
        assertThat(ordered.indexOf(b.getName())).isLessThan(ordered.indexOf(a.getName()));
        // 미분류는 sort_order 9999 라 언제나 끝쪽이다.
        assertThat(ordered).last().isEqualTo(Zone.UNASSIGNED);
    }
}
