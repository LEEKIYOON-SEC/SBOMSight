package kr.sbomsight.service;

import kr.sbomsight.domain.Zone;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.ZoneRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.util.List;

/**
 * 구역 관리.
 *
 * <p>지키는 것은 하나다: <b>자산이 갈 곳을 잃지 않는다.</b> 구역을 지우거나
 * 이름을 바꾸는 일이 자산을 미아로 만들면 구역별 합계와 전체가 어긋나고,
 * 그 순간 어느 쪽이 맞는지 아무도 모른다.
 */
@Service
public class ZoneService {

    private final ZoneRepository zones;
    private final AssetRepository assets;

    public ZoneService(ZoneRepository zones, AssetRepository assets) {
        this.zones = zones;
        this.assets = assets;
    }

    @Transactional(readOnly = true)
    public List<Zone> all() {
        return zones.findAllByOrderBySortOrderAscNameAsc();
    }

    /**
     * 없는 구역 — 지운 구역의 주소를 열었거나, 다른 창에서 지운 구역을 골랐다.
     *
     * <p>{@link IllegalArgumentException} 이라 폼 처리({@code ZoneController.act} ·
     * 자산 등록 · 구역 옮기기)는 안내로 띄운다. 잡지 않은 조회 화면(취약점 ·
     * 구역 보고서)은 404 로 답한다 — 앞서 500 이었고, 구역 보고서는 자산 0대짜리
     * "전체" 보고서를 200 으로 냈다(ZoneNotFoundTest).
     */
    @ResponseStatus(value = HttpStatus.NOT_FOUND, reason = NoSuchZoneException.MESSAGE)
    public static class NoSuchZoneException extends IllegalArgumentException {
        static final String MESSAGE = "구역을 찾을 수 없습니다.";

        public NoSuchZoneException() {
            super(MESSAGE);
        }
    }

    @Transactional(readOnly = true)
    public Zone require(Long id) {
        return zones.findById(id).orElseThrow(NoSuchZoneException::new);
    }

    /**
     * 미분류 구역. 마이그레이션이 만들어 두지만, 누군가 지웠거나 개발 중
     * 새 스키마로 시작한 경우를 대비해 없으면 만든다.
     */
    @Transactional
    public Zone unassigned() {
        return zones.findByName(Zone.UNASSIGNED).orElseGet(() -> {
            Zone zone = new Zone(Zone.UNASSIGNED);
            zone.setSortOrder(9999);
            zone.setColor("#6f7e8d");
            return zones.save(zone);
        });
    }

    @Transactional
    public Zone create(String name, String color, String note) {
        String clean = name == null ? "" : name.trim();
        if (clean.isEmpty()) {
            throw new IllegalArgumentException("구역 이름을 입력하세요.");
        }
        if (zones.existsByName(clean)) {
            throw new IllegalArgumentException("이미 있는 구역입니다: " + clean);
        }
        Zone zone = new Zone(clean);
        zone.setColor(color);
        zone.setNote(note);
        // 새 구역은 미분류 앞, 기존 구역 뒤에 선다.
        zone.setSortOrder(nextOrder());
        return zones.save(zone);
    }

    private int nextOrder() {
        return zones.findAll().stream()
                    .filter(z -> !z.isUnassigned())
                    .mapToInt(Zone::getSortOrder)
                    .max().orElse(0) + 1;
    }

    @Transactional
    public void rename(Long id, String name) {
        Zone zone = require(id);
        if (zone.isUnassigned()) {
            throw new IllegalArgumentException(
                    Zone.UNASSIGNED + " 구역은 이름을 바꿀 수 없습니다. 자산이 갈 곳을 잃습니다.");
        }
        String clean = name == null ? "" : name.trim();
        if (clean.isEmpty()) {
            throw new IllegalArgumentException("구역 이름을 입력하세요.");
        }
        if (!clean.equals(zone.getName()) && zones.existsByName(clean)) {
            throw new IllegalArgumentException("이미 있는 구역입니다: " + clean);
        }
        zone.setName(clean);
    }

    @Transactional
    public void recolor(Long id, String color) {
        require(id).setColor(color);
    }

    /**
     * 구역 삭제.
     *
     * <p>자산이 하나라도 남아 있으면 거절한다. 남은 자산을 조용히 미분류로
     * 옮기는 쪽이 친절해 보이지만, 그러면 삭제 한 번에 구역 배치가 소리 없이
     * 바뀐다 — 무엇이 어디로 갔는지 화면에 나타나지 않는다. 옮기는 것은
     * 사람이 먼저 하고, 이 함수는 빈 구역만 치운다.
     */
    @Transactional
    public void delete(Long id) {
        Zone zone = require(id);
        if (zone.isUnassigned()) {
            throw new IllegalArgumentException(Zone.UNASSIGNED + " 구역은 지울 수 없습니다.");
        }
        long count = assets.countByZoneId(id);
        if (count > 0) {
            throw new IllegalArgumentException(
                    "이 구역에 자산이 " + count + "대 있습니다. 먼저 다른 구역으로 옮기세요.");
        }
        zones.delete(zone);
    }
}
