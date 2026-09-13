package kr.sbomsight.web;

import kr.sbomsight.domain.AuditEvent;
import kr.sbomsight.domain.Zone;
import kr.sbomsight.service.AuditService;
import kr.sbomsight.service.ZoneService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.function.Supplier;

/**
 * 구역 관리.
 *
 * <p><b>왜 설정에서 나왔나.</b> 구역은 자산을 묶는 방식이지 도구의 설정이
 * 아니다. 설정 안에 있으면 자산을 보다가 구역 하나를 더하려고 화면을 두 번
 * 옮겨야 하고, 돌아올 때 보던 자리를 잃는다. 이제 자산 화면의
 * <b>구역 관리</b> 버튼이 연다.
 *
 * <p>끝나면 자산 목록으로 돌아간다 — 온 자리로 돌려보낸다.
 */
@Controller
@RequestMapping("/zones")
@PreAuthorize("hasRole('ADMIN')")
public class ZoneController {

    private final ZoneService zones;
    private final AuditService audit;

    public ZoneController(ZoneService zones, AuditService audit) {
        this.zones = zones;
        this.audit = audit;
    }

    @PostMapping
    public String create(@RequestParam String name,
                         @RequestParam(required = false) String color,
                         @RequestParam(required = false) String note,
                         RedirectAttributes flash) {
        return act(flash, () -> {
            Zone zone = zones.create(name, color, note);
            audit.record(AuditEvent.ZONE_CREATED, zone.getName(), "");
            return zone.getName() + " 구역을 만들었습니다.";
        });
    }

    @PostMapping("/{id}/rename")
    public String rename(@PathVariable Long id, @RequestParam String name,
                         RedirectAttributes flash) {
        return act(flash, () -> {
            String before = zones.require(id).getName();
            zones.rename(id, name);
            audit.record(AuditEvent.ZONE_RENAMED, name, before + " → " + name);
            return "구역 이름을 바꿨습니다.";
        });
    }

    @PostMapping("/{id}/color")
    public String recolor(@PathVariable Long id, @RequestParam String color,
                          RedirectAttributes flash) {
        return act(flash, () -> {
            zones.recolor(id, color);
            audit.record(AuditEvent.ZONE_RECOLORED, zones.require(id).getName(), color);
            return "구역 색을 바꿨습니다.";
        });
    }

    @PostMapping("/{id}/delete")
    public String delete(@PathVariable Long id, RedirectAttributes flash) {
        return act(flash, () -> {
            // 지우기 전에 이름을 읽어 둔다 — 지운 뒤에는 남지 않는다.
            String name = zones.require(id).getName();
            zones.delete(id);
            audit.record(AuditEvent.ZONE_DELETED, name, "");
            return name + " 구역을 지웠습니다.";
        });
    }

    /**
     * 구역 작업의 공통 처리.
     *
     * <p>{@link ZoneService} 는 규칙을 어기면 {@link IllegalArgumentException}
     * 을 던진다 — 자산이 남은 구역을 지우려 했다든지. 그 사유를 그대로 화면에
     * 띄운다. 500 으로 터뜨리면 무엇이 잘못됐는지 알 수 없다.
     */
    private String act(RedirectAttributes flash, Supplier<String> work) {
        try {
            flash.addFlashAttribute("message", work.get());
        } catch (IllegalArgumentException e) {
            flash.addFlashAttribute("error", e.getMessage());
        }
        return "redirect:/";
    }
}
