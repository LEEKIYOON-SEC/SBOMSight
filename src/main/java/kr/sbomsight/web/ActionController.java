package kr.sbomsight.web;

import jakarta.servlet.http.HttpServletResponse;
import kr.sbomsight.domain.*;
import kr.sbomsight.repo.RemediationRepository;
import kr.sbomsight.repo.ScanRepository;
import kr.sbomsight.service.AuditService;
import kr.sbomsight.service.CsvWriter;
import kr.sbomsight.service.FindingAnalysisService;
import kr.sbomsight.service.Paging;
import kr.sbomsight.service.RemediationService;
import kr.sbomsight.service.VulnQuery;
import kr.sbomsight.service.ZoneService;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.security.Principal;
import java.time.LocalDate;
import java.util.List;

import static org.springframework.http.HttpStatus.NOT_FOUND;

/**
 * 대응 — <b>내린 결정을 모아 보는 자리.</b>
 *
 * <p>탭 둘이다. 앞서는 화면이 둘이었고 기둥에서도 갈라져 있어서, 어느 쪽이
 * 급한지 알려면 두 번 봐야 했다. 둘 다 "이 건을 어떻게 할 것인가" 에 대한
 * 답이므로 한자리에 둔다.
 *
 * <ul>
 *   <li><b>조치</b> — 올리기로 한 것. 기한이 지난 것이 맨 위로.</li>
 *   <li><b>검토 결과</b> — 그 탐지를 어떻게 판단했는가. 재검토일이 지난 것이 맨 위로.</li>
 * </ul>
 *
 * <p><b>여기서 등록하지 않는다.</b> 조치도 검토 결과도 취약점 화면에서 건을
 * 보면서 적는다 — 목록만 보고 "무엇을 조치할지" 고를 수는 없다. 이 화면은
 * 이미 내린 결정이 어떻게 되어 가는지 보는 곳이다.
 */
@Controller
@RequestMapping("/actions")
public class ActionController {

    private final RemediationRepository remediations;
    private final RemediationService service;
    private final FindingAnalysisService analyses;
    private final ScanRepository scans;
    private final ZoneService zones;
    private final AuditService audit;

    public ActionController(RemediationRepository remediations, RemediationService service,
                            FindingAnalysisService analyses, ScanRepository scans,
                            ZoneService zones, AuditService audit) {
        this.remediations = remediations;
        this.service = service;
        this.analyses = analyses;
        this.scans = scans;
        this.zones = zones;
        this.audit = audit;
    }

    @GetMapping
    public String index(@RequestParam(defaultValue = "remediations") String tab,
                        @RequestParam(required = false) Long zone,
                        @RequestParam(required = false) RemediationStatus status,
                        @RequestParam(defaultValue = "false") boolean includeDone,
                        @RequestParam(defaultValue = "0") int page,
                        @RequestParam(required = false) Integer size,
                        @RequestParam(required = false) Integer jump,
                        Model model) {
        // 화면 안의 링크. 탭·거르개·쪽 크기를 이어 간다 — 쪽을 넘길 때
        // 구역을 잃으면 다른 목록을 보게 된다.
        VulnQuery.Links links = new VulnQuery.Links("/actions", null)
                .with("tab", "analyses".equals(tab) ? "analyses" : null)
                .with("zone", zone)
                .with("status", "analyses".equals(tab) ? null : status)
                .with("includeDone", includeDone ? "true" : null)
                .size(size);
        String jumped = Paging.jump(links, jump);
        if (jumped != null) {
            return jumped;
        }
        model.addAttribute("links", links);
        // 탭 숫자는 **거르기 전** 전체를 센다. 거른 뒤 세면 구역을 고르는
        // 순간 탭의 수가 함께 줄어, 다른 탭에 무엇이 있는지 알 수 없게 된다.
        model.addAttribute("remediationCount", service.all().size());
        model.addAttribute("analysisCount", analyses.list(false, null).size());

        model.addAttribute("tab", tab);
        model.addAttribute("zones", zones.all());
        model.addAttribute("selectedZone", zone);
        model.addAttribute("status", status);
        model.addAttribute("statuses", RemediationStatus.values());
        model.addAttribute("includeDone", includeDone);

        // CSV 링크를 자바에서 만든다. `@{/actions/export.csv(zone=${zone}, …)}`
        // 는 값이 없어도 이름을 적어서 `?zone=&status=&includeDone=false` 가
        // 됐다 — `includeDone=false` 는 안 고른 것이 아니라 "볼 일 끝난 것은
        // 빼기로 골랐다" 고 읽힌다(N12).
        model.addAttribute("csv", new VulnQuery.Links("/actions/export.csv", null)
                .with("tab", "analyses".equals(tab) ? "analyses" : null)
                .with("zone", zone)
                .with("status", status)
                .with("includeDone", includeDone ? "true" : null));

        if ("analyses".equals(tab)) {
            List<FindingAnalysis> rows = analyses.list(includeDone, zone);
            model.addAttribute("analyses", Paging.slice(rows, page, size));
            model.addAttribute("overdue", analyses.reviewOverdue());
            // 검토 결과 줄에서 조치로 넘어가는 길. 조치는 `(자산, 패키지)`
            // 하나에 하나라 검토 여러 건이 조치 하나를 가리킨다 — 이미
            // 열려 있으면 `조치 등록` 이 아니라 `조치 보기` 다.
            model.addAttribute("actions", service.byAssetPackage(
                    rows.stream().map(a -> a.getAsset().getId()).distinct().toList()));
        } else {
            model.addAttribute("remediations",
                               Paging.slice(service.list(zone, status), page, size));
            model.addAttribute("overdue", remediations.findOverdue(LocalDate.now()));
        }
        return "actions";
    }

    /** 조치 하나 — 상태·담당·기한과 그동안의 발자취. */
    @GetMapping("/{id}")
    public String detail(@PathVariable Long id, Model model) {
        Remediation remediation = remediation(id);
        model.addAttribute("remediation", remediation);
        model.addAttribute("statuses", RemediationStatus.values());

        // 최신 검사에서 이 패키지가 아직 몇 건인가. **상태를 자동으로 바꾸지는
        // 않는다** — 대상이 바뀌어 사라진 것인지 정말 올린 것인지 우리가
        // 판단할 수 없다. 숫자만 보여 주고 판단은 담당자가 한다.
        Scan latest = scans.findFirstByAssetIdAndStatusOrderByCreatedAtDesc(
                remediation.getAsset().getId(), ScanStatus.DONE).orElse(null);
        model.addAttribute("latest", latest);
        model.addAttribute("remaining",
                latest == null ? -1L
                        : service.remainingCounts(remediation.getAsset().getId(), latest)
                                 .getOrDefault(remediation.getId(), 0L));
        return "action-detail";
    }

    @PostMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public String update(@PathVariable Long id,
                         @RequestParam RemediationStatus status,
                         @RequestParam(required = false) String owner,
                         @RequestParam(required = false)
                         @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate dueDate,
                         @RequestParam(required = false) String note,
                         @RequestParam(required = false) String comment,
                         Principal principal, RedirectAttributes flash) {
        Remediation remediation = remediation(id);
        // **고치기 전에 읽는다.** `service.update` 가 같은 객체를 바꾼다.
        String changed = changes(remediation, status, owner, dueDate, note);
        service.update(remediation, status, owner, dueDate, note, principal.getName(), comment);
        if (!changed.isEmpty()) {
            audit.record(AuditEvent.REMEDIATION_UPDATED,
                         remediation.getAsset().getName() + " · "
                         + remediation.getPackageName(), changed);
        }
        flash.addFlashAttribute("message", "조치를 갱신했습니다.");
        return "redirect:/actions/" + id;
    }

    /**
     * 무엇이 바뀌었는가 — <b>바뀐 칸만</b> 적는다.
     *
     * <p>상태를 그대로 두고 담당·기한만 고치면 조치 발자취에는 한 줄도 남지
     * 않는다({@link Remediation#moveTo} 는 상태가 바뀔 때만 부른다). 그러면
     * "누가 기한을 밀었나" 에 답할 것이 {@code updated_by} 하나뿐이고 그것은
     * 다음 수정이 덮어쓴다.
     *
     * <p>바뀐 것이 없으면 빈 글자다 — <b>누른 적만 있는 것을 기록하지
     * 않는다.</b> 손대지 않은 칸까지 쌓으면 감사 로그가 읽히지 않는다.
     *
     * <p>설명은 <b>바뀐 사실만</b> 적는다. 1,000자까지 들어오는 자유 기술이라
     * 그대로 담으면 감사 로그 한 줄이 화면을 밀어낸다 — 적힌 내용은 조치
     * 상세에 있다.
     */
    private String changes(Remediation before, RemediationStatus status, String owner,
                           LocalDate dueDate, String note) {
        List<String> changed = new java.util.ArrayList<>();
        if (before.getStatus() != status) {
            changed.add("조치 상태 " + before.getStatus().label() + " → " + status.label());
        }
        String newOwner = owner == null ? "" : owner.trim();
        if (!before.getOwner().equals(newOwner)) {
            changed.add("담당 " + or(before.getOwner()) + " → " + or(newOwner));
        }
        if (!java.util.Objects.equals(before.getDueDate(), dueDate)) {
            changed.add("기한 " + or(before.getDueDate()) + " → " + or(dueDate));
        }
        if (!before.getNote().equals(note == null ? "" : note)) {
            changed.add("설명 고침");
        }
        return String.join(" · ", changed);
    }

    /** 빈 값은 {@code —} 로. 화살표 양쪽이 비면 무엇이 바뀌었는지 읽히지 않는다. */
    private static String or(Object value) {
        return value == null || value.toString().isBlank() ? "—" : value.toString();
    }

    /**
     * 잘못 등록한 조치를 지운다.
     *
     * <p>이력까지 함께 사라지므로 <b>감사 로그에 남긴다</b> — 지운 뒤에
     * 남는 자취는 그 줄 하나뿐이다. 무엇을 지웠는지(자산 · 패키지 ·
     * 그때 상태)를 함께 적는다.
     */
    @PostMapping("/{id}/delete")
    @PreAuthorize("hasRole('ADMIN')")
    public String delete(@PathVariable Long id, RedirectAttributes flash) {
        Remediation remediation = remediation(id);
        String target = remediation.getAsset().getName() + " · " + remediation.getPackageName();
        service.delete(remediation);
        audit.record(AuditEvent.REMEDIATION_DELETED, target,
                     "등록 당시 " + remediation.getOpenedCount() + "건 · "
                     + remediation.getStatus().label());
        flash.addFlashAttribute("message", target + " 조치를 지웠습니다.");
        return "redirect:/actions";
    }

    /** 내려받기는 보고 있는 탭의 것이다. 다른 탭의 것이 섞여 나오면 대조를 못 한다. */
    @GetMapping("/export.csv")
    public void export(@RequestParam(defaultValue = "remediations") String tab,
                       @RequestParam(required = false) Long zone,
                       @RequestParam(required = false) RemediationStatus status,
                       @RequestParam(defaultValue = "false") boolean includeDone,
                       HttpServletResponse response) throws java.io.IOException {
        boolean isAnalyses = "analyses".equals(tab);
        response.setContentType("text/csv; charset=UTF-8");
        response.setHeader("Content-Disposition",
                "attachment; filename=\"" + (isAnalyses ? "analyses" : "remediations")
                + "-" + LocalDate.now() + ".csv\"");

        if (isAnalyses) {
            CsvWriter.writeAnalyses(response.getOutputStream(), analyses.list(includeDone, zone));
        } else {
            CsvWriter.writeRemediations(response.getOutputStream(), service.list(zone, status));
        }
    }

    /** 자산과 발자취까지 함께 읽는다 — 화면이 둘 다 쓴다. */
    private Remediation remediation(Long id) {
        return remediations.findDetail(id)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "조치를 찾을 수 없습니다."));
    }
}
