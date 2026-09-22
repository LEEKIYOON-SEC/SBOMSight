package kr.sbomsight.web;

import kr.sbomsight.domain.Asset;
import kr.sbomsight.domain.AuditEvent;
import kr.sbomsight.domain.Remediation;
import kr.sbomsight.domain.Scan;
import kr.sbomsight.domain.ScanStatus;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.ScanRepository;
import kr.sbomsight.service.AuditService;
import kr.sbomsight.service.RemediationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.security.Principal;

import static org.springframework.http.HttpStatus.NOT_FOUND;

/**
 * 조치를 <b>여는</b> 자리.
 *
 * <p>목록과 상세는 {@link ActionController}(`/actions`)로 옮겼다. 여기 남은
 * 것은 패키지 하나를 집어 조치로 올리는 길이다 — <b>등록은 목록이 아니라
 * 건을 보면서 한다.</b>
 *
 * <p>길이 둘이다. 보고서는 <b>그 검사</b>를 놓고 말하고, 취약점 화면과 검토
 * 결과는 <b>지금 상태</b>를 놓고 말한다. 뒤엣것은 자산의 최신 완료 검사를
 * 스스로 찾는다 — 화면에 검사 번호를 물으면 답할 것이 없다.
 */
@Controller
public class RemediationController {

    private static final Logger log = LoggerFactory.getLogger(RemediationController.class);

    private final ScanRepository scans;
    private final AssetRepository assets;
    private final RemediationService service;
    private final AuditService audit;

    public RemediationController(ScanRepository scans, AssetRepository assets,
                                 RemediationService service, AuditService audit) {
        this.scans = scans;
        this.assets = assets;
        this.service = service;
        this.audit = audit;
    }

    /**
     * 검사 하나에서 — 보고서 3장의 {@code 조치 등록}.
     *
     * <p>보고서는 그 검사를 놓고 말하므로 검사를 그대로 받는다. 등록 당시
     * 버전과 건수는 <b>그 검사</b>의 것으로 남는다.
     */
    @PostMapping("/scans/{scanId}/remediations")
    @PreAuthorize("hasRole('ADMIN')")
    public String open(@PathVariable Long scanId, @RequestParam String packageName,
                       Principal principal, RedirectAttributes flash) {
        Scan scan = scans.findWithAsset(scanId)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "검사를 찾을 수 없습니다."));
        return opened(openOrRejoin(scan.getAsset(), scan, packageName, principal.getName()),
                      packageName, flash);
    }

    /**
     * 자산에서 — 취약점 화면과 대응 화면의 {@code 조치 등록}.
     *
     * <p><b>왜 길이 둘인가.</b> 보고서는 그 검사를 놓고 말하지만, 취약점
     * 화면과 검토 결과는 <b>지금 상태</b>를 놓고 말한다. 거기서 검사 번호를
     * 물으면 화면이 답할 것이 없다 — 자산의 <b>최신 완료 검사</b>가 곧
     * 지금이다.
     *
     * <p>검사가 한 번도 끝나지 않은 자산에는 열지 않는다. 등록 당시 버전과
     * 건수를 남길 근거가 없고, 근거 없는 스냅샷은 나중에 "그때 무엇을 보고
     * 정했나" 에 답하지 못한다.
     */
    @PostMapping("/assets/{assetId}/remediations")
    @PreAuthorize("hasRole('ADMIN')")
    public String openForAsset(@PathVariable Long assetId, @RequestParam String packageName,
                               Principal principal, RedirectAttributes flash) {
        Asset asset = assets.findById(assetId)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "자산을 찾을 수 없습니다."));
        Scan latest = scans.findFirstByAssetIdAndStatusOrderByCreatedAtDesc(
                assetId, ScanStatus.DONE).orElse(null);
        if (latest == null) {
            flash.addFlashAttribute("error",
                                    asset.getName() + " 은 완료된 검사가 없어 조치를 열 수 없습니다.");
            return "redirect:/assets/" + assetId;
        }
        return opened(openOrRejoin(asset, latest, packageName, principal.getName()),
                      packageName, flash);
    }

    /**
     * 열거나, <b>동시에 눌린 다른 요청이 먼저 연 것에 합류한다.</b>
     *
     * <p>조치는 {@code (자산, 패키지)} 하나에 하나이고 같은 패키지의 검토
     * 여러 줄이 모두 `조치 등록` 을 달고 있다 — 두 번 눌리는 것은 예외가
     * 아니라 보통이고, 빠르게 두 번 누르면 두 요청이 겹친다. 그때 DB 의
     * 유일 제약이 막아 <b>데이터는 갈라지지 않지만</b>, 예외가 그대로
     * 올라가면 화면이 500 이 되어 <b>조치가 열렸는지 아닌지를 알 수 없다.</b>
     *
     * <p>열린 것을 읽어 그리로 보낸다 — 두 번 눌러 하나가 열리는 것은
     * 원래 의도한 동작이고, 겹쳐 눌렸다는 사정은 누른 사람이 알 필요가 없다.
     */
    private RemediationService.Opened openOrRejoin(Asset asset, Scan scan,
                                                   String packageName, String actor) {
        try {
            return service.open(asset, scan, packageName, actor);
        } catch (DataIntegrityViolationException race) {
            log.info("조치를 여는 요청이 겹쳤습니다 — 먼저 열린 것으로 보냅니다: {} · {}",
                     asset.getName(), packageName);
            return service.rejoin(asset.getId(), packageName);
        }
    }

    /**
     * 연 뒤에는 그 조치로 간다 — <b>담당과 기한을 적을 자리가 거기다.</b>
     *
     * <p>{@link RemediationService#open} 은 같은 {@code (자산, 패키지)} 에
     * 둘을 만들지 않는다. 이미 있으면 그것을 돌려주므로 두 번 눌러도 조치가
     * 늘지 않는다 — 대신 말이 달라야 한다. "등록했습니다" 라고 해 놓고
     * 아무것도 안 생기면 다음에 또 누른다. <b>앞서 이 주석만 있고 코드는
     * 양쪽에 같은 말을 하고 있었다.</b>
     *
     * <p>새로 만든 것만 감사 로그에 남긴다. 등록 당시 건수와 목표 버전을
     * 함께 적는다 — 조치를 지우면 그 스냅샷이 함께 사라지고, 남는 것은
     * 감사 로그의 이 줄뿐이다.
     */
    private String opened(RemediationService.Opened opened, String packageName,
                          RedirectAttributes flash) {
        Remediation remediation = opened.remediation();
        if (opened.created()) {
            audit.record(AuditEvent.REMEDIATION_CREATED,
                         remediation.getAsset().getName() + " · " + packageName,
                         "등록 당시 " + remediation.getOpenedCount() + "건"
                         + (remediation.getFromVersion().isBlank() ? ""
                            : " · 현재 " + remediation.getFromVersion())
                         + (remediation.getToVersion().isBlank() ? ""
                            : " · 목표 " + remediation.getToVersion()));
            flash.addFlashAttribute("message", packageName + " 조치를 등록했습니다.");
        } else {
            flash.addFlashAttribute("message", packageName + " 조치는 이미 등록되어 있습니다.");
        }
        return "redirect:/actions/" + remediation.getId();
    }
}
