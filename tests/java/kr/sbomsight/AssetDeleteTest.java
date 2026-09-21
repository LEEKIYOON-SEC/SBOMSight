package kr.sbomsight;

import kr.sbomsight.domain.AnalysisJustification;
import kr.sbomsight.domain.AnalysisResponse;
import kr.sbomsight.domain.AnalysisState;
import kr.sbomsight.domain.Asset;
import kr.sbomsight.domain.Finding;
import kr.sbomsight.domain.Remediation;
import kr.sbomsight.domain.Scan;
import kr.sbomsight.domain.ScanStatus;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.AuditLogRepository;
import kr.sbomsight.repo.ComponentRepository;
import kr.sbomsight.repo.FindingAnalysisRepository;
import kr.sbomsight.repo.FindingRepository;
import kr.sbomsight.repo.RemediationRepository;
import kr.sbomsight.repo.ScanRepository;
import kr.sbomsight.service.AssetService;
import kr.sbomsight.service.ComponentInventoryService;
import kr.sbomsight.service.FindingAnalysisService;
import kr.sbomsight.service.ZoneService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.math.BigDecimal;
import java.time.LocalDate;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 자산을 지우면 <b>그 안의 것이 전부 함께 사라지는가.</b>
 *
 * <p><b>왜 새로 만드는가.</b> 시험 270개 중 {@link AssetService#delete} 를 도는
 * 것이 하나도 없었다. 화면에는 삭제 단추가 있고, 지우는 것이 몇 건인지까지
 * 세어 보여 주는데, 그 길을 지나가는 시험이 없었다.
 *
 * <p>지워지는 것은 네 갈래다 — 검사·탐지·조치·검토 결과. 그리고 **전부 FK
 * {@code ON DELETE CASCADE} 에 기대고 있다.** 그래서 다음 둘이 어긋나면
 * 조용히 깨진다.
 *
 * <ol>
 *   <li><b>Flyway 에 {@code CASCADE} 가 없으면 운영에서 삭제가 실패한다.</b>
 *       {@code finding_analysis} 가 그랬다 — 검토 결과를 한 건이라도 적은
 *       자산은 지울 수 없었다.</li>
 *   <li><b>엔티티에 {@code @OnDelete} 가 없으면 H2 에만 없다.</b> 하이버네이트가
 *       만드는 DDL 은 그 표시 없이는 {@code CASCADE} 를 넣지 않으므로, 운영은
 *       되는데 시험에서만 참조 무결성 위반이 난다 — 즉 <b>이 삭제를 시험으로
 *       지킬 수 없다.</b></li>
 * </ol>
 *
 * <p>이 시험은 트랜잭션 없이 돈다. {@code @Transactional} 을 붙이면 시험이 끝나며
 * 롤백되어 <b>FK 가 실제로 어떻게 걸렸는지 보지 못한다.</b>
 */
@SpringBootTest
@org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
class AssetDeleteTest {

    @Autowired AssetService assetService;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired RemediationRepository remediations;
    @Autowired FindingAnalysisRepository analyses;
    @Autowired FindingAnalysisService analysisService;
    @Autowired ComponentRepository components;
    @Autowired ComponentInventoryService inventory;
    @Autowired ZoneService zoneService;
    @Autowired AuditLogRepository auditLogs;
    @Autowired org.springframework.test.web.servlet.MockMvc mvc;

    @Test
    @DisplayName("검토 결과까지 적힌 자산도 지워진다 — 네 갈래가 함께 사라진다")
    void deletesEverythingUnderTheAsset() {
        Asset asset = new Asset();
        asset.setName("delete-" + System.nanoTime());
        asset.setZone(zoneService.unassigned());
        assets.saveAndFlush(asset);
        Long assetId = asset.getId();

        Scan scan = new Scan(asset, "tester");
        scan.setStatus(ScanStatus.DONE);
        scans.saveAndFlush(scan);

        Finding finding = new Finding(scan, "CVE-2024-3094|xz", "CVE-2024-3094", "xz");
        finding.setPackageVersion("5.6.0");
        finding.setSeverity("Critical");
        finding.setCvssScore(BigDecimal.valueOf(10.0));
        findings.saveAndFlush(finding);

        // `impactOf` 는 스캔에 적힌 건수 열을 더한다 — 화면이 보여 주는 값이다.
        scan.setMatchCount(1);
        scan.setFindingCount(1);
        scans.saveAndFlush(scan);

        Remediation remediation = new Remediation(asset, "xz", "tester");
        remediation.setFromVersion("5.6.0");
        remediation.setToVersion("5.6.2");
        remediations.saveAndFlush(remediation);

        // 검토 결과 — 이력(event)까지 함께 생긴다. 두 번 적어 이력을 두 줄로.
        analysisService.record(asset, "CVE-2024-3094", "xz",
                               AnalysisState.IN_TRIAGE, null, null,
                               "확인 중", null, null, null, "tester");
        analysisService.record(asset, "CVE-2024-3094", "xz",
                               AnalysisState.NOT_AFFECTED,
                               AnalysisJustification.CODE_NOT_REACHABLE,
                               AnalysisResponse.WILL_NOT_FIX,
                               "이 기능을 쓰지 않습니다", null, "보안-2026-0001",
                               LocalDate.now().plusDays(30), "tester");

        assertThat(analyses.findByAsset(assetId)).hasSize(1);

        AssetService.Impact impact = assetService.impactOf(asset);
        assertThat(impact.scanCount()).isEqualTo(1);
        assertThat(impact.findingCount()).isEqualTo(1);
        assertThat(impact.remediationCount()).isEqualTo(1);
        assertThat(impact.analysisCount())
                .as("지울 것을 세어 보여 주는데 검토 결과가 빠지면 안 된다")
                .isEqualTo(1);

        // 여기가 터지던 자리다 — finding_analysis 의 FK 에 CASCADE 가 없었다.
        assetService.delete(asset, "tester");

        assertThat(assets.findById(assetId)).isEmpty();
        assertThat(scans.findByAssetIdOrderByCreatedAtDesc(assetId)).isEmpty();
        assertThat(findings.findById(finding.getId()))
                .as("없는 자산의 탐지가 남았다")
                .isEmpty();
        assertThat(remediations.findById(remediation.getId()))
                .as("없는 자산의 조치가 남았다")
                .isEmpty();
        assertThat(analyses.findByAsset(assetId))
                .as("없는 자산의 검토 결과가 남았다")
                .isEmpty();
        assertThat(components.countByAssetId(assetId)).isZero();
    }

    /**
     * <b>지운 기록이 실제보다 적게 남지 않는가.</b>
     *
     * <p>누르기 전 확인 상자는 검토 결과 건수를 세어 보여 주는데, <b>감사
     * 로그와 완료 안내에는 그 항목이 빠져 있었다.</b> 파괴적 작업의 기록이
     * 실제와 다르면 점검에서 답이 어긋난다 — 조치만 지워진 줄 알고 넘어간다.
     */
    @Test
    @DisplayName("지운 기록에 검토 결과 건수가 함께 남는다")
    void auditRecordsWhatWasDestroyed() throws Exception {
        Asset asset = new Asset();
        asset.setName("audit-" + System.nanoTime());
        asset.setZone(zoneService.unassigned());
        assets.saveAndFlush(asset);

        analysisService.record(asset, "CVE-2024-3094", "xz",
                               AnalysisState.IN_TRIAGE, null, null,
                               "확인 중", null, null, null, "tester");

        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                            .post("/assets/" + asset.getId() + "/delete")
                            .param("confirm", asset.getName())
                            .with(org.springframework.security.test.web.servlet.request
                                          .SecurityMockMvcRequestPostProcessors
                                          .user("tester").roles("ADMIN"))
                            .with(org.springframework.security.test.web.servlet.request
                                          .SecurityMockMvcRequestPostProcessors.csrf()))
               .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                                  .status().is3xxRedirection());

        String detail = auditLogs.findAll().stream()
                .filter(a -> a.getAction() == kr.sbomsight.domain.AuditEvent.ASSET_DELETED)
                .filter(a -> asset.getName().equals(a.getTarget()))
                .findFirst().orElseThrow(() -> new AssertionError("삭제 기록이 없습니다"))
                .getDetail();
        assertThat(detail)
                .as("지운 기록에 검토 결과가 빠지면 점검에서 답이 어긋난다")
                .contains("검토 결과 1건");
    }
}
