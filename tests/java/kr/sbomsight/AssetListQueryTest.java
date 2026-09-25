package kr.sbomsight;

import jakarta.persistence.EntityManagerFactory;
import kr.sbomsight.domain.*;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.FindingRepository;
import kr.sbomsight.repo.RemediationRepository;
import kr.sbomsight.repo.ScanRepository;
import kr.sbomsight.service.ZoneService;
import org.hibernate.SessionFactory;
import org.hibernate.stat.Statistics;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * <b>자산 목록의 질의 수가 자산 수를 따라 늘지 않는다.</b>
 *
 * <p>앞서 자산마다 심각도 분포 한 번, 열린 조치 수 한 번을 따로 물었다. 요약
 * 줄이 거르기 전 전체를 세므로 쪽에 안 보이는 자산까지 — 자산 3천 대면 한 번
 * 여는 데 질의가 6천 번이다. 스무 대를 더 넣고 두 번 재어, 늘어난 질의 수가
 * 자산 수와 상관없는지 본다.
 */
@SpringBootTest(properties = "spring.jpa.properties.hibernate.generate_statistics=true")
@AutoConfigureMockMvc
@Transactional
class AssetListQueryTest {

    @Autowired MockMvc mvc;
    @Autowired AssetRepository assets;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired RemediationRepository remediations;
    @Autowired ZoneService zoneService;
    @Autowired EntityManagerFactory emf;

    @Test
    @DisplayName("자산을 스무 대 더 넣어도 자산 목록의 질의 수가 늘지 않는다")
    void queriesDoNotGrowWithAssets() throws Exception {
        add(5);
        long few = statementsFor("/");
        add(20);
        long many = statementsFor("/");

        assertThat(many - few)
                .as("자산 스무 대를 더 넣었더니 질의가 %d 번 늘었다 — 자산마다 묻고 있다", many - few)
                .isLessThanOrEqualTo(2);
    }

    private long statementsFor(String url) throws Exception {
        Statistics stats = emf.unwrap(SessionFactory.class).getStatistics();
        stats.clear();
        mvc.perform(get(url).with(user("tester").roles("ADMIN"))).andExpect(status().isOk());
        return stats.getPrepareStatementCount();
    }

    private void add(int count) {
        for (int i = 0; i < count; i++) {
            Asset asset = new Asset();
            asset.setName("q-" + System.nanoTime());
            asset.setZone(zoneService.unassigned());
            assets.save(asset);

            Scan scan = new Scan(asset, "tester");
            scan.setStatus(ScanStatus.DONE);
            scan.setCreatedAt(Instant.now());
            scans.save(scan);

            Finding f = new Finding(scan, "CVE-2099-1|q-pkg", "CVE-2099-1", "q-pkg");
            f.setSeverity("High");
            findings.save(f);

            Remediation r = new Remediation(asset, "q-pkg", "tester");
            r.moveTo(RemediationStatus.OPEN, "tester", "조치 등록");
            remediations.save(r);
        }
        assets.flush();
    }
}
