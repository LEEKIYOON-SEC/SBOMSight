package kr.sbomsight.grype;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import kr.sbomsight.domain.Finding;
import kr.sbomsight.domain.Scan;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.*;

/**
 * grype JSON 을 저장할 행으로 옮긴다.
 *
 * <p>이 클래스가 지키는 규칙은 하나다 — <b>옮기기만 하고 판단하지 않는다.</b>
 * 설치 버전과 수정 버전을 비교해 "취약한가"를 다시 계산하지 않고, 심각도를
 * 재분류하지 않으며, 값이 없을 때 그럴듯한 기본값을 지어내지 않는다. grype 이
 * 틀렸다면 그것은 grype 의 오류로 감수하지만, 우리 코드 때문에 결과가 달라지는
 * 것은 감수 대상이 아니다.
 *
 * <p>버리는 건이 있으면 세어서 남긴다({@link Result}). 조용히 버리면 몇 건이
 * 사라졌는지 아무도 모른다.
 */
@Component
public class GrypeMapper {

    private static final Logger log = LoggerFactory.getLogger(GrypeMapper.class);

    /** CVSS 판 우선순위. 높은 판이 더 정확한 벡터를 준다. */
    private static final Map<String, Integer> CVSS_RANK =
            Map.of("4.0", 4, "3.1", 3, "3.0", 2, "2.0", 1);

    private final ObjectMapper json;

    public GrypeMapper(ObjectMapper json) {
        this.json = json;
    }

    /**
     * @param findings 저장할 건들
     * @param matches  grype 이 낸 match 수
     * @param merged   같은 키라 합쳐진 수
     * @param dropped  패키지 이름이나 CVE 가 없어 버린 수
     */
    public record Result(List<Finding> findings, int matches, int merged, int dropped) {
    }

    public Result map(Scan scan, GrypeReport report) {
        List<GrypeReport.Match> matches = report.matchesOrEmpty();

        // 같은 키가 두 번 나오는 일이 있다(같은 CVE 를 여러 네임스페이스가 잡을 때).
        // 먼저 온 것을 남기되 몇 건이 합쳐졌는지 센다.
        Map<String, Finding> byKey = new LinkedHashMap<>();
        int merged = 0;
        int dropped = 0;

        for (GrypeReport.Match match : matches) {
            GrypeReport.Vulnerability vuln = match.vulnerability();
            GrypeReport.Artifact artifact = match.artifact();

            String cve = vuln == null ? null : trim(vuln.id());
            String name = artifact == null ? null : trim(artifact.name());
            if (cve == null || cve.isBlank() || name == null || name.isBlank()) {
                // 무엇을 버렸는지 로그로 남긴다. 숫자만 남으면 원인을 못 찾는다.
                log.warn("이름이나 CVE 가 없어 건너뛴 match: cve={} package={}", cve, name);
                dropped++;
                continue;
            }

            String key = key(cve, artifact);
            if (byKey.containsKey(key)) {
                merged++;
                continue;
            }
            byKey.put(key, toFinding(scan, key, cve, name, match));
        }

        return new Result(List.copyOf(byKey.values()), matches.size(), merged, dropped);
    }

    /** 스캔 자체에 대한 값 — grype 판·DB 기준일·배포판. */
    public void applyMetadata(Scan scan, GrypeReport report) {
        GrypeReport.Descriptor descriptor = report.descriptor();
        if (descriptor != null) {
            scan.setGrypeVersion(trim(descriptor.version()));
            if (descriptor.db() != null) {
                scan.setGrypeDbBuilt(parseInstant(descriptor.db().built()));
            }
        }
        GrypeReport.Distro distro = report.distro();
        if (distro != null) {
            scan.setDistroName(trim(distro.name()));
            scan.setDistroVersion(trim(distro.version()));
        }
    }

    // -----------------------------------------------------------------------

    private Finding toFinding(Scan scan, String key, String cve, String name,
                              GrypeReport.Match match) {
        GrypeReport.Vulnerability vuln = match.vulnerability();
        GrypeReport.Artifact artifact = match.artifact();

        Finding finding = new Finding(scan, key, cve, name);
        finding.setSeverity(trim(vuln.severity()));
        finding.setDataSource(trim(vuln.dataSource()));
        finding.setDescription(description(vuln, match.relatedVulnerabilities()));

        applyCvss(finding, vuln, match.relatedVulnerabilities());
        applyExploit(finding, vuln, cve);
        applyArtifact(finding, artifact);
        applyFix(finding, vuln);
        applyMatchDetail(finding, match.matchDetails());

        finding.setDetailJson(detailJson(vuln, artifact, match.relatedVulnerabilities()));
        return finding;
    }

    /**
     * CVSS 는 여러 개가 온다. 판이 높고 Primary 인 것을 고른다.
     *
     * <p>고른 뒤 점수를 손보지 않는다 — 반올림도 grype 이 준 값 그대로 두 자리로
     * 담을 뿐이다.
     */
    private void applyCvss(Finding finding, GrypeReport.Vulnerability vuln,
                           List<GrypeReport.Vulnerability> related) {
        List<GrypeReport.Cvss> all = new ArrayList<>();
        if (vuln.cvss() != null) {
            all.addAll(vuln.cvss());
        }
        // 주 항목에 CVSS 가 없으면 관련 CVE(보통 NVD) 것을 쓴다. grype 자신이
        // 그 둘을 한 건으로 묶어 낸 것이므로 출처를 넘나드는 것이 아니다.
        if (related != null) {
            for (GrypeReport.Vulnerability rel : related) {
                if (rel != null && rel.cvss() != null) {
                    all.addAll(rel.cvss());
                }
            }
        }

        GrypeReport.Cvss best = null;
        int bestRank = -1;
        for (GrypeReport.Cvss entry : all) {
            if (entry == null || entry.metrics() == null || entry.metrics().baseScore() == null) {
                continue;
            }
            int rank = CVSS_RANK.getOrDefault(trim(entry.version()), 0) * 2
                     + ("primary".equalsIgnoreCase(trim(entry.type())) ? 1 : 0);
            if (rank > bestRank) {
                bestRank = rank;
                best = entry;
            }
        }
        if (best == null) {
            return;
        }
        finding.setCvssScore(BigDecimal.valueOf(best.metrics().baseScore())
                                       .setScale(2, RoundingMode.HALF_UP));
        finding.setCvssVector(trim(best.vector()));
        finding.setCvssVersion(trim(best.version()));
    }

    /**
     * EPSS 와 KEV.
     *
     * <p>grype 이 주지 않으면 <b>null 로 남긴다.</b> 0 이나 false 로 채우면
     * "악용 확률 0%"·"악용된 적 없음"이라는, 아무도 확인하지 않은 판정이 화면에
     * 뜬다. 없는 것은 없는 것으로 표시해야 한다.
     */
    private void applyExploit(Finding finding, GrypeReport.Vulnerability vuln, String cve) {
        if (vuln.epss() != null && !vuln.epss().isEmpty()) {
            vuln.epss().stream()
                .filter(e -> e != null && e.epss() != null)
                // 같은 match 안에 여러 CVE 의 EPSS 가 실릴 수 있다. 이 건의 것만 쓴다.
                .filter(e -> e.cve() == null || e.cve().isBlank() || cve.equalsIgnoreCase(e.cve()))
                .findFirst()
                .ifPresent(e -> finding.setEpss(
                        BigDecimal.valueOf(e.epss()).setScale(8, RoundingMode.HALF_UP)));
        }

        if (vuln.knownExploited() != null) {
            List<GrypeReport.KnownExploited> kev = vuln.knownExploited().stream()
                    .filter(Objects::nonNull)
                    .filter(k -> k.cve() == null || k.cve().isBlank() || cve.equalsIgnoreCase(k.cve()))
                    .toList();
            // 목록 자체가 왔다는 것은 grype 이 KEV 를 확인했다는 뜻이다. 그때만
            // true/false 를 쓰고, 목록이 아예 없으면 null 로 둔다.
            finding.setKev(!kev.isEmpty());
            finding.setKevRansomware(kev.stream().anyMatch(GrypeReport.KnownExploited::ransomware));
        }

        if (vuln.risk() != null) {
            finding.setGrypeRisk(BigDecimal.valueOf(vuln.risk()).setScale(4, RoundingMode.HALF_UP));
        }
    }

    private void applyArtifact(Finding finding, GrypeReport.Artifact artifact) {
        if (artifact == null) {
            return;
        }
        finding.setPackageVersion(trim(artifact.version()));
        finding.setPackageType(trim(artifact.type()));
        finding.setPackagePurl(trim(artifact.purl()));
        finding.setPackageLanguage(trim(artifact.language()));
    }

    private void applyFix(Finding finding, GrypeReport.Vulnerability vuln) {
        GrypeReport.Fix fix = vuln.fix();
        if (fix == null) {
            return;
        }
        finding.setFixState(trim(fix.state()));
        if (fix.versions() != null && !fix.versions().isEmpty()) {
            // 여러 개면 첫 번째를 쓰고 나머지는 상세에 남긴다. 어느 것이 우리
            // 환경에 맞는지 고르는 것은 우리가 할 판단이 아니다.
            finding.setFixedVersion(trim(fix.versions().get(0)));
        }
    }

    private void applyMatchDetail(Finding finding, List<GrypeReport.MatchDetail> details) {
        if (details == null) {
            return;
        }
        for (GrypeReport.MatchDetail detail : details) {
            if (detail == null) {
                continue;
            }
            if (finding.getMatchType().isBlank()) {
                finding.setMatchType(trim(detail.type()));
            }
            if (finding.getMatcher().isBlank()) {
                finding.setMatcher(trim(detail.matcher()));
            }
            if (finding.getNamespace().isBlank() && detail.searchedBy() != null) {
                finding.setNamespace(trim(detail.searchedBy().namespace()));
            }
            if (finding.getVersionConstraint().isBlank() && detail.found() != null) {
                finding.setVersionConstraint(trim(detail.found().versionConstraint()));
            }
        }
    }

    private String description(GrypeReport.Vulnerability vuln,
                               List<GrypeReport.Vulnerability> related) {
        String text = trim(vuln.description());
        if (!text.isBlank()) {
            return text;
        }
        // 배포판 권고는 설명이 비는 일이 흔하다. NVD 쪽(관련 CVE)에서 가져온다.
        if (related != null) {
            for (GrypeReport.Vulnerability rel : related) {
                if (rel != null && rel.description() != null && !rel.description().isBlank()) {
                    return rel.description().trim();
                }
            }
        }
        return null;
    }

    /** 표에 안 쓰는 나머지. 상세 화면에서만 편다. */
    private String detailJson(GrypeReport.Vulnerability vuln, GrypeReport.Artifact artifact,
                              List<GrypeReport.Vulnerability> related) {
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("urls", vuln.urls());
        detail.put("namespace", vuln.namespace());
        detail.put("advisories", vuln.advisories());
        if (vuln.fix() != null) {
            detail.put("fixVersions", vuln.fix().versions());
        }
        if (artifact != null) {
            detail.put("cpes", artifact.cpes());
            detail.put("locations", artifact.locations());
            detail.put("metadata", artifact.metadata());
        }
        if (related != null && !related.isEmpty()) {
            detail.put("relatedIds", related.stream()
                    .filter(Objects::nonNull)
                    .map(GrypeReport.Vulnerability::id)
                    .filter(Objects::nonNull)
                    .toList());
        }
        try {
            return json.writeValueAsString(detail);
        } catch (JsonProcessingException e) {
            log.warn("상세 JSON 을 만들지 못했습니다: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 중복 제거와 이력 대조의 키.
     *
     * <p>버전을 넣는다 — 같은 CVE 라도 5.6.0 에서 잡힌 것과 5.6.3 에서 잡힌 것은
     * 다른 사건이다. 대신 이력 비교는 (CVE, 패키지명) 으로 따로 본다.
     */
    private String key(String cve, GrypeReport.Artifact artifact) {
        String name = artifact == null ? "" : trim(artifact.name());
        String version = artifact == null ? "" : trim(artifact.version());
        String purl = artifact == null ? "" : trim(artifact.purl());
        String key = cve + "|" + name + "|" + version + "|" + purl;
        // 열 길이를 넘으면 잘린 두 건이 같은 키가 되어 조용히 합쳐진다.
        // 그럴 일은 거의 없지만, 그때는 purl 을 줄여 충돌을 피한다.
        return key.length() <= 512 ? key
                : cve + "|" + name + "|" + version + "|#" + Integer.toHexString(purl.hashCode());
    }

    private Instant parseInstant(String text) {
        if (text == null || text.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(text.trim());
        } catch (DateTimeParseException e) {
            log.warn("grype DB 기준일을 읽지 못했습니다: {}", text);
            return null;
        }
    }

    private String trim(String value) {
        return value == null ? "" : value.trim();
    }
}
