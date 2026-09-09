package kr.sbomsight.grype;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;
import java.util.Map;

/**
 * grype JSON 출력의 모양.
 *
 * <p>모르는 필드는 무시한다({@code ignoreUnknown}). grype 이 판을 올릴 때마다
 * 필드가 붙는데, 그때마다 파싱이 깨지면 취약점 DB 를 최신으로 못 쓴다.
 *
 * <p>반대로 <b>있는 값을 없는 것으로 만들지는 않는다.</b> epss·knownExploited 는
 * 새 grype 만 주는데, 없을 때 0/false 로 채우면 "악용 확률 0%" 라는 없는 판정이
 * 생긴다. 그래서 전부 참조형이고 null 이 그대로 흘러간다.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GrypeReport(
        List<Match> matches,
        Source source,
        Distro distro,
        Descriptor descriptor
) {

    public List<Match> matchesOrEmpty() {
        return matches == null ? List.of() : matches;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Match(
            Vulnerability vulnerability,
            List<Vulnerability> relatedVulnerabilities,
            List<MatchDetail> matchDetails,
            Artifact artifact
    ) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Vulnerability(
            String id,
            String dataSource,
            String namespace,
            String severity,
            List<String> urls,
            String description,
            List<Cvss> cvss,
            Fix fix,
            List<Map<String, Object>> advisories,
            // --- grype 0.8x 이상 ---
            List<Epss> epss,
            List<KnownExploited> knownExploited,
            Double risk
    ) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Cvss(
            String source,
            String type,
            String version,
            String vector,
            Metrics metrics
    ) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Metrics(Double baseScore, Double exploitabilityScore, Double impactScore) {
    }

    /**
     * @param state    fixed · not-fixed · wont-fix · unknown — <b>이것이 조치 가능 여부의
     *                 유일한 근거다.</b> 설치 버전을 다시 비교하지 않는다.
     * @param versions 수정된 버전들. 보통 하나다.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Fix(List<String> versions, String state) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Epss(String cve, Double epss, Double percentile, String date) {
    }

    /** KEV — 실제로 악용이 확인된 것. 있으면 그 자체가 최우선 근거다. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record KnownExploited(
            String cve,
            String knownRansomwareCampaignUse,
            String dateAdded,
            String vendorProject,
            String product
    ) {
        public boolean ransomware() {
            return "known".equalsIgnoreCase(knownRansomwareCampaignUse);
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record MatchDetail(
            String type,
            String matcher,
            SearchedBy searchedBy,
            Found found
    ) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record SearchedBy(String namespace, String language, Map<String, Object> pkg) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Found(String vulnerabilityID, String versionConstraint) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Artifact(
            String id,
            String name,
            String version,
            String type,
            List<Location> locations,
            String language,
            List<String> cpes,
            String purl,
            String metadataType,
            Map<String, Object> metadata
    ) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Location(String path, String layerID) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Source(String type, Object target) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Distro(String name, String version, List<String> idLike) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Descriptor(String name, String version, Db db) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Db(String built, Integer schemaVersion, Long location) {
    }
}
