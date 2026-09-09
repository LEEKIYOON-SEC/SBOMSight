package kr.sbomsight.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.nio.file.Path;

/**
 * {@code sbomsight.*} 설정.
 *
 * @param dataDir             SBOM 원본과 grype 결과를 gzip 으로 보관하는 곳
 * @param grypePath           grype 실행 파일. PATH 에 있으면 이름만으로 충분하다
 * @param syftPath            syft 실행 파일 (서버에서 직접 SBOM 을 뜰 때만 쓴다)
 * @param grypeTimeoutMinutes 이 시간을 넘기면 실패로 남긴다 — 영원히 도는 것보다 낫다
 * @param bootstrapAdmin      계정이 하나도 없을 때 만들 최초 관리자 이름
 * @param allowedIps          접속 허용 IP·CIDR — **부트스트랩 값이다.** 웹의
 *                            설정에서 한 번이라도 저장하면 그때부터 DB 값이 쓰인다
 */
@ConfigurationProperties(prefix = "sbomsight")
public record SbomSightProperties(
        Path dataDir,
        String grypePath,
        String syftPath,
        int grypeTimeoutMinutes,
        String bootstrapAdmin,
        String allowedIps
) {
    public Path scanDir(long assetId, long scanId) {
        return dataDir.resolve("assets").resolve(String.valueOf(assetId))
                      .resolve(String.valueOf(scanId));
    }
}
