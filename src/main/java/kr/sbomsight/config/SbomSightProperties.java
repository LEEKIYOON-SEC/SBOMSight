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
 * @param maxLoginFailures    연속 실패 이 횟수에 이르면 계정을 잠근다. 0 이면 잠그지 않는다
 * @param lockMinutes         잠금이 스스로 풀리기까지의 시간(분). <b>0 이면 관리자가
 *                            풀어 줄 때까지 잠긴 채로 있다.</b> 기본 30분은 절충이다 —
 *                            영구 잠금은 점검 기준에 더 맞지만, 이름만 알면 누구든
 *                            남의 계정을 잠글 수 있고 새벽에 본인이 잠기면 손쓸 데가 없다
 * @param passwordMaxAgeDays  이 기간이 지나면 다음 로그인에서 변경을 강제한다. 0 이면 강제하지 않는다
 */
@ConfigurationProperties(prefix = "sbomsight")
public record SbomSightProperties(
        Path dataDir,
        String grypePath,
        String syftPath,
        int grypeTimeoutMinutes,
        String bootstrapAdmin,
        String allowedIps,
        int maxLoginFailures,
        int lockMinutes,
        int passwordMaxAgeDays
) {
    /** 잠금이 스스로 풀리기까지. {@code null} 이면 관리자가 풀어 줄 때까지. */
    public java.time.Duration autoUnlockAfter() {
        return lockMinutes <= 0 ? null : java.time.Duration.ofMinutes(lockMinutes);
    }

    public boolean lockoutEnabled() {
        return maxLoginFailures > 0;
    }

    public boolean passwordExpiryEnabled() {
        return passwordMaxAgeDays > 0;
    }

    public Path scanDir(long assetId, long scanId) {
        return dataDir.resolve("assets").resolve(String.valueOf(assetId))
                      .resolve(String.valueOf(scanId));
    }
}
