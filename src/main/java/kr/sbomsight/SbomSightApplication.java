package kr.sbomsight;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.scheduling.annotation.EnableAsync;

/**
 * SBOMSight — SBOM 기반 취약점 대응 검토.
 *
 * <p>흐름은 넷이다. 서버에서 syft 로 SBOM 을 뜬다 → 이 웹에 올린다 →
 * grype 이 돌아 결과가 자산에 쌓인다 → 이력과 조치를 관리한다.
 *
 * <p>판정은 전부 grype 의 것이다. 이 애플리케이션은 grype 이 낸 결과를
 * 보관·정렬·집계할 뿐 다시 계산하지 않는다.
 */
@SpringBootApplication
@ConfigurationPropertiesScan
@EnableAsync
public class SbomSightApplication {

    public static void main(String[] args) {
        SpringApplication.run(SbomSightApplication.class, args);
    }
}
