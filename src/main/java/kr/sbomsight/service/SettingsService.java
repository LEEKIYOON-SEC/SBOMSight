package kr.sbomsight.service;

import kr.sbomsight.domain.AppSetting;
import kr.sbomsight.repo.AppSettingRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 웹에서 바꾸는 설정.
 *
 * <p>허용 IP 는 <b>요청마다</b> 필요한데 DB 에 있다. 매번 읽으면 정적 파일 한
 * 장을 받는 데도 질의가 한 번 더 나간다. 값이 바뀌는 자리를 이 클래스가 전부
 * 쥐고 있으므로 캐시해 두고 저장할 때 버린다.
 */
@Service
public class SettingsService {

    private static final Logger log = LoggerFactory.getLogger(SettingsService.class);

    private final AppSettingRepository settings;

    /** 환경변수 부트스트랩 값. 웹에서 한 번이라도 저장하면 DB 값이 이긴다. */
    private final String bootstrapIps;

    private final AtomicReference<IpAllowlist> cached = new AtomicReference<>();

    public SettingsService(AppSettingRepository settings,
                           @Value("${sbomsight.allowed-ips:}") String bootstrapIps) {
        this.settings = settings;
        this.bootstrapIps = bootstrapIps;
    }

    public IpAllowlist allowlist() {
        IpAllowlist current = cached.get();
        if (current == null) {
            current = IpAllowlist.parse(allowedIpsText());
            cached.set(current);
        }
        return current;
    }

    @Transactional(readOnly = true)
    public String allowedIpsText() {
        return settings.findById(AppSetting.ALLOWED_IPS)
                       .map(AppSetting::getValue)
                       .orElse(bootstrapIps);
    }

    /**
     * 허용 IP 를 저장한다.
     *
     * <p>지금 접속 중인 주소가 빠진 목록은 <b>저장하지 않는다.</b> 저장하는
     * 순간 본인이 잠기고, 그러면 웹으로는 되돌릴 방법이 없다.
     *
     * @param currentIp 저장을 요청한 사람의 소켓 주소
     * @return 거부 사유. 저장했으면 비어 있다.
     */
    @Transactional
    public Optional<String> saveAllowedIps(String text, String currentIp, String actor) {
        IpAllowlist next = IpAllowlist.parse(text);
        if (!next.isEmpty() && !next.permits(currentIp)) {
            return Optional.of(
                    "지금 접속 중인 주소(" + currentIp + ")가 목록에 없습니다. "
                    + "저장하면 본인이 접속할 수 없게 되므로 저장하지 않았습니다.");
        }

        AppSetting setting = settings.findById(AppSetting.ALLOWED_IPS)
                .orElseGet(() -> new AppSetting(AppSetting.ALLOWED_IPS, "", actor));
        setting.set(text == null ? "" : text.trim(), actor);
        settings.save(setting);
        cached.set(null);

        log.info("접근 허용 IP 를 바꿨습니다 ({}): {}", actor,
                 next.isEmpty() ? "제한 없음" : text.replaceAll("\\s+", " "));
        return Optional.empty();
    }
}
