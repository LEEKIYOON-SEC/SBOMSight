package kr.sbomsight.domain;

import jakarta.persistence.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 설치된 패키지 하나 — SBOM 이 담아 온 것.
 *
 * <p><b>{@link Finding} 과 다르다.</b> 탐지는 grype 이 "이 패키지에 이 CVE 가
 * 있다" 고 말한 것이고, 이것은 SBOM 이 "이 패키지가 깔려 있다" 고 말한 것이다.
 * 취약점이 하나도 없는 패키지도 여기 있다 — 그것이 이 표를 두는 이유다.
 * {@code log4j} 가 어디 깔려 있는지 <b>CVE 가 터지기 전에</b> 물을 수 있어야
 * 한다.
 *
 * <p><b>자산마다 최신 검사 것만 둔다.</b> 검사마다 쌓으면 컴포넌트 12만 개짜리
 * SBOM × 100대 × 12개월이 1억 4천만 행이다. 새 검사가 읽히면 그 자산의 이전
 * 행을 지운다 — 그래서 이 표는 "지금 깔려 있는 것" 이지 이력이 아니다.
 *
 * <p>값은 SBOM 이 준 것을 그대로 옮긴다. 비어 있는 칸은 <b>SBOM 이 안 담은
 * 것</b>이고, 우리가 채워 넣지 않는다.
 */
@Entity
@Table(name = "component")
public class Component {

    private static final Logger log = LoggerFactory.getLogger(Component.class);

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * <b>{@code @OnDelete} 를 왜 붙이는가.</b>
     *
     * <p>V13 의 FK 에는 {@code ON DELETE CASCADE} 가 붙어 있다. 그런데 시험은
     * H2 에 {@code ddl-auto=create-drop} 으로 도므로 <b>스키마를 하이버네이트가
     * 만든다</b> — 그리고 하이버네이트는 이 표시가 없으면 CASCADE 없는 FK 를
     * 낸다. 그러면 "자산을 지우면 패키지 목록도 사라지는가" 를 시험이 확인할
     * 수 없고, 실제로 처음 돌렸을 때 H2 에서만 참조 제약 위반이 났다.
     *
     * <p>이 표시가 있으면 생성되는 DDL 에도 CASCADE 가 들어가 <b>시험하는 것과
     * 운영하는 것이 같아진다.</b>
     */
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "asset_id", nullable = false)
    @org.hibernate.annotations.OnDelete(action = org.hibernate.annotations.OnDeleteAction.CASCADE)
    private Asset asset;

    /**
     * 어느 검사에서 온 것인가.
     *
     * <p>화면에 <b>기준이 된 검사</b>를 찍는다 — 언제 본 것인지 모르는 목록을
     * "지금 깔려 있는 것" 이라고 말할 수 없다. 스캔을 지우면 여기서 온 행도
     * 함께 사라진다.
     */
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "scan_id", nullable = false)
    @org.hibernate.annotations.OnDelete(action = org.hibernate.annotations.OnDeleteAction.CASCADE)
    private Scan scan;

    @Column(nullable = false, length = 255)
    private String name = "";

    @Column(nullable = false, length = 255)
    private String version = "";

    /** {@code rpm} · {@code deb} · {@code java-archive} … purl 에서 딴다. */
    @Column(nullable = false, length = 64)
    private String type = "";

    @Column(nullable = false, length = 512)
    private String purl = "";

    /**
     * 설치 경로. SBOM 이 담아 줄 때만 있다.
     *
     * <p>비어 있는 것은 "경로가 없는 패키지" 가 아니라 <b>SBOM 이 안 담은
     * 것</b>이다. 화면에서 그 둘을 같은 모양으로 보여 주지 않는다.
     */
    @Column(nullable = false, length = 1000)
    private String location = "";

    protected Component() {
    }

    public Component(Asset asset, Scan scan, String name, String version,
                     String type, String purl, String location) {
        this.asset = asset;
        this.scan = scan;
        this.name = clip(name, 255);
        this.version = clip(version, 255);
        this.type = clip(type, 64);
        this.purl = clip(purl, 512);
        this.location = clip(location, 1000);
    }

    public Long getId() {
        return id;
    }

    public Asset getAsset() {
        return asset;
    }

    public Scan getScan() {
        return scan;
    }

    public String getName() {
        return name;
    }

    public String getVersion() {
        return version;
    }

    /** 버전을 SBOM 이 안 담았으면 그렇다고 말한다. 빈 칸으로 두면 읽는 사람이 헷갈린다. */
    public String versionOrDash() {
        return version.isBlank() ? "—" : version;
    }

    public String getType() {
        return type;
    }

    public String getPurl() {
        return purl;
    }

    public String getLocation() {
        return location;
    }

    /** 같은 패키지의 같은 버전인가. 버전 분포를 묶는 축이다. */
    public String key() {
        return name + "@" + version;
    }

    private static String clip(String value, int max) {
        if (value == null) {
            return "";
        }
        String trimmed = value.trim();
        if (trimmed.length() <= max) {
            return trimmed;
        }
        log.warn("값이 열 폭({})을 넘어 잘랐습니다: {}…", max, trimmed.substring(0, Math.min(60, max)));
        return trimmed.substring(0, max);
    }
}
