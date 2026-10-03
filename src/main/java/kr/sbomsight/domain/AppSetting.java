package kr.sbomsight.domain;

import jakarta.persistence.*;

import java.time.Instant;

/**
 * 설정 한 줄 — 웹에서 바꾸는 값, 그리고 마이그레이션이 한 번 적는 표시
 * ({@link #HISTORY_FIELDS_SINCE}).
 */
@Entity
@Table(name = "app_settings")
public class AppSetting {

    /** 접속 허용 IP·CIDR 목록. 줄바꿈이나 쉼표로 구분한다. */
    public static final String ALLOWED_IPS = "allowed_ips";

    /**
     * 이력이 <b>적는 칸까지</b> 남기 시작한 시각 — V19 가 한 번 적는다({@code updated_at}).
     * 웹에서 바꾸지 않는다.
     *
     * <p>그 전에 바뀐 조치의 담당 · 기한 · 설명, 검토 결과의 설명 · 추가 보안 통제 ·
     * 결재 문서 번호는 이력에 없다. 그보다 먼저 만든 조치 · 검토 결과의 상세가 이
     * 시각을 각주로 밝힌다 — 없는 기록을 있는 것처럼 보이게 두지 않는다. 이 줄이 없으면
     * (마이그레이션을 거치지 않는 시험 DB) 처음부터 전부 남긴 것으로 본다.
     */
    public static final String HISTORY_FIELDS_SINCE = "history_fields_since";

    @Id
    @Column(nullable = false, length = 64)
    private String name;

    /**
     * 값.
     *
     * <p>열 이름은 {@code setting_value} 다 — {@code value} 는 여러 DB 에서
     * 예약어라 그대로 쓰면 방언에 따라 표가 조용히 안 만들어진다.
     */
    @Column(name = "setting_value", nullable = false, length = 4000)
    private String value = "";

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    @Column(name = "updated_by", nullable = false, length = 64)
    private String updatedBy = "";

    protected AppSetting() {
    }

    public AppSetting(String name, String value, String updatedBy) {
        this.name = name;
        set(value, updatedBy);
    }

    public void set(String value, String updatedBy) {
        String text = value == null ? "" : value;
        this.value = text.length() <= 4000 ? text : text.substring(0, 4000);
        this.updatedBy = updatedBy == null ? "" : updatedBy;
        this.updatedAt = Instant.now();
    }

    public String getName() {
        return name;
    }

    public String getValue() {
        return value;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public String getUpdatedBy() {
        return updatedBy;
    }
}
