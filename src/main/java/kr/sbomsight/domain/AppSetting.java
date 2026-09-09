package kr.sbomsight.domain;

import jakarta.persistence.*;

import java.time.Instant;

/** 웹에서 바꾸는 설정 한 줄. */
@Entity
@Table(name = "app_settings")
public class AppSetting {

    /** 접속 허용 IP·CIDR 목록. 줄바꿈이나 쉼표로 구분한다. */
    public static final String ALLOWED_IPS = "allowed_ips";

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
