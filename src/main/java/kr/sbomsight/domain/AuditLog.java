package kr.sbomsight.domain;

import jakarta.persistence.*;

import java.time.Instant;

/**
 * 감사 로그 한 줄 — 누가 · 언제 · 무엇을 · 어디서.
 *
 * <p>값은 <b>넣을 때 잘린다.</b> 한 줄이 열 폭을 넘겨 전체가 실패하면 그
 * 작업까지 함께 롤백된다. 기록을 남기려다 자산 삭제가 취소되는 것은 앞뒤가
 * 맞지 않는다.
 */
@Entity
@Table(name = "audit_log")
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Instant at = Instant.now();

    @Column(nullable = false, length = 64)
    private String actor = "";

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 48)
    private AuditEvent action;

    @Column(nullable = false, length = 256)
    private String target = "";

    @Column(nullable = false, length = 1000)
    private String detail = "";

    @Column(name = "client_ip", nullable = false, length = 64)
    private String clientIp = "";

    protected AuditLog() {
    }

    public AuditLog(AuditEvent action, String actor, String target, String detail, String clientIp) {
        this.action = action;
        this.actor = clip(actor, 64);
        this.target = clip(target, 256);
        this.detail = clip(detail, 1000);
        this.clientIp = clip(clientIp, 64);
    }

    private static String clip(String value, int max) {
        if (value == null) {
            return "";
        }
        String trimmed = value.trim();
        return trimmed.length() <= max ? trimmed : trimmed.substring(0, max);
    }

    public Long getId() {
        return id;
    }

    public Instant getAt() {
        return at;
    }

    public String getActor() {
        return actor;
    }

    public AuditEvent getAction() {
        return action;
    }

    public String getTarget() {
        return target;
    }

    public String getDetail() {
        return detail;
    }

    public String getClientIp() {
        return clientIp;
    }
}
