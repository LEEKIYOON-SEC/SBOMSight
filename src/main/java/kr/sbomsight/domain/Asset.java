package kr.sbomsight.domain;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.time.Instant;

/**
 * 자산 — 서버 한 대.
 *
 * <p>관리 단위가 스캔이 아니라 서버라는 것이 이 도구의 전제다. "지난달 대비
 * web-01 에 무엇이 생기고 무엇이 사라졌나"가 실제로 묻는 질문이고, 최근 스캔
 * 목록으로는 그 답이 안 나온다.
 *
 * <p>담당자 필드는 두지 않는다 — 업무분장에 따라 바뀌는 것은 자산의 속성이
 * 아니다. 담당은 조치({@link Remediation})에 붙인다.
 */
@Entity
@Table(name = "assets")
public class Asset {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "서버 이름을 입력하세요.")
    @Size(max = 128)
    @Pattern(regexp = "^[A-Za-z0-9][A-Za-z0-9._-]*$",
             message = "영문·숫자로 시작하고 . _ - 만 쓸 수 있습니다.")
    @Column(nullable = false, unique = true, length = 128)
    private String name;

    @Size(max = 128)
    @Column(name = "group_name", nullable = false, length = 128)
    private String groupName = "";

    @Size(max = 128)
    @Column(name = "os_name", nullable = false, length = 128)
    private String osName = "";

    @Size(max = 500)
    @Column(nullable = false, length = 500)
    private String note = "";

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "archived_at")
    private Instant archivedAt;

    public Long getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getGroupName() {
        return groupName;
    }

    public void setGroupName(String groupName) {
        this.groupName = groupName == null ? "" : groupName.trim();
    }

    public String getOsName() {
        return osName;
    }

    public void setOsName(String osName) {
        this.osName = osName == null ? "" : osName.trim();
    }

    public String getNote() {
        return note;
    }

    public void setNote(String note) {
        this.note = note == null ? "" : note.trim();
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getArchivedAt() {
        return archivedAt;
    }

    public void setArchivedAt(Instant archivedAt) {
        this.archivedAt = archivedAt;
    }
}
