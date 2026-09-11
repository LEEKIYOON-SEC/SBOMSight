package kr.sbomsight.domain;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.time.Instant;

/**
 * 구역 — 망분리 단위.
 *
 * <p>DMZ · 내부업무 · 개발 · 관리처럼 <b>통제가 다르게 걸리는 묶음</b>이다.
 * 앞서는 자산에 붙은 문자열이었고 표에 찍히기만 했다. 그러면 'DMZ' 와 'DMZ '
 * 가 다른 구역이 되고, 화면에 세우는 순서도 정할 수 없고, "이 구역 전체
 * 현황"을 묻는 순간 답이 안 나온다.
 *
 * <p>자산은 반드시 하나의 구역에 속한다. 어디에도 속하지 않는 자산이 생기면
 * 구역별 합계가 전체와 어긋나고, 그때 어느 쪽이 맞는지 알 수 없다.
 */
@Entity
@Table(name = "zones")
public class Zone {

    /** 옮겨 갈 곳이 없는 자산을 받는 자리. 마이그레이션이 만들어 둔다. */
    public static final String UNASSIGNED = "미분류";

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "구역 이름을 입력하세요.")
    @Size(max = 64, message = "구역 이름은 64자까지입니다.")
    @Column(nullable = false, unique = true, length = 64)
    private String name;

    /** 화면에 세우는 순서. 같으면 이름순. */
    @Column(name = "sort_order", nullable = false)
    private int sortOrder = 0;

    /** 좌측 레일에 쓰는 색. 비어 있으면 화면이 기본색을 준다. */
    @Size(max = 16)
    @Column(nullable = false, length = 16)
    private String color = "";

    @Size(max = 500)
    @Column(nullable = false, length = 500)
    private String note = "";

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    protected Zone() {
    }

    public Zone(String name) {
        setName(name);
    }

    /** 미분류는 자산이 갈 곳이 없을 때의 마지막 자리라 지우거나 이름을 바꿀 수 없다. */
    public boolean isUnassigned() {
        return UNASSIGNED.equals(name);
    }

    public Long getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        // 앞뒤 공백을 남기면 'DMZ ' 와 'DMZ' 가 다른 구역이 된다.
        this.name = name == null ? "" : name.trim();
    }

    public int getSortOrder() {
        return sortOrder;
    }

    public void setSortOrder(int sortOrder) {
        this.sortOrder = sortOrder;
    }

    public String getColor() {
        return color;
    }

    public void setColor(String color) {
        this.color = color == null ? "" : color.trim();
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
}
