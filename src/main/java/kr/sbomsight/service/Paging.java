package kr.sbomsight.service;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;

import java.util.List;

/**
 * 목록을 쪽으로 나누는 한 벌 — <b>화면마다 다르게 굴지 않게.</b>
 *
 * <p>앞서는 목록이 화면마다 다른 방식으로 끝났다. 취약점과 감사 로그만 쪽
 * 넘김이 있었고, 패키지는 <b>앞 200개에서 말없이 잘렸으며</b>, 자산의 패키지
 * 탭·CVE별·패키지별·조치·검토 결과는 몇 천 줄이든 한 쪽에 쏟아졌다. 어느
 * 화면에서 무엇이 잘렸는지 알 방법이 없었다.
 *
 * <p>쪽 크기와 고를 수 있는 값은 <b>여기 한 곳에서만</b> 정한다. 화면마다
 * 적어 두면 한쪽만 고치는 날이 오고, 그때부터 같은 목록이 화면마다 다르게
 * 센다.
 *
 * <p>고를 수 있는 값만 받는다 — 주소에 손으로 적은 {@code size=50000} 이
 * 그대로 질의로 들어가면 한 사람이 화면 한 장으로 DB 를 붙잡는다.
 */
public final class Paging {

    /** 한 쪽에 몇 건. 주소에 적지 않는 기본값이다. */
    public static final int PAGE_SIZE = 100;

    /** 화면에서 고를 수 있는 값. 이 목록에 없는 값은 기본값으로 되돌린다. */
    public static final List<Integer> PAGE_SIZES = List.of(10, 30, 50, 100);

    private Paging() {
    }

    /** 목록에 없는 값은 기본값으로 되돌린다. {@code null} 도 기본값이다. */
    public static int sizeOf(Integer size) {
        return size != null && PAGE_SIZES.contains(size) ? size : PAGE_SIZE;
    }

    public static PageRequest request(int page, Integer size) {
        return PageRequest.of(Math.max(page, 0), sizeOf(size));
    }

    public static PageRequest request(int page, Integer size, Sort sort) {
        return PageRequest.of(Math.max(page, 0), sizeOf(size), sort);
    }

    /**
     * <b>이미 다 읽어 온 목록</b>을 자른다.
     *
     * <p>DB 에서 자르는 것이 낫지만 그럴 수 없는 목록이 있다 — 여러 질의를
     * 맞춰 조립한 것(자산 목록), 묶어 세는 질의(CVE별·패키지별)가 그렇다.
     * 그런 목록은 <b>지금도 전부 읽고 있다.</b> 여기서 자르는 것이 읽는 양을
     * 늘리지는 않고, 화면이 몇 천 줄을 한 번에 그리는 것만 막는다.
     *
     * <p><b>범위를 넘은 쪽 번호는 마지막 쪽으로 되돌린다.</b> 3쪽을 보다가
     * 거르개를 좁히거나 한 줄을 지우면 주소에 남은 {@code page=2} 가 갈 곳을
     * 잃는다 — 그때 빈 표를 내밀면 "조건에 맞는 것이 없다" 로 읽힌다.
     */
    public static <T> Page<T> slice(List<T> all, int page, Integer size) {
        int rows = sizeOf(size);
        int p = Math.max(page, 0);
        if ((long) p * rows >= all.size()) {
            p = all.isEmpty() ? 0 : (all.size() - 1) / rows;
        }
        int from = Math.min(p * rows, all.size());
        int to = Math.min(from + rows, all.size());
        return new PageImpl<>(all.subList(from, to), PageRequest.of(p, rows), all.size());
    }

    /**
     * 쪽 이동 칸에 적힌 번호를 주소로. 갈 곳이 없으면 {@code null}.
     *
     * <p><b>사람이 적는 값은 1부터</b>이고 주소의 {@code page} 는 0부터 센다
     * (스프링의 셈). 같은 이름으로 받으면 한 칸 어긋난 쪽으로 가므로 다른
     * 이름({@code jump})으로 받아 여기서 환산하고, 주소에는 남기지 않는다 —
     * 남기면 거르개를 바꿀 때마다 따라다니며 엉뚱한 쪽으로 튄다.
     */
    public static String jump(VulnQuery.Links links, Integer jump) {
        return jump != null && jump > 0 ? "redirect:" + links.page(jump - 1) : null;
    }
}
