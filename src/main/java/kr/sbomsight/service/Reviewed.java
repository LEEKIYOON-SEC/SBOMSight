package kr.sbomsight.service;

/**
 * 검토가 어디까지 됐는가 — <b>{@code 2 / 7건}.</b>
 *
 * <p>묶어 세는 자리마다 필요하다. 취약점 화면의 CVE별·패키지별 줄, 자산
 * 보고서 4장, 구역 보고서 5장이 모두 "이 묶음의 몇 건에 답이 있나" 를
 * 말해야 한다. <b>한 곳에 두고 같은 조각으로 그린다</b>
 * ({@code fragments/ui :: reviewmark}) — 화면마다 따로 세면 같은 묶음이
 * 한쪽에서는 `검토함` 이고 다른 쪽에서는 `미검토` 가 된다.
 *
 * <p><b>참·거짓으로 두지 않는다.</b> 한 건만 적어 두고 묶음 전체를 `검토함`
 * 으로 말하면, 결재로 올라가는 문서가 아무도 보지 않은 건까지 설명된 것으로
 * 셈한다. 실제로 그랬다 — 보고서 4장이 {@code sudo 3건 · 최고 CVSS 9.60 ·
 * 해당 없음} 이라고 찍고 있었는데, 적어 둔 것은 CVSS 5.10 짜리 한 건이었다.
 *
 * @param done  적어 둔 것이 있는 건 수. 손대지 않은 행은 세지 않는다
 * @param total 그 묶음의 건 수 — <b>거르개를 건 뒤</b>의 수다
 */
public record Reviewed(long done, long total) {

    public boolean none() {
        return done == 0;
    }

    public boolean all() {
        return total > 0 && done == total;
    }
}
