package kr.sbomsight;

import kr.sbomsight.service.IpAllowlist;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 접근 허용 목록.
 *
 * <p>이 판단이 틀리면 스캔 결과 — 어느 서버에 무엇이 열려 있는지 — 를 아무나
 * 열어 보게 되거나, 반대로 운영자가 자기 도구에서 잠긴다. 둘 다 심각하다.
 */
class IpAllowlistTest {

    @Test
    @DisplayName("목록이 비면 제한하지 않는다 — 켜 본 적 없는 운영자가 잠기지 않아야 한다")
    void emptyPermitsEverything() {
        assertThat(IpAllowlist.parse("").permits("203.0.113.9")).isTrue();
        assertThat(IpAllowlist.parse(null).permits("203.0.113.9")).isTrue();
        assertThat(IpAllowlist.unrestricted().permits("203.0.113.9")).isTrue();
    }

    @Test
    @DisplayName("접두 길이가 없으면 그 한 대를 뜻한다")
    void singleAddressIsOneHost() {
        IpAllowlist list = IpAllowlist.parse("10.0.0.5");
        assertThat(list.permits("10.0.0.5")).isTrue();
        assertThat(list.permits("10.0.0.6")).isFalse();
        assertThat(list.permits("10.0.0.0")).isFalse();
    }

    @Test
    @DisplayName("CIDR 은 그 대역을 덮는다")
    void cidrCoversRange() {
        IpAllowlist list = IpAllowlist.parse("192.168.10.0/24");
        assertThat(list.permits("192.168.10.1")).isTrue();
        assertThat(list.permits("192.168.10.254")).isTrue();
        assertThat(list.permits("192.168.11.1")).isFalse();
        assertThat(list.permits("192.168.9.255")).isFalse();
    }

    @Test
    @DisplayName("바이트 경계가 아닌 접두 길이도 맞게 자른다")
    void handlesNonByteBoundaryPrefix() {
        IpAllowlist list = IpAllowlist.parse("10.1.0.0/22");   // 10.1.0.0 ~ 10.1.3.255
        assertThat(list.permits("10.1.0.1")).isTrue();
        assertThat(list.permits("10.1.3.255")).isTrue();
        assertThat(list.permits("10.1.4.0")).isFalse();
    }

    @Test
    @DisplayName("줄바꿈·쉼표·공백 어느 것으로 구분해도 읽는다")
    void acceptsAnySeparator() {
        IpAllowlist list = IpAllowlist.parse("192.168.10.0/24, 10.0.0.5\n  ::1  ");
        assertThat(list.permits("192.168.10.7")).isTrue();
        assertThat(list.permits("10.0.0.5")).isTrue();
        assertThat(list.permits("::1")).isTrue();
        assertThat(list.permits("172.16.0.1")).isFalse();
    }

    @Test
    @DisplayName("판단할 수 없으면 막는다")
    void refusesWhatItCannotRead() {
        IpAllowlist list = IpAllowlist.parse("192.168.10.0/24");
        // 허용으로 처리하면 이 경로 하나로 목록 전체가 무력화된다.
        assertThat(list.permits("")).isFalse();
        assertThat(list.permits(null)).isFalse();
        assertThat(list.permits("아무말")).isFalse();
    }

    @Test
    @DisplayName("잘못 쓴 항목 하나가 목록 전체를 버리게 하지 않는다")
    void badEntryDoesNotDiscardTheRest() {
        // 오타 한 글자에 모두가 잠기면 안 된다.
        IpAllowlist list = IpAllowlist.parse("192.168.10.0/24\n오타\n10.0.0.5/999");
        assertThat(list.permits("192.168.10.7")).isTrue();
        assertThat(list.permits("172.16.0.1")).isFalse();
    }

    @Test
    @DisplayName("이름을 조회하지 않는다 — 접근 통제가 DNS 에 흔들리면 안 된다")
    void neverResolvesNames() {
        // 이름이 들어오면 그냥 못 읽는 것으로 본다. 조회가 느리거나 결과가
        // 바뀔 때 접근 통제가 함께 흔들리는 것이 더 나쁘다.
        IpAllowlist list = IpAllowlist.parse("localhost");
        assertThat(list.isEmpty()).isTrue();
    }

    @Test
    @DisplayName("IPv4 를 감싼 IPv6 주소도 IPv4 규칙에 걸린다")
    void matchesIpv4MappedIpv6() {
        // 톰캣이 이중 스택으로 뜨면 ::ffff:192.168.0.7 형태로 들어온다.
        // 목록에 192.168.0.0/24 를 적어 둔 운영자가 잠기면 안 된다.
        IpAllowlist list = IpAllowlist.parse("192.168.0.0/24");
        assertThat(list.permits("::ffff:192.168.0.7")).isTrue();
        assertThat(list.permits("::ffff:10.0.0.7")).isFalse();
    }

    @Test
    @DisplayName("IPv4 규칙에 IPv6 주소를 잘못 대보지 않는다")
    void doesNotMixFamilies() {
        IpAllowlist list = IpAllowlist.parse("10.0.0.0/8");
        assertThat(list.permits("2001:db8::1")).isFalse();
    }

    @Test
    @DisplayName("IPv6 대역도 다룬다")
    void handlesIpv6Ranges() {
        IpAllowlist list = IpAllowlist.parse("2001:db8::/32");
        assertThat(list.permits("2001:db8::1")).isTrue();
        assertThat(list.permits("2001:db8:1234::9")).isTrue();
        assertThat(list.permits("2001:db9::1")).isFalse();
    }

    @Test
    @DisplayName("대괄호로 감싼 IPv6 도 읽는다")
    void acceptsBracketedIpv6() {
        assertThat(IpAllowlist.parse("[::1]").permits("::1")).isTrue();
    }
}
