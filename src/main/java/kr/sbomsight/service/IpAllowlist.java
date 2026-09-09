package kr.sbomsight.service;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * 접속 허용 IP 목록.
 *
 * <p>표준 라이브러리만 쓴다. {@code 192.168.10.0/24} 같은 CIDR 과 낱개 주소를
 * 함께 받는다.
 *
 * <p><b>판단할 수 없으면 막는다.</b> 주소를 못 읽었을 때 허용으로 처리하면
 * 그 경로 하나로 목록 전체가 무력화된다.
 */
public final class IpAllowlist {

    private record Rule(byte[] network, int prefixBits) {

        boolean covers(byte[] address) {
            if (address.length != network.length) {
                return false;   // IPv4 규칙에 IPv6 주소를 대볼 수 없다
            }
            int fullBytes = prefixBits / 8;
            for (int i = 0; i < fullBytes; i++) {
                if (address[i] != network[i]) {
                    return false;
                }
            }
            int remaining = prefixBits % 8;
            if (remaining == 0) {
                return true;
            }
            int mask = 0xFF << (8 - remaining);
            return (address[fullBytes] & mask) == (network[fullBytes] & mask);
        }
    }

    private final List<Rule> rules;

    private IpAllowlist(List<Rule> rules) {
        this.rules = Collections.unmodifiableList(rules);
    }

    /** 비어 있는 목록 — 제한 없음. */
    public static IpAllowlist unrestricted() {
        return new IpAllowlist(List.of());
    }

    /**
     * 쉼표·줄바꿈·공백으로 구분된 목록을 읽는다.
     *
     * <p>읽을 수 없는 항목은 건너뛴다. 하나가 잘못됐다고 목록 전체를 버리면
     * 오타 한 글자에 모두가 잠긴다.
     */
    public static IpAllowlist parse(String text) {
        if (text == null || text.isBlank()) {
            return unrestricted();
        }
        List<Rule> rules = new ArrayList<>();
        for (String raw : text.split("[,\\s]+")) {
            String entry = raw.trim();
            if (entry.isEmpty()) {
                continue;
            }
            Rule rule = rule(entry);
            if (rule != null) {
                rules.add(rule);
            }
        }
        return new IpAllowlist(rules);
    }

    private static Rule rule(String entry) {
        String host = entry;
        Integer prefix = null;

        int slash = entry.lastIndexOf('/');
        if (slash >= 0) {
            host = entry.substring(0, slash);
            try {
                prefix = Integer.parseInt(entry.substring(slash + 1).trim());
            } catch (NumberFormatException e) {
                return null;
            }
        }

        byte[] address = literalAddress(host.trim());
        if (address == null) {
            return null;
        }
        int bits = address.length * 8;
        // 접두 길이가 없으면 그 한 대를 뜻한 것이다. "10.0.0.5" 라고 쓴 사람은
        // 대역이 아니라 그 서버 하나를 말한 것이다.
        int prefixBits = prefix == null ? bits : prefix;
        if (prefixBits < 0 || prefixBits > bits) {
            return null;
        }
        return new Rule(address, prefixBits);
    }

    /**
     * 이름 조회 없이 문자열 그대로 주소로 읽는다.
     *
     * <p>{@code InetAddress.getByName} 은 IP 가 아닌 문자열을 받으면 DNS 를
     * 찾아간다. 허용 목록을 읽는 데 이름 조회가 끼면, 조회가 느리거나 결과가
     * 바뀔 때 접근 통제가 함께 흔들린다.
     */
    private static byte[] literalAddress(String host) {
        String text = host;
        if (text.startsWith("[") && text.endsWith("]")) {
            text = text.substring(1, text.length() - 1);   // [::1] 형태
        }
        if (!text.matches("[0-9A-Fa-f:.%]+")) {
            return null;
        }
        try {
            return InetAddress.getByName(text).getAddress();
        } catch (UnknownHostException e) {
            return null;
        }
    }

    public boolean isEmpty() {
        return rules.isEmpty();
    }

    /** 이 주소로 들어와도 되는가. 목록이 비어 있으면 모두 허용한다. */
    public boolean permits(String ip) {
        if (rules.isEmpty()) {
            return true;
        }
        byte[] address = ip == null ? null : literalAddress(ip);
        if (address == null) {
            return false;   // 판단할 수 없으면 막는다
        }
        // IPv4 를 감싼 IPv6(::ffff:192.168.0.1)은 IPv4 규칙에도 걸리게 편다.
        byte[] unwrapped = unwrapIpv4(address);
        return rules.stream()
                .anyMatch(rule -> rule.covers(address)
                        || (unwrapped != null && rule.covers(unwrapped)));
    }

    private static byte[] unwrapIpv4(byte[] address) {
        if (address.length != 16) {
            return null;
        }
        for (int i = 0; i < 10; i++) {
            if (address[i] != 0) {
                return null;
            }
        }
        if ((address[10] & 0xFF) != 0xFF || (address[11] & 0xFF) != 0xFF) {
            return null;
        }
        return Arrays.copyOfRange(address, 12, 16);
    }
}
