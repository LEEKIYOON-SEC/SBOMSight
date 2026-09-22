package kr.sbomsight.service;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * 비밀번호로 쓸 수 있는 글자인가 — <b>한 곳에서만 판단한다.</b>
 *
 * <p>앞서 규칙이 두 군데에 있었다. {@code AuthController.MIN_LENGTH} 와
 * {@code AccountService.MIN_PASSWORD_LENGTH} 가 각각 8 이었고, 둘 다 길이만
 * 봤다. 같은 규칙을 두 벌 두면 한쪽만 고치는 날이 오고, 그때부터 <b>스스로
 * 바꾸는 길과 관리자가 넣어 주는 길의 기준이 다르다.</b>
 *
 * <h2>조합을 센다</h2>
 *
 * <p>길이만 보면 {@code password} 가 통과한다. 금융권 점검 기준이 요구하는
 * 것은 <b>문자 종류의 조합</b>이다 — 영문 · 숫자 · 특수문자 가운데
 *
 * <ul>
 *   <li><b>세 가지</b>를 섞으면 {@value #MIN_WITH_THREE}자 이상</li>
 *   <li><b>두 가지</b>를 섞으면 {@value #MIN_WITH_TWO}자 이상</li>
 *   <li>한 가지만 쓰면 <b>길어도 받지 않는다</b></li>
 * </ul>
 *
 * <h2>계정 이름을 담지 않는다</h2>
 *
 * <p>이 도구의 계정 이름은 사번이나 이름이다. 그것을 담은 비밀번호는 아는
 * 사람이 가장 먼저 넣어 보는 것이고, 조합 규칙만으로는 {@code hong123!} 이
 * 통과한다.
 *
 * <h2>같은 글자를 세 번 잇지 않는다</h2>
 *
 * <p>{@code aaa} · {@code 111} 로 길이를 채우는 것을 막는다. 네 번이 아니라
 * 세 번에서 막는다 — 세 번을 허용하면 {@code aaa1!aaa} 처럼 조합 규칙까지
 * 형식적으로 만족시키는 것이 쉬워진다.
 *
 * <h2>지난 비밀번호는 아직 보지 못한다</h2>
 *
 * <p>재사용 금지는 지난 해시를 보관해야 하므로 표를 하나 더 만들어야 한다.
 * 스키마를 바꾸는 일이라 따로 정한다 — 지금은 <b>현재 비밀번호와 같은 것</b>
 * 만 막는다({@code AuthController}).
 */
public final class PasswordStrength {

    /** 영문·숫자·특수문자 세 가지를 다 섞었을 때의 최소 길이. */
    public static final int MIN_WITH_THREE = 8;

    /** 두 가지만 섞었을 때의 최소 길이. */
    public static final int MIN_WITH_TWO = 10;

    private PasswordStrength() {
    }

    /**
     * 받을 수 없는 이유. 받을 수 있으면 {@code null}.
     *
     * <p><b>왜 예외가 아니라 글자를 돌려주는가.</b> 부르는 쪽이 셋인데 각각
     * 실패를 다르게 전한다 — 화면 플래시({@code AuthController}) ·
     * {@code AccountException}({@code AccountService}). 여기서 예외를 정하면
     * 한쪽이 그것을 다시 감싸야 한다.
     *
     * @param password 사람이 넣은 글자. {@code null} 도 받는다
     * @param username 그 계정 이름. 없으면 {@code null}
     */
    public static String rejection(String password, String username) {
        if (password == null || password.isBlank()) {
            return "새 비밀번호를 넣어 주세요.";
        }

        int kinds = kinds(password);
        if (kinds < 2) {
            return "영문 · 숫자 · 특수문자 가운데 두 가지 이상을 섞어 주세요.";
        }
        int need = kinds >= 3 ? MIN_WITH_THREE : MIN_WITH_TWO;
        if (password.length() < need) {
            return kinds >= 3
                    ? MIN_WITH_THREE + "자 이상으로 정해 주세요 (세 가지를 섞었습니다)."
                    : MIN_WITH_TWO + "자 이상으로 정해 주세요. "
                      + "특수문자를 섞으면 " + MIN_WITH_THREE + "자부터 됩니다.";
        }

        if (username != null && !username.isBlank()
                && password.toLowerCase().contains(username.toLowerCase())) {
            return "계정 이름이 들어 있습니다.";
        }
        if (hasRunOfThree(password)) {
            return "같은 글자를 세 번 이어 쓰지 마세요.";
        }
        return null;
    }

    /** 영문 · 숫자 · 특수문자 가운데 몇 가지를 썼는가. */
    private static int kinds(String password) {
        boolean letter = false, digit = false, other = false;
        for (char c : password.toCharArray()) {
            if (Character.isLetter(c)) {
                letter = true;
            } else if (Character.isDigit(c)) {
                digit = true;
            } else {
                // 공백과 한글도 여기 든다. 쓸 수 있게 두는 것이 맞다 —
                // 긴 한글 구절은 외우기 쉽고 맞히기 어렵다.
                other = true;
            }
        }
        return (letter ? 1 : 0) + (digit ? 1 : 0) + (other ? 1 : 0);
    }

    private static boolean hasRunOfThree(String password) {
        for (int i = 2; i < password.length(); i++) {
            if (password.charAt(i) == password.charAt(i - 1)
                    && password.charAt(i) == password.charAt(i - 2)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 한 번 쓰고 버릴 임시 비밀번호.
     *
     * <p><b>계정 이름으로 되돌리지 않는다.</b> 앞서 관리자의 `초기화` 는
     * 비밀번호를 <b>계정 이름과 같게</b> 만들었다. 계정 이름은 설정 화면과
     * 감사 로그에 그대로 보이고 대개 사번이다 — <b>이름을 아는 사람이라면
     * 누구든, 본인이 로그인하기 전에 그 계정으로 들어갈 수 있었다.</b>
     * `첫 로그인에 반드시 바꾸게` 하는 것도 도움이 되지 않는다: 먼저 들어간
     * 사람이 새 비밀번호를 정한다.
     *
     * <p>그래서 {@link java.security.SecureRandom} 으로 만들어 <b>화면에 한
     * 번만</b> 보여 준다. 저장하지도 로그에 남기지도 않는다 — 감사 로그에는
     * `초기화했다` 는 사실만 남는다.
     *
     * <p>18바이트를 Base64 로 적어 24자다. 위의 조합 규칙을 늘 만족시키도록
     * 숫자와 특수문자를 하나씩 덧붙인다 — 난수가 우연히 영문만으로 나오는
     * 경우에도 규칙과 어긋나지 않게 한다.
     *
     * <p><b>규칙을 지날 때까지 다시 뽑는다.</b> Base64 는 같은 글자가 세 번
     * 이어진 것을 낼 수 있고({@code …ym999pu07!}), 그러면 <b>제가 만든
     * 비밀번호를 제 규칙이 거절한다</b> — 받은 사람이 로그인 자체를 못 한다.
     * 시험에서 200번 뽑아 보고 잡았다({@code PasswordStrengthTest}).
     *
     * <p>돌 횟수를 한정한다. 24자 난수가 스무 번 내리 걸릴 일은 없지만,
     * 끝을 두지 않은 되풀이는 언젠가 서버를 멈추는 자리가 된다. 스무 번을
     * 넘기면 규칙이 바뀌었다는 뜻이므로 그렇게 말하고 멈춘다.
     */
    public static String temporary() {
        SecureRandom random = new SecureRandom();
        for (int attempt = 0; attempt < 20; attempt++) {
            byte[] bytes = new byte[18];
            random.nextBytes(bytes);
            String candidate =
                    Base64.getUrlEncoder().withoutPadding().encodeToString(bytes) + "7!";
            if (rejection(candidate, null) == null) {
                return candidate;
            }
        }
        throw new IllegalStateException(
                "임시 비밀번호를 스무 번 뽑아도 규칙을 지나지 못했습니다 — "
                + "규칙과 만드는 방식이 어긋났습니다.");
    }
}
