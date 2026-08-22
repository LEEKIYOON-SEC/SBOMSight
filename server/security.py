"""접근 통제 — IP 허용 목록과 세션 로그인.

두 층이 순서대로 선다.

    소켓 상대 IP 확인  →  세션 확인  →  권한 확인  →  라우트
      (허용 대역 밖이면 로그인 화면도 안 보인다)

계정이 하나도 없으면 로그인 화면이 "관리자 계정 만들기"로 바뀐다. 그 화면은
접속한 자리를 가리지 않는다 — 서버를 네트워크에 붙이기 전에 만드는 것이
정상적인 순서이고, 자리를 가리면 그 순서가 막힌다.

미들웨어로 두는 이유는 라우트가 아니라 **모든 요청**을 지나가야 하기 때문이다.
정적 파일(`/`, `/scan.html`, `/js/...`)은 StaticFiles 마운트가 처리하므로
라우트 의존성(Depends)으로는 걸러지지 않는다. 화면은 열리는데 API 만 막히면
"로그인이 있다"고 말할 수 없다.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from fastapi.responses import JSONResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from core.accounts import Accounts
from core.netacl import Allowlist

COOKIE = "sbomsight_session"

# 로그인 화면과 그 화면이 쓰는 것들. 여기까지는 인증 없이 닿아야 로그인을 할 수 있다.
PUBLIC_PATHS = frozenset({
    "/login.html",
    "/api/auth/state",
    "/api/auth/login",
    "/api/auth/setup",
    "/favicon.svg",
    "/favicon.ico",
})
PUBLIC_PREFIXES = ("/css/", "/js/", "/assets/")

# 인증만 되면 권한과 무관하게 허용하는 쓰기 동작 (자기 자신에 대한 것).
SELF_WRITE_PATHS = frozenset({"/api/auth/logout", "/api/auth/password"})

WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def client_ip(request: Request) -> str:
    """소켓 상대방 주소. **헤더는 보지 않는다.**

    `X-Forwarded-For` 는 누구든 채워 보낼 수 있어서, 그것을 믿으면 허용 목록이
    한 줄의 헤더로 우회된다.
    """
    return request.client.host if request.client else ""


def _wants_html(request: Request) -> bool:
    """브라우저가 문서를 요청한 것인가, 스크립트가 API 를 부른 것인가.

    문서면 로그인 화면으로 보내고, API 면 401 을 준다. 화면 이동으로 답하면
    fetch() 쪽에서는 로그인 페이지 HTML 이 JSON 인 척 도착해 엉뚱한 오류가 난다.
    """
    if request.url.path.startswith("/api/"):
        return False
    return "text/html" in request.headers.get("accept", "")


@dataclass
class LoginThrottle:
    """같은 자리에서 반복 실패하면 잠시 막는다.

    내부망이라도 8자 비밀번호를 초당 수십 번 두드리는 것을 막을 이유는 있다.
    실패한 자리(IP)를 기준으로 세며, 성공하면 즉시 지운다. 프로세스 메모리에만
    두므로 서버를 다시 띄우면 풀린다 — 잠긴 운영자를 구제하는 수단이기도 하다.
    """

    limit: int = 10
    window_sec: int = 300
    failures: dict[str, list[float]] = field(default_factory=dict)

    def _recent(self, key: str, now: float) -> list[float]:
        kept = [t for t in self.failures.get(key, ()) if now - t < self.window_sec]
        if kept:
            self.failures[key] = kept
        else:
            self.failures.pop(key, None)
        return kept

    def blocked_for(self, key: str) -> int:
        """남은 차단 시간(초). 0이면 시도할 수 있다."""
        now = time.monotonic()
        recent = self._recent(key, now)
        if len(recent) < self.limit:
            return 0
        return max(1, int(self.window_sec - (now - recent[0])))

    def fail(self, key: str) -> None:
        self.failures.setdefault(key, []).append(time.monotonic())

    def succeed(self, key: str) -> None:
        self.failures.pop(key, None)


class AccessControl:
    """설정과 저장소를 묶어 미들웨어와 라우트가 함께 쓰는 판단 지점.

    허용 목록과 "계정이 있는가"는 **요청마다** 필요한데 둘 다 DB 에 있다. 매번
    읽으면 정적 파일 한 장을 받는 데도 SQLite 연결이 두 번 열린다. 값이 바뀌는
    자리를 이 클래스가 전부 쥐고 있으므로, 캐시해 두고 바뀔 때 버린다.
    """

    def __init__(self, config):
        self.config = config
        self.accounts = Accounts(config.db_path)
        self.throttle = LoginThrottle()
        self._allowlist: Allowlist | None = None
        self._has_users = False

    # --- IP 허용 목록 ------------------------------------------------------

    def allowlist(self) -> Allowlist:
        """DB 에 저장된 목록. 저장한 적이 없으면 환경변수 부트스트랩 값을 쓴다.

        환경변수는 처음 한 번 문을 여는 용도다. 웹에서 한 번이라도 저장하면
        그때부터는 DB 가 유일한 출처가 된다 — 두 곳에 다른 값이 남아 어느
        쪽이 적용 중인지 모르게 되는 상황을 만들지 않는다.
        """
        if self._allowlist is None:
            from core.store import Store

            # 빈 문자열도 "제한 없음"이라는 유효한 저장값이라, 기본값으로는
            # 절대 나올 수 없는 표식을 써서 "저장한 적 없음"과 구분한다.
            saved = Store(self.config.db_path).meta_get("access.allowed_ips", "\x00")
            source = self.config.allowed_ips if saved == "\x00" else saved
            self._allowlist = Allowlist.parse(source)
        return self._allowlist

    def save_allowlist(self, allowlist: Allowlist) -> None:
        from core.store import Store

        Store(self.config.db_path).meta_set("access.allowed_ips", allowlist.to_text())
        self._allowlist = allowlist

    # --- 상태 -------------------------------------------------------------

    def needs_setup(self) -> bool:
        """계정이 하나도 없다. 최초 관리자를 만들어야 하는 상태.

        한 번 계정이 생기면 다시 0이 될 수 없다(마지막 관리자는 지워지지 않는다).
        그래서 True 인 동안만 확인하면 된다.
        """
        if not self._has_users:
            self._has_users = self.accounts.count() > 0
        return not self._has_users


class AccessMiddleware(BaseHTTPMiddleware):
    """IP → 세션 → 권한 순서로 거른다."""

    def __init__(self, app, access: AccessControl):
        super().__init__(app)
        self.access = access

    async def dispatch(self, request: Request, call_next):
        ip = client_ip(request)

        # ① 허용 대역 밖이면 여기서 끝. 로그인 화면도 보여 주지 않는다.
        if not self.access.allowlist().permits(ip):
            return JSONResponse(
                {"detail": f"이 주소({ip or '알 수 없음'})에서는 접속할 수 없습니다."},
                status_code=403,
            )

        request.state.client_ip = ip
        request.state.user = None

        path = request.url.path

        # ② 세션 확인.
        session = self.access.accounts.resolve(request.cookies.get(COOKIE, ""))
        if session is not None:
            request.state.user = session

        if path in PUBLIC_PATHS or path.startswith(PUBLIC_PREFIXES):
            return await call_next(request)

        if session is None:
            if _wants_html(request):
                nxt = request.url.path
                if request.url.query:
                    nxt += "?" + request.url.query
                return RedirectResponse(f"/login.html?next={nxt}", status_code=302)
            return JSONResponse({"detail": "로그인이 필요합니다."}, status_code=401)

        # ③ 권한. viewer 는 읽기 전용이다 — 자기 비밀번호와 로그아웃만 예외.
        if request.method in WRITE_METHODS and session.role != "admin":
            if path not in SELF_WRITE_PATHS:
                return JSONResponse(
                    {"detail": "이 작업은 관리자만 할 수 있습니다."}, status_code=403
                )

        return await call_next(request)


def set_session_cookie(response, token: str, *, max_age: int) -> None:
    """HttpOnly · SameSite=Lax.

    HttpOnly 라 자바스크립트가 토큰을 읽지 못한다 — 화면 어딘가에 XSS 가 나도
    세션이 바로 새어 나가지는 않는다. Secure 는 붙이지 않는다: 내부망 http 로
    접속하는 것이 전제라, 붙이면 쿠키가 아예 저장되지 않아 로그인이 안 된다.
    """
    response.set_cookie(
        COOKIE, token,
        max_age=max_age, httponly=True, samesite="lax", path="/",
    )


def clear_session_cookie(response) -> None:
    response.delete_cookie(COOKIE, path="/")
