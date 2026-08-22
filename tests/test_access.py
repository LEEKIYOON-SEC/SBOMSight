"""접근 통제 — 로그인, 권한, IP 허용 목록.

이 도구가 보여 주는 것은 "어느 서버에 어떤 취약점이 열려 있는가" 다. 그 목록은
공격자에게 그대로 지도가 되므로, 내부망이라는 이유로 아무나 열어 볼 수 있게
두면 안 된다. 여기서 고정하는 것은 그 문이 실제로 잠기는가다.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from core.accounts import AccountError, Accounts, hash_password, verify_password
from core.netacl import Allowlist, is_loopback, parse_list

from .conftest import ADMIN

# anon·client·viewer·seeded_scan 픽스처는 conftest.py 와 test_server.py 에 있다.
from .test_server import seeded_scan  # noqa: F401


# ---------------------------------------------------------------------------
# 비밀번호 해싱
# ---------------------------------------------------------------------------


class TestPasswordHashing:
    def test_hash_is_not_the_password(self):
        assert "hunter2hunter2" not in hash_password("hunter2hunter2")

    def test_same_password_hashes_differently_each_time(self):
        """소금이 매번 달라야 한다. 같으면 해시 목록에서 같은 비밀번호를 쓴
        계정들이 한눈에 드러나고, 무지개표가 통한다."""
        assert hash_password("same-password") != hash_password("same-password")

    def test_round_trip(self):
        assert verify_password("correct horse", hash_password("correct horse"))

    def test_wrong_password_fails(self):
        assert not verify_password("wrong", hash_password("correct horse"))

    @pytest.mark.parametrize(
        "stored",
        ["", "not-a-hash", "scrypt$bad", "md5$1$1$1$aa$bb", "scrypt$x$8$1$aa$bb"],
    )
    def test_broken_stored_hash_never_authenticates(self, stored):
        """저장값이 깨져 있으면 거부한다. 예외로 터져 500을 내거나, 더 나쁘게는
        비교를 건너뛰고 통과시키면 안 된다."""
        assert verify_password("anything", stored) is False

    def test_parameters_travel_with_the_hash(self):
        """파라미터가 해시에 함께 담겨야 나중에 강도를 올려도 기존 계정이
        계속 로그인할 수 있다."""
        assert hash_password("x" * 12).startswith("scrypt$16384$8$1$")


# ---------------------------------------------------------------------------
# 계정 저장소
# ---------------------------------------------------------------------------


@pytest.fixture
def accounts(tmp_path):
    return Accounts(tmp_path / "test.db")


class TestAccounts:
    def test_starts_empty(self, accounts):
        assert accounts.count() == 0

    def test_create_and_authenticate(self, accounts):
        accounts.create("alice", "alice-password", "admin")
        user = accounts.authenticate("alice", "alice-password")
        assert user is not None and user.is_admin

    def test_wrong_password_is_rejected(self, accounts):
        accounts.create("alice", "alice-password")
        assert accounts.authenticate("alice", "nope") is None

    def test_missing_account_is_rejected(self, accounts):
        assert accounts.authenticate("nobody", "whatever") is None

    def test_duplicate_username_is_refused(self, accounts):
        accounts.create("alice", "alice-password")
        with pytest.raises(AccountError, match="이미 있습니다"):
            accounts.create("alice", "another-password")

    @pytest.mark.parametrize("username", ["", "a", "x" * 33, "alice bob", "al;ice", "관리자"])
    def test_bad_usernames_are_refused(self, accounts, username):
        with pytest.raises(AccountError):
            accounts.create(username, "long-enough-password")

    def test_short_password_is_refused(self, accounts):
        with pytest.raises(AccountError, match="8자 이상"):
            accounts.create("alice", "short")

    def test_bad_role_is_refused(self, accounts):
        with pytest.raises(AccountError):
            accounts.create("alice", "alice-password", "superuser")

    def test_last_admin_cannot_be_deleted(self, accounts):
        """관리자가 사라지면 웹에서 계정을 만들 수도 지울 수도 없게 된다."""
        accounts.create("root", "root-password", "admin")
        accounts.create("reader", "reader-password", "viewer")
        with pytest.raises(AccountError, match="마지막 관리자"):
            accounts.delete("root")
        accounts.delete("reader")  # 관리자가 아니면 지워진다

    def test_last_admin_cannot_be_demoted(self, accounts):
        accounts.create("root", "root-password", "admin")
        with pytest.raises(AccountError, match="마지막 관리자"):
            accounts.set_role("root", "viewer")

    def test_second_admin_frees_the_first(self, accounts):
        accounts.create("root", "root-password", "admin")
        accounts.create("other", "other-password", "admin")
        accounts.delete("root")
        assert [u.username for u in accounts.list_users()] == ["other"]


class TestSessions:
    def test_open_and_resolve(self, accounts):
        accounts.create("alice", "alice-password", "admin")
        session = accounts.open_session("alice")
        resolved = accounts.resolve(session.token)
        assert resolved is not None
        assert resolved.username == "alice" and resolved.role == "admin"

    def test_unknown_token_resolves_to_nothing(self, accounts):
        assert accounts.resolve("made-up-token") is None
        assert accounts.resolve("") is None

    def test_expired_session_is_rejected_and_removed(self, accounts):
        accounts.create("alice", "alice-password")
        session = accounts.open_session("alice", ttl_hours=-1)
        assert accounts.resolve(session.token) is None
        assert accounts.resolve(session.token) is None  # 두 번째도 마찬가지

    def test_logout_kills_the_token(self, accounts):
        accounts.create("alice", "alice-password")
        session = accounts.open_session("alice")
        accounts.close_session(session.token)
        assert accounts.resolve(session.token) is None

    def test_password_change_kills_every_session(self, accounts):
        """비밀번호를 바꾸는 것은 대개 유출을 의심할 때다. 예전 세션이 살아
        있으면 바꾼 의미가 없다."""
        accounts.create("alice", "alice-password")
        first, second = accounts.open_session("alice"), accounts.open_session("alice")
        accounts.set_password("alice", "brand-new-password")
        assert accounts.resolve(first.token) is None
        assert accounts.resolve(second.token) is None

    def test_deleting_a_user_kills_their_sessions(self, accounts):
        accounts.create("root", "root-password", "admin")
        accounts.create("alice", "alice-password")
        session = accounts.open_session("alice")
        accounts.delete("alice")
        assert accounts.resolve(session.token) is None

    def test_login_records_the_time(self, accounts):
        accounts.create("alice", "alice-password")
        assert accounts.get("alice").last_login_at == ""
        accounts.open_session("alice")
        assert accounts.get("alice").last_login_at


# ---------------------------------------------------------------------------
# IP 허용 목록
# ---------------------------------------------------------------------------


class TestAllowlist:
    def test_empty_list_permits_everything(self):
        """켜 본 적 없는 운영자가 잠기지 않아야 한다."""
        assert Allowlist().permits("203.0.113.9")

    def test_single_address_is_that_one_host(self):
        """`10.0.0.5` 라고 쓴 사람은 그 한 대를 뜻한 것이지 대역이 아니다."""
        allowlist = Allowlist.parse("10.0.0.5")
        assert allowlist.permits("10.0.0.5")
        assert not allowlist.permits("10.0.0.6")

    def test_cidr_covers_the_range(self):
        allowlist = Allowlist.parse("192.168.10.0/24")
        assert allowlist.permits("192.168.10.1")
        assert allowlist.permits("192.168.10.254")
        assert not allowlist.permits("192.168.11.1")

    def test_multiple_entries(self):
        allowlist = Allowlist.parse("192.168.10.0/24, 10.0.0.5\n::1")
        assert allowlist.permits("192.168.10.7")
        assert allowlist.permits("10.0.0.5")
        assert allowlist.permits("::1")
        assert not allowlist.permits("172.16.0.1")

    def test_unreadable_address_is_refused(self):
        """판단할 수 없으면 막는다. 허용으로 처리하면 그 경로 하나로 목록
        전체가 무력화된다."""
        allowlist = Allowlist.parse("192.168.10.0/24")
        assert not allowlist.permits("")
        assert not allowlist.permits("testclient")
        assert not allowlist.permits(None)

    def test_bad_entry_is_reported_not_silently_dropped(self):
        """조용히 버리면 운영자는 목록에 넣었다고 믿는데 실제로는 없다."""
        with pytest.raises(ValueError, match="IP 또는 CIDR"):
            Allowlist.parse("192.168.10.0/24, 여기는사무실")

    def test_duplicates_collapse(self):
        assert parse_list("10.0.0.5, 10.0.0.5/32") == ("10.0.0.5/32",)

    def test_loopback_detection(self):
        assert is_loopback("127.0.0.1") and is_loopback("::1")
        assert not is_loopback("192.168.0.1")
        assert not is_loopback("testclient")


# ---------------------------------------------------------------------------
# 미들웨어 — 실제로 문이 잠기는가
# ---------------------------------------------------------------------------


class TestSetupGate:
    def test_first_visit_asks_for_setup(self, anon):
        state = anon.get("/api/auth/state").json()
        assert state["needs_setup"] is True
        assert state["authenticated"] is False

    def test_setup_creates_an_admin_and_logs_in(self, anon):
        body = anon.post("/api/auth/setup", json=ADMIN).json()
        assert body == {"username": "tester", "role": "admin"}
        assert anon.get("/api/auth/state").json()["authenticated"] is True

    def test_setup_is_refused_once_an_account_exists(self, client):
        response = client.post(
            "/api/auth/setup", json={"username": "second", "password": "second-password"}
        )
        assert response.status_code == 409

    def test_setup_is_refused_from_the_network(self, anon):
        """계정이 없는 동안 네트워크의 아무나 먼저 와서 관리자를 차지할 수 없다."""
        remote = TestClient(anon.app, client=("192.168.1.50", 40002))
        response = remote.post("/api/auth/setup", json=ADMIN)
        assert response.status_code == 503
        assert response.json()["needs_setup"] is True

    def test_short_password_is_refused_at_setup(self, anon):
        response = anon.post("/api/auth/setup", json={"username": "root", "password": "short"})
        assert response.status_code == 400
        assert "8자" in response.json()["detail"]


class TestLoginGate:
    def test_api_without_login_is_401(self, anon):
        anon.post("/api/auth/setup", json=ADMIN)
        anon.post("/api/auth/logout")
        assert anon.get("/api/scans").status_code == 401

    def test_page_without_login_redirects_to_login(self, anon):
        anon.post("/api/auth/setup", json=ADMIN)
        anon.post("/api/auth/logout")
        response = anon.get("/scan.html", headers={"accept": "text/html"}, follow_redirects=False)
        assert response.status_code == 302
        assert response.headers["location"].startswith("/login.html?next=/scan.html")

    def test_login_page_itself_is_reachable(self, anon):
        anon.post("/api/auth/setup", json=ADMIN)
        anon.post("/api/auth/logout")
        assert anon.get("/login.html").status_code == 200
        assert anon.get("/css/app.css").status_code == 200
        assert anon.get("/js/core/ui.js").status_code == 200

    def test_login_and_logout(self, anon):
        anon.post("/api/auth/setup", json=ADMIN)
        anon.post("/api/auth/logout")
        assert anon.get("/api/scans").status_code == 401
        assert anon.post("/api/auth/login", json=ADMIN).status_code == 200
        assert anon.get("/api/scans").status_code == 200

    def test_wrong_password_does_not_say_which_half_was_wrong(self, anon):
        anon.post("/api/auth/setup", json=ADMIN)
        anon.post("/api/auth/logout")
        wrong_pw = anon.post("/api/auth/login", json={"username": "tester", "password": "nope"})
        no_user = anon.post("/api/auth/login", json={"username": "ghost", "password": "nope"})
        assert wrong_pw.status_code == no_user.status_code == 401
        assert wrong_pw.json()["detail"] == no_user.json()["detail"]

    def test_session_cookie_is_httponly(self, anon):
        """자바스크립트가 토큰을 읽지 못해야 XSS 하나로 세션이 새지 않는다."""
        response = anon.post("/api/auth/setup", json=ADMIN)
        cookie = response.headers["set-cookie"]
        assert "httponly" in cookie.lower()
        assert "samesite=lax" in cookie.lower()

    def test_repeated_failures_are_throttled(self, anon):
        anon.post("/api/auth/setup", json=ADMIN)
        anon.post("/api/auth/logout")
        for _ in range(10):
            anon.post("/api/auth/login", json={"username": "tester", "password": "nope"})
        blocked = anon.post("/api/auth/login", json=ADMIN)
        assert blocked.status_code == 429


class TestRoles:
    def test_viewer_can_read(self, viewer, seeded_scan):
        assert viewer.get("/api/scans").status_code == 200
        assert viewer.get(f"/api/scans/{seeded_scan}").status_code == 200

    def test_viewer_cannot_write(self, viewer, seeded_scan):
        assert viewer.delete(f"/api/scans/{seeded_scan}").status_code == 403
        assert viewer.post("/api/scan?upload_id=whatever").status_code == 403
        assert viewer.put(
            f"/api/scans/{seeded_scan}/selection", json={"selection": []}
        ).status_code == 403

    def test_viewer_cannot_manage_accounts(self, viewer):
        assert viewer.get("/api/users").status_code == 403
        assert viewer.post(
            "/api/users", json={"username": "sneaky", "password": "sneaky-password"}
        ).status_code == 403
        assert viewer.delete("/api/users/tester").status_code == 403

    def test_viewer_cannot_see_or_change_the_ip_allowlist(self, viewer):
        assert viewer.get("/api/access/ips").status_code == 403
        assert viewer.put("/api/access/ips", json={"entries": ""}).status_code == 403

    def test_viewer_can_change_their_own_password(self, viewer):
        response = viewer.post(
            "/api/auth/password",
            json={"current": "reader-password", "password": "a-new-password"},
        )
        assert response.status_code == 200
        assert viewer.get("/api/scans").status_code == 200  # 세션이 이어진다

    def test_own_password_change_needs_the_current_one(self, viewer):
        response = viewer.post(
            "/api/auth/password", json={"current": "wrong", "password": "a-new-password"}
        )
        assert response.status_code == 403


class TestAccountManagementApi:
    def test_admin_lists_creates_and_deletes(self, client):
        client.post("/api/users", json={"username": "bob", "password": "bob-password"})
        names = [u["username"] for u in client.get("/api/users").json()["users"]]
        assert names == ["bob", "tester"]

        assert client.delete("/api/users/bob").status_code == 200
        assert [u["username"] for u in client.get("/api/users").json()["users"]] == ["tester"]

    def test_admin_cannot_delete_themselves(self, client):
        """자기 계정을 지우면 그 순간 로그아웃되고, 마지막 관리자였다면 잠긴다."""
        assert client.delete("/api/users/tester").status_code == 400

    def test_password_reset_logs_that_user_out(self, client, viewer):
        assert viewer.get("/api/scans").status_code == 200
        assert client.put(
            "/api/users/reader", json={"password": "reset-by-admin"}
        ).status_code == 200
        assert viewer.get("/api/scans").status_code == 401

    def test_role_change_takes_effect(self, client, viewer):
        assert viewer.post("/api/users", json={"username": "newbie", "password": "newbie-password"}).status_code == 403
        assert client.put("/api/users/reader", json={"role": "admin"}).status_code == 200
        assert viewer.post("/api/users", json={"username": "newbie", "password": "newbie-password"}).status_code == 200

    def test_unknown_user_is_404(self, client):
        assert client.put("/api/users/ghost", json={"role": "admin"}).status_code == 404

    def test_never_returns_a_password_hash(self, client):
        body = client.get("/api/users").text
        assert "scrypt" not in body and "pw_hash" not in body


class TestIpAllowlistApi:
    def test_default_is_no_restriction(self, client):
        body = client.get("/api/access/ips").json()
        assert body["entries"] == [] and body["active"] is False

    def test_saving_and_enforcing(self, client):
        assert client.put(
            "/api/access/ips", json={"entries": "127.0.0.1\n192.168.10.0/24"}
        ).status_code == 200

        outsider = TestClient(client.app, client=("203.0.113.9", 40003))
        response = outsider.get("/login.html")
        assert response.status_code == 403
        assert "203.0.113.9" in response.json()["detail"]

    def test_blocked_before_login_is_even_offered(self, client):
        """허용 대역 밖에서는 로그인 화면도 보이지 않아야 한다. 비밀번호가
        새어도 그 자리에서는 쓸 수 없다."""
        client.put("/api/access/ips", json={"entries": "127.0.0.1"})
        outsider = TestClient(client.app, client=("203.0.113.9", 40004))
        for path in ("/", "/login.html", "/api/auth/state", "/api/auth/login"):
            assert outsider.get(path).status_code == 403

    def test_locking_yourself_out_is_refused(self, client):
        response = client.put("/api/access/ips", json={"entries": "192.168.10.0/24"})
        assert response.status_code == 400
        assert "127.0.0.1" in response.json()["detail"]
        # 저장되지 않았으므로 여전히 들어올 수 있다.
        assert client.get("/api/scans").status_code == 200

    def test_bad_entry_is_refused(self, client):
        response = client.put("/api/access/ips", json={"entries": "127.0.0.1, 사무실"})
        assert response.status_code == 400

    def test_clearing_the_list_removes_the_restriction(self, client):
        client.put("/api/access/ips", json={"entries": "127.0.0.1"})
        assert client.put("/api/access/ips", json={"entries": ""}).status_code == 200
        outsider = TestClient(client.app, client=("203.0.113.9", 40005))
        assert outsider.get("/login.html").status_code == 200

    def test_forwarded_header_cannot_get_past_the_list(self, client):
        """`X-Forwarded-For` 는 누구든 채워 보낼 수 있다. 그것을 믿으면 허용
        목록이 헤더 한 줄로 우회된다."""
        client.put("/api/access/ips", json={"entries": "127.0.0.1"})
        outsider = TestClient(client.app, client=("203.0.113.9", 40006))
        response = outsider.get(
            "/login.html",
            headers={"x-forwarded-for": "127.0.0.1", "x-real-ip": "127.0.0.1"},
        )
        assert response.status_code == 403
