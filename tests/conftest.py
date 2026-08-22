"""여러 테스트 모듈이 함께 쓰는 픽스처.

앱에 로그인이 붙으면서 "서버를 띄우고 관리자로 들어간 상태"가 거의 모든
API 테스트의 출발점이 됐다. 모듈마다 다시 만들면 인증 방식이 바뀔 때마다
전부 고쳐야 하므로 여기 한 곳에 둔다.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

ADMIN = {"username": "tester", "password": "test-password"}


@pytest.fixture
def anon(tmp_path, monkeypatch):
    """로그인하지 않은 클라이언트. 접근 통제 자체를 볼 때 쓴다.

    `client=` 로 상대 주소를 127.0.0.1 로 준다. TestClient 의 기본값은
    `"testclient"` 라는 IP 가 아닌 문자열이라, 최초 관리자 생성이 본 PC 에서만
    열린다는 규칙에 걸린다 — 실제 브라우저가 하는 것과 같은 자리에서 시작한다.
    """
    monkeypatch.setenv("SBOMSIGHT_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SBOMSIGHT_OFFLINE", "1")
    monkeypatch.delenv("SBOMSIGHT_ALLOWED_IPS", raising=False)

    import core.config
    core.config.get_config(refresh=True)

    import importlib
    import server.app
    importlib.reload(server.app)
    return TestClient(server.app.app, client=("127.0.0.1", 40000))


@pytest.fixture
def client(anon):
    """관리자로 로그인한 클라이언트. 대부분의 테스트가 쓰는 것."""
    assert anon.post("/api/auth/setup", json=ADMIN).status_code == 200
    return anon


@pytest.fixture
def viewer(client):
    """조회 권한 계정으로 로그인한 별도 클라이언트."""
    assert client.post(
        "/api/users",
        json={"username": "reader", "password": "reader-password", "role": "viewer"},
    ).status_code == 200

    other = TestClient(client.app, client=("127.0.0.1", 40001))
    assert other.post(
        "/api/auth/login", json={"username": "reader", "password": "reader-password"}
    ).status_code == 200
    return other
