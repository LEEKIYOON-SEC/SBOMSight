"""자산(서버) 모델과 이력 비교.

이 도구의 관리 단위는 스캔이 아니라 서버 한 대다. `web-01` 의 SBOM 을 매달
올리고 지난달 대비 무엇이 새로 생기고 무엇이 사라졌는지를 보는 것이 실제 운영이다.
"최근 스캔 목록"으로는 그 질문에 답할 수 없다.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from core.assets import Asset, AssetError, Assets, check_name, diff_findings
from core.models import ScanResult
from core.normalize import normalize_grype_report
from core.store import Store

from .test_server import seeded_scan  # noqa: F401

FIXTURE = Path(__file__).parent / "fixtures" / "grype-sample.json"


@pytest.fixture
def assets(tmp_path):
    return Assets(tmp_path / "test.db")


def finding(cve: str, package: str, version: str, *, fixed: str = "", priority: str = "P2") -> dict:
    return {
        "intel": {"cve": cve},
        "installed": {"name": package, "version": version},
        "advisory": {"fixed_version": fixed},
        "verdict": {"priority": priority},
    }


# ---------------------------------------------------------------------------
# 이름 규칙
# ---------------------------------------------------------------------------


class TestNaming:
    @pytest.mark.parametrize("name", ["web-01", "db.internal", "a", "srv_1", "X" * 64])
    def test_hostname_shaped_names_pass(self, name):
        assert check_name(name) == name

    @pytest.mark.parametrize("name", ["", "  ", "-web", "web 01", "web/01", "웹서버", "X" * 65])
    def test_others_are_refused(self, name):
        """공백과 슬래시를 허용하면 URL·파일 경로 양쪽에서 성가시고, `web-01 ` 같은
        별개의 자산이 실수로 생긴다."""
        with pytest.raises(AssetError):
            check_name(name)

    def test_surrounding_space_is_trimmed(self):
        assert check_name("  web-01  ") == "web-01"


# ---------------------------------------------------------------------------
# 저장소
# ---------------------------------------------------------------------------


class TestAssets:
    def test_create_and_get(self, assets):
        created = assets.create("web-01", group_name="DMZ", os="Rocky 9.3")
        assert assets.get(created.asset_id) == created
        assert assets.by_name("web-01") == created

    def test_duplicate_name_is_refused(self, assets):
        assets.create("web-01")
        with pytest.raises(AssetError, match="이미 있습니다"):
            assets.create("web-01")

    def test_rename_to_an_existing_name_is_refused(self, assets):
        assets.create("web-01")
        other = assets.create("web-02")
        with pytest.raises(AssetError, match="이미 있습니다"):
            assets.update(other.asset_id, name="web-01")

    def test_update_changes_only_what_was_given(self, assets):
        created = assets.create("web-01", group_name="DMZ", os="Rocky 9.3", note="원본")
        updated = assets.update(created.asset_id, group_name="내부업무")
        assert updated.group_name == "내부업무"
        assert (updated.name, updated.os, updated.note) == ("web-01", "Rocky 9.3", "원본")

    def test_list_hides_archived_by_default(self, assets):
        assets.create("web-01")
        archived = assets.create("old-01")
        assets.set_archived(archived.asset_id, True)

        assert [a.name for a in assets.list()] == ["web-01"]
        assert sorted(a.name for a in assets.list(include_archived=True)) == ["old-01", "web-01"]

    def test_archive_can_be_undone(self, assets):
        created = assets.create("web-01")
        assert assets.set_archived(created.asset_id, True).archived
        assert not assets.set_archived(created.asset_id, False).archived

    def test_list_is_ordered_by_group_then_name(self, assets):
        """그룹으로 묶어 보여 주므로 그룹이 첫 정렬 키다."""
        assets.create("web-02", group_name="DMZ")
        assets.create("app-01", group_name="내부업무")
        assets.create("web-01", group_name="DMZ")
        assert [a.name for a in assets.list()] == ["web-01", "web-02", "app-01"]

    def test_missing_asset_operations_are_refused(self, assets):
        assert assets.get("nope") is None
        for call in (
            lambda: assets.update("nope", name="x"),
            lambda: assets.set_archived("nope", True),
            lambda: assets.delete("nope"),
        ):
            with pytest.raises(AssetError):
                call()


class TestAssetDeletionKeepsScans:
    def test_deleting_an_asset_leaves_its_scans_unassigned(self, tmp_path):
        """스캔까지 함께 지우면 실수 한 번에 몇 달치 이력이 사라진다."""
        db = tmp_path / "test.db"
        store = Store(db)
        assets = Assets(db)
        asset = assets.create("web-01")

        result = normalize_grype_report(
            json.loads(FIXTURE.read_text(encoding="utf-8")), scan_id="s1", sbom_filename="a.json"
        )
        store.save_scan(result, asset_id=asset.asset_id)
        assert store.list_scans(asset_id=asset.asset_id)

        assets.delete(asset.asset_id)
        assert store.get_scan("s1") is not None
        assert [s["scan_id"] for s in store.list_scans(asset_id="")] == ["s1"]


# ---------------------------------------------------------------------------
# 스캔 ↔ 자산 연결
# ---------------------------------------------------------------------------


class TestScanAssignment:
    @pytest.fixture
    def store(self, tmp_path):
        return Store(tmp_path / "test.db")

    def _save(self, store, scan_id, asset_id="", created_at=None):
        result = normalize_grype_report(
            json.loads(FIXTURE.read_text(encoding="utf-8")),
            scan_id=scan_id, sbom_filename=f"{scan_id}.json",
        )
        if created_at:
            object.__setattr__(result.metadata, "created_at", created_at)
        store.save_scan(result, asset_id=asset_id)

    def test_scans_default_to_unassigned(self, store):
        self._save(store, "s1")
        assert store.list_scans()[0]["asset_id"] == ""

    def test_assign_and_unassign(self, store):
        self._save(store, "s1")
        assert store.assign_scan("s1", "asset-a") is True
        assert store.get_scan("s1")["asset_id"] == "asset-a"
        assert store.assign_scan("s1", "") is True
        assert store.get_scan("s1")["asset_id"] == ""

    def test_assigning_a_missing_scan_reports_failure(self, store):
        assert store.assign_scan("ghost", "asset-a") is False

    def test_list_filters_by_asset(self, store):
        self._save(store, "s1", "asset-a")
        self._save(store, "s2", "asset-b")
        self._save(store, "s3")
        assert [s["scan_id"] for s in store.list_scans(asset_id="asset-a")] == ["s1"]
        assert [s["scan_id"] for s in store.list_scans(asset_id="")] == ["s3"]
        assert len(store.list_scans()) == 3

    def test_summary_reports_the_latest_scan_per_asset(self, store):
        self._save(store, "old", "asset-a", created_at="2026-01-01T00:00:00+00:00")
        self._save(store, "new", "asset-a", created_at="2026-06-01T00:00:00+00:00")
        self._save(store, "other", "asset-b", created_at="2026-03-01T00:00:00+00:00")

        summary = store.asset_summary()
        assert summary["asset-a"]["scan_count"] == 2
        assert summary["asset-a"]["last_scan_id"] == "new"
        assert summary["asset-a"]["last_scan_at"] == "2026-06-01T00:00:00+00:00"
        assert summary["asset-b"]["last_scan_id"] == "other"


class TestMigration:
    def test_existing_database_gains_asset_id_without_losing_scans(self, tmp_path):
        """스캔 결과에는 내부 자산 정보가 담겨 있다. 지우고 다시 만들라고 할 수 없다."""
        db = tmp_path / "old.db"
        conn = sqlite3.connect(db)
        conn.executescript("""
            CREATE TABLE scans (
                scan_id TEXT PRIMARY KEY, created_at TEXT NOT NULL,
                metadata TEXT NOT NULL, finding_count INTEGER NOT NULL DEFAULT 0
            );
            INSERT INTO scans VALUES ('legacy', '2026-01-01T00:00:00+00:00', '{"sbom_filename":"x"}', 7);
        """)
        conn.commit()
        conn.close()

        store = Store(db)  # 여기서 마이그레이션이 돈다
        rows = store.list_scans()
        assert len(rows) == 1
        assert rows[0]["scan_id"] == "legacy"
        assert rows[0]["finding_count"] == 7
        assert rows[0]["asset_id"] == ""  # 미분류로 남아 화면에서 배정할 수 있다


# ---------------------------------------------------------------------------
# 이력 비교
# ---------------------------------------------------------------------------


class TestDiff:
    def test_new_finding_shows_as_added(self):
        base = [finding("CVE-2024-0001", "openssl", "3.0.7")]
        head = [
            finding("CVE-2024-0001", "openssl", "3.0.7"),
            finding("CVE-2024-9999", "curl", "8.4.0"),
        ]
        diff = diff_findings(base, head)
        assert [c.cve for c in diff.added] == ["CVE-2024-9999"]
        assert [c.cve for c in diff.remaining] == ["CVE-2024-0001"]
        assert diff.resolved == ()

    def test_patched_finding_shows_as_resolved(self):
        base = [finding("CVE-2024-0001", "openssl", "3.0.7")]
        diff = diff_findings(base, [])
        assert [c.cve for c in diff.resolved] == ["CVE-2024-0001"]

    def test_version_bump_alone_is_not_a_new_finding(self):
        """비교 축이 `(cve, 패키지명)` 인 이유가 이것이다.

        `Finding.key` 는 설치 버전을 포함하므로 패치하면 키가 바뀐다. 그것으로
        비교하면 부분 패치가 "해소 1건 + 신규 1건"으로 갈라져 화면이 거짓말을 한다.
        """
        base = [finding("CVE-2024-0001", "openssl", "3.0.7")]
        head = [finding("CVE-2024-0001", "openssl", "3.0.9")]
        diff = diff_findings(base, head)
        assert diff.added == () and diff.resolved == ()
        assert len(diff.remaining) == 1
        assert diff.remaining[0].previous_version == "3.0.7"
        assert diff.remaining[0].installed_version == "3.0.9"

    def test_same_cve_in_two_packages_counts_twice(self):
        """CVE 만으로 묶으면 한쪽만 패치했을 때 둘 다 해소된 것처럼 보인다."""
        base = [
            finding("CVE-2024-0001", "openssl", "3.0.7"),
            finding("CVE-2024-0001", "openssl-libs", "3.0.7"),
        ]
        head = [finding("CVE-2024-0001", "openssl-libs", "3.0.7")]
        diff = diff_findings(base, head)
        assert [c.package_name for c in diff.resolved] == ["openssl"]
        assert [c.package_name for c in diff.remaining] == ["openssl-libs"]

    def test_findings_without_a_key_are_ignored_not_miscounted(self):
        base = [{"intel": {}, "installed": {}}, finding("CVE-2024-0001", "openssl", "3.0.7")]
        diff = diff_findings(base, [])
        assert len(diff.resolved) == 1

    def test_results_are_ordered_for_reading(self):
        head = [
            finding("CVE-2024-0003", "zlib", "1.2.11"),
            finding("CVE-2024-0001", "curl", "8.4.0"),
            finding("CVE-2024-0002", "curl", "8.4.0"),
        ]
        diff = diff_findings([], head)
        assert [(c.package_name, c.cve) for c in diff.added] == [
            ("curl", "CVE-2024-0001"),
            ("curl", "CVE-2024-0002"),
            ("zlib", "CVE-2024-0003"),
        ]

    def test_carries_the_fix_information_through(self):
        head = [finding("CVE-2024-0001", "openssl", "3.0.7", fixed="3.0.9", priority="P0")]
        change = diff_findings([], head).added[0]
        assert change.fixed_version == "3.0.9"
        assert change.priority == "P0"

    def test_to_dict_carries_counts(self):
        payload = diff_findings(
            [finding("CVE-1", "a", "1")], [finding("CVE-2", "b", "1")],
            base_scan_id="s1", head_scan_id="s2",
        ).to_dict()
        assert payload["counts"] == {"added": 1, "resolved": 1, "remaining": 0}
        assert payload["base_scan_id"] == "s1" and payload["head_scan_id"] == "s2"


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------


class TestAssetApi:
    def test_empty_at_first(self, client):
        body = client.get("/api/assets").json()
        assert body["assets"] == [] and body["unassigned_scans"] == 0

    def test_create_and_list(self, client):
        client.post("/api/assets", json={"name": "web-01", "group_name": "DMZ", "os": "Rocky 9.3"})
        assets = client.get("/api/assets").json()["assets"]
        assert len(assets) == 1
        assert assets[0]["name"] == "web-01"
        assert assets[0]["scan_count"] == 0
        assert assets[0]["last_scan_at"] == ""

    def test_bad_name_is_refused(self, client):
        response = client.post("/api/assets", json={"name": "web 01"})
        assert response.status_code == 400
        assert "영문" in response.json()["detail"]

    def test_viewer_cannot_create_or_delete(self, viewer, client):
        created = client.post("/api/assets", json={"name": "web-01"}).json()
        assert viewer.get("/api/assets").status_code == 200          # 조회는 된다
        assert viewer.post("/api/assets", json={"name": "x-01"}).status_code == 403
        assert viewer.delete(f"/api/assets/{created['asset_id']}").status_code == 403

    def test_unknown_asset_is_404(self, client):
        assert client.get("/api/assets/ghost").status_code == 404
        assert client.put("/api/assets/ghost", json={"name": "x"}).status_code == 404
        assert client.delete("/api/assets/ghost").status_code == 404

    def test_assign_a_scan(self, client, seeded_scan):
        asset = client.post("/api/assets", json={"name": "web-01"}).json()
        assert client.put(
            f"/api/scans/{seeded_scan}/asset", json={"asset_id": asset["asset_id"]}
        ).status_code == 200

        detail = client.get(f"/api/assets/{asset['asset_id']}").json()
        assert [s["scan_id"] for s in detail["scans"]] == [seeded_scan]

        listed = client.get("/api/assets").json()
        assert listed["assets"][0]["scan_count"] == 1
        assert listed["unassigned_scans"] == 0

    def test_unassigned_scans_are_counted(self, client, seeded_scan):
        assert client.get("/api/assets").json()["unassigned_scans"] == 1

    def test_assigning_to_a_missing_asset_is_404(self, client, seeded_scan):
        response = client.put(f"/api/scans/{seeded_scan}/asset", json={"asset_id": "ghost"})
        assert response.status_code == 404

    def test_assigning_a_missing_scan_is_404(self, client):
        asset = client.post("/api/assets", json={"name": "web-01"}).json()
        response = client.put("/api/scans/ghost/asset", json={"asset_id": asset["asset_id"]})
        assert response.status_code == 404

    def test_scan_can_be_started_against_an_asset(self, client):
        asset = client.post("/api/assets", json={"name": "web-01"}).json()
        response = client.post(
            f"/api/scan?upload_id=missing&asset_id={asset['asset_id']}"
        )
        # 업로드가 없어 404 지만, 자산 확인은 통과했다는 뜻이다.
        assert response.status_code == 404
        assert "업로드" in response.json()["detail"]

    def test_scan_against_an_unknown_asset_is_refused(self, client):
        response = client.post("/api/scan?upload_id=missing&asset_id=ghost")
        assert response.status_code == 404
        assert "자산" in response.json()["detail"]

    def test_deleting_an_asset_keeps_its_scan(self, client, seeded_scan):
        asset = client.post("/api/assets", json={"name": "web-01"}).json()
        client.put(f"/api/scans/{seeded_scan}/asset", json={"asset_id": asset["asset_id"]})
        client.delete(f"/api/assets/{asset['asset_id']}")

        assert client.get(f"/api/scans/{seeded_scan}").status_code == 200
        assert client.get("/api/assets").json()["unassigned_scans"] == 1


class TestHistoryApi:
    def _seed(self, client, asset_id, scan_id, findings_source):
        """정규화된 결과를 직접 저장한다 — grype 실행 없이 이력만 본다."""
        from core.config import get_config

        result = normalize_grype_report(
            json.loads(FIXTURE.read_text(encoding="utf-8")),
            scan_id=scan_id, sbom_filename=f"{scan_id}.json",
        )
        kept = tuple(f for f in result.findings if f.intel.cve in findings_source)
        Store(get_config().db_path).save_scan(
            ScanResult(metadata=result.metadata, findings=kept), asset_id=asset_id
        )

    def test_needs_two_scans(self, client, seeded_scan):
        asset = client.post("/api/assets", json={"name": "web-01"}).json()
        client.put(f"/api/scans/{seeded_scan}/asset", json={"asset_id": asset["asset_id"]})
        body = client.get(f"/api/assets/{asset['asset_id']}/history").json()
        assert body["comparable"] is False
        assert "2건 이상" in body["detail"]

    def test_compares_the_two_most_recent(self, client):
        asset = client.post("/api/assets", json={"name": "web-01"}).json()
        raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
        every = {m["vulnerability"]["id"] for m in raw["matches"]}
        first = sorted(every)[0]

        self._seed(client, asset["asset_id"], "20260101T000000Z-aaaa", every)
        self._seed(client, asset["asset_id"], "20260201T000000Z-bbbb", every - {first})

        body = client.get(f"/api/assets/{asset['asset_id']}/history").json()
        assert body["comparable"] is True
        assert body["head_scan_id"] == "20260201T000000Z-bbbb"
        assert body["base_scan_id"] == "20260101T000000Z-aaaa"
        assert body["counts"]["resolved"] >= 1
        assert first in {c["cve"] for c in body["resolved"]}

    def test_refuses_a_scan_from_another_asset(self, client, seeded_scan):
        asset = client.post("/api/assets", json={"name": "web-01"}).json()
        response = client.get(
            f"/api/assets/{asset['asset_id']}/history?base={seeded_scan}&head={seeded_scan}"
        )
        assert response.status_code == 404
        assert seeded_scan in response.json()["detail"]

    def test_unknown_asset_is_404(self, client):
        assert client.get("/api/assets/ghost/history").status_code == 404
