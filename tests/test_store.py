"""SQLite 저장소 테스트."""

import json
from pathlib import Path

import pytest

from core.normalize import normalize_grype_report
from core.store import Store

FIXTURE = Path(__file__).parent / "fixtures" / "grype-sample.json"


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "test.db")


@pytest.fixture
def scan_result():
    return normalize_grype_report(json.loads(FIXTURE.read_text()), scan_id="s1", sbom_filename="a.json")


def test_save_and_load_roundtrip(store, scan_result):
    store.save_scan(scan_result)
    loaded = store.get_scan("s1")
    assert loaded is not None
    assert len(loaded["findings"]) == len(scan_result.findings)
    assert loaded["metadata"]["sbom_filename"] == "a.json"
    # 계층이 직렬화 이후에도 유지되어야 한다.
    first = loaded["findings"][0]
    assert set(first) >= {"installed", "advisory", "intel", "detection", "fix"}


def test_save_is_idempotent(store, scan_result):
    store.save_scan(scan_result)
    store.save_scan(scan_result)
    assert len(store.get_scan("s1")["findings"]) == len(scan_result.findings)
    assert len(store.list_scans()) == 1


def test_missing_scan_returns_none(store):
    assert store.get_scan("nope") is None


def test_delete_scan_removes_findings(store, scan_result):
    store.save_scan(scan_result)
    store.delete_scan("s1")
    assert store.get_scan("s1") is None
    assert store.list_scans() == []


def test_intel_cache_roundtrip(store):
    store.cache_put_many("epss", {"CVE-1": {"score": 0.9}, "CVE-2": {"score": 0.1}})
    got = store.cache_get_many("epss", ["CVE-1", "CVE-2", "CVE-3"])
    assert set(got) == {"CVE-1", "CVE-2"}
    payload, fetched_at = got["CVE-1"]
    assert payload["score"] == 0.9
    assert fetched_at


class TestProvenancePersistence:
    """보고서가 "어떤 데이터로, 어떤 기준으로 판정했는지"를 스스로 증명하려면
    스냅샷 기준일과 정책 해시가 결과와 함께 남아 있어야 한다."""

    def test_enrichment_and_policy_survive_roundtrip(self, store, scan_result):
        from core.models import ScanResult

        enriched = ScanResult(
            metadata=scan_result.metadata,
            findings=scan_result.findings,
            enrichment={"epss": {"state": "ok", "snapshot_date": "2026-08-18", "entries": 3, "matched": 2}},
            policy={"version": "1", "sha256": "a" * 64, "label": "priority.json v1 (sha256:aaaaaaaaaaaa)"},
        )
        store.save_scan(enriched)

        loaded = store.get_scan("s1")
        assert loaded["enrichment"]["epss"]["snapshot_date"] == "2026-08-18"
        assert loaded["policy"]["sha256"] == "a" * 64

    def test_policy_is_visible_in_scan_list(self, store, scan_result):
        from core.models import ScanResult

        store.save_scan(
            ScanResult(metadata=scan_result.metadata, findings=scan_result.findings,
                       policy={"label": "priority.json v1"})
        )
        assert store.list_scans()[0]["policy"]["label"] == "priority.json v1"

    def test_missing_provenance_defaults_to_empty(self, store, scan_result):
        store.save_scan(scan_result)          # enrichment/policy 없이 저장
        loaded = store.get_scan("s1")
        assert loaded["enrichment"] == {}
        assert loaded["policy"] == {}


def test_migration_adds_columns_to_older_database(tmp_path):
    """스캔 결과에는 내부 자산 정보가 담겨 있어 지우고 다시 만들라고 할 수 없다.
    앞선 버전의 DB를 파괴하지 않고 컬럼만 덧붙여야 한다."""
    import sqlite3

    db = tmp_path / "old.db"
    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE scans (scan_id TEXT PRIMARY KEY, created_at TEXT NOT NULL,
                            metadata TEXT NOT NULL, finding_count INTEGER NOT NULL DEFAULT 0);
        INSERT INTO scans VALUES ('legacy-1', '2026-01-01T00:00:00+00:00', '{"scan_id":"legacy-1"}', 7);
    """)
    conn.commit()
    conn.close()

    store = Store(db)                          # 마이그레이션이 여기서 일어난다
    rows = store.list_scans()
    assert [r["scan_id"] for r in rows] == ["legacy-1"]
    assert rows[0]["finding_count"] == 7       # 기존 데이터는 그대로
    assert rows[0]["policy"] == {}             # 새 컬럼은 기본값


def test_meta_kv(store):
    assert store.meta_get("missing", "default") == "default"
    store.meta_set("kev_snapshot_date", "2026-08-18")
    assert store.meta_get("kev_snapshot_date") == "2026-08-18"
