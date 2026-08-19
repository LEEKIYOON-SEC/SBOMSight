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


def test_meta_kv(store):
    assert store.meta_get("missing", "default") == "default"
    store.meta_set("kev_snapshot_date", "2026-08-18")
    assert store.meta_get("kev_snapshot_date") == "2026-08-18"
