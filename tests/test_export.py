"""전시물 내보내기 테스트.

`core.cli export` 가 만드는 파일은 **공개 리포에 커밋될 것을 전제로 한다.**
그러니 무엇이 담기고 무엇이 지워지는지가 테스트로 고정되어 있어야 한다.
"여기 들어가면 안 되는 것"은 코드 리뷰가 아니라 벡터가 지켜야 한다.
"""

import json
from pathlib import Path

import pytest

from core.config import get_config
from core.export import export_all
from core.models import ScanResult
from core.normalize import normalize_grype_report
from core.ruleengine import RuleEngine
from core.store import Store

FIXTURE = Path(__file__).parent / "fixtures" / "grype-sample.json"


@pytest.fixture
def seeded(tmp_path, monkeypatch):
    monkeypatch.setenv("SBOMSIGHT_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SBOMSIGHT_OFFLINE", "1")
    import core.config

    config = core.config.get_config(refresh=True)
    config.ensure_dirs()

    result = normalize_grype_report(
        json.loads(FIXTURE.read_text()),
        scan_id="exp-1",
        sbom_filename="prod-web-01.cdx.json",
        component_count=1204,
    )
    engine = RuleEngine.from_config(config)
    Store(config.db_path).save_scan(
        ScanResult(
            metadata=result.metadata,
            findings=engine.apply(result.findings),
            policy={"label": engine.policy.label, "version": engine.policy.version,
                    "sha256": engine.policy.sha256, "sources": list(engine.policy.sources)},
        )
    )
    return config


def _load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


class TestLayout:
    def test_writes_the_files_the_static_viewer_expects(self, seeded, tmp_path):
        out = tmp_path / "results"
        export_all(out, config=seeded)

        assert (out / "index.json").is_file()
        for name in ("scan.json", "report.json", "report.md", "report.html", "egress.json"):
            assert (out / "exp-1" / name).is_file(), name

    def test_index_lists_the_scan(self, seeded, tmp_path):
        out = tmp_path / "results"
        index = export_all(out, config=seeded)
        assert [s["scan_id"] for s in index["scans"]] == ["exp-1"]
        assert index["scans"][0]["finding_count"] > 0
        assert index["generated_at"]

    def test_scan_json_matches_the_api_shape(self, seeded, tmp_path):
        """정적 뷰어는 /api/scans/{id} 와 같은 모양을 기대한다."""
        out = tmp_path / "results"
        export_all(out, config=seeded)
        scan = _load(out / "exp-1" / "scan.json")
        assert set(scan) >= {"scan_id", "created_at", "metadata", "findings", "selection"}
        assert scan["findings"][0]["intel"]["cve"]
        assert scan["findings"][0]["verdict"]["priority"]

    def test_rerun_drops_scans_that_are_gone(self, seeded, tmp_path):
        out = tmp_path / "results"
        export_all(out, config=seeded)
        stale = out / "deleted-scan"
        stale.mkdir()
        (stale / "scan.json").write_text("{}", encoding="utf-8")

        export_all(out, config=seeded)
        assert not stale.exists(), "전시 목록과 파일이 어긋나면 안 된다"


class TestRedaction:
    def test_paths_and_filenames_are_removed_by_default(self, seeded, tmp_path):
        out = tmp_path / "results"
        export_all(out, config=seeded)
        blob = (out / "exp-1" / "scan.json").read_text(encoding="utf-8")

        assert "prod-web-01" not in blob
        assert "/var/lib/rpm" not in blob
        assert "rpm-matcher" in blob, "탐지 근거 자체는 남는다 — 지우는 것은 검색 조건이다"

    def test_report_json_is_redacted_too(self, seeded, tmp_path):
        out = tmp_path / "results"
        export_all(out, config=seeded)
        blob = (out / "exp-1" / "report.json").read_text(encoding="utf-8")
        assert "prod-web-01" not in blob
        assert "/var/lib/rpm" not in blob

    def test_installed_versions_survive(self, seeded, tmp_path):
        """설치 버전을 지우면 '설치 버전 대 Fixed Version 비교'라는 요점이 사라진다."""
        out = tmp_path / "results"
        export_all(out, config=seeded)
        scan = _load(out / "exp-1" / "scan.json")
        assert all(f["installed"]["version"] for f in scan["findings"])
        assert any(f["fix"]["is_vulnerable"] == "true" for f in scan["findings"])

    def test_no_redact_keeps_everything(self, seeded, tmp_path):
        out = tmp_path / "results"
        export_all(out, config=seeded, redact=False)
        blob = (out / "exp-1" / "scan.json").read_text(encoding="utf-8")
        assert "prod-web-01" in blob
        assert "/var/lib/rpm" in blob


class TestEgressRecord:
    def test_record_holds_only_public_data(self, seeded, tmp_path):
        out = tmp_path / "results"
        export_all(out, config=seeded)
        record = _load(out / "exp-1" / "egress.json")

        assert record["ok"] is True
        assert record["violations"] == []
        payload = json.dumps(record["facts"], ensure_ascii=False)
        request_body = record["prompt"].split("=== 요청 ===", 1)[-1]
        for internal in ("5.6.0-2.el9", "/var/lib/rpm", "prod-web-01",
                         "rpm-matcher", "cvss_critical"):
            assert internal not in payload, f"facts에 {internal} 유출"
            assert internal not in request_body, f"프롬프트에 {internal} 유출"

    def test_record_follows_the_stored_selection(self, seeded, tmp_path):
        store = Store(seeded.db_path)
        scan = store.get_scan("exp-1")
        first = scan["findings"][0]
        key = "|".join([first["intel"]["cve"], first["installed"]["name"],
                        first["installed"]["version"], first["installed"]["purl"]])
        store.save_selection("exp-1", [key])

        out = tmp_path / "results"
        index = export_all(out, config=seeded)
        record = _load(out / "exp-1" / "egress.json")

        assert record["selection"]["scope"] == "selection"
        assert record["finding_count"] == 1
        assert index["scans"][0]["selected_count"] == 1

        report = _load(out / "exp-1" / "report.json")
        assert len(report["findings"]) == 1

    def test_ai_off_is_recorded_as_such(self, seeded, tmp_path):
        out = tmp_path / "results"
        export_all(out, config=seeded)
        record = _load(out / "exp-1" / "egress.json")
        assert record["would_send"] is False
        assert record["model"] == ""


class TestEmpty:
    def test_export_without_scans_is_an_error(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SBOMSIGHT_DATA_DIR", str(tmp_path / "empty"))
        import core.config

        config = core.config.get_config(refresh=True)
        with pytest.raises(FileNotFoundError):
            export_all(tmp_path / "results", config=config)
