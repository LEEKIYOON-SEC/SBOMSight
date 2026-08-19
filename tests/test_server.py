"""웹 API 계약 테스트.

Grype 없이도 검증할 수 있는 것들을 다룬다: 업로드 파싱, 파이프라인의 단계
전이, 보고서 엔드포인트, 오류 경로. 진짜 grype 실행이 필요한 부분은
정규화된 결과를 직접 저장해 우회한다 — grype 자체는 M1에서 이미 픽스처로
검증했다.
"""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from core.models import ScanResult
from core.normalize import normalize_grype_report
from core.ruleengine import RuleEngine
from core.store import Store

FIXTURE = Path(__file__).parent / "fixtures" / "grype-sample.json"

CYCLONEDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": [
        {"type": "library", "name": "xz", "version": "5.6.0-2.el9",
         "purl": "pkg:rpm/rocky/xz@5.6.0-2.el9",
         "properties": [{"name": "syft:package:type", "value": "rpm"}]},
        {"type": "library", "name": "requests", "version": "2.31.0",
         "purl": "pkg:pypi/requests@2.31.0"},
    ],
}


@pytest.fixture
def client(tmp_path, monkeypatch):
    """데이터 디렉터리를 임시 경로로 돌린 앱 인스턴스."""
    monkeypatch.setenv("SBOMSIGHT_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SBOMSIGHT_OFFLINE", "1")

    import core.config
    core.config.get_config(refresh=True)

    import importlib
    import server.app
    importlib.reload(server.app)
    return TestClient(server.app.app)


@pytest.fixture
def seeded_scan(client):
    """정규화·판정까지 마친 스캔을 저장해 두고 scan_id를 돌려준다."""
    from core.config import get_config

    result = normalize_grype_report(json.loads(FIXTURE.read_text()), scan_id="seeded-1",
                                    sbom_filename="seed.cdx.json", component_count=1204)
    engine = RuleEngine.from_config()
    Store(get_config().db_path).save_scan(
        ScanResult(
            metadata=result.metadata,
            findings=engine.apply(result.findings),
            policy={"label": engine.policy.label, "version": engine.policy.version,
                    "sha256": engine.policy.sha256, "sources": list(engine.policy.sources)},
        )
    )
    return "seeded-1"


class TestHealthAndPolicy:
    def test_health_reports_tool_and_policy_state(self, client):
        body = client.get("/api/health").json()
        assert "tools" in body and "policy" in body
        assert body["policy"]["sha256"]
        # AI는 기본적으로 꺼져 있어야 한다 — 이 제품의 전제다.
        assert body["ai"]["enabled"] is False
        assert body["ai"]["ready"] is False

    def test_policy_returns_full_document(self, client):
        body = client.get("/api/policy").json()
        assert body["version"]
        assert "signals" in body["policy"]
        assert "levels" in body["policy"]
        # 등급 정의가 UI에서 설명 가능한 형태여야 한다.
        assert all("priority" in level and "when" in level for level in body["policy"]["levels"])


class TestUpload:
    def test_upload_reports_format_and_component_count(self, client):
        response = client.post(
            "/api/upload",
            files={"file": ("sbom.cdx.json", json.dumps(CYCLONEDX), "application/json")},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["format"] == "cyclonedx-json"
        assert body["component_count"] == 2
        assert len(body["sha256"]) == 64
        assert body["upload_id"]

    def test_non_json_upload_is_rejected(self, client):
        response = client.post(
            "/api/upload", files={"file": ("x.json", b"not json at all", "application/json")}
        )
        assert response.status_code == 400
        assert "JSON" in response.json()["detail"]

    def test_unknown_format_is_accepted_but_labelled(self, client):
        """형식을 몰라도 거부하지 않는다 — Grype가 읽을 수도 있다."""
        response = client.post(
            "/api/upload", files={"file": ("x.json", json.dumps({"hello": "world"}), "application/json")}
        )
        assert response.status_code == 200
        assert response.json()["format"] == "unknown"


class TestScanJob:
    def test_scan_requires_existing_upload(self, client):
        response = client.post("/api/scan?upload_id=doesnotexist")
        assert response.status_code == 404

    def test_scan_reports_all_seven_steps(self, client):
        upload = client.post(
            "/api/upload",
            files={"file": ("sbom.json", json.dumps(CYCLONEDX), "application/json")},
        ).json()
        started = client.post(f"/api/scan?upload_id={upload['upload_id']}&enrich=false").json()

        keys = [s["key"] for s in started["steps"]]
        assert keys == ["upload", "detect", "enrich", "prioritize", "rationale", "recommend", "report"]

        # 이 환경에는 grype가 없으므로 detect에서 멈춘다. 중요한 것은
        # 실패가 조용히 삼켜지지 않고 해당 단계에 기록된다는 점이다.
        job = client.get(f"/api/scan/{started['job_id']}").json()
        assert job["steps"][0]["state"] == "done"          # 업로드 파싱은 성공
        assert job["steps"][0]["metric"].startswith("컴포넌트 2")
        if job["state"] == "failed":
            detect = next(s for s in job["steps"] if s["key"] == "detect")
            assert detect["state"] == "failed"
            assert detect["detail"]

    def test_unknown_job_is_404(self, client):
        assert client.get("/api/scan/nope").status_code == 404


class TestResults:
    def test_list_and_get_scan(self, client, seeded_scan):
        scans = client.get("/api/scans").json()["scans"]
        assert [s["scan_id"] for s in scans] == [seeded_scan]

        scan = client.get(f"/api/scans/{seeded_scan}").json()
        assert len(scan["findings"]) == 5
        assert scan["metadata"]["component_count"] == 1204

    def test_missing_scan_is_404(self, client):
        assert client.get("/api/scans/nope").status_code == 404
        assert client.get("/api/scans/nope/report").status_code == 404

    def test_delete_scan(self, client, seeded_scan):
        assert client.delete(f"/api/scans/{seeded_scan}").status_code == 200
        assert client.get(f"/api/scans/{seeded_scan}").status_code == 404


class TestReportEndpoint:
    def test_json_report_has_six_sections_per_finding(self, client, seeded_scan):
        report = client.get(f"/api/scans/{seeded_scan}/report?format=json").json()
        assert report["ai_used"] is False        # 서버는 AI를 쓰지 않는다
        assert len(report["findings"]) == 5
        for item in report["findings"]:
            assert item["overview"]["cve"]
            assert item["technical_risk"]["narrative"]
            assert item["exploitability"]["narrative"]
            assert item["response_rationale"]["narrative"]
            assert item["recommendation"]["action"]
            assert item["references"]

    def test_local_analysis_is_marked_not_transmitted(self, client, seeded_scan):
        report = client.get(f"/api/scans/{seeded_scan}/report?format=json").json()
        for item in report["findings"]:
            assert item["local_analysis"]["ai_transmitted"] is False

    def test_installed_version_stays_out_of_public_sections(self, client, seeded_scan):
        """API 응답에서도 설치 버전이 공개 절로 새면 안 된다."""
        report = client.get(f"/api/scans/{seeded_scan}/report?format=json").json()
        item = next(i for i in report["findings"] if i["cve"] == "CVE-2024-3094")
        public = json.dumps(
            [item["overview"], item["technical_risk"], item["exploitability"],
             item["response_rationale"]],
            ensure_ascii=False,
        )
        assert "5.6.0-2.el9" not in public
        assert "/var/lib/rpm" not in public

    def test_markdown_and_html_formats(self, client, seeded_scan):
        md = client.get(f"/api/scans/{seeded_scan}/report?format=markdown")
        assert md.status_code == 200
        assert "취약점 대응 검토 보고서" in md.text
        assert "[로컬 분석 정보] · AI 미전달" in md.text

        html = client.get(f"/api/scans/{seeded_scan}/report?format=html")
        assert html.status_code == 200
        assert html.text.startswith("<!doctype html>")

    def test_invalid_format_is_rejected(self, client, seeded_scan):
        assert client.get(f"/api/scans/{seeded_scan}/report?format=pdf").status_code == 422


class TestStaticFrontend:
    @pytest.mark.parametrize("path", ["/", "/scan.html", "/report.html", "/about.html"])
    def test_pages_are_served(self, client, path):
        response = client.get(path)
        assert response.status_code == 200
        assert "SBOMSight" in response.text

    @pytest.mark.parametrize(
        "path",
        ["/js/core/model.js", "/js/core/ui.js", "/js/providers/live-api.js",
         "/js/providers/index.js", "/css/app.css"],
    )
    def test_assets_are_served(self, client, path):
        assert client.get(path).status_code == 200
