"""웹 API 계약 테스트.

Grype 없이도 검증할 수 있는 것들을 다룬다: 업로드 파싱, 파이프라인의 단계
전이, 보고서 엔드포인트, 오류 경로. 진짜 grype 실행이 필요한 부분은
정규화된 결과를 직접 저장해 우회한다 — grype 자체는 M1에서 이미 픽스처로
검증했다.
"""

import dataclasses
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


def _upload(client, payload, name="sbom.cdx.json"):
    """새 업로드 방식 — 본문에 파일 바이트를 그대로 싣는다.

    multipart 를 쓰지 않는 이유는 Starlette 의 `max_part_size` 가 1MB로 고정되어
    있어 실 서버 SBOM(100MB+)이 아예 올라가지 않기 때문이다.
    """
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    return client.post(f"/api/upload?filename={name}", content=body)


class TestUpload:
    def test_upload_reports_format_and_component_count(self, client):
        response = _upload(client, CYCLONEDX)
        assert response.status_code == 200
        body = response.json()
        assert body["format"] == "cyclonedx-json"
        assert body["component_count"] == 2
        assert len(body["sha256"]) == 64
        assert body["upload_id"]
        assert body["filename"] == "sbom.cdx.json"

    def test_upload_is_stored_compressed(self, client):
        """SBOM JSON은 압축이 아주 잘 먹는다. 보관 비용이 곧 운영 수명이다."""
        big = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
            {"type": "library", "name": f"package-{i}", "version": "1.0.0",
             "purl": f"pkg:rpm/rocky/package-{i}@1.0.0"} for i in range(2000)
        ]}
        body = _upload(client, big).json()
        assert body["compressed"] is True
        assert body["component_count"] == 2000
        # 저장본이 원본보다 확실히 작아야 한다.
        assert body["stored_bytes"] < body["size"] / 5

    def test_upload_larger_than_starlette_multipart_limit(self, client):
        """1MB는 예전 구현이 죽던 지점이다. 이제는 통과해야 한다."""
        payload = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
            {"type": "library", "name": f"pkg-{i}", "version": "1.0",
             "description": "x" * 200} for i in range(5000)
        ]}
        raw = json.dumps(payload).encode()
        assert len(raw) > 1024 * 1024, "이 테스트는 1MB를 넘겨야 의미가 있다"

        response = _upload(client, raw)
        assert response.status_code == 200
        assert response.json()["component_count"] == 5000

    def test_empty_upload_is_rejected(self, client):
        response = _upload(client, b"")
        assert response.status_code == 400

    def test_oversized_upload_is_rejected(self, client, monkeypatch):
        import server.app

        monkeypatch.setattr(server.app.config, "max_upload_mb", 1)
        response = _upload(client, b"x" * (2 * 1024 * 1024))
        assert response.status_code == 413
        assert "1MB" in response.json()["detail"]

    def test_unknown_format_is_accepted_but_labelled(self, client):
        """형식을 몰라도 거부하지 않는다 — Grype가 읽을 수도 있다."""
        response = _upload(client, {"hello": "world"}, name="x.json")
        assert response.status_code == 200
        body = response.json()
        assert body["format"] == "unknown"
        # 셀 수 없으면 0이 아니라 미상이다. 0은 "컴포넌트가 없다"는 거짓말이 된다.
        assert body["component_count"] is None


def _asset(client, name="web-01"):
    """스캔에는 자산이 **필수**다. 어느 서버의 SBOM 인지 정해지지 않은 채로
    결과가 쌓이면 나중에 파일명으로 추측하게 된다."""
    return client.post("/api/assets", json={"name": name}).json()["asset_id"]


class TestScanJob:
    def test_scan_without_an_asset_is_refused(self, client):
        """등록이 먼저다. 이 순서가 이 도구의 관리 단위를 정한다."""
        upload = _upload(client, CYCLONEDX, name="sbom.json").json()
        response = client.post(f"/api/scan?upload_id={upload['upload_id']}")
        assert response.status_code == 400
        assert "자산" in response.json()["detail"]

    def test_scan_requires_existing_upload(self, client):
        asset_id = _asset(client)
        response = client.post(f"/api/scan?upload_id=doesnotexist&asset_id={asset_id}")
        assert response.status_code == 404

    def test_scan_reports_all_seven_steps(self, client):
        asset_id = _asset(client)
        upload = _upload(client, CYCLONEDX, name="sbom.json").json()
        started = client.post(
            f"/api/scan?upload_id={upload['upload_id']}&enrich=false&asset_id={asset_id}"
        ).json()

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
        assert "## 2. 조치 대상" in md.text
        # AI 를 쓰지 않은 보고서에는 전송 관련 문구가 한 줄도 없다.
        assert "AI 미전달" not in md.text

        html = client.get(f"/api/scans/{seeded_scan}/report?format=html")
        assert html.status_code == 200
        assert html.text.startswith("<!doctype html>")

    def test_invalid_format_is_rejected(self, client, seeded_scan):
        assert client.get(f"/api/scans/{seeded_scan}/report?format=pdf").status_code == 422


class TestEgressEndpoints:
    """'공개 데이터만 보냅니다'라는 주장은 검증할 수 있어야 의미가 있다."""

    def test_policy_is_exposed(self, client):
        body = client.get("/api/egress/policy").json()
        assert body["version"]
        assert len(body["sha256"]) == 64
        assert "allowed_fields" in body["policy"]
        assert "forbidden_patterns" in body["policy"]

    def test_preview_returns_exactly_what_would_be_sent(self, client, seeded_scan):
        body = client.get(f"/api/scans/{seeded_scan}/egress/preview").json()
        assert body["ok"] is True
        assert body["violations"] == []
        assert body["fact_count"] > 0
        assert body["prompt"]

        allowed = set(client.get("/api/egress/policy").json()["policy"]["allowed_fields"])
        for fact in body["facts"]:
            assert set(fact) <= allowed

    def test_preview_contains_no_internal_strings(self, client, seeded_scan):
        body = client.get(f"/api/scans/{seeded_scan}/egress/preview").json()
        payload = json.dumps(body["facts"], ensure_ascii=False)
        # 요청 본문만 검사한다 — 시스템 지시문에는 "P0~P3 등급을 말하지 마십시오"
        # 같은 가드 문구가 들어 있고 그것은 유출이 아니다.
        request_body = body["prompt"].split("=== 요청 ===", 1)[-1]

        for internal in ("5.6.0-2.el9", "/var/lib/rpm", "rocky:distro:rocky:9",
                         "rpm-matcher", "1.2.11-40.el9", "cvss_critical"):
            assert internal not in payload, f"facts에 {internal} 유출"
            assert internal not in request_body, f"프롬프트에 {internal} 유출"

    def test_preview_deduplicates(self, client, seeded_scan):
        body = client.get(f"/api/scans/{seeded_scan}/egress/preview").json()
        assert body["fact_count"] + body["deduplicated"] == body["finding_count"]

    def test_preview_is_audited(self, client, seeded_scan):
        client.get(f"/api/scans/{seeded_scan}/egress/preview")
        records = client.get("/api/egress/audit").json()["records"]
        assert records
        assert records[0]["action"] == "preview"
        assert records[0]["outcome"] == "allowed"
        assert len(records[0]["payload_sha256"]) == 64

    def test_preview_of_missing_scan_is_404(self, client):
        assert client.get("/api/scans/nope/egress/preview").status_code == 404

    def test_ai_is_off_so_nothing_would_be_sent(self, client, seeded_scan):
        body = client.get(f"/api/scans/{seeded_scan}/egress/preview").json()
        assert body["would_send"] is False


class TestSelectionScope:
    """고른 것만 나가고, 고른 것만 보고서가 된다."""

    def _keys(self, client, seeded_scan):
        findings = client.get(f"/api/scans/{seeded_scan}").json()["findings"]
        return [
            "|".join([f["intel"]["cve"], f["installed"]["name"],
                      f["installed"]["version"], f["installed"]["purl"]])
            for f in findings
        ]

    def test_preview_is_limited_to_the_selection(self, client, seeded_scan):
        keys = self._keys(client, seeded_scan)
        body = client.get(
            f"/api/scans/{seeded_scan}/egress/preview", params={"select": keys[:1]}
        ).json()
        assert body["finding_count"] == 1
        assert body["selection"]["scope"] == "selection"
        assert body["scan_finding_count"] > 1

    def test_unselected_cve_is_absent_from_the_prompt(self, client, seeded_scan):
        keys = self._keys(client, seeded_scan)
        full = client.get(f"/api/scans/{seeded_scan}/egress/preview").json()
        one = client.get(
            f"/api/scans/{seeded_scan}/egress/preview", params={"select": keys[:1]}
        ).json()

        picked = {f["cve"] for f in one["facts"]}
        dropped = {f["cve"] for f in full["facts"]} - picked
        assert dropped, "픽스처에 CVE가 하나뿐이라 이 테스트가 의미가 없다"
        for cve in dropped:
            assert cve not in one["prompt"]

    def test_report_is_limited_to_the_selection(self, client, seeded_scan):
        keys = self._keys(client, seeded_scan)
        body = client.get(
            f"/api/scans/{seeded_scan}/report", params={"format": "json", "select": keys[:1]}
        ).json()
        assert len(body["findings"]) == 1
        assert body["selection"]["scope"] == "selection"

    def test_empty_selection_is_the_whole_scan(self, client, seeded_scan):
        body = client.get(f"/api/scans/{seeded_scan}/report?format=json").json()
        assert body["selection"]["scope"] == "all"
        assert len(body["findings"]) == len(self._keys(client, seeded_scan))

    def test_selection_of_nothing_known_is_rejected(self, client, seeded_scan):
        response = client.get(
            f"/api/scans/{seeded_scan}/egress/preview", params={"select": ["nope"]}
        )
        assert response.status_code == 400

    def test_selection_round_trips(self, client, seeded_scan):
        keys = self._keys(client, seeded_scan)
        put = client.put(f"/api/scans/{seeded_scan}/selection", json={"selection": keys[:1]})
        assert put.status_code == 200
        stored = client.get(f"/api/scans/{seeded_scan}").json()["selection"]["keys"]
        assert stored == keys[:1]

    def test_saving_an_empty_selection_clears_the_scope(self, client, seeded_scan):
        keys = self._keys(client, seeded_scan)
        client.put(f"/api/scans/{seeded_scan}/selection", json={"selection": keys[:1]})
        client.put(f"/api/scans/{seeded_scan}/selection", json={"selection": []})
        assert client.get(f"/api/scans/{seeded_scan}").json()["selection"]["keys"] == []

    def test_selection_must_be_a_list(self, client, seeded_scan):
        response = client.put(f"/api/scans/{seeded_scan}/selection", json={"selection": "all"})
        assert response.status_code == 400


class TestNarrativeEndpoint:
    """AI 호출은 서버에서만 일어나고, 키는 브라우저로 내려가지 않는다."""

    def test_key_never_appears_in_any_response(self, client, seeded_scan):
        health = client.get("/api/health").json()
        assert "key" not in json.dumps(health["ai"]).lower().replace("key_source", "")
        assert health["ai"]["key_source"] == "server-env"

    @staticmethod
    def _one_package(client, scan_id):
        group = client.get(f"/api/scans/{scan_id}/packages").json()["packages"][0]
        return {"package": group["package"], "version": group["installed_version"]}

    def test_a_package_must_be_named(self, client, seeded_scan):
        """한 번에 하나씩 만든다 — 범위를 넓게 잡으면 분당 토큰 한도를 넘긴다."""
        response = client.post(f"/api/scans/{seeded_scan}/narratives", json={})
        assert response.status_code == 400
        assert "패키지" in response.json()["detail"]

    def test_refused_when_ai_is_disabled(self, client, seeded_scan):
        response = client.post(
            f"/api/scans/{seeded_scan}/narratives", json=self._one_package(client, seeded_scan)
        )
        assert response.status_code == 409
        assert "SBOMSIGHT_AI_ENABLED" in response.json()["detail"]

    def test_refused_when_key_is_missing(self, client, seeded_scan, monkeypatch):
        import server.app

        monkeypatch.setattr(server.app.config, "ai_enabled", True)
        monkeypatch.setattr(server.app.config, "gemini_api_key", "")
        response = client.post(
            f"/api/scans/{seeded_scan}/narratives", json=self._one_package(client, seeded_scan)
        )
        assert response.status_code == 409
        assert "GEMINI_API_KEY" in response.json()["detail"]

    @staticmethod
    def _stub_ai(client, monkeypatch, seen=None, model=""):
        """모델을 실제로 부르지 않고 서술 생성 경로만 태운다."""
        import server.app
        from core.ai_narrative import NarrativeRun
        from core.report import Narrative

        def fake_run(findings, *, config, scan_id):
            if seen is not None:
                seen["cves"] = [f.intel.cve for f in findings]
            return NarrativeRun(
                narratives={
                    f.intel.cve: Narrative(technical_risk="설명", source="ai") for f in findings
                },
                model=model,
                requested=len(findings),
            )

        monkeypatch.setattr(server.app.config, "ai_enabled", True)
        monkeypatch.setattr(server.app.config, "gemini_api_key", "test-key")
        monkeypatch.setattr(server.app, "run_narratives", fake_run)

    def test_generates_only_for_the_named_package(self, client, seeded_scan, monkeypatch):
        seen = {}
        group = client.get(f"/api/scans/{seeded_scan}/packages").json()["packages"][0]
        self._stub_ai(client, monkeypatch, seen, model="gemini-3.5-flash-lite")

        body = client.post(f"/api/scans/{seeded_scan}/narratives", json={
            "package": group["package"], "version": group["installed_version"],
        }).json()

        # 그 묶음에 속한 것만 나간다. 다른 패키지의 CVE 는 섞이지 않는다.
        assert len(seen["cves"]) == group["cve_count"]
        assert body["applied"] == group["cve_count"]
        assert body["package"] == group["package"]
        assert body["model"] == "gemini-3.5-flash-lite"

        # 생성한 서술이 보고서에 실제로 얹혀야 한다.
        report = client.get(f"/api/scans/{seeded_scan}/report", params={
            "format": "json", "package": group["package"],
            "version": group["installed_version"],
        }).json()
        assert report["ai_used"] is True
        assert report["findings"][0]["technical_risk"]["narrative"] == "설명"

    def test_dropping_narratives_returns_to_rule_text(self, client, seeded_scan, monkeypatch):
        keys = TestSelectionScope()._keys(client, seeded_scan)
        self._stub_ai(client, monkeypatch)
        client.post(f"/api/scans/{seeded_scan}/narratives", json={"selection": keys[:1]})

        client.delete(f"/api/scans/{seeded_scan}/narratives")
        report = client.get(f"/api/scans/{seeded_scan}/report?format=json").json()
        assert report["ai_used"] is False


class TestStaticFrontend:
    @pytest.mark.parametrize("path", ["/", "/scan.html", "/report.html", "/settings.html", "/login.html"])
    def test_pages_are_served(self, client, path):
        response = client.get(path)
        assert response.status_code == 200
        assert "SBOMSight" in response.text

    @pytest.mark.parametrize(
        "path",
        ["/js/core/model.js", "/js/core/ui.js", "/js/providers/live-api.js",
         "/js/providers/static-results.js", "/js/providers/index.js",
         "/css/app.css", "/favicon.svg"],
    )
    def test_assets_are_served(self, client, path):
        assert client.get(path).status_code == 200


class TestPackageView:
    """결과 표의 한 줄은 **패키지 하나**다.

    조치는 패키지당 한 번이다 — `openssl` 을 3.0.7로 올리면 CVE 5건이 한 번에
    해소되는데, CVE 단위로 늘어놓으면 같은 패치를 5번 읽게 된다.
    """

    def test_packages_group_by_name_and_installed_version(self, client, seeded_scan):
        body = client.get(f"/api/scans/{seeded_scan}/packages").json()
        assert body["packages"], "패키지가 하나도 안 나오면 표가 빈다"

        first = body["packages"][0]
        # 키는 `이름@설치버전`. 같은 이름이 두 버전으로 깔려 있으면 조치도 따로다.
        assert first["key"] == f"{first['package']}@{first['installed_version']}"
        assert first["cve_count"] >= 1
        assert first["priority_label"]

        total_cves = sum(p["cve_count"] for p in body["packages"])
        findings = client.get(f"/api/scans/{seeded_scan}/summary").json()["total"]
        assert total_cves == findings, "묶었더니 건수가 달라지면 셈이 틀린 것이다"

    def test_package_sort_keys_are_accepted(self, client, seeded_scan):
        for sort in ("priority", "count", "cvss", "epss", "package"):
            body = client.get(
                f"/api/scans/{seeded_scan}/packages", params={"sort": sort, "order": "desc"}
            ).json()
            assert body["total"] >= 1, sort

    def test_package_keys_have_no_cap(self, client, seeded_scan):
        """"전체 선택"은 전체여야 한다. 조용히 자르면 보고서에서 빠진 것을
        나중에야 알게 된다."""
        listed = client.get(f"/api/scans/{seeded_scan}/packages", params={"limit": 500}).json()
        keys = client.get(f"/api/scans/{seeded_scan}/package-keys").json()
        assert keys["total"] == listed["total"]
        assert sorted(keys["keys"]) == sorted(p["key"] for p in listed["packages"])

    def test_package_findings_are_listed_without_building_a_report(self, client, seeded_scan):
        group = client.get(f"/api/scans/{seeded_scan}/packages").json()["packages"][0]
        body = client.get(
            f"/api/scans/{seeded_scan}/package/findings",
            params={"name": group["package"], "version": group["installed_version"]},
        ).json()
        assert body["total"] == group["cve_count"]
        assert {f["intel"]["cve"] for f in body["findings"]}


class TestSelectionByPackage:
    """화면은 패키지를 고르고, 보고서·이그레스는 finding 단위로 돈다."""

    def test_packages_expand_to_their_findings(self, client, seeded_scan):
        listed = client.get(f"/api/scans/{seeded_scan}/packages", params={"limit": 500}).json()
        one = listed["packages"][0]

        put = client.put(f"/api/scans/{seeded_scan}/selection", json={"packages": [one["key"]]})
        assert put.status_code == 200
        assert put.json()["count"] == one["cve_count"]
        assert put.json()["packages"] == [one["key"]]

        # 되살릴 때도 같은 묶음 키가 나와야 화면 체크가 맞는다.
        got = client.get(f"/api/scans/{seeded_scan}/selection").json()
        assert got["packages"] == [one["key"]]

    def test_selection_response_does_not_ship_every_finding_key(self, client, seeded_scan):
        """48,923건짜리 스캔에서 이 한 줄이 응답을 4MB로 불렸다."""
        client.put(f"/api/scans/{seeded_scan}/selection", json={"packages": []})
        body = client.get(f"/api/scans/{seeded_scan}/selection").json()
        assert "keys" not in body
        assert "keys" in client.get(
            f"/api/scans/{seeded_scan}/selection", params={"keys": "true"}
        ).json()

    def test_meta_carries_a_count_not_the_keys(self, client, seeded_scan):
        body = client.get(f"/api/scans/{seeded_scan}/meta").json()
        assert "keys" not in body["selection"]
        assert "count" in body["selection"]

    def test_report_can_read_the_saved_selection(self, client, seeded_scan):
        """고른 키를 주소창에 실으면 5,000건에서 URL 이 250KB 가 되고
        uvicorn 이 `Invalid HTTP request received` 로 끊는다."""
        listed = client.get(f"/api/scans/{seeded_scan}/packages", params={"limit": 500}).json()
        one = listed["packages"][0]
        client.put(f"/api/scans/{seeded_scan}/selection", json={"packages": [one["key"]]})

        body = client.get(
            f"/api/scans/{seeded_scan}/report", params={"format": "json", "saved": "true"}
        ).json()
        assert len(body["findings"]) == one["cve_count"]
        assert {f["local_analysis"]["installed_package"] for f in body["findings"]} == {one["package"]}

    def test_report_of_one_cve_is_one_section(self, client, seeded_scan):
        """근거 팝업이 내려받는 것. 6건짜리 패키지 문서를 받아 한 절만 읽을
        이유가 없다."""
        group = client.get(f"/api/scans/{seeded_scan}/packages").json()["packages"][0]
        findings = client.get(
            f"/api/scans/{seeded_scan}/package/findings",
            params={"name": group["package"], "version": group["installed_version"]},
        ).json()["findings"]
        cve = findings[0]["intel"]["cve"]

        body = client.get(f"/api/scans/{seeded_scan}/report", params={
            "format": "json", "package": group["package"],
            "version": group["installed_version"], "cve": cve,
        }).json()
        assert [f["cve"] for f in body["findings"]] == [cve]


class TestPackageNamesWithSlashes:
    """이름은 **경로가 아니라 쿼리**로 받는다.

    경로에 두면 `github.com/gogo/protobuf`·`@babel/core` 같은 이름이 404 가
    된다 — uvicorn 이 `%2F` 를 실제 슬래시로 되돌려 놓아서 한 세그먼트를
    넘지 못한다. Go 모듈과 npm 스코프 패키지가 전부 여기에 걸렸다.
    """

    def test_a_package_name_with_a_slash_is_reachable(self, client, tmp_path):
        from core.config import get_config

        result = normalize_grype_report(
            json.loads(FIXTURE.read_text()), scan_id="slash-1", sbom_filename="a.json"
        )
        engine = RuleEngine.from_config()
        findings = engine.apply(result.findings)
        # 첫 항목의 설치 패키지 이름만 Go 모듈처럼 바꾼다.
        renamed = dataclasses.replace(
            findings[0],
            installed=dataclasses.replace(findings[0].installed, name="github.com/gogo/protobuf"),
        )
        Store(get_config().db_path).save_scan(ScanResult(
            metadata=result.metadata, findings=(renamed, *findings[1:]), policy={},
        ))

        listed = client.get("/api/scans/slash-1/packages").json()["packages"]
        target = next(p for p in listed if "/" in p["package"])
        assert target["package"] == "github.com/gogo/protobuf"

        detail = client.get("/api/scans/slash-1/package/findings", params={
            "name": target["package"], "version": target["installed_version"],
        })
        assert detail.status_code == 200, detail.text
        assert detail.json()["total"] == target["cve_count"]

        report = client.get("/api/scans/slash-1/report", params={
            "format": "json", "package": target["package"],
            "version": target["installed_version"],
        })
        assert report.status_code == 200, report.text


class TestScanNeedsAnAsset:
    def test_moving_a_scan_needs_a_target(self, client, seeded_scan):
        """자산 없는 상태로 되돌리는 길은 없앴다 — 그것이 곧 미분류다."""
        response = client.put(f"/api/scans/{seeded_scan}/asset", json={"asset_id": ""})
        assert response.status_code == 400


class TestEverySortWorks:
    """`ORDER BY 0` 은 상수가 아니라 **컬럼 번호**로 읽힌다.

    그래서 패키지·CVE 정렬이 `1st ORDER BY term out of range` 로 죽고 있었다.
    화면에서 헤더를 눌러야만 드러나는 종류의 고장이라 여기서 전부 밟는다.
    """

    def test_all_finding_sorts_in_both_directions(self, client, seeded_scan):
        from core.store import Store

        for sort in Store.SORT_KEYS:
            for order in ("asc", "desc"):
                response = client.get(f"/api/scans/{seeded_scan}/findings", params={
                    "sort": sort, "order": order, "limit": 5,
                })
                assert response.status_code == 200, f"{sort} {order}: {response.text}"

    def test_all_package_sorts_in_both_directions(self, client, seeded_scan):
        from core.store import Store

        for sort in Store.PACKAGE_SORT_KEYS:
            for order in ("asc", "desc"):
                response = client.get(f"/api/scans/{seeded_scan}/packages", params={
                    "sort": sort, "order": order, "limit": 5,
                })
                assert response.status_code == 200, f"{sort} {order}: {response.text}"
