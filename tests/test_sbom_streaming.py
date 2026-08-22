"""대용량 SBOM 훑기 — 형식·개수·해시를 파일을 통째로 올리지 않고 얻는다.

이 파일이 존재하는 이유는 실제로 겪은 고장 때문이다. Rocky 9 서버 한 대의
SBOM이 100MB였고, `json.load()` 는 입력의 6배 남짓한 메모리를 쓴다. 1GB면 6GB,
10GB면 62GB — PC에서는 불가능하다.

그럴 이유도 없었다. 우리가 SBOM에서 쓰는 것은 형식과 컴포넌트 수 두 개뿐이고
취약점 매칭은 Grype가 파일을 직접 읽어 한다.

여기서 지키는 것 세 가지:
  1. 청크 크기와 무관하게 **정확히** 센다 (경계에 걸쳐도)
  2. 셀 수 없으면 0이 아니라 **미상(None)** 이다 — 0은 "없다"는 거짓말이다
  3. 파일 크기와 무관하게 메모리가 **일정**하다
"""

import gzip
import json
import tracemalloc

import pytest

from core.sbom import SbomInfo, StreamingInspector, inspect

CHUNKS = (3, 17, 997, 65536, 1 << 20)


def cyclonedx(n, *, bom_ref=True):
    components = []
    for i in range(n):
        comp = {"type": "library", "name": f"p{i}", "version": f"1.{i}.0"}
        if bom_ref:
            comp["bom-ref"] = f"ref-{i}"
        components.append(comp)
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "metadata": {"component": {"bom-ref": "root", "type": "file", "name": "/"}},
        "components": components,
        # 참조 배열은 세면 안 된다 — 컴포넌트가 아니다.
        "dependencies": [{"ref": f"ref-{i}", "dependsOn": []} for i in range(n)],
    }


def spdx(n):
    return {
        "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "x",
        "packages": [{"SPDXID": f"SPDXRef-{i}", "name": f"p{i}"} for i in range(n)],
        "relationships": [{"spdxElementId": "a", "relatedSpdxElement": "b"} for _ in range(n)],
    }


def syft(n):
    return {
        "artifacts": [{"id": f"{i:016x}", "name": f"p{i}", "foundBy": "rpm-db-cataloger"}
                      for i in range(n)],
        "artifactRelationships": [{"parent": "a", "child": "b"} for _ in range(n)],
        "descriptor": {"name": "syft", "version": "1.50.0"},
    }


def run(doc, chunk):
    raw = doc if isinstance(doc, bytes) else json.dumps(doc).encode()
    inspector = StreamingInspector()
    for offset in range(0, len(raw), chunk):
        inspector.feed(raw[offset : offset + chunk])
    return inspector.finish()


class TestFormatDetection:
    @pytest.mark.parametrize("chunk", CHUNKS)
    @pytest.mark.parametrize(
        "maker,expected",
        [(cyclonedx, "cyclonedx-json"), (spdx, "spdx-json"), (syft, "syft-json")],
        ids=["cyclonedx", "spdx", "syft"],
    )
    def test_detects_format(self, maker, expected, chunk):
        assert run(maker(20), chunk).format == expected

    def test_unknown_format_is_labelled_not_guessed(self):
        info = run({"hello": "world"}, 64)
        assert info.format == "unknown"
        assert info.component_count is None
        assert info.count_label == "미상"


class TestExactCount:
    @pytest.mark.parametrize("chunk", CHUNKS)
    @pytest.mark.parametrize(
        "maker", [cyclonedx, spdx, syft], ids=["cyclonedx", "spdx", "syft"]
    )
    def test_counts_exactly_at_any_chunk_size(self, maker, chunk):
        """청크 경계가 어디에 떨어져도 같은 숫자가 나와야 한다."""
        assert run(maker(300), chunk).component_count == 300

    def test_cyclonedx_without_bom_ref(self):
        """`bom-ref` 가 없는 CycloneDX 도 있다.

        표지 문자열을 세는 방식이었다면 여기서 0개가 나왔다. 실제로 그렇게
        구현했다가 이 경우에 걸려 정확한 배열 계수로 바꿨다.
        """
        assert run(cyclonedx(300, bom_ref=False), 1024).component_count == 300

    def test_does_not_count_reference_arrays(self):
        """dependencies · relationships 는 컴포넌트가 아니다."""
        assert run(cyclonedx(50), 512).component_count == 50
        assert run(spdx(50), 512).component_count == 50
        assert run(syft(50), 512).component_count == 50

    def test_empty_component_array(self):
        assert run({"bomFormat": "CycloneDX", "components": []}, 64).component_count == 0

    @pytest.mark.parametrize("chunk", (3, 17, 1024))
    def test_structural_characters_inside_strings(self, chunk):
        """설명이나 라이선스 본문에 중괄호가 들어 있어도 깊이가 틀어지면 안 된다."""
        doc = {"bomFormat": "CycloneDX", "components": [
            {"name": "a", "description": '중괄호 { } 대괄호 [ ] 이스케이프 \\" 포함'},
            {"name": "b", "description": '}}}]]]{{{'},
            {"name": "c", "description": r'역슬래시로 끝남 \\'},
        ]}
        assert run(doc, chunk).component_count == 3

    def test_counts_large_documents_without_giving_up(self):
        """크다고 세기를 포기하지 않는다.

        한때 예산 제한을 두어 큰 파일에서 "미상"을 냈지만 걷어냈다. 이 도구는
        운영용이고 화면에 뜨는 숫자는 전부 정확해야 한다. 시간이 더 걸리는 것은
        감수할 수 있어도 불확실한 숫자를 남기는 것은 감수 대상이 아니다.
        """
        assert run(cyclonedx(20_000), 1 << 20).component_count == 20_000


class TestDigestAndSize:
    @pytest.mark.parametrize("chunk", CHUNKS)
    def test_sha256_matches_regardless_of_chunking(self, chunk):
        import hashlib

        raw = json.dumps(cyclonedx(100)).encode()
        assert run(cyclonedx(100), chunk).sha256 == hashlib.sha256(raw).hexdigest()

    def test_size_is_the_uncompressed_length(self):
        raw = json.dumps(cyclonedx(100)).encode()
        assert run(cyclonedx(100), 4096).size == len(raw)


class TestFileInspect:
    def test_reads_plain_file(self, tmp_path):
        path = tmp_path / "sbom.json"
        path.write_bytes(json.dumps(cyclonedx(120)).encode())
        info = inspect(path)
        assert (info.format, info.component_count) == ("cyclonedx-json", 120)

    def test_reads_gzip_file_with_same_result(self, tmp_path):
        """압축 저장본과 원본이 같은 결과를 내야 한다 — 해시는 압축 해제본 기준."""
        raw = json.dumps(cyclonedx(120)).encode()
        plain, packed = tmp_path / "a.json", tmp_path / "b.json.gz"
        plain.write_bytes(raw)
        packed.write_bytes(gzip.compress(raw))
        assert inspect(plain) == inspect(packed)


def cyclonedx_chunks(n, per_chunk=200):
    """CycloneDX 문서를 조각으로 흘려보낸다.

    문서 전체를 한 번도 메모리에 만들지 않는다 — 그래야 메모리 측정이
    검사 대상(StreamingInspector)만 재게 된다.
    """
    yield b'{"bomFormat":"CycloneDX","specVersion":"1.5","components":['
    buffer: list[bytes] = []
    for i in range(n):
        item = json.dumps(
            {"type": "library", "name": f"package-{i}", "version": f"1.{i}.0",
             "purl": f"pkg:rpm/rocky/package-{i}@1.{i}.0"}
        ).encode()
        buffer.append(item if i == 0 else b"," + item)
        if len(buffer) >= per_chunk:
            yield b"".join(buffer)
            buffer.clear()
    if buffer:
        yield b"".join(buffer)
    yield b"]}"


class TestMemory:
    def test_memory_stays_flat_as_input_grows(self):
        """입력을 8배로 늘려도 피크 메모리가 그만큼 늘면 안 된다.

        이것이 이 모듈의 존재 이유다. `json.load()` 는 입력에 비례해 늘어난다
        (실측 6.2배). 스트리밍은 청크 하나에 머물러야 한다.
        """
        peaks, sizes = [], []
        for count in (2_000, 16_000):
            tracemalloc.start()
            inspector = StreamingInspector()
            for chunk in cyclonedx_chunks(count):
                inspector.feed(chunk)
            info = inspector.finish()
            peaks.append(tracemalloc.get_traced_memory()[1])
            tracemalloc.stop()
            sizes.append(info.size)
            assert info.component_count == count

        grew_input = sizes[1] / sizes[0]
        grew_memory = peaks[1] / peaks[0]
        assert grew_input > 7, "입력이 충분히 커지지 않아 이 테스트는 의미가 없다"
        assert grew_memory < 2, (
            f"입력이 {grew_input:.1f}배인데 메모리가 {grew_memory:.1f}배 늘었다 — "
            f"파일 크기에 비례하고 있다"
        )


class TestSbomInfo:
    def test_count_label_reads_naturally(self):
        assert SbomInfo("cyclonedx-json", 1204, "x", 1).count_label == "1,204개"
        assert SbomInfo("unknown", None, "x", 1).count_label == "미상"
