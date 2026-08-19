# SBOMSight

**SBOM 기반 취약점 대응 검토 · 근거 정리 플랫폼**

실제 자산에서 생성한 SBOM을 받아 취약점을 식별하고, 공개된 위협정보
(CVSS · EPSS · CISA KEV · 공개 Exploit)를 결합해 **대응 우선순위와 조치 근거**를
산출한다. 선택적으로 AI를 붙여 사람이 검토하기 쉬운 문장을 덧붙인다.

> AI가 판단을 대신하는 시스템이 아니라,
> **객관적인 취약점 데이터를 기반으로 사람이 대응 여부를 판단할 수 있도록
> 근거를 정리해주는 시스템**이다.

SBOM Viewer도, Grype Web UI도, 패치 작업 자동화 도구도 아니다.

## SBOMSight가 답하는 질문

1. 우리 SBOM에서 어떤 취약점이 발견되었는가
2. 어떤 제품 / 버전의 문제인가
3. CVSS · EPSS · KEV · Exploit 관점에서 얼마나 주의해야 하는가
4. 왜 우선 대응을 검토해야 하는가
5. Fixed Version은 무엇인가
6. 어떤 대응을 권고하는가
7. 그 판단의 객관적 근거는 무엇인가
8. 담당자가 검토 · 결재할 수 있는 보고서로 만들 수 있는가

## 설계 원칙

### 판정은 룰이, 설명은 AI가

| 결정론적 · 전부 로컬 | AI |
|---|---|
| Grype 탐지 결과 | 기술적 위험성 서술 |
| CVSS / EPSS / KEV / Exploit | 공격 시나리오 설명 |
| 설치 버전 ↔ Fixed Version 비교 | 대응 필요성 근거 서술 |
| 대응 검토 우선순위 (P0~P3) + 발화 룰 | 권고사항 부연 |

AI는 우선순위를 산출하지도, 입력으로 받지도 않는다.

### 데이터 모델을 3층으로 분리

내부 자산 정보와 공개 advisory 정보가 같은 객체에 섞이면 유출은 시간
문제다. 그래서 계층을 타입으로 갈라 두었다 (`core/models.py`).

| 계층 | 내용 | 외부 전송 |
|---|---|---|
| `InstalledPackage` | 자산에 실제 설치된 패키지 · 버전 · 파일 경로 | **불가** |
| `Detection` | Grype가 어떻게 탐지했는가 | **불가** |
| `AdvisoryPackage` | 공개 advisory가 지목한 식별자 · 영향 버전범위 · Fixed Version | 가능 |
| `VulnIntel` | CVE · CVSS · EPSS · KEV · Exploit | 가능 |
| `FixAnalysis` | 설치 버전 ↔ Fixed Version 비교 판정 | **불가** |
| `RuleVerdict` | 대응 검토 우선순위 · 발화 룰 | **불가** |

외부로 나가는 것은 `VulnFact` 하나뿐이며, 이는 공개 계층에서만 조립된다.

### 판단할 수 없으면 `unknown`

비표준 버전 문자열을 만났을 때 "취약하지 않음"이라고 답하는 것은 거짓말이고,
그 거짓말은 패치 누락으로 이어진다. 비교 불가는 `unknown`으로 남기고 사유를
리포트에 적는다.

## 현재 상태

| 마일스톤 | 내용 | 상태 |
|---|---|---|
| M1 | 코어 파이프라인 + 데이터 모델 3층 분리 | ✅ |
| M2 | 위협정보 보강 (EPSS · KEV · Exploit) + Rule Engine | 진행 예정 |
| M3 | 리포트 생성 (AI 없이 완결) | 진행 예정 |
| M4 | 웹 서버 + 공용 UI | 진행 예정 |
| M5 | 이그레스 가드 + AI 산문 계층 | 진행 예정 |
| M6 | 브라우저 매칭 엔진 + GitHub Pages 데모 | 진행 예정 |
| M7 | 마감 (문서 · 패키징) | 진행 예정 |

## 사용법

```bash
# 1. 외부 도구 설치
scripts/install-tools.sh          # Linux / macOS
scripts/install-tools.ps1         # Windows 11

# 2. 의존성
python3 -m pip install -r requirements.txt

# 3. SBOM 생성 (폐쇄망에서는 담당자가 직접 syft를 돌려 JSON을 반출)
python3 -m core.cli sbom rockylinux:9.3 -o sbom.cdx.json

# 4. 스캔
python3 -m core.cli scan sbom.cdx.json -o findings.json

# 5. 저장된 스캔 목록
python3 -m core.cli scans
```

## 개발

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest
```

rpm 버전 비교는 rpm 프로젝트의 `rpmvercmp` 테스트 스위트 벡터로 검증한다
(`tests/test_versioning.py`). 이 비교가 틀리면 FixAnalysis가 틀리고, 그것은 곧
패치 누락이나 헛된 패치 작업이 된다.

## 라이선스

MIT
