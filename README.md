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

### KEV와 Exploit은 별개 신호

| 신호 | 의미 | 출처 |
|---|---|---|
| `kev` | CISA가 **실제 악용을 확인**해 등재 | CISA KEV 카탈로그 |
| `exploit_available` | **공개된 exploit/PoC 코드가 존재** | Exploit-DB, Metasploit |

KEV 등재인데 공개 exploit이 없을 수 있고, 공개 PoC가 있는데 KEV에는 없을 수도
있다. 두 신호는 Rule Engine에서 독립 조건으로 평가한다. 모든 exploit 판정에는
`exploit_sources`로 출처가 따라붙으며, 출처를 댈 수 없으면 `false`가 아니라
`unknown`이다.

### 판단할 수 없으면 `unknown`

비표준 버전 문자열을 만났을 때 "취약하지 않음"이라고 답하는 것은 거짓말이고,
그 거짓말은 패치 누락으로 이어진다. 비교 불가는 `unknown`으로 남기고 사유를
리포트에 적는다. 같은 이유로 EPSS를 못 받아왔을 때 0.0으로 채우지 않고,
KEV 조회에 실패했을 때 "등재 안 됨"으로 처리하지 않는다.

### 대응 검토 우선순위는 조직이 정한다

`rules/priority.json`은 **기본 정책**이다. `config/priority.local.json`으로
임계값을 덮어쓸 수 있고(gitignore 대상), 리포트에는 적용된 정책의 버전과
sha256이 기록되어 "어떤 기준으로 판정했는지"를 사후에 추적할 수 있다.

```
P0  ←  발화 룰: CISA KEV 등재, EPSS 높음 (0.9134 ≥ 0.5), CVSS High 이상 (10 ≥ 7)
       적용 정책: priority.json v1 (sha256:4e70371ff604)
```

명칭은 "위험도"가 아니라 **"대응 검토 우선순위"** 다. 최종적인 내부 위험도와
패치 여부는 보안담당자가 판단한다.

## 현재 상태

| 마일스톤 | 내용 | 상태 |
|---|---|---|
| M1 | 코어 파이프라인 + 데이터 모델 3층 분리 | ✅ |
| M2 | 위협정보 보강 (EPSS · KEV · Exploit) + Rule Engine | ✅ |
| M3 | 리포트 생성 (AI 없이 완결) | ✅ |
| M4 | 웹 서버 + 공용 UI | ✅ |
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

# 4. 스캔 (Grype 탐지 → 위협정보 보강 → 우선순위 판정)
python3 -m core.cli scan sbom.cdx.json -o findings.json

# 이미 Grype 산출물이 있다면
python3 -m core.cli analyze grype-report.json -o findings.json

# 네트워크 없이 캐시된 스냅샷만 사용
python3 -m core.cli scan sbom.cdx.json --offline

# 5. 보고서 생성 — AI 없이도 완결된다
python3 -m core.cli report findings.json -o report.md
python3 -m core.cli report findings.json --format html -o report.html

# 6. 저장된 스캔 목록
python3 -m core.cli scans

# 7. 웹 UI
scripts/run-server.sh          # Linux / macOS  → http://127.0.0.1:8000
scripts/run-server.ps1         # Windows 11
```

### 웹 UI

업로드부터 보고서까지의 파이프라인을 7단계 스테퍼로 그대로 보여준다.
"취약점 몇 개 발견"이 아니라 **근거가 쌓여가는 과정**이 보이는 것이 목적이다.

```
SBOM 업로드 → 취약점 탐지 → 위협정보 보강 → 대응 우선순위 → 대응 검토 근거 → 권고사항 → 보고서
 컴포넌트 1,204개   87건 탐지    4/5개 소스     P0 3 · P1 12    12건에 발화 룰   패치 가능 71건   87개 항목
```

| 페이지 | 내용 |
|---|---|
| `/` | 개요 · 설계 원칙 · 최근 스캔 |
| `/scan.html` | 업로드 · 7단계 진행 · 결과 표(우선순위/생태계/상태 필터) · CVE 상세 드로어 |
| `/report.html` | 보고서 뷰어 · 목차 · 인쇄(PDF) · Markdown/HTML 내려받기 |
| `/about.html` | 데이터 흐름 · 3층 모델 · AI 전송 범위 · 적용 정책 전문 · 폐쇄망 운영 |

프론트엔드는 **스캔 제공자로부터 분리**되어 있다(`web/js/providers/`). 실 운영에서는
로컬 FastAPI를 호출해 진짜 Grype를 돌리고, GitHub Pages 데모에서는 브라우저 매칭
엔진을 쓴다(M6). 나머지 코드는 어느 쪽인지 알지 못한다.

기본 바인딩은 `127.0.0.1`이다. 업로드된 SBOM과 스캔 결과에는 내부 자산 정보가
담기므로, 외부 노출은 `SBOMSIGHT_HOST`를 명시적으로 바꿔야만 일어난다.

### 보고서 구성

CVE 단위로 6개 절 + 로컬 전용 영역:

| 절 | 내용 | 출처 |
|---|---|---|
| ① 취약점 개요 | CVE · 취약 제품 · 취약 버전 · Fixed Version · CWE · CVSS | 공개 |
| ② 기술적 위험성 | 공격 조건 · 영향 유형 (CVSS 벡터·CWE 해석) | 룰 + (선택) AI |
| ③ 악용 가능성 | EPSS · KEV · 공개 Exploit **(출처 포함)** | 공개 |
| ④ 대응 필요성 분석 | 종합 근거 · 권고 우선순위 **+ 발화 룰** | 우선순위=룰, 서술=AI |
| ⑤ 권고사항 | Fixed Version · 온라인/폐쇄망 패치 절차 · 임시 완화 | Playbook(룰) |
| ⑥ 근거 및 Reference | NVD · CISA KEV · Vendor Advisory · FIRST EPSS · exploit 출처 | 공개 |
| **[로컬 분석 정보]** | 설치 버전 · FixAnalysis · Grype 탐지 근거 | **AI 미전달** |

모든 CVE 항목에 근거 배지가 고정 노출된다:

```
CVSS         : 10 / Critical (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
EPSS         : 0.9134 · 백분위 0.9991 · 기준일 2026-08-18
CISA KEV     : YES (등재 2024-03-29)
공개 Exploit : YES (무기화 · Exploit-DB EDB-52128, Metasploit exploit/linux/local/xz)
Fixed Version: 5.6.2
판정          : P0 즉시 대응 검토 ← kev_listed
적용 정책     : priority.json v1 (sha256:4e70371ff604)
```

### 패치 절차는 AI가 아니라 룰이 만든다

`rules/playbooks/*.json`이 생태계별 절차를 결정론적으로 생성한다. 이유는 두 가지다:
AI가 없거나 꺼져 있어도 실행 가능한 권고가 항상 나와야 하고, 운영 서버에 입력될
명령어를 생성 모델에 맡기면 환각의 대가가 너무 크다. AI는 절차를 만들지 않고
**왜 이 조치가 필요한지를 설명**할 뿐이다.

폐쇄망 절차(RPM 예시)는 실제 운영 방식을 그대로 담았다 —
`dnf download --resolve --alldeps` → 매체 반입 → `rpm -K` 서명 검증 →
`dnf localinstall` 또는 `createrepo_c` 로컬 저장소 구성 → `rpm -q` 및 Grype 재스캔.

### 위협정보 소스

| 소스 | 용도 | 오프라인 |
|---|---|---|
| Grype 출력 내장 | CVSS · severity · fix state · 참조 URL | 가능 |
| FIRST EPSS | 악용 시도 확률 · 백분위 | 캐시 |
| CISA KEV | 실제 악용 확인 여부 · 등재일 | 캐시 |
| Exploit-DB | 공개 exploit/PoC 존재 (`public_poc`) | 캐시 |
| Metasploit | 무기화된 모듈 존재 (`weaponized`) | 캐시 |
| NVD (선택) | CWE · 공개일 | 캐시 |

모든 소스는 스냅샷 기준일과 함께 캐시된다. 기준일이 오래되면 판정에
`stale_snapshot` 플래그가 붙는다.

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
