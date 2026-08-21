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

### 내부 정보는 나갈 자리가 없다

AI로 나가는 것은 `VulnFact` 하나뿐이며, 조립 함수의 **시그니처**가 1차 방어다:

```python
def build_vuln_fact(advisory: AdvisoryPackage, intel: VulnIntel) -> dict
```

`InstalledPackage`(설치 버전·파일 경로), `FixAnalysis`(취약 여부 판정),
`RuleVerdict`(대응 우선순위), `Detection`(탐지 근거)은 인자로 들어오지도 않는다.
실수로 넣으려면 시그니처를 고쳐야 하고, 그러면 리뷰에서 보인다.

2차 방어는 `policy/egress-policy.json`에 대고 하는 3중 검증이다:

1. **스키마** — 모든 키가 허용 목록에 있는가, 금칙 필드명이 아닌가
2. **값** — 타입·범위·enum·정규식·길이를 통과하는가
3. **금칙 패턴** — IP · 파일 경로 · 이메일 · MAC · UUID · 내부 도메인 · 컨테이너 다이제스트 ·
   한글 · 자격증명 흔적이 없는가

하나라도 걸리면 **전송을 중단한다**(fail-closed). "문제 있는 항목만 빼고 나머지를
보낸다"를 하지 않는 이유는, 무엇이 어떻게 새려 했는지 모르는 상태에서 나머지가
안전하다고 볼 근거가 없기 때문이다.

같은 정책 파일을 브라우저 가드(`web/js/core/sanitizer.js`)도 읽으며, 두 구현은
`policy/egress-test-vectors.json`의 **같은 벡터 74건**으로 채점받는다.
정책 해시가 양쪽에서 일치하는지도 확인한다.

전송 전에 사람이 전문을 볼 수 있다 — 스캔 화면의 **"AI에게 전송될 내용 보기"** 는
실제 전송에 쓰이는 것과 같은 조립기·같은 가드를 통과시킨 결과와 프롬프트 원문을
그대로 보여 준다. 모든 전송 시도(성공·차단 모두)는 payload 원문·SHA-256·정책
해시와 함께 감사 로그에 남는다.

### AI는 설명만 한다

AI 응답을 담는 `Narrative`에는 우선순위를 담을 자리가 **타입 수준에서** 없다.
모델이 등급을 우겨넣어도 병합 단계에서 버려진다. 패치 명령도 AI가 만들지 않는다.

프롬프트 제약만으로는 부족하므로 생성 후 `rules/tone-policy.json`으로 다시 점검한다:

| 걸리는 표현 | 이유 |
|---|---|
| "귀사의 WEB 서버는 매우 위험합니다" | AI는 조직·자산 정보를 받지 않았다 |
| "해당 서버는 반드시 패치해야 합니다" | 최종 조치 여부는 담당자가 판단한다 |
| "이 취약점은 P0 등급에 해당합니다" | 등급은 로컬 룰 엔진의 산출물이다 |
| "`dnf upgrade openssl`을 실행하십시오" | 실행 절차는 플레이북이 결정론적으로 생성한다 |

위반한 서술은 리포트에 싣지 않고 룰 문장으로 되돌린다.

### 데모는 시늉이 아니다

GitHub Pages에는 서버가 없다. 그래서 프론트엔드를 **스캔 제공자로부터 분리**했다
(`web/js/providers/`). 실 운영에서는 로컬 FastAPI가 진짜 Grype 서브프로세스를 돌리고,
데모에서는 브라우저 매칭 엔진이 돈다. 나머지 코드는 어느 쪽인지 알지 못한다.

데모용 취약점 인덱스는 CI에서 **진짜 Syft와 진짜 Grype**로 만든다
(`.github/workflows/build-demo.yml`, 주 1회). 브라우저가 하는 일은 Grype가 하는 것과
같다 — 설치 버전이 advisory의 영향 버전범위에 드는지 생태계 규칙으로 평가한다.

그래서 방문자가 **샘플 SBOM에서 패키지를 지우거나 버전을 바꾸면 결과가 실제로 달라진다.**
취약한 패키지를 지우면 그 항목이 사라지고, 버전을 Fixed Version으로 올리면 영향 범위를
벗어나 탐지되지 않는다.

세 겹의 검증이 이를 뒷받침한다:

| 검증 | 대조 대상 | 건수 |
|---|---|---|
| 버전 비교자 | `tests/fixtures/version-vectors.json` (rpm 공식 스위트 포함) | 152 |
| 파리티 | JavaScript 구현 ↔ Python 구현 (FixAnalysis · 룰엔진 · 프롬프트 · 보고서 6절) | 221 |
| 실제 Grype 대비 | 브라우저 엔진 ↔ 진짜 Grype 스캔 결과 (CI, 불일치 시 배포 중단) | 매 빌드 |

인덱스에 없는 패키지는 **"인덱스 미수록"으로 정직하게 표기**한다. 조용히 "취약점 없음"으로
처리하지 않는다.

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

## 데모

**https://leekiyoon-sec.github.io/SBOMSight/**

샘플 SBOM으로 바로 스캔해 볼 수 있다. 서버 없이 브라우저 안에서 돌지만
**시늉이 아니다** — 인덱스는 CI에서 진짜 Syft/Grype로 만들고, 매칭은 Grype가 하는
것과 같은 판정이다. 패키지를 지우거나 버전을 바꾸면 결과가 실제로 달라진다.

## 현재 상태

| 마일스톤 | 내용 | 상태 |
|---|---|---|
| M1 | 코어 파이프라인 + 데이터 모델 3층 분리 | ✅ |
| M2 | 위협정보 보강 (EPSS · KEV · Exploit) + Rule Engine | ✅ |
| M3 | 리포트 생성 (AI 없이 완결) | ✅ |
| M4 | 웹 서버 + 공용 UI | ✅ |
| M5 | 이그레스 가드 + AI 산문 계층 | ✅ |
| M6 | 브라우저 매칭 엔진 + GitHub Pages 데모 | ✅ |
| M7 | 마감 (문서 · 패키징) | ✅ |

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

# 7. AI 서술 사용 (선택). 기본값은 미사용이며, AI 없이도 보고서는 완결된다.
export SBOMSIGHT_AI_ENABLED=1 GEMINI_API_KEY=...
python3 -m core.cli report findings.json --ai -o report.md

# 8. 웹 UI
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
scripts/test.sh          # Python + JavaScript + 파리티
```

이그레스 가드와 매칭 엔진은 두 언어로 구현되어 있고 같은 정책·같은 벡터로
채점받는다. 한쪽만 돌리면 두 구현이 갈라진 것을 잡지 못한다.

파리티 기대값은 **실제 Python 구현을 돌려** 생성한다 — 손으로 적은 기대값이라면
두 구현이 함께 틀린 것을 잡지 못한다.

```bash
python3 scripts/gen_parity_fixture.py   # 구현을 바꿨다면 다시 생성
```

### 데모 로컬 실행

```bash
scripts/install-tools.sh
grype db update
python3 scripts/build_demo_index.py --out demo-data   # 진짜 Syft + Grype
python3 scripts/build_pages.py --out dist
python3 -m http.server -d dist 8080
```

`demo-data/` 는 커밋하지 않는다. 수 MB가 주 단위로 바뀌어 리포가 부풀고,
커밋본과 배포본이 갈라지면 어느 쪽이 진짜인지 알 수 없게 되기 때문이다.

rpm 버전 비교는 rpm 프로젝트의 `rpmvercmp` 테스트 스위트 벡터로 검증한다
(`tests/test_versioning.py`). 이 비교가 틀리면 FixAnalysis가 틀리고, 그것은 곧
패치 누락이나 헛된 패치 작업이 된다.

## 문서

| 문서 | 내용 |
|---|---|
| [`docs/offline-operations.md`](docs/offline-operations.md) | 폐쇄망 패치 절차 · 오프라인 DB/스냅샷 반입 · 환경변수 |
| `/about.html` (웹 UI) | 데이터 흐름 · 3층 모델 · AI 전송 범위 · 적용 정책 전문 · 데모 동작 원리 |
| [`.env.example`](.env.example) | 설정 전체와 각 값의 의미 |

## 프로젝트 구조

```
core/          파이프라인 — 모델 · 러너 · 정규화 · 비교자 · 보강 · 룰엔진 · 보고서
               이그레스(vulnfact · sanitizer · audit) · AI(prompt · gemini · tone)
server/        FastAPI — 업로드 · 비동기 스캔 job · 결과 · 보고서 · 이그레스 미리보기
web/           프론트엔드 (빌드 없음). 실 운영과 Pages 데모가 같은 코드를 쓴다
  js/core/     JS 동형 구현 — 비교자 · 매처 · 룰엔진 · 이그레스 가드 · 보고서 · 렌더
  js/providers/ live-api(진짜 Grype) ↔ browser-engine(브라우저 매칭)
policy/        이그레스 정책과 공용 테스트 벡터 — Python·JS가 같은 파일을 읽는다
rules/         우선순위 정책 · 표현 정책 · 패치 플레이북 6종
scripts/       도구 설치 · 서버 기동 · 데모 인덱스 생성 · Pages 조립 · 테스트
tests/         pytest + tests/js/*.mjs (이그레스 적합성 · 파리티 · AI 가드)
```

### 정책 파일이 단일 진실인 이유

`policy/egress-policy.json`, `rules/priority.json`, `rules/tone-policy.json`,
`rules/playbooks/*.json` 은 Python 구현과 브라우저 구현이 **같은 파일**을 읽는다.
사본을 두면 두 벌이 갈라지고, 그러면 데모가 보여 주는 판정이 실 운영과 달라진다.
그래서 서버는 `policy/`·`rules/` 원본을 그대로 노출하고, Pages 빌드는 복사만 한다.

이 대조가 실제로 버그를 잡았다 — 이그레스 정책의 `(?i)` 인라인 플래그는 Python은
컴파일하지만 JavaScript는 못 한다. 공용 벡터를 두 언어로 돌리지 않았다면
데모에서만 조용히 통과했을 것이다.

## 라이선스

MIT
