# SBOMSight

**SBOM 기반 취약점 대응 검토 · 근거 정리 플랫폼**

실제 자산에서 생성한 SBOM을 받아 취약점을 식별하고, 공개된 위협정보
(CVSS · EPSS · CISA KEV · 공개 Exploit)를 결합해 **대응 우선순위와 조치 근거**를
산출한다. 선택적으로 AI를 붙여 사람이 검토하기 쉬운 문장을 덧붙인다.

> AI가 판단을 대신하는 시스템이 아니라,
> **객관적인 취약점 데이터를 기반으로 사람이 대응 여부를 판단할 수 있도록
> 근거를 정리해주는 시스템**이다.

SBOM Viewer도, Grype Web UI도, 패치 작업 자동화 도구도 아니다.

```
sbom.json 업로드  →  진짜 Grype 스캔  →  결과 표에서 취약점 체크
                 →  AI에 보낼 내용 확인  →  전송  →  대응 검토 보고서
```

담당자 PC(Windows 11 / Rocky Linux 10)에서 돌고, 그 결과를
[GitHub Pages](https://leekiyoon-sec.github.io/SBOMSight/)에 **전시**한다.

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

정책은 `policy/egress-policy.json` 한 벌이고, `policy/egress-test-vectors.json`의
**벡터 35건**으로 채점받는다.

### 무엇을 보낼지 사람이 고른다

전송 대상은 **결과 표에서 체크한 항목뿐**이다. 체크하지 않은 취약점은 조립
단계에 들어가지도 않는다.

```
결과 표에서 체크  →  "AI에 전송될 내용 보기"  →  사람이 확인  →  전송  →  보고서
                     선택분만 조립·검증된
                     VulnFact + 프롬프트 원문
```

미리보기와 실제 전송은 **같은 함수를 거친다**(`server/app.py`의 `_scoped()`).
확인한 범위와 나가는 범위가 갈라질 수 없다. 모든 전송 시도(성공·차단 모두)는
payload 원문·SHA-256·정책 해시와 함께 감사 로그에 남는다.

API 키는 **서버 프로세스의 환경변수에만** 있다. 브라우저로 내려가지 않고,
방문자에게 입력받지도 않으며, 호출은 전부 서버에서 나간다.

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

### 판정 구현은 한 벌뿐이다

한때 GitHub Pages에서도 "실제로 스캔되는" 데모를 만들려고 Grype의 매칭을
JavaScript로 다시 구현했었다. CI 파리티 게이트가 **92건의 불일치**를 잡아냈고,
원인은 근본적이었다 — 데모 인덱스의 샤드 키에 배포판 성분이 없어 Debian 13
advisory와 Debian 11 advisory가 같은 샤드에 섞였고, 브라우저 매처는 네임스페이스를
보지 않고 버전 제약만 평가했다. 그 결과 `node:18-bullseye`의 `libblkid1@2.36.1-8+deb11u2`에
Debian 13용 CVE가 붙었다.

배포판 네임스페이스·CPE 매칭·상위 소스패키지 해석까지 Grype를 브라우저에서
재현하는 것은 이길 수 없는 싸움이고, 두 번째 구현은 반드시 갈라진다. 갈라진 쪽은
**조용히 틀린 판정을 낸다** — 취약점 도구에서 가장 나쁜 실패다.

그래서 브라우저 매칭 엔진을 걷어냈다. 지금 `web/js/` 에 남은 것은 표시 라벨
(`model.js`)과 DOM 렌더(`ui.js`)뿐이며, **프론트엔드는 아무것도 판정하지 않는다.**

### GitHub Pages는 전시장이다

Pages는 정적 호스팅이라 Grype(Go 바이너리 + 취약점 DB)를 돌릴 수 없고, 시크릿을
읽을 수도 없다. 그래서 **판정은 담당자 PC에서 일어나고**, Pages는 그 결과를 전시한다.

```bash
# 담당자 PC (Windows 11 / Rocky Linux 10)
python -m core.cli export --out results   # 실제 스캔·선택·전송 기록·보고서를 내보냄
git add results && git commit && git push # pages.yml 이 프론트엔드와 묶어 배포
```

전시되는 것은 그때 실제로 일어난 일의 기록이다 — 탐지 결과, 담당자가 고른 항목,
AI에 전송된 내용, 그 결과로 나온 보고서. 전시 모드에서는 업로드 카드가 사라지고,
체크박스는 기록된 선택을 보여 주되 비활성이며, 전송 버튼 대신 "이미 전송된 기록"이
표시된다.

> `export`는 기본으로 파일 경로·SBOM 파일명·스캔 대상 문자열·Grype `search_criteria`를
> 지운다. 설치 패키지명과 설치 버전은 "설치 버전 대 Fixed Version 비교"라는 전시의
> 요점이라 남긴다. 무엇이 담겼는지는 실행 시 화면에 알린다 — **공개 리포에 커밋할
> 파일이므로 그 판단은 사람이 해야 한다.**

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

## 설치와 사용

### 1. 도구와 의존성

```powershell
# Windows 11
scripts\install-tools.ps1
python -m pip install -r requirements.txt
grype db update
```

```bash
# Rocky Linux 10 / macOS
scripts/install-tools.sh
python3 -m pip install -r requirements.txt
grype db update
```

### 2. 웹 UI로 쓰기 (기본 사용법)

```powershell
scripts\run-server.ps1      # Windows 11  → http://127.0.0.1:8000
```
```bash
scripts/run-server.sh       # Linux / macOS
```

```
SBOM 업로드 → 진짜 Grype 스캔 → 결과 표에서 취약점 체크
           → "AI에 전송될 내용 보기" → 확인 → 전송 → 보고서
```

| 페이지 | 내용 |
|---|---|
| `/` | 개요 · 설계 원칙 · 최근 스캔 |
| `/scan.html` | 업로드 · 진행 스테퍼 · 결과 표(체크박스 · 우선순위/생태계/상태 필터) · CVE 상세 · 이그레스 미리보기 |
| `/report.html` | 보고서 뷰어 · 목차 · 인쇄(PDF) · Markdown/HTML 내려받기 |
| `/about.html` | 데이터 흐름 · 3층 모델 · AI 전송 범위 · 적용 정책 전문 · 폐쇄망 운영 |

기본 바인딩은 `127.0.0.1`이다. 업로드된 SBOM과 스캔 결과에는 내부 자산 정보가
담기므로, 외부 노출은 `SBOMSIGHT_HOST`를 명시적으로 바꿔야만 일어나고 그때 경고가 뜬다.

AI를 쓰려면 `.env` 에 두 줄을 넣고 서버를 다시 시작한다. **키는 서버에만 있고
브라우저로 내려가지 않는다.**

```
SBOMSIGHT_AI_ENABLED=1
GEMINI_API_KEY=...            # https://aistudio.google.com/apikey
```

### 3. CLI로 쓰기

웹 서버 없이도 전체 파이프라인이 돈다.

```bash
# SBOM 생성 (폐쇄망에서는 담당자가 직접 syft를 돌려 JSON을 반출)
python3 -m core.cli sbom rockylinux:9.3 -o sbom.cdx.json

# 스캔 (Grype 탐지 → 위협정보 보강 → 우선순위 판정)
python3 -m core.cli scan sbom.cdx.json -o findings.json
python3 -m core.cli analyze grype-report.json -o findings.json   # 이미 Grype 산출물이 있다면
python3 -m core.cli scan sbom.cdx.json --offline                 # 캐시된 스냅샷만 사용

# 보고서 — AI 없이도 완결된다
python3 -m core.cli report findings.json -o report.md
python3 -m core.cli report findings.json --format html -o report.html
python3 -m core.cli report findings.json --ai -o report.md       # AI 서술 사용 (선택)

python3 -m core.cli scans                                        # 저장된 스캔 목록
```

### 4. 결과를 GitHub Pages에 전시하기

```bash
python3 -m core.cli export --out results        # 최근 5건
python3 -m core.cli export --out results --scan <scan_id>
python3 -m core.cli export --out results --no-redact   # 경로까지 그대로 (권장하지 않음)
```

`results/` 를 커밋해 `main` 에 밀면 `.github/workflows/pages.yml` 이 프론트엔드와
묶어 배포한다. 로컬에서 먼저 확인하려면:

```bash
python3 scripts/build_pages.py --out dist
python3 -m http.server -d dist 8080
```

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
scripts/test.sh
```

판정 로직은 Python 한 벌뿐이다. 브라우저에는 매칭 엔진도, 룰 엔진도, 이그레스
가드도 두지 않는다 — 두 벌을 두면 반드시 갈라지고, 갈라진 쪽이 틀린 판정을 낸다.

rpm 버전 비교는 rpm 프로젝트의 `rpmvercmp` 테스트 스위트 벡터로 검증한다
(`tests/test_versioning.py`). 이 비교가 틀리면 FixAnalysis가 틀리고, 그것은 곧
패치 누락이나 헛된 패치 작업이 된다.

| 테스트 | 무엇을 지키는가 |
|---|---|
| `test_versioning.py` | rpm EVR · dpkg · semver · PEP 440 비교가 상류와 같은 답을 내는가 |
| `test_egress.py` | 정책 벡터 35건 — 무엇이 나갈 수 있고 무엇이 차단되는가 |
| `test_selection.py` | 고른 것만 조립되는가, 선택 키가 VulnFact로 새지 않는가 |
| `test_export.py` | 전시물에 무엇이 담기고 무엇이 지워지는가 |
| `test_server.py` | API 계약 · 선택 범위 · AI 경로(키 없으면 호출 없음) |

## 문서

| 문서 | 내용 |
|---|---|
| [`docs/offline-operations.md`](docs/offline-operations.md) | 폐쇄망 패치 절차 · 오프라인 DB/스냅샷 반입 · 환경변수 |
| `/about.html` (웹 UI) | 데이터 흐름 · 3층 모델 · AI 전송 범위 · 적용 정책 전문 |
| [`.env.example`](.env.example) | 설정 전체와 각 값의 의미 |

## 프로젝트 구조

```
core/          파이프라인 — 모델 · 러너 · 정규화 · 비교자 · 보강 · 룰엔진 · 보고서
               선택(selection) · 이그레스(vulnfact · sanitizer · audit)
               AI(prompt · gemini · tone · ai_narrative) · 전시물 내보내기(export)
server/        FastAPI — 업로드 · 비동기 스캔 job · 결과 · 선택 · 보고서
               이그레스 미리보기 · AI 서술 생성
web/           프론트엔드 (빌드 없음). 판정하지 않고 그리기만 한다
  js/core/     model.js(표시 라벨) · ui.js(DOM 렌더)
  js/providers/ live-api(로컬 서버) ↔ static-results(Pages 전시)
policy/        이그레스 정책과 테스트 벡터
rules/         우선순위 정책 · 표현 정책 · 패치 플레이북 6종
results/       실 PC에서 내보낸 전시물 (커밋 대상 — 내용 확인 후 커밋할 것)
scripts/       도구 설치 · 서버 기동 · Pages 조립 · 테스트
tests/         pytest
```

### 정책 파일이 단일 진실인 이유

`policy/egress-policy.json`, `rules/priority.json`, `rules/tone-policy.json`,
`rules/playbooks/*.json` 은 리포에 커밋된 한 벌이고, 서버는 이 원본을 그대로
노출한다. 사본을 두면 두 벌이 갈라지고, 그러면 UI가 "이 기준으로 판정했습니다"라고
보여 주는 문서가 실제로 적용된 문서와 달라진다. Pages 빌드도 복사만 한다.

리포트에는 적용된 정책의 버전과 sha256이 함께 기록되어, **어떤 기준으로
판정했는지를 사후에 추적**할 수 있다.

## 라이선스

MIT
