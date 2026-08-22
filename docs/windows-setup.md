# Windows 11 설치 가이드

초기화된 Windows 11 PC에 SBOMSight를 처음부터 구축하는 절차다. 위에서부터
순서대로 따라가면 된다. 각 단계 끝에 **확인** 명령이 있으니 통과하고 다음으로 넘어가라.

## 준비물 요약

| 무엇 | 어디서 | 크기 | 필수 |
|---|---|---|---|
| Python 3.12 | [python.org](https://www.python.org/downloads/windows/) | 약 25MB | 필수 |
| Git for Windows | [git-scm.com](https://git-scm.com/download/win) | 약 65MB | 권장 (ZIP으로 대체 가능) |
| SBOMSight 소스 | GitHub `LEEKIYOON-SEC/SBOMSight` | 약 1MB | 필수 |
| Syft · Grype | 설치 스크립트가 자동으로 받음 | 각 약 30MB | 필수 |
| Grype 취약점 DB | `grype db update` 가 자동으로 받음 | **146MB** (압축) | 필수 |
| Google AI Studio 키 | [aistudio.google.com/apikey](https://aistudio.google.com/apikey) | — | 선택 |
| Docker Desktop | [docker.com](https://www.docker.com/products/docker-desktop/) | 약 600MB | **불필요** (아래 설명) |

**디스크 여유 공간 5GB 이상**을 확보해 두라. Grype DB는 압축 146MB지만 풀리면
훨씬 커진다.

> **Docker는 필요 없다.** Syft가 컨테이너 이미지를 스캔할 때만 쓰이는데,
> `registry:` 접두사를 쓰면 Docker 없이 레지스트리에서 직접 받아 스캔한다.
> 게다가 실제 운용에서는 폐쇄망 서버에서 만든 SBOM 파일을 받아 쓰므로
> 이 PC에서 이미지를 스캔할 일 자체가 없다.

---

## 1단계 — Python 설치

### 받기

[python.org/downloads/windows](https://www.python.org/downloads/windows/) 에서
**Python 3.12.x → Windows installer (64-bit)** 를 받는다.

> 3.11 ~ 3.13 이 동작한다. 3.12를 권하는 이유는 모든 의존성의 Windows 휠(wheel)이
> 확실히 준비되어 있어 컴파일러 없이 설치되기 때문이다.

### 설치할 때 반드시

설치 첫 화면 맨 아래 **`Add python.exe to PATH` 를 체크**하고 `Install Now`.

체크를 놓치면 이후 모든 명령에서 `python을 찾을 수 없습니다`가 난다. 이미 놓쳤다면
설치 관리자를 다시 실행해 `Modify` → `Next` → `Add Python to environment variables`
를 켜면 된다.

> **Microsoft Store의 Python은 쓰지 마라.** 샌드박스 안에서 돌아 경로와 스크립트
> 실행이 꼬인다.

### 확인

**시작 → `terminal` 검색 → Windows 터미널** 을 새로 연다(설치 전에 열어 둔 창은
PATH가 갱신되지 않는다).

```powershell
python --version
pip --version
```

`Python 3.12.x` 가 나와야 한다.

<details>
<summary>Microsoft Store가 열리거나 아무것도 안 나올 때</summary>

Windows의 "앱 실행 별칭"이 가로챈 것이다.

**설정 → 앱 → 고급 앱 설정 → 앱 실행 별칭** 에서
`python.exe` 와 `python3.exe` 를 **끈다**. 터미널을 새로 열고 다시 확인하라.
</details>

---

## 2단계 — Git 설치

[git-scm.com/download/win](https://git-scm.com/download/win) 에서 받아
**모든 옵션을 기본값 그대로** 두고 설치한다.

### 확인

터미널을 새로 열고:

```powershell
git --version
```

<details>
<summary>Git 없이 진행하고 싶다면</summary>

브라우저로 저장소 페이지에 가서 **Code → Download ZIP** 으로 받아 압축을 풀어도 된다.
다만 **결과를 GitHub Pages에 올리는 단계(9단계)에는 Git이 필요하다.**
</details>

---

## 3단계 — 소스 받기

작업 폴더를 만들고 클론한다.

```powershell
cd $env:USERPROFILE
mkdir work -Force
cd work
git clone https://github.com/LEEKIYOON-SEC/SBOMSight.git
cd SBOMSight
```

### 브랜치 확인

```powershell
git branch --show-current
```

`claude/sbomsight-dev-plan-g327hs` 가 나와야 한다. 이 저장소에는 아직 `main` 이
없고 이 브랜치가 기본 브랜치라 클론하면 자동으로 선택된다.

> 경로에 공백이나 한글이 없는 곳에 두라. `C:\Users\<이름>\work\SBOMSight` 처럼
> 사용자 이름이 한글이면 일부 도구가 걸릴 수 있다. 그런 경우 `C:\work\SBOMSight`
> 를 쓰라.

---

## 4단계 — PowerShell 실행 정책 풀기

Windows는 기본적으로 로컬 `.ps1` 스크립트 실행을 막는다. 이대로면 5·8단계의
설치·기동 스크립트가 돌지 않는다.

```powershell
Get-ExecutionPolicy -Scope CurrentUser
```

`Restricted` 또는 `Undefined` 라면:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

`Y` 를 눌러 승인한다.

> `RemoteSigned` 는 **내 PC에서 만든 스크립트는 실행하고, 인터넷에서 받은
> 스크립트는 서명이 있어야 실행**하는 설정이다. `Unrestricted` 로 완전히 풀지
> 마라 — 필요한 것보다 넓다. 범위도 `CurrentUser` 로만 바꿔 시스템 전체를
> 건드리지 않는다.

---

## 5단계 — Python 의존성 설치

가상환경을 만들어 이 프로젝트의 패키지가 시스템 Python을 오염시키지 않게 한다.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

활성화되면 프롬프트 앞에 `(.venv)` 가 붙는다.

### 확인

```powershell
python -c "import fastapi, uvicorn, google.genai; print('의존성 OK')"
```

> 터미널을 새로 열 때마다 `.\.venv\Scripts\Activate.ps1` 로 다시 활성화해야 한다.
> 깜빡해도 기동 스크립트(`run-server.ps1`)는 `.venv` 를 자동으로 찾아 쓰지만,
> `python -m core.cli ...` 를 직접 칠 때는 활성화가 필요하다.

---

## 6단계 — Syft · Grype 설치

```powershell
.\scripts\install-tools.ps1
```

이 스크립트는 GitHub 릴리스에서 ZIP을 받아 **릴리스의 `checksums.txt` 와
SHA-256을 대조한 뒤**에만 설치한다. 취약점 스캐너를 검증 없이 설치하는 것은
앞뒤가 맞지 않기 때문이다.

설치 위치는 `%LOCALAPPDATA%\SBOMSight\bin` 이다.

버전을 고정하고 싶으면:

```powershell
.\scripts\install-tools.ps1 -SyftVersion 1.50.0 -GrypeVersion 0.115.0
```

### PATH에 추가

스크립트가 마지막에 안내하는 명령을 그대로 실행한다:

```powershell
[Environment]::SetEnvironmentVariable('Path', "$env:Path;$env:LOCALAPPDATA\SBOMSight\bin", 'User')
```

**터미널을 닫고 새로 연다.** (`.venv` 재활성화도 잊지 말 것)

### 확인

```powershell
syft version
grype version
```

<details>
<summary>PATH를 건드리고 싶지 않다면</summary>

8단계에서 만들 `.env` 파일에 경로를 직접 적어도 된다:

```
SYFT_BIN=C:\Users\<사용자명>\AppData\Local\SBOMSight\bin\syft.exe
GRYPE_BIN=C:\Users\<사용자명>\AppData\Local\SBOMSight\bin\grype.exe
```
</details>

<details>
<summary>"Windows에서 PC를 보호했습니다" (SmartScreen) 가 뜰 때</summary>

Syft와 Grype는 Anchore가 배포하는 서명 없는 실행 파일이라 SmartScreen이 경고할 수
있다. **추가 정보 → 실행** 을 누르면 된다.

무턱대고 누르라는 뜻은 아니다. 이 경우에 한해 안전하다고 말할 수 있는 근거는
설치 스크립트가 **다운로드한 ZIP의 SHA-256을 릴리스가 공표한 값과 이미 대조했다**는
것이다. 해시가 어긋나면 스크립트가 설치를 중단한다.
</details>

---

## 7단계 — 취약점 DB 준비

```powershell
grype db update
```

**146MB를 받는다.** 회선에 따라 몇 분 걸린다.

### 확인

```powershell
grype db status
```

`Status: valid` 와 최근 `Built` 날짜가 보이면 된다.

> 이 DB는 주기적으로 갱신된다. 판정의 신선도가 곧 보고서의 신뢰도이므로
> 스캔 전에 `grype db update` 를 돌리는 습관을 들이라. 오프라인 PC로 운용할
> 계획이라면 [`docs/offline-operations.md`](offline-operations.md) 의 DB 반입
> 절차를 보라.

---

## 8단계 — 설정 파일

```powershell
Copy-Item .env.example .env
notepad .env
```

기본값 그대로도 **전부 동작한다.** AI 없이도 보고서는 룰 기반으로 완결되며,
그것이 기본 모드다.

### AI 서술을 쓰려면 (선택)

[aistudio.google.com/apikey](https://aistudio.google.com/apikey) 에서 키를 발급받아
`.env` 에서 아래 두 줄의 `#` 을 지우고 값을 채운다:

```
SBOMSIGHT_AI_ENABLED=1
GEMINI_API_KEY=여기에_발급받은_키
```

> **키는 이 파일에만 둔다.** 브라우저로 내려가지 않고, 방문자에게 입력받지도
> 않으며, 호출은 전부 서버에서 나간다. `.env` 는 `.gitignore` 대상이라 커밋되지
> 않는다 — 이 상태를 유지하라.

---

## 9단계 — 서버 기동

```powershell
.\scripts\run-server.ps1
```

이런 출력이 나오면 정상이다:

```
[i] .env 로드
[i] 가상환경 사용: .venv
[i] AI 미사용 (기본값). 보고서는 룰 기반으로 완결됩니다.
[i] http://127.0.0.1:8000
```

브라우저에서 **http://127.0.0.1:8000** 을 연다.

첫 화면 상단 띠에 `grype <버전> · DB <날짜> · 판정 기준 …` 이 보이면 모든 준비가
끝난 것이다.

> 방화벽 경고는 뜨지 않는 것이 정상이다. 기본 바인딩이 `127.0.0.1` 이라 이 PC
> 밖으로 열리지 않는다. 스캔 결과에는 내부 자산 정보가 담기므로 **외부에
> 노출하지 마라.**

서버를 멈추려면 터미널에서 `Ctrl+C`.

---

## 10단계 — 관리자 계정 만들기

처음 접속하면 **관리자 계정 만들기** 화면이 뜬다. 계정 이름과 8자 이상 비밀번호를
넣으면 그 계정이 관리자가 되고 그대로 로그인된다.

> 이 화면은 **이 PC 자신(`127.0.0.1`)에서 접속했을 때만** 열린다. 계정이 없는
> 동안 네트워크의 누군가가 먼저 와서 관리자를 차지할 수 없게 하기 위함이다.

터미널에서 만들어도 된다. 비밀번호를 잊어 웹으로 못 들어갈 때도 이 명령을 쓴다.

```powershell
python -m core.cli user add kiyoon --role admin   # 비밀번호는 프롬프트로 입력
python -m core.cli user list
python -m core.cli user passwd kiyoon             # 비밀번호 재설정
```

이후 계정 추가·삭제·비밀번호 초기화·권한 변경은 웹의 **설정 → 계정**에서 한다.
권한은 둘이다.

| 권한 | 할 수 있는 것 |
|---|---|
| `admin` | 전부 — 스캔, 삭제, 계정 관리, 접근 IP 설정 |
| `viewer` | 조회만 — 스캔 결과와 보고서를 볼 수 있고, 자기 비밀번호를 바꿀 수 있다 |

---

## 11단계 — 첫 스캔

### 테스트용 SBOM 만들기

실제 운용에서는 폐쇄망 서버에서 만들어 반출한 SBOM을 올리지만, 지금은 동작
확인이 목적이니 Syft로 하나 만들어 본다. **Docker 없이** 레지스트리에서 직접
받아 스캔한다:

```powershell
syft registry:python:3.10-slim -o cyclonedx-json=test-sbom.json
```

구버전 이미지라 취약점이 넉넉히 나온다. 몇 분 걸릴 수 있다.

### 웹 UI에서 스캔

1. 브라우저에서 **스캔** 탭으로 간다
2. `test-sbom.json` 을 끌어다 놓는다
3. **스캔 시작** — 진행 단계가 순서대로 채워진다
4. 결과 표가 뜬다

### 흐름 확인

1. 표에서 취약점 **몇 건을 체크**한다 (또는 `P0 · P1 선택`)
2. **AI에 전송될 내용 보기** — 선택한 항목만 조립된 데이터와 프롬프트 원문 전체가
   보인다. 자산명·경로·설치 버전·판정 결과가 **없는지 직접 확인하라.** 그것을
   확인할 수 있게 만든 화면이다
3. AI를 켰다면 **이 내용을 전송해 서술 생성**
4. **선택 N건으로 보고서** → 6절 보고서

<details>
<summary>CLI로만 해 보고 싶다면</summary>

```powershell
python -m core.cli scan test-sbom.json -o findings.json
python -m core.cli report findings.json -o report.md
python -m core.cli scans
```
</details>

---

## 12단계 — 내부망에 열기 (다른 PC에서 접속)

기본 바인딩은 `127.0.0.1` 이라 이 PC 밖에서는 보이지 않는다. 팀에서 함께 쓰려면
세 가지가 모두 되어야 한다 — **바인딩 · 방화벽 · 계정**. 하나라도 빠지면 접속이
조용히 실패한다.

```powershell
.\scripts\run-server.ps1 -Listen
```

스크립트가 순서대로 해 준다.

1. **계정 확인** — 계정이 하나도 없으면 열지 않고 멈춘다. 취약점 목록은
   공격자에게 그대로 지도가 되므로 로그인이 설 수 있기 전에는 문을 열지 않는다.
   10단계를 먼저 하라.
2. **방화벽 규칙 확인** — 없으면 만들 명령을 알려 준다. 관리자 PowerShell에서
   한 번만 실행하면 된다.

   ```powershell
   New-NetFirewallRule -DisplayName 'SBOMSight (8000)' -Direction Inbound `
     -LocalPort 8000 -Protocol TCP -Action Allow -Profile Private
   ```

   > `-Profile Private` 이다. 이 PC의 네트워크가 Windows에서 **개인 네트워크**로
   > 잡혀 있어야 규칙이 먹는다. **설정 → 네트워크 → 속성**에서 확인하라.
   > 공용 네트워크로 잡혀 있으면 규칙이 있어도 막힌다.

3. **접속 주소 안내** — `0.0.0.0` 은 주소가 아니라 '전부'라는 뜻이라 브라우저에
   그대로 칠 수 없다. 스크립트가 이 PC의 실제 IP를 뽑아 알려 준다.

```
[i] 접속 주소  http://192.168.10.23:8000
```

다른 PC 브라우저에서 그 주소를 열면 **로그인 화면**이 뜬다. 관리자 계정으로
들어간 뒤 **설정 → 계정**에서 팀원 계정을 만들어 주면 된다.

### 허용 IP를 좁히기

로그인만으로 부족하면 **설정 → 접근 IP** 에서 대역을 지정한다. 목록 밖에서는
로그인 화면조차 보이지 않는다.

```
192.168.10.0/24
10.0.0.5
```

판단은 **소켓 상대 주소로만** 한다 — `X-Forwarded-For` 같은 헤더는 누구든
채워 보낼 수 있어서 그것을 믿으면 목록이 헤더 한 줄로 우회된다. 지금 접속 중인
주소가 빠진 목록은 저장되지 않으니 스스로 잠길 걱정은 없다.

---

## 13단계 — 결과를 GitHub Pages에 전시

PC에서 나온 실제 결과를 포트폴리오로 공개하는 단계다.

```powershell
python -m core.cli export --out results
```

실행하면 **무엇이 담기고 무엇이 지워졌는지** 화면에 나온다:

```
담긴 것 : 설치 패키지명, 설치 버전, 취약 여부 판정, 대응 검토 우선순위
지운 것 : 파일 경로, SBOM 파일명·해시, 스캔 대상 문자열, Grype search_criteria
```

> ⚠ **`results/` 는 공개된다.** 커밋 전에 내용을 직접 열어 보라. 설치 패키지명과
> 설치 버전은 "설치 버전 대 Fixed Version 비교"라는 전시의 요점이라 일부러 남긴다.
> 실제 사내 자산으로 만든 결과를 올릴 생각이라면 그 판단은 반드시 사람이 해야 한다.
> 테스트 이미지(`python:3.10-slim`)로 만든 결과라면 공개해도 무방하다.

먼저 로컬에서 확인해 본다:

```powershell
python scripts\build_pages.py --out dist
python -m http.server -d dist 8080
```

http://127.0.0.1:8080 에서 전시 모드가 어떻게 보이는지 확인한 뒤(`Ctrl+C` 로 종료),
커밋해서 올린다:

```powershell
git add results
git commit -m "실제 스캔 결과 전시"
git push
```

푸시되면 `Pages 배포` 워크플로가 돌고, 몇 분 뒤
**https://leekiyoon-sec.github.io/SBOMSight/** 에 반영된다.

<details>
<summary>Pages가 처음이라면 한 번만 켜 주어야 한다</summary>

저장소 → **Settings → Pages → Build and deployment → Source** 를
**`GitHub Actions`** 로 바꾼다. `Deploy from a branch` 로 두면 워크플로 결과가
반영되지 않는다.
</details>

---

## 문제 해결

### `python`을 찾을 수 없습니다 / Microsoft Store가 열린다
1단계의 접기 항목 참고 — 앱 실행 별칭을 끄고 터미널을 새로 연다.

### `이 시스템에서 스크립트를 실행할 수 없으므로`
4단계를 건너뛴 것이다. `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`

### `식에 닫는 ')'가 없습니다` + 한글이 깨져 보인다

`.ps1` 파일에 UTF-8 BOM이 없을 때 난다. Windows PowerShell 5.1은 BOM이 없는
`.ps1` 을 시스템 ANSI 코드페이지(한국어 Windows에서는 CP949)로 읽는데, 한글의
UTF-8 바이트가 CP949 lead 바이트로 해석되면서 **뒤따르는 ASCII 문자가 먹힌다.**
닫는 따옴표가 사라져 파서가 죽는 것이다.

저장소의 `.ps1` 은 BOM으로 저장되어 있고 `tests/test_scripts.py` 가 이를
검사하므로 정상적으로 클론했다면 이 오류를 볼 일이 없다. 그래도 났다면
파일을 직접 편집하다 BOM이 날아간 것이니 최신 상태로 되돌리라:

```powershell
git checkout -- scripts/
```

직접 확인하려면:

```powershell
Format-Hex -Path .\scripts\run-server.ps1 -Count 3
```

첫 3바이트가 `EF BB BF` 여야 한다.

### `grype를 찾을 수 없습니다`
PATH 변경 후 **터미널을 새로 열지 않았을** 가능성이 가장 크다. 새 창에서
`grype version` 을 확인하라. 그래도 안 되면 `.env` 에 `GRYPE_BIN` 경로를 직접 적으라.

### `의존성이 없습니다`
가상환경이 활성화되지 않았다. `.\.venv\Scripts\Activate.ps1` 후 다시 시도.
`.venv` 폴더 자체가 없으면 5단계를 다시 하라.

### 포트 8000이 이미 사용 중
`.env` 에 `SBOMSIGHT_PORT=8001` 을 추가하고 다시 기동한다.

### 회사 네트워크(프록시·TLS 검사) 안에서 다운로드가 실패
사내 프록시가 TLS를 가로채는 환경이면 `grype db update` 와 도구 다운로드가
인증서 오류로 실패한다. 사내 루트 CA를 신뢰 저장소에 넣거나, 인터넷이 되는
구간에서 받아 반입하라 — 반입 절차는
[`docs/offline-operations.md`](offline-operations.md) 에 있다.

### 스캔은 되는데 EPSS·KEV가 전부 "미확인"
위협정보 소스에 접근하지 못한 것이다. 판정은 여전히 유효하되 CVSS만 반영된
상태이며, 보고서에 그렇게 표기된다 — **0으로 채우거나 "없음"으로 처리하지
않는다.** 네트워크가 열린 상태에서 다시 스캔하면 채워진다.

---

## 다음 읽을거리

| 문서 | 내용 |
|---|---|
| [`README.md`](../README.md) | 설계 원칙 · 데이터 3층 분리 · 이그레스 가드 |
| [`docs/offline-operations.md`](offline-operations.md) | 폐쇄망 패치 절차 · 오프라인 DB 반입 · 결과 반출 |
| [`.env.example`](../.env.example) | 설정 전체와 각 값의 의미 |
