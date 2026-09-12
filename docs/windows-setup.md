# Windows 11 설치 가이드

초기화된 Windows 11 PC 에 SBOMSight 을 처음부터 올리는 절차다. 위에서부터
순서대로 따라간다. 각 단계 끝의 **확인** 을 통과하고 다음으로 넘어간다.

이 도구는 **Java(Spring Boot) + MySQL** 로 돌고 **HTTPS 443** 으로만 열린다.
Python 은 쓰지 않는다.

---

## 준비물

| 무엇 | 어디서 | 크기 | 필수 |
|---|---|---|---|
| **JDK 21** | [adoptium.net](https://adoptium.net/temurin/releases/?version=21) | 약 190MB | 필수 |
| **MySQL 8** | [dev.mysql.com](https://dev.mysql.com/downloads/installer/) | 약 450MB | 필수 |
| Git for Windows | [git-scm.com](https://git-scm.com/download/win) | 약 65MB | 권장 (ZIP 으로 대체 가능) |
| SBOMSight 소스 | GitHub `LEEKIYOON-SEC/SBOMSight` | 약 10MB | 필수 |
| **grype** | 설치 스크립트가 받는다 | 약 30MB | 필수 (이 PC) |
| **syft** | 설치 스크립트가 받는다 | 약 30MB | 검사할 **대상 서버** 에 |
| grype 취약점 DB | `grype db update` 가 받는다 | **약 150MB** | 필수 |

**디스크 여유 10GB 이상.** 취약점 DB 가 풀리면 커지고, 올린 SBOM 원본과 grype
결과가 `data\` 에 계속 쌓인다(gzip 보관, 서버 한 대 한 번에 수 MB).

필요 없는 것:

- **Maven** — 저장소의 `mvnw.cmd` 래퍼가 알아서 받는다.
- **Docker** — 실제 운용에서는 대상 서버에서 만든 SBOM 파일을 받아 쓴다.
- **인터넷(화면용)** — 글꼴을 저장소에 담아 직접 서비스한다. 외부 CDN 을
  부르지 않으므로 폐쇄망에서도 화면이 그대로 나온다.

---

## 1단계 — JDK 21

### 받기

[adoptium.net](https://adoptium.net/temurin/releases/?version=21) 에서
**Temurin 21 (LTS) → Windows → x64 → JDK → .msi** 를 받는다.

> **JRE 가 아니라 JDK 다.** 인증서를 만드는 `keytool` 이 JDK 에만 들어 있다.

### 설치할 때 반드시

설치 화면에서 **`Set JAVA_HOME variable`** 과 **`Add to PATH`** 를 켠다
(기본값이 꺼져 있을 수 있다).

### 확인

**시작 → `terminal` 검색 → Windows 터미널** 을 새로 연다(설치 전에 열어 둔
창은 PATH 가 갱신되지 않는다).

```powershell
java -version
keytool -help
```

`openjdk version "21..."` 이 나와야 한다. 21 미만이면 Spring Boot 3.3 이 뜨지
않는다.

---

## 2단계 — MySQL 8

### 받기

[dev.mysql.com/downloads/installer](https://dev.mysql.com/downloads/installer/)
에서 **MySQL Installer for Windows** → `Server only` 로 설치한다.

설치 중 물어보는 것:

- **Authentication Method** — `Use Strong Password Encryption` (기본값) 그대로.
- **Root Password** — 정해서 적어 둔다. 다음 단계에서 쓴다.
- **Windows Service** — `Start the MySQL Server at System Startup` 을 켠다.
  PC 를 재부팅하면 DB 가 자동으로 올라와야 한다.

### 데이터베이스와 계정 만들기

```powershell
mysql -u root -p
```

```sql
CREATE DATABASE sbomsight CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'sbomsight'@'localhost' IDENTIFIED BY '여기에-DB-비밀번호';
GRANT ALL PRIVILEGES ON sbomsight.* TO 'sbomsight'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

> `utf8mb4` 가 아니면 한글 자산명·비고가 깨지거나 저장에서 거부된다.
> 표는 첫 기동 때 Flyway 가 만든다 — 손으로 만들지 않는다.

### 확인

```powershell
mysql -u sbomsight -p -e "SELECT DATABASE(), @@character_set_database;" sbomsight
```

`sbomsight` 와 `utf8mb4` 가 나와야 한다.

---

## 3단계 — Git 설치

[git-scm.com/download/win](https://git-scm.com/download/win) 에서 받아
**모든 옵션을 기본값 그대로** 두고 설치한다.

```powershell
git --version
```

<details>
<summary>Git 없이 진행하려면</summary>

저장소 페이지에서 **Code → Download ZIP** 으로 받아 압축을 풀어도 된다.
다만 나중에 갱신을 받을 때 다시 내려받아야 한다.
</details>

---

## 4단계 — 소스 받기

```powershell
mkdir C:\work -Force
cd C:\work
git clone https://github.com/LEEKIYOON-SEC/SBOMSight.git
cd SBOMSight
git checkout claude/sbomsight-dev-plan-g327hs
```

```powershell
git branch --show-current
```

> **경로에 공백과 한글이 없는 곳에 두라.** `C:\work\SBOMSight` 를 권한다.
> 사용자 이름이 한글인 `C:\Users\<한글>\...` 아래에 두면 일부 도구가 걸린다.

---

## 5단계 — PowerShell 실행 정책

Windows 는 기본적으로 로컬 `.ps1` 실행을 막는다. 이대로면 설치·기동 스크립트가
돌지 않는다.

```powershell
Get-ExecutionPolicy -Scope CurrentUser
```

`Restricted` 또는 `Undefined` 라면:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

`Y` 로 승인한다.

> `RemoteSigned` 는 내 PC 에서 만든 스크립트는 실행하고 인터넷에서 받은
> 스크립트는 서명을 요구하는 설정이다. `Unrestricted` 로 완전히 풀지 마라 —
> 필요한 것보다 넓다. 범위도 `CurrentUser` 로만 두어 시스템 전체를 건드리지
> 않는다.

---

## 6단계 — grype 설치

```powershell
.\scripts\install-tools.ps1
```

GitHub 릴리스에서 ZIP 을 받아 **릴리스의 `checksums.txt` 와 SHA-256 을 대조한
뒤**에만 설치한다. 취약점 스캐너를 검증 없이 설치하는 것은 앞뒤가 맞지 않는다.
설치 위치는 `%LOCALAPPDATA%\SBOMSight\bin` 이다.

syft 도 함께 설치되지만 **이 PC 에서는 쓰지 않는다** — syft 는 SBOM 을 뜰
대상 서버에서 돌린다. 이 PC 에 있으면 시험용 SBOM 을 만들어 볼 때 편하다.

버전을 고정하려면:

```powershell
.\scripts\install-tools.ps1 -GrypeVersion 0.115.0
```

### PATH 에 추가

스크립트가 마지막에 안내하는 명령을 그대로 실행하고 **터미널을 새로 연다.**

```powershell
[Environment]::SetEnvironmentVariable('Path', "$env:Path;$env:LOCALAPPDATA\SBOMSight\bin", 'User')
```

### 취약점 DB 받기

```powershell
grype db update
```

**약 150MB 를 받는다.** 회선에 따라 몇 분 걸린다.

### 확인

```powershell
grype version
grype db status
```

`Status: valid` 와 최근 `Built` 날짜가 보이면 된다.

> 이 DB 의 신선도가 곧 보고서의 신뢰도다. 주기적으로 `grype db update` 를
> 돌려라. 같은 SBOM 을 새 DB 로 다시 검사하려면 웹의 **다시 검사** 를 쓴다 —
> SBOM 을 다시 올리지 않아도 된다.

<details>
<summary>"Windows에서 PC를 보호했습니다" (SmartScreen) 가 뜰 때</summary>

grype 는 Anchore 가 배포하는 서명 없는 실행 파일이라 SmartScreen 이 경고할 수
있다. **추가 정보 → 실행.**

무턱대고 누르라는 뜻이 아니다. 이 경우에 한해 근거가 있다 — 설치 스크립트가
**받은 ZIP 의 SHA-256 을 릴리스가 공표한 값과 이미 대조했다.** 해시가 어긋나면
스크립트가 설치를 중단한다.
</details>

<details>
<summary>PATH 를 건드리고 싶지 않다면</summary>

9단계의 `config\env.ps1` 에 경로를 직접 적는다.

```powershell
$env:SBOMSIGHT_GRYPE = "$env:LOCALAPPDATA\SBOMSight\bin\grype.exe"
```
</details>

---

## 7단계 — 빌드

```powershell
.\mvnw.cmd clean package
```

처음에는 Maven 과 의존성을 받느라 몇 분 걸린다. 끝나면
`target\sbomsight-1.0.0.jar` 가 생긴다.

### 확인

```powershell
Test-Path target\sbomsight-1.0.0.jar
```

> 시험까지 돌려 보려면 `.\mvnw.cmd test`. H2 메모리 DB 로 돌기 때문에 MySQL 을
> 건드리지 않는다.

---

## 8단계 — 인증서

HTTPS 는 필수다. 정식 인증서를 받기 전에는 자체 서명으로 시작한다.

```powershell
.\scripts\make-keystore.ps1 -HostName sbomsight.example.co.kr -Password '여기에-키스토어-비밀번호'
```

`config\keystore.p12` 가 만들어진다. 인증서의 SAN 에 호스트 이름과 **이 PC 의
IP 들** 이 함께 들어간다 — 내부망에서는 이름 대신 IP 로 접속하는 일이 흔하고,
요즘 브라우저는 CN 을 보지 않아 SAN 에 없으면 막는다.

> **정식 인증서를 받으면 이 파일만 바꿔 끼운다.** 사내 CA 가 내주는 `.pfx` 는
> 그대로 PKCS12 라 `config\keystore.p12` 자리에 놓고 비밀번호만 맞추면 된다.

자체 서명은 브라우저가 경고를 낸다. 사내 CA 로 신뢰 등록하거나 정식 인증서로
교체하면 사라진다. 경고를 무시하고 쓰라는 뜻이 아니다 — 초기 구축용이다.

---

## 9단계 — 설정 파일

운영 값(DB 비밀번호·키스토어 비밀번호)은 저장소에 두지 않는다.

```powershell
Copy-Item scripts\env.example.ps1 config\env.ps1
notepad config\env.ps1
```

채울 것은 셋이다.

```powershell
$env:SBOMSIGHT_KEYSTORE_PASSWORD = '8단계에서 정한 키스토어 비밀번호'
$env:SBOMSIGHT_DB_PASSWORD       = '2단계에서 정한 DB 비밀번호'
$env:SBOMSIGHT_DATA_DIR          = 'C:\work\SBOMSight\data'
```

> `config\env.ps1` 은 `.gitignore` 대상이라 커밋되지 않는다. **이 상태를
> 유지하라.** 편집기로 저장할 때 **UTF-8** 을 유지해야 한다 — 비밀번호에 한글이
> 없으면 문제가 없지만, 주석의 한글이 깨지면 그 파일을 읽다 파서가 죽는다.

설정 전체와 각 값의 뜻은 `scripts\env.example.ps1` 의 주석에 있다.

---

## 10단계 — 기동

먼저 준비 상태만 본다.

```powershell
.\scripts\run-server.ps1 -Check
```

```
SBOMSight 준비 상태
------------------------------------------------------------
  OK   Java 21 이상    openjdk version "21.0.12"
  OK   빌드된 jar      C:\work\SBOMSight\target\sbomsight-1.0.0.jar
  OK   config\env.ps1  읽었습니다
  OK   인증서          config\keystore.p12
  OK   grype           grype
  OK   443 포트        비어 있음
------------------------------------------------------------

준비되었습니다.
```

전부 `OK` 면 띄운다.

```powershell
.\scripts\run-server.ps1
```

브라우저에서 **https://localhost** (또는 스크립트가 안내하는 주소) 를 연다.
자체 서명 경고가 뜨면 **고급 → 계속** 으로 들어간다.

멈추려면 터미널에서 `Ctrl+C`.

> **Windows 에서 443 은 관리자 권한이 필요 없다.** 낮은 포트를 제한하는 것은
> Linux 다. Windows 에서 443 이 안 열리면 대개 둘 중 하나다 — IIS 나
> `World Wide Web Publishing Service` 가 이미 쓰고 있거나, Hyper-V·WSL 이
> 예약해 둔 포트 구간에 걸린 것이다. `-Check` 가 둘 다 확인해 준다.
> 다른 포트로 돌리려면 `config\env.ps1` 의 `$env:SBOMSIGHT_PORT = '8443'`.

---

## 11단계 — 첫 로그인

**첫 기동 때 관리자 계정과 임시 비밀번호가 콘솔에 한 번만 표시된다.**

```
┌──────────────────────────────────────────────────────────┐
│  계정이 없어 최초 관리자를 만들었습니다.                 │
│                                                          │
│    계정   admin                                          │
│    비밀번호  oIWpvTy97aw7rUVx3KDlJ0Jq                    │
│                                                          │
│  이 비밀번호는 지금 한 번만 표시됩니다.                  │
│  로그인하면 곧바로 새 비밀번호를 정해야 합니다.          │
└──────────────────────────────────────────────────────────┘
```

이 값으로 로그인하면 **비밀번호 변경 화면으로 바로 넘어가고, 새 비밀번호를
정하기 전에는 다른 화면이 열리지 않는다.**

터미널을 닫아 놓쳤다면 계정을 **전부** 지우고 다시 띄운다. 이 상자는
`users` 표가 완전히 빈 경우에만 나온다 — `admin` 만 지우고 다른 계정이 남아
있으면 아무 일도 일어나지 않는다.

```powershell
mysql -u sbomsight -p sbomsight -e "DELETE FROM users;"
.\scripts\run-server.ps1
```

> 구축 직후라면 `admin` 하나뿐이라 안전하다. 이미 팀원 계정을 만든 뒤라면
> 이 방법을 쓰지 말고, 다른 관리자 계정으로 들어가 **설정 → 계정** 에서
> 비밀번호를 초기화하라.

이후 계정 추가·삭제·비밀번호 초기화·권한 변경은 웹의 **설정 → 계정** 에서
한다. 권한은 둘이다.

| 권한 | 할 수 있는 것 |
|---|---|
| 관리자 | 전부 — 자산 등록, SBOM 업로드, 삭제, 계정 관리, 접근 IP |
| 조회 | 읽기 전용 — 결과와 보고서를 보고, 자기 비밀번호를 바꾼다 |

로그인 관련 기본값:

| 항목 | 기본값 | 바꾸는 변수 |
|---|---|---|
| 연속 실패 잠금 | 5회 | `SBOMSIGHT_MAX_LOGIN_FAILURES` |
| 잠금 자동 해제 | 30분 | `SBOMSIGHT_LOCK_MINUTES` |
| 비밀번호 변경 주기 | 90일 | `SBOMSIGHT_PASSWORD_MAX_AGE_DAYS` |
| 세션 유휴 만료 | 10분 | `SBOMSIGHT_SESSION_TIMEOUT` |

---

## 12단계 — 첫 한 바퀴

### 구역 만들기

**설정 → 구역** 에서 `DMZ` · `내부업무` 처럼 관리 단위를 만든다. 색을 주면
목록과 보고서에서 그 띠로 구분된다. 구역을 안 만들어도 자산은 `미분류` 로
들어간다.

### 자산 등록

**자산 → 자산 등록.** 서버 한 대가 자산 하나다. 관리 단위는 스캔이 아니라
서버다.

여러 대를 한 번에 넣으려면 **자산 → 일괄 등록** 에서 CSV 를 올린다.
**서식 내려받기** 로 받은 파일에 채워 넣으면 된다.

```
서버 이름,구역,운영체제,비고
web-01,DMZ,Rocky Linux 9.3,대외 웹
db-01,내부업무,Rocky Linux 8.9,원장 DB
```

> 한국어 엑셀에서 "CSV(쉼표로 분리)" 로 저장하면 UTF-8 이 아니라 **CP949** 로
> 나온다. 그대로 올려도 된다 — 읽을 때 알아서 가른다. 어떤 인코딩으로 읽었는지
> 미리보기 화면에 적히니, 한글이 깨져 보이면 거기부터 본다.
>
> 넣기 전에 줄마다 판정(등록/중복/이름 규칙 위반 등)을 보여 준다. 건너뛴 줄은
> 줄 번호와 사유가 그대로 남는다.

### 대상 서버에서 SBOM 뜨기

검사할 서버에서 syft 를 돌린다. **이 PC 가 아니다.**

```bash
syft dir:/ -o cyclonedx-json > web-01.sbom.json      # 서버 전체
syft <이미지> -o cyclonedx-json > app.sbom.json       # 컨테이너
```

CycloneDX · SPDX · syft 자체 형식 모두 받는다. grype 이 읽을 수 있으면 된다.
만든 JSON 을 이 PC 로 옮긴다.

<details>
<summary>지금은 동작 확인만 하고 싶다면</summary>

이 PC 의 syft 로 시험용 SBOM 을 하나 만든다. 구버전 이미지라 취약점이 넉넉히
나온다.

```powershell
syft registry:python:3.10-slim -o cyclonedx-json > test-sbom.json
```
</details>

### 올리고 검사

자산 상세 화면의 **SBOM 올리기** 에서 파일을 고르고 **올리고 검사.** grype 이
뒤에서 돌고, 끝나면 검사 이력에 나타난다. 서버 전체 SBOM 은 수백 MB 가 예사고
grype 도 몇 분 걸린다.

### 보고서

- **취약점 보기** — 심각도·수정본 유무·실제 악용으로 거르고 정렬한다.
  누르면 바로 걸린다(적용 버튼이 없다).
- **보고서** — 자산 한 대의 기승전결 네 장. 인쇄하면 그대로 PDF 가 된다.
- **구역 보고서** — "9월 DMZ 현황". 구역과 기간을 고르면 그 구역 전체를 한
  장으로 낸다. **기간 안에 검사되지 않은 자산을 먼저 이름까지 밝힌다** — 서른
  대 중 열 대만 검사하고 "탐지 1,200건" 이라고 쓰면 구역의 현황이 아니다.
- **CSV 내려받기** — 화면의 필터가 그대로 적용된다. 엑셀에서 바로 열린다.

---

## 13단계 — 내부망에 열기

기본 바인딩은 이 PC 전체지만 **방화벽이 막고 있다.** 팀에서 함께 쓰려면
관리자 PowerShell 에서 한 번:

```powershell
.\scripts\run-server.ps1 -Listen
```

방화벽 인바운드 규칙을 만들고(`Private` 프로파일) 접속 주소를 알려 준다.

```
접속 주소
  https://localhost
  https://192.168.10.23
```

> `-Profile Private` 이다. 이 PC 의 네트워크가 Windows 에서 **개인 네트워크** 로
> 잡혀 있어야 규칙이 먹는다. **설정 → 네트워크 → 속성** 에서 확인하라. 공용
> 네트워크로 잡혀 있으면 규칙이 있어도 막힌다.

다른 PC 에서 그 주소를 열면 로그인 화면이 뜬다. **설정 → 계정** 에서 팀원
계정을 만들어 준다.

### 허용 IP 좁히기

로그인만으로 부족하면 **설정 → 접근 IP** 에서 대역을 지정한다. 목록 밖에서는
로그인 화면조차 열리지 않는다.

```
192.168.10.0/24
10.0.0.5
```

판단은 **소켓 상대 주소로만** 한다 — `X-Forwarded-For` 같은 헤더는 누구든 채워
보낼 수 있어서 그것을 믿으면 목록이 헤더 한 줄로 우회된다. 지금 접속 중인
주소가 빠진 목록은 저장되지 않으니 스스로 잠길 걱정은 없다.

---

## 갱신받기

```powershell
cd C:\work\SBOMSight
```

**DB 를 먼저 백업한다.** 마이그레이션이 표 구조를 바꾸고, 되돌리는 길은 백업
뿐이다.

```powershell
mysqldump -u root -p --single-transaction --routines sbomsight > C:\work\backup-sbomsight.sql
```

> **V5 마이그레이션은 `assets.group_name` 열을 지운다.** 구역(zone) 표로 옮긴
> 뒤 원본을 없앤다. 이전 판에서 올라온다면 위 백업을 **반드시** 먼저 받으라.

```powershell
git pull
.\mvnw.cmd clean package
.\scripts\run-server.ps1
```

표 변경은 첫 기동 때 Flyway 가 알아서 적용한다.

---

## 백업 대상

| 무엇 | 어디 | 없으면 |
|---|---|---|
| DB | MySQL `sbomsight` | 자산·이력·조치·감사 로그가 전부 사라진다 |
| 보관 파일 | `$env:SBOMSIGHT_DATA_DIR` (기본 `.\data`) | 옛 SBOM 과 grype 원본이 사라져 **다시 검사** 를 못 한다 |
| 인증서 | `config\keystore.p12` | 다시 만들면 된다 (자체 서명) |
| 설정 | `config\env.ps1` | 다시 채우면 된다 |

`data\` 에는 서버에 설치된 패키지 목록이 통째로 들어 있다. 백업 매체도 같은
등급으로 다뤄야 한다.

---

## 문제 해결

### `식에 닫는 ')' 가 없습니다` + 한글이 깨져 보인다

`.ps1` 파일에 UTF-8 BOM 이 없을 때 난다. Windows PowerShell 5.1 은 BOM 없는
`.ps1` 을 시스템 ANSI 코드페이지(한국어 Windows 는 CP949)로 읽는데, 한글의
UTF-8 바이트가 CP949 lead 바이트로 해석되면서 **뒤따르는 ASCII 문자가 먹힌다.**
닫는 따옴표가 사라져 파서가 죽는 것이다.

저장소의 `.ps1` 은 BOM 으로 저장되어 있고 `ScriptEncodingTest` 가 매 빌드마다
검사하므로 정상적으로 클론했다면 볼 일이 없다. 그래도 났다면 직접 편집하다 BOM
이 날아간 것이다.

```powershell
git checkout -- scripts/
Format-Hex -Path .\scripts\run-server.ps1 -Count 3   # 첫 3바이트가 EF BB BF
```

### `java.exe : openjdk version ...` 이 빨간 오류로 뜬다

`java -version` 은 버전을 stderr 로 낸다. 오류라서가 아니라 처음부터 그렇다.
스크립트는 이미 이 구간을 따로 처리한다. 직접 확인할 때 거슬리면
`java -version 2>$null` 로 본다.

### `443 포트 — 이미 쓰는 중: w3wp, svchost`

IIS 나 `World Wide Web Publishing Service` 가 쓰고 있다. 끄거나 포트를 바꾼다.

```powershell
Stop-Service W3SVC; Set-Service W3SVC -StartupType Disabled   # 관리자
```

### `443 예약 구간 — 윈도우가 예약해 둔 범위에 들어갑니다`

Hyper-V·WSL 이 잡아 둔 구간이다. 이때는 바인딩이 **조용히** 실패한다.

```powershell
netsh interface ipv4 show excludedportrange protocol=tcp
```

포트를 바꾸는 편이 빠르다(`$env:SBOMSIGHT_PORT = '8443'`).

### `grype 를 찾을 수 없습니다`

PATH 변경 후 **터미널을 새로 열지 않은** 경우가 대부분이다. 새 창에서
`grype version` 을 확인하라. 그래도 안 되면 `config\env.ps1` 에
`$env:SBOMSIGHT_GRYPE` 로 전체 경로를 적는다.

### 한글 자산명·비고가 물음표나 깨진 글자로 저장된다

DB 문자셋이 `utf8mb4` 가 아니다.

```sql
ALTER DATABASE sbomsight CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

이미 깨진 채로 저장된 행은 되살릴 수 없다. 다시 입력해야 한다.

### 브라우저가 "연결이 비공개로 설정되어 있지 않습니다" 라고 막는다

자체 서명 인증서다. 정상이다. 사내 CA 로 신뢰 등록하거나 정식 인증서로
교체하면 사라진다.

이름이 맞지 않는다는 경고(`NET::ERR_CERT_COMMON_NAME_INVALID`)라면 인증서를
만든 뒤 이 PC 의 IP 가 바뀐 것이다. 다시 만든다.

```powershell
.\scripts\make-keystore.ps1 -HostName <이름> -Password <비밀번호>
```

### SBOM 을 올렸는데 검사가 실패한다

**설정 → 도구 상태** 에서 grype 을 실제로 불러 본다. 실행할 수 없다고 나오면
6단계로 돌아간다. 실행은 되는데 실패한다면 검사 이력의 오류 문구를 본다.
시간 초과라면 기본 60분을 늘린다(`$env:SBOMSIGHT_GRYPE_TIMEOUT = '120'`).

### 회사 네트워크(프록시·TLS 검사)에서 다운로드가 실패

사내 프록시가 TLS 를 가로채는 환경이면 `grype db update` 와 도구 다운로드가
인증서 오류로 실패한다. 사내 루트 CA 를 신뢰 저장소에 넣거나, 인터넷이 되는
구간에서 받아 반입하라 — 절차는
[`docs/offline-operations.md`](offline-operations.md) 에 있다.

### 악용 확률(EPSS)·실제 악용(KEV) 이 전부 `—`

그 grype 판이 주지 않은 것이다. **0 이나 "없음" 으로 채우지 않는다** — 확인하지
못한 것과 없는 것은 다른 이야기다. 보고서에도 그렇게 적힌다. 최신 판으로
`grype db update` 한 뒤 **다시 검사** 하면 채워질 수 있다.

---

## 다음 읽을거리

| 문서 | 내용 |
|---|---|
| [`README.md`](../README.md) | 설계에서 지키는 것 · 설정 변수 전체 |
| [`docs/offline-operations.md`](offline-operations.md) | 폐쇄망 패치 절차 · 오프라인 취약점 DB 반입 |
| [`scripts/env.example.ps1`](../scripts/env.example.ps1) | 설정 값과 각각의 뜻 |
