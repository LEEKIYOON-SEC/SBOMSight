# SBOMSight

SBOM 기반 취약점 대응 검토. **Syft 와 Grype 이 전부이고**, 이 웹은 그 결과를
서버별로 쌓아 이력과 조치를 관리한다.

```
대상 서버에서 syft 로 SBOM 을 뜬다
        ↓  (파일을 웹에 올린다)
이 서버에서 grype 이 돈다
        ↓
자산별로 결과가 쌓인다 — 이력 비교 · 조치 관리 · 기승전결 보고서
```

**판정은 전부 grype 의 것이다.** 이 애플리케이션은 grype 이 낸 값을 보관·정렬·
집계할 뿐, 다시 계산하지 않는다. grype 이 틀렸다면 그것은 grype 의 오류로
감수하지만, 이 코드 때문에 결과가 달라지는 것은 감수 대상이 아니다.

---

## 무엇으로 만들었나

| | |
|---|---|
| 웹 | Spring Boot 3.3 (내장 Tomcat) · Java 21 |
| 화면 | Thymeleaf 서버 렌더링 — 로그인 상태와 화면이 어긋날 자리를 만들지 않는다 |
| 로그인 | Spring Security 폼 로그인 · 세션 유휴 만료 · CSRF |
| DB | MariaDB 또는 MySQL 8 · Flyway 마이그레이션 · 드라이버는 MariaDB Connector/J (LGPL-2.1) |
| 검사 | **syft**(SBOM 생성, 대상 서버에서) · **grype**(취약점 매칭, 이 서버에서) |

HTTPS 는 필수다(443). 금융권 지침상 http 로는 열지 않는다.

---

## 설치

아래는 요약이다. **Windows 11 PC 에 처음부터 올리는 전체 절차는
[`docs/windows-setup.md`](docs/windows-setup.md) 에 있다** — 단계마다 확인
명령과 막혔을 때 볼 곳이 붙어 있다.

### 1. 준비물

- JDK 21 (Maven 은 필요 없다 — 저장소의 `mvnw` 래퍼가 알아서 받는다)
- MariaDB 10.6+ 또는 MySQL 8 (드라이버 하나로 둘 다 붙는다)
- grype (이 서버에)
- syft (검사할 대상 서버들에)

```powershell
# Windows — grype 설치 후 취약점 DB 를 한 번 받는다
grype db update
```

### 2. 데이터베이스

```sql
CREATE DATABASE sbomsight CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'sbomsight'@'localhost' IDENTIFIED BY '<비밀번호>';
GRANT ALL PRIVILEGES ON sbomsight.* TO 'sbomsight'@'localhost';
```

표는 첫 기동 때 Flyway 가 만든다.

### 3. 인증서

정식 인증서를 받기 전에는 자체 서명으로 시작한다.

```powershell
# Windows
.\scripts\make-keystore.ps1 -HostName sbomsight.example.co.kr -Password '<키스토어비밀번호>'
```
```bash
# Linux
./scripts/make-keystore.sh sbomsight.example.co.kr <키스토어비밀번호>
```

`config/keystore.p12` 가 만들어진다. **정식 인증서를 받으면 이 파일만 바꿔
끼우면 된다** — 사내 CA 가 내주는 `.pfx` 를 같은 자리에 놓고 비밀번호만 맞춘다.

> 자체 서명은 브라우저가 경고를 낸다. 사내 CA 로 신뢰 등록하거나 정식 인증서로
> 교체하면 사라진다. 경고를 무시하고 쓰라는 뜻이 아니다 — 초기 구축용이다.

### 4. 기동

```powershell
# Windows — config\env.ps1 에 값을 적어 두고 스크립트가 읽게 한다.
Copy-Item scripts\env.example.ps1 config\env.ps1
notepad config\env.ps1          # 비밀번호 채우기

.\mvnw.cmd clean package
.\scripts\run-server.ps1 -Check     # 준비 상태만 확인
.\scripts\run-server.ps1 -Listen    # 방화벽까지 열고 기동 (관리자 PowerShell)
```
```bash
# Linux — 환경변수로 준다. 저장소에 두지 않는다.
export SBOMSIGHT_PORT=443
export SBOMSIGHT_DB_URL='jdbc:mariadb://localhost:3306/sbomsight?...'
export SBOMSIGHT_DB_PASSWORD='<비밀번호>'
export SBOMSIGHT_KEYSTORE_PASSWORD='<키스토어비밀번호>'

./mvnw clean package
java -jar target/sbomsight-1.0.0.jar
```

**Windows 는 443 에 관리자 권한이 필요 없다** — 낮은 포트를 제한하는 것은
Linux 다(`setcap 'cap_net_bind_service=+ep' $(which java)`). Windows 에서
443 이 안 열리면 대개 IIS 나 `World Wide Web Publishing Service` 가 이미
쓰고 있거나, Hyper-V·WSL 이 예약해 둔 포트 구간에 걸린 것이다.
`scripts\run-server.ps1 -Check` 가 둘 다 확인해 준다.

**첫 기동 때 관리자 계정과 임시 비밀번호가 콘솔에 한 번만 표시된다.**
로그인하면 곧바로 새 비밀번호를 정해야 한다.

---

## 쓰는 법

### SBOM 만들기 (대상 서버에서)

```bash
syft dir:/ -o cyclonedx-json > web-01.sbom.json      # 서버 전체
syft <이미지> -o cyclonedx-json > app.sbom.json       # 컨테이너
```

CycloneDX · SPDX · syft 자체 형식 모두 받는다. grype 이 읽을 수 있으면 된다.

### 웹에서

1. **자산 등록** — 서버 한 대를 등록한다. 관리 단위는 스캔이 아니라 서버다.
2. **SBOM 올리기** — 그 자산 안에서 올린다. grype 이 뒤에서 돌고, 끝나면
   이력에 나타난다.
3. **취약점 보기** — 심각도·수정본 유무·CVE 로 거르고 정렬한다.
4. **조치 등록** — 보고서의 조치 대상 표에서 그 자리에 담당·기한을 정한다.
5. **보고서** — 기승전결 네 장. 인쇄하면 그대로 PDF 가 된다.
6. **CSV 내려받기** — 화면의 필터가 그대로 적용된다. 엑셀에서 바로 열린다.

### 관리 (설정 화면)

- **계정** — 만들고 지우고 권한을 바꾼다. 권한은 둘이다: `관리자`(전체)와
  `조회`(읽기 전용 — 자산 등록·SBOM 업로드·삭제 불가).
  비밀번호 초기화는 계정 이름과 같게 되돌리고 다음 로그인에서 반드시 바꾸게
  한다. 마지막 관리자는 지우거나 강등할 수 없다.
- **접근 IP** — 허용 대역 밖이면 로그인 화면도 열리지 않는다. 비워 두면
  제한하지 않는다(로그인은 여전히 필요하다). 지금 접속 중인 주소가 빠진
  목록은 저장되지 않는다 — 저장하는 순간 본인이 잠긴다.
- **도구 상태** — grype 을 실제로 불러 판을 확인한다.

### 지울 때

자산을 지우면 **그 안의 스캔·탐지·조치와 디스크에 보관된 SBOM·검사 결과가
함께 사라진다.** 무엇이 몇 건 지워지는지 화면에 표시되고, 자산 이름을 정확히
입력해야 실행된다.

---

## 설정

전부 환경변수다. 기본값은 `src/main/resources/application.yml` 에 있다.

| 변수 | 기본값 | 뜻 |
|---|---|---|
| `SBOMSIGHT_PORT` | 8443 | 운영은 443 |
| `SBOMSIGHT_KEYSTORE` | `file:./config/keystore.p12` | 인증서 |
| `SBOMSIGHT_KEYSTORE_PASSWORD` | changeit | 키스토어 비밀번호 |
| `SBOMSIGHT_SESSION_TIMEOUT` | 10m | 유휴 만료 |
| `SBOMSIGHT_DB_URL` · `_USER` · `_PASSWORD` | | DB 접속 — 주소는 `jdbc:mariadb://` |
| `SBOMSIGHT_DATA_DIR` | `./data` | SBOM·grype 결과 보관 |
| `SBOMSIGHT_GRYPE` | grype | grype 경로 |
| `SBOMSIGHT_MAX_UPLOAD` | 10GB | 업로드 상한 |
| `SBOMSIGHT_GRYPE_TIMEOUT` | 60 | grype 제한 시간(분) |

---

## 설계에서 지키는 것

**grype 의 판정을 바꾸지 않는다.** 설치 버전과 수정 버전을 다시 비교하지 않고,
심각도를 재분류하지 않는다. 조치 가능 여부의 유일한 근거는 grype 의
`fix.state` 다. 자체 비교자에 흠이 하나만 있어도 grype 이 잡은 건이 화면에서
"해당 없음"으로 사라진다.

**없는 값을 지어내지 않는다.** EPSS·KEV·CVSS 가 없으면 `—` 로 둔다. 0 이나
false 로 채우면 "악용 확률 0%"·"악용된 적 없음"이라는, 아무도 확인하지 않은
판정이 화면에 뜬다. 정렬할 때도 값이 없는 건은 방향과 무관하게 뒤로 보낸다.

**버린 건을 센다.** grype 이 낸 match 수와 저장된 건수가 다르면 그 차이를
보고서에 적는다. 조용히 버리면 몇 건이 사라졌는지 아무도 모른다.

**무엇으로 판정했는지 남긴다.** grype 판과 취약점 DB 기준일을 결과와 함께
저장한다. 없으면 몇 달 뒤 같은 SBOM 의 결과가 달라진 이유를 설명할 수 없다.

**CVE 번호를 앞에 놓는다.** 언어 생태계에서 grype 의 주 식별자는 GHSA 인데,
결재·보고는 CVE 번호로 돈다. grype 이 함께 준 CVE 를 꺼내 크게 쓰고 GHSA 는
옆에 남긴다 — 주 식별자를 바꾸는 것이 아니라 같은 응답 안의 값을 옮긴 것이고,
CVE 가 없으면 지어내지 않는다.

**이력은 (CVE, 패키지명) 으로 대조한다.** 버전을 넣으면 부분 패치한 건이
"해소 1건 + 신규 1건"으로 갈라져 화면이 거짓말을 한다.

**접근 통제는 소켓 주소로만 한다.** `X-Forwarded-For` 는 누구든 채워 보낼 수
있어서, 그것을 믿으면 허용 목록이 헤더 한 줄로 우회된다. 이름 조회도 하지
않는다 — DNS 가 느리거나 결과가 바뀔 때 접근 통제가 함께 흔들린다.

**지우면 파일도 지운다.** 스캔 결과의 DB 행만 지우면 디스크에 SBOM 이 남고,
그 안에는 그 서버에 설치된 패키지 목록이 통째로 들어 있다.

---

## 시험

```bash
./mvnw test          # Windows: .\mvnw.cmd test
```

`GrypeMapperTest` 는 **실제 grype 0.87 이 낸 98건짜리 출력 전체**를 태운다.
손으로 만든 픽스처로는 안 잡히는 것들이 있었다 — `descriptor.db.location` 이
숫자가 아니라 경로 문자열이었고, CVSS 벡터가 174자여서 열 폭을 넘겼다. 둘 다
스캔 전체를 잃게 만드는 오류였다.

---

## 개발

```bash
./mvnw spring-boot:run     # 8443 · 자체 서명
```

`scripts/` 에 인증서 생성과 기동 스크립트가 있다 (Windows `.ps1`, Linux `.sh`).
