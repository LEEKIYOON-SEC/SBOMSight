# 운영 가이드

설치가 끝난 PC 에서 **서비스로 올리고, 날마다 무엇을 하는지**를 적는다.
설치 절차 자체는 [`docs/windows-setup.md`](windows-setup.md) 에 있다.

---

## 1. 서비스로 올리기

`run-server.ps1` 은 앞단에서 돈다 — **창을 닫거나 PC 가 재부팅되면 내려간다.**
팀이 함께 쓰는 도구가 그러면 언제부터 안 됐는지 아무도 모른다.

**작업 스케줄러에 등록한다.** 윈도우에 들어 있는 것이라 폐쇄망에 따로 반입할
것이 없다 — NSSM 같은 외부 프로그램을 쓰지 않는 이유가 그것이다.

> **순서가 있다 — 첫 로그인을 먼저 끝낸다.** 최초 관리자 비밀번호는 계정이
> 하나도 없는 첫 기동에 **한 번만** 찍힌다. 서비스로 먼저 올리면 그 줄이
> 화면이 아니라 `logs\service.log` 안으로 들어간다. windows-setup.md 의
> 11단계까지 끝낸 뒤에 등록하는 편이 쉽다.

관리자 PowerShell 에서:

```powershell
cd C:\work\SBOMSight
.\scripts\install-service.ps1
```

등록되는 것:

| | |
|---|---|
| 작업 이름 | `SBOMSight` |
| 트리거 | 시스템 시작 **1분 뒤** — DB 가 먼저 올라와 있어야 한다 |
| 계정 | `SYSTEM` — **로그온하지 않아도 돈다** |
| 실패 시 | 1분 뒤 다시 시작, 세 번까지 |
| 기록 | `logs\service.log` (10MB 를 넘으면 `.1` 로 밀어 둔다) |

등록한 뒤 바로 띄우고, 포트를 듣기 시작할 때까지 기다려 접속 주소를 낸다.
안 올라오면 기록의 끝 20줄을 그 자리에서 보여 준다.

### 다루기

| 무엇 | 명령 (관리자 PowerShell) |
|---|---|
| 내리기 | `.\scripts\install-service.ps1 -Stop` |
| 띄우기 | `.\scripts\install-service.ps1 -Start` |
| 등록 지우기 | `.\scripts\install-service.ps1 -Remove` |
| 마지막 결과 | `(Get-ScheduledTaskInfo -TaskName SBOMSight).LastTaskResult` — `0` 이어야 한다 |
| 지금 도는가 | `Get-NetTCPConnection -LocalPort 443 -State Listen` |

### 기록 보기

```powershell
Get-Content .\logs\service.log -Tail 50
Get-Content .\logs\service.log -Wait      # 흐르는 것을 본다 (Ctrl+C 로 나온다)
```

서비스에는 창이 없으니 **콘솔에 찍히던 것이 전부 이 파일로 간다** — 기동 실패
이유도, 최초 관리자 비밀번호도, 검사가 실패한 까닭도 여기에만 남는다.

### SYSTEM 으로 돌면 달라지는 것

| | 로그인 계정으로 돌릴 때 | SYSTEM (서비스) |
|---|---|---|
| grype 취약점 DB | `%LOCALAPPDATA%\grype` | `C:\Windows\System32\config\systemprofile\AppData\Local\grype` |
| PATH | 사용자 PATH 포함 | 시스템 PATH 만 |

**둘이 같은 DB 를 보게 못 박아야 한다.** 로그인 계정으로 `grype db update` 를
돌려도 서비스는 그 DB 를 쓰지 않는다. `config\env.ps1` 에:

```powershell
$env:GRYPE_DB_CACHE_DIR = 'C:\work\grype-db'
```

PATH 도 같은 이유로 믿지 않는다. `install-service.ps1` 은 java 를 전체 경로로
박아 등록하고, grype 이 PATH 에 없으면 `config\env.ps1` 의
`$env:SBOMSIGHT_GRYPE` 에 전체 경로를 적는다.

---

## 2. 운영 리듬

| 언제 | 무엇 | 어디서 |
|---|---|---|
| 날마다 | **대응** 기둥의 붉은 숫자(기한 지남)가 있으면 연다 | 대응 |
| SBOM 을 받을 때마다 | 그 자산에 올리고 검사 | 자산 → 자산 상세 |
| 주마다 | 취약점 DB 갱신 → 자산마다 **다시 검사** | 3절 |
| 주마다 | `버전이 갈린 것만` 으로 덜 올린 자산 확인 | 패키지 |
| 달마다 | 구역·기간 보고서 | 보고서 |
| 달마다 | 백업이 실제로 되고 있는지 확인 | 6절 |
| 계정이 바뀔 때 | 추가·삭제·비밀번호 초기화 | 설정 → 계정 |
| 판올림할 때 | 7절 절차 | |

주기는 규정에 맞춰 정하면 된다. **다만 취약점 DB 갱신 주기는 적어 두라** —
보고서에 DB 기준일이 찍히므로, 받는 사람이 "이 판정이 언제 것인가" 를 읽는다.

---

## 3. 취약점 DB 를 갱신하고 다시 검사

새 CVE 는 서버가 아니라 **DB 쪽에서 생긴다.** 서버가 그대로라도 DB 가 새로
알게 된 것이 있다.

```powershell
$env:GRYPE_DB_CACHE_DIR = 'C:\work\grype-db'   # 서비스와 같은 자리를 본다
grype db update
grype db status                                 # Status: valid · Built 날짜 확인
```

그다음 자산마다 검사 이력의 **`다시 검사`** 를 누른다.

- **SBOM 을 다시 올릴 필요가 없다.** 보관해 둔 원본을 그대로 다시 읽는다.
- 자산마다 **최신 검사 것만** 남는다. 여러 번 눌러도 행이 쌓이지 않는다.
- 자산이 많으면 구역 단위로 나눠 돈다 — grype 한 번이 몇 분이다.

폐쇄망이면 DB 를 반입해야 한다. 절차는
[`docs/offline-operations.md`](offline-operations.md) 에 있다.

> **패치했는지 확인하는 것은 `다시 검사` 가 아니다.** 서버를 고쳤으면 **SBOM 을
> 새로 떠서 올려야** 한다. `다시 검사` 는 *서버는 그대로인데 DB 가 새로 알게 된
> 것*을 본다. 둘을 섞으면 패치하지 않았는데 해소된 것으로 읽는다.

---

## 4. 한 바퀴 — SBOM 을 받아서 검사까지

| 누가 | 무엇을 |
|---|---|
| 서버 담당자 | `syft dir:/ -o cyclonedx-json > web-01.sbom.json` → 파일만 넘긴다 |
| 이 PC | 자산 상세 → **SBOM 올리기** → **올리고 검사** |

SBOM 에는 그 서버에 설치된 패키지 목록과 파일 경로가 담긴다. **반출 승인 절차가
있다면 이 파일이 그 대상이다.**

검사가 끝나면 자산 상세의 `취약점` 탭에서 본다. 전사 기준으로 보려면 기둥의
**취약점**, 무엇이 어디 깔려 있나는 **패키지** 다.

---

## 5. 검토 결과와 대응

**grype 이 낸 것은 `탐지`, 우리가 적는 것은 `검토 결과` 다.** 둘을 같은 말로
부르지 않는다 — 탐지 건수는 우리가 무엇을 적어도 변하지 않는다.

행의 **적기** 로 검토 결과를 남긴다.

| 검토 결과 | 뜻 | 기본 목록 |
|---|---|---|
| 미검토 | 아직 보지 않았다 | 보인다 |
| 검토 중 | 우리 환경에 해당되는지 확인하고 있다 | 보인다 |
| 해당됨 | 영향이 있다. 고쳐야 한다 | 보인다 |
| 해당 없음 | 탐지는 맞지만 영향이 없다 — **근거를 골라야 한다** | 빠진다 |
| 오탐 | 탐지 자체가 틀렸다 | 빠진다 |

목록에서 빠지는 것은 **상태로 자동으로 정해진다.** 감추는 체크박스는 없다.
끝난 것까지 보려면 거르개의 `검토 끝난 것도 보기` 를 켠다.

`조치 안 함 (위험 수용)` 으로 닫으려면 **근거 · 재검토일**을 받는다. 재검토일이
지나면 **대응** 기둥의 붉은 숫자에 함께 센다 — 한 번 닫고 잊는 자리를 두지
않는다. 기록한 사람과 시각은 자동으로 남는다.

조치 상태는 셋이다: **대기 · 진행 · 완료.** "하지 않고 닫음" 은 없앴다 — 같은
결정을 검토 결과의 `조치 안 함` 에도 적을 수 있어 두 곳이 어긋났다.

---

## 6. 보고서와 CSV

| 무엇 | 어디 |
|---|---|
| 자산 한 대 | 보고서 → `자산별 · 최신 검사` 에서 고른다. 6장 |
| 구역 · 기간 | 보고서 → 구역·기간. **기간 안에 검사되지 않은 자산을 먼저 이름까지 밝힌다** |
| CSV | 취약점 · 대응 · 감사 로그 · 패키지 화면 머리. 화면의 거르개가 그대로 적용된다 |

인쇄하면 그대로 PDF 가 된다. 산문이 없고 표와 각주뿐이다.

---

## 7. 백업

| 무엇 | 없으면 |
|---|---|
| `sbomsight` 데이터베이스 | 자산·이력·검토 결과·대응·감사 로그가 전부 사라진다 |
| `$env:SBOMSIGHT_DATA_DIR` (기본 `.\data`) | 옛 SBOM 과 grype 원본이 사라져 **다시 검사** 를 못 한다 |
| `config\keystore.p12` · `config\env.ps1` | 다시 만들면 된다 |

```powershell
$stamp = Get-Date -Format 'yyyyMMdd'
mysqldump -u root -p --single-transaction --routines sbomsight > D:\backup\sbomsight-$stamp.sql
Copy-Item C:\work\SBOMSight\data D:\backup\data-$stamp -Recurse
```

- **서비스를 내리지 않아도 된다.** `--single-transaction` 이 일관된 시점을 뜬다.
- `data\` 에는 서버에 설치된 패키지 목록이 통째로 들어 있다. **백업 매체도 같은
  등급으로 다룬다.**
- 날마다 받으려면 위 두 줄을 `.ps1` 로 두고 작업 스케줄러에 등록한다.

**한 번은 되살려 봐야 한다.** 받아 둔 것이 실제로 열리는지는 복구해 보기 전까지
알 수 없다.

```powershell
mysql -u root -p -e "CREATE DATABASE sbomsight_restore CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
mysql -u root -p sbomsight_restore < D:\backup\sbomsight-20260901.sql
mysql -u root -p sbomsight_restore -e "SELECT COUNT(*) FROM assets; SELECT COUNT(*) FROM findings;"
```

---

## 8. 판올림

**도는 동안에는 jar 가 잠겨 있어 빌드가 실패한다.** 먼저 내린다.

```powershell
cd C:\work\SBOMSight
.\scripts\install-service.ps1 -Stop

# DB 를 먼저 백업한다. 마이그레이션이 표 구조를 바꾸고, 되돌리는 길은 백업뿐이다.
mysqldump -u root -p --single-transaction --routines sbomsight > D:\backup\before-upgrade.sql

git pull
.\mvnw.cmd clean package
.\scripts\install-service.ps1 -Start
```

표 변경은 기동할 때 Flyway 가 적용한다. 올라온 뒤:

1. 로그인해 본다 — **로그아웃하고 다시** 들어간다.
2. **패키지** 화면이 비어 있으면 자산마다 `다시 검사` 를 한 번 누른다. 패키지
   목록은 검사할 때 SBOM 에서 담기고, 판올림이 이미 쌓인 SBOM 을 되읽지는
   않는다.
3. `logs\service.log` 에 예외가 없는지 본다.

---

## 9. 잘 안 될 때

| 증상 | 먼저 볼 곳 |
|---|---|
| 아무것도 안 열린다 | `logs\service.log` 끝 50줄 · `LastTaskResult` |
| 재부팅 뒤 안 올라온다 | **부팅 1분 뒤에 뜬다.** 그래도 안 되면 MySQL/MariaDB 서비스가 `자동` 인지 확인한다 — DB 가 없으면 기동이 죽고, 1분 간격으로 세 번까지만 다시 시도한다 |
| 검사만 실패한다 | 설정 → 도구 상태에서 grype 을 불러 본다. SYSTEM 이 grype·DB 를 못 찾는 경우가 대부분이다 (1절) |
| 악용 확률·실제 악용이 전부 `—` | 그 grype 판이 주지 않은 것이다. 0 으로 채우지 않는다 |
| 그 밖에 | [`docs/windows-setup.md` 문제 해결](windows-setup.md#문제-해결) |

---

## 10. 아직 확인하지 못한 것

**`scripts\install-service.ps1` 은 윈도우에서 실행해 보지 못했다.** 개발 환경이
리눅스라 PowerShell 과 작업 스케줄러를 돌릴 수 없었다 — 빌드가 확인한 것은 이
파일의 인코딩(`ScriptEncodingTest`)뿐이다.

그래서 **처음 등록할 때 이 셋을 직접 확인하라.**

```powershell
(Get-ScheduledTaskInfo -TaskName SBOMSight).LastTaskResult   # 0
Get-Content .\logs\service.log -Tail 30                      # Started SBOMSightApplication
Restart-Computer                                              # 재부팅 뒤 저절로 열리는가
```

세 번째가 핵심이다 — 재부팅해도 올라오는 것이 이 스크립트의 유일한 목적이다.
안 되면 등록을 지우고(`-Remove`) `run-server.ps1` 로 돌리면서 이유를 찾으면
된다. 그 사이에도 도구는 그대로 쓸 수 있다.
