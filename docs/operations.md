# 운영 가이드

설치가 끝난 PC 에서 **서비스로 띄우고, 날마다 무엇을 하는지**를 적는다.
설치 절차 자체는 [`docs/windows-setup.md`](windows-setup.md) 에 있다.

---

## 1. 서비스로 띄우기

`run-server.ps1` 은 앞단에서 돈다 — **창을 닫거나 PC 가 재부팅되면 내려간다.**
팀이 함께 쓰는 도구가 그러면 언제부터 안 됐는지 아무도 모른다.

**작업 스케줄러에 등록한다.** 윈도우에 들어 있는 것이라 폐쇄망에 따로 반입할
것이 없다 — NSSM 같은 외부 프로그램을 쓰지 않는 이유가 그것이다.

> **순서가 있다 — 첫 로그인을 먼저 끝낸다.** 최초 관리자 비밀번호는 계정이
> 하나도 없는 첫 기동에 **한 번만** 찍힌다. 서비스로 먼저 띄우면 그 줄이
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
이유도, 최초 관리자 비밀번호도, 검사가 실패한 자세한 까닭도 여기에만 남는다
(화면에는 사유 한 줄이 뜬다).

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
| SBOM 을 받을 때마다 | 그 자산에 업로드하고 검사 | 자산 → 자산 상세 |
| 주마다 | 취약점 DB 갱신 → 자산마다 **다시 검사** | 3절 |
| 주마다 | `일부 자산만 업그레이드` 로 덜 업그레이드한 자산 확인 | 패키지 |
| 달마다 | 구역·기간 보고서 | 보고서 |
| 달마다 | 백업이 실제로 되고 있는지 확인 | 7절 |
| 계정이 바뀔 때 | 추가·삭제·비밀번호 초기화 | 설정 → 계정 |
| 업그레이드할 때 | 8절 절차 | |

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

- **SBOM 을 다시 업로드할 필요가 없다.** 보관해 둔 원본을 그대로 다시 읽는다.
- 자산마다 **최신 검사 것만** 남는다. 여러 번 눌러도 행이 쌓이지 않는다.
- 자산이 많으면 구역 단위로 나눠 돈다 — grype 한 번이 몇 분이다.

폐쇄망이면 DB 를 반입해야 한다. 절차는
[`docs/offline-operations.md`](offline-operations.md) 에 있다.

> **패치했는지 확인하는 것은 `다시 검사` 가 아니다.** 서버를 고쳤으면 **SBOM 을
> 새로 떠서 업로드해야** 한다. `다시 검사` 는 *서버는 그대로인데 DB 가 새로 알게 된
> 것*을 본다. 둘을 섞으면 패치하지 않았는데 해소된 것으로 읽는다.

---

## 4. 한 바퀴 — SBOM 을 받아서 검사까지

| 누가 | 무엇을 |
|---|---|
| 서버 담당자 | `syft dir:/ -o cyclonedx-json > web-01.sbom.json` → 파일만 넘긴다 |
| 이 PC | 자산 상세 → **SBOM 업로드** → **검사 시작** |

SBOM 에는 그 서버에 설치된 패키지 목록과 파일 경로가 담긴다. **반출 승인 절차가
있다면 이 파일이 그 대상이다.**

검사가 끝나면 자산 상세의 `취약점` 탭에서 본다. 전사 기준으로 보려면 기둥의
**취약점**, 무엇이 어디 깔려 있나는 **패키지** 다.

---

## 5. 검토 결과와 대응

**grype 이 낸 것은 `탐지`, 우리가 적는 것은 `검토 결과` 다.** 둘을 같은 말로
부르지 않는다 — 탐지 건수는 우리가 무엇을 적어도 변하지 않는다.

행의 **작성** 으로 검토 결과를 남긴다.

| 검토 결과 | 뜻 | 기본 목록 |
|---|---|---|
| 미검토 | 아직 보지 않았다 | 보인다 |
| 검토 중 | 우리 환경에 해당되는지 확인하고 있다 | 보인다 |
| 해당됨 | 영향이 있다. 고쳐야 한다 | 보인다 |
| 해당 없음 | 탐지는 맞지만 영향이 없다 — **근거를 골라야 한다** | 빠진다 |
| 오탐 | 탐지 자체가 틀렸다 | 빠진다 |

목록에서 빠지는 것은 **상태로 자동으로 정해진다.** 감추는 체크박스는 없다.
빠진 것까지 보려면 필터의 `해당 없음·오탐 포함` 을 켠다 — 이름표에 빠진 건수가
붙는다(`해당 없음·오탐 포함 (3건)`). 취약점 화면 · 자산의 취약점 탭 · CVE 상세 ·
보고서의 목록 장(자산 보고서 3·4장, 구역 보고서 4·5장)이 같은 규칙이다. 보고서
1장이 뺀 건수를 적는다. 자산 목록 요약 줄의 숫자는 탐지 건수라, 누르면 켠 채로
열린다.

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
| CSV | 취약점 · 대응 · 감사 로그 · 패키지 화면 머리. 화면의 필터가 그대로 적용된다 |

인쇄하면 그대로 PDF 가 된다. 산문이 없고 표와 각주뿐이다.

---

## 7. 백업

| 무엇 | 없으면 |
|---|---|
| `sbomsight` 데이터베이스 | 자산·이력·검토 결과·대응·감사 로그가 전부 사라진다 |
| `SBOMSIGHT_DATA_DIR` (기본은 저장소 폴더의 `data`) | 옛 SBOM 과 grype 원본이 사라져 **다시 검사** 를 못 한다 |
| `config` 의 `keystore.p12` · `env.ps1` (Linux 는 환경변수) | 다시 만들면 된다 |

**파일은 `--result-file` 로 쓴다.** 덤프 도구가 파일을 직접 쓴다. PowerShell 의
`>` 는 받은 글자를 다시 인코딩해 쓴다(Windows PowerShell 5.1 은 UTF-16) — 이
저장소가 syft 출력에서 이미 겪은 일이다(SBOM 생성 가이드). MariaDB 는 `mysqldump` ·
`mysql` 대신 `mariadb-dump` · `mariadb` 를 쓴다(옵션은 같다).

```powershell
# Windows (PowerShell)
$stamp = Get-Date -Format 'yyyyMMdd'
mysqldump -u root -p --single-transaction --routines sbomsight --result-file=D:\backup\sbomsight-$stamp.sql
Copy-Item C:\work\SBOMSight\data D:\backup\data-$stamp -Recurse
```

```bash
# Linux — 저장소 폴더에서
stamp=$(date +%Y%m%d)
mariadb-dump -u root -p --single-transaction --routines sbomsight --result-file=/backup/sbomsight-$stamp.sql
cp -a ./data /backup/data-$stamp
```

- **서비스를 내리지 않아도 된다.** 표가 전부 InnoDB 라 `--single-transaction` 이
  일관된 시점을 뜬다.
- `data` 에는 서버에 설치된 패키지 목록이 통째로 들어 있다. **백업 매체도 같은
  등급으로 다룬다.**
- 날마다 받으려면 위 명령을 `.ps1`(Windows 작업 스케줄러) · `.sh`(Linux cron)
  로 두고 등록한다. **예약 작업에서는 `-p` 를 쓰지 않는다** — 비밀번호를 물어
  거기서 멈춘다. 대신 옵션 파일을 두고 `-u root -p` 자리에
  `--defaults-extra-file=<파일>` 을 **맨 앞 옵션으로** 준다(뒤에 두면 모르는
  옵션이라며 멈춘다). 그 파일은 백업을 도는 계정만 읽게 둔다. 앱 계정
  (`sbomsight`)으로도 받힌다.

  ```ini
  [client]
  user=sbomsight
  password=여기에-DB-비밀번호
  ```

**한 번은 되살려 봐야 한다.** 받아 둔 것이 실제로 열리는지는 복구해 보기 전까지
알 수 없다. 운영 DB 가 아니라 **다른 이름**(`sbomsight_restore`)으로 되살린다.

```powershell
# Windows — PowerShell 에는 `<` 가 없다. 클라이언트의 source 로 읽는다(경로는 / 로 쓴다).
mysql -u root -p -e "CREATE DATABASE sbomsight_restore CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
mysql -u root -p sbomsight_restore -e "source D:/backup/sbomsight-20260901.sql"
mysql -u root -p sbomsight_restore -e "SELECT COUNT(*) FROM assets; SELECT COUNT(*) FROM findings;"
```

```bash
# Linux
mariadb -u root -p -e "CREATE DATABASE sbomsight_restore CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
mariadb -u root -p sbomsight_restore < /backup/sbomsight-20260901.sql
mariadb -u root -p sbomsight_restore -e "SELECT COUNT(*) FROM assets; SELECT COUNT(*) FROM findings;"
```

수가 맞으면 `DROP DATABASE sbomsight_restore;` 로 지운다 — 되살린 것도 같은
내용이다.

---

## 8. 업그레이드

**도는 동안에는 jar 가 잠겨 있어 빌드가 실패한다.** 먼저 내린다.

**DB 와 지금 jar 를 먼저 백업한다.** 마이그레이션이 표 구조를 바꾸고, 되돌리는
길은 그 둘뿐이다.

```powershell
# Windows
cd C:\work\SBOMSight
.\scripts\install-service.ps1 -Stop

mysqldump -u root -p --single-transaction --routines sbomsight --result-file=D:\backup\before-upgrade.sql
Copy-Item target\sbomsight-1.0.0.jar D:\backup\sbomsight-before-upgrade.jar

git pull
.\mvnw.cmd clean package -DskipTests
.\scripts\install-service.ps1 -Start
```

```bash
# Linux — run-server.sh 로 띄운 창에서 Ctrl+C 로 먼저 내린다
cd /경로/SBOMSight
mariadb-dump -u root -p --single-transaction --routines sbomsight --result-file=/backup/before-upgrade.sql
cp target/sbomsight-1.0.0.jar /backup/sbomsight-before-upgrade.jar

git pull
./mvnw clean package -DskipTests
./scripts/run-server.sh
```

표 변경은 기동할 때 Flyway 가 적용한다. 올라온 뒤:

1. 로그인해 본다 — **로그아웃하고 다시** 들어간다.
2. **패키지** 화면이 비어 있으면 자산마다 `다시 검사` 를 한 번 누른다. 패키지
   목록은 검사할 때 SBOM 에서 담기고, 업그레이드가 이미 쌓인 SBOM 을 되읽지는
   않는다.
3. `logs\service.log` 에 예외가 없는지 본다.

### V15 — 조치의 목표 버전을 다시 모은다

앞서 조치 하나에는 수정 버전을 **하나**(CVSS 가 가장 높은 건의 것) 적었다. V15 는
그 칸을 넓히고(255 → 4000자), 조치를 등록한 검사에서 **수정 버전 전부**를 글자
순으로 다시 모아 덮어쓴다 — 해당 없음 · 오탐으로 적은 건과 수정 버전이 없는 건은
빼고. 등록한 검사가 지워진 조치는 적혀 있던 값을 그대로 둔다. 기록에
`Migrating schema ... to version "15 - remediation fix versions"` 가 한 번 찍힌다.

### 되돌리기

서비스를 내리고, DB 를 비운 뒤 업그레이드 전 백업으로 되살리고, 백업해 둔 jar 로
띄운다. DB 를 지웠다 다시 만들어도 계정의 권한은 남는다.

```powershell
# Windows
cd C:\work\SBOMSight
.\scripts\install-service.ps1 -Stop
mysql -u root -p -e "DROP DATABASE sbomsight; CREATE DATABASE sbomsight CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
mysql -u root -p sbomsight -e "source D:/backup/before-upgrade.sql"
Copy-Item D:\backup\sbomsight-before-upgrade.jar target\sbomsight-1.0.0.jar
.\scripts\install-service.ps1 -Start
```

```bash
# Linux — run-server.sh 로 띄운 창에서 Ctrl+C 로 먼저 내린다
cd /경로/SBOMSight
mariadb -u root -p -e "DROP DATABASE sbomsight; CREATE DATABASE sbomsight CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
mariadb -u root -p sbomsight < /backup/before-upgrade.sql
cp /backup/sbomsight-before-upgrade.jar target/sbomsight-1.0.0.jar
./scripts/run-server.sh
```

V15 는 이 길을 MariaDB 10.11 에서 끝까지 밟아 보았다. V14 인 DB 를 백업하고, 새
jar 로 V15 를 적용한 뒤 되살렸다. 되살린 DB 는 마이그레이션 14까지로 돌아갔고,
목표 버전과 한글 값도 원래대로였다. 이전 jar 도 그 DB 로 떴다.
백업 없이 jar 만 되돌려도 기동은 된다. Flyway 가 "DB 가 더 새 판" 이라고 경고하고
넘어가며, 목표 버전 칸에는 여러 버전이 띄어 쓴 한 줄로 보인다.

---

## 9. 잘 안 될 때

| 증상 | 먼저 볼 곳 |
|---|---|
| 아무것도 안 열린다 | `logs\service.log` 끝 50줄 · `LastTaskResult` |
| 재부팅한 다음부터 안 뜬다 · 로그에 `RSA public key ...` | 접속 주소에 `allowPublicKeyRetrieval=true` 를 더한다 — [windows-setup.md 문제 해결](windows-setup.md#어제까지-잘-되다가-재부팅한-다음부터-기동이-안-된다-rsa-public-key-) |
| 재부팅 뒤 안 올라온다 | **부팅 1분 뒤에 뜬다.** 그래도 안 되면 MySQL/MariaDB 서비스가 `자동` 인지 확인한다 — DB 가 없으면 기동이 죽고, 1분 간격으로 세 번까지만 다시 시도한다 |
| 검사만 실패한다 | 설정 → 도구 상태에서 grype 을 불러 본다. SYSTEM 이 grype·DB 를 못 찾는 경우가 대부분이다 (1절). 고친 뒤 자산 상세 개요(또는 검사 이력)의 `다시 검사` — SBOM 을 다시 업로드할 필요 없다 |
| 화면에 `처리하지 못했습니다` 와 시각이 뜬다 | 그 시각 앞뒤의 `logs\service.log`. 오류 화면은 안의 사정(예외 문구)을 적지 않는다 — 기록에만 남는다 |
| `요청을 처리할 수 없습니다` 에 `쓸 수 없는 글자` 라고 뜨거나, 오류 번호 없이 뜬다 | 앱에 닿기 전에 톰캣이 끊은 요청이다 — 복사하다 잘린 주소 · 깨진 링크가 대부분이다. 화면의 링크로 다시 연다. 이런 요청은 `logs\service.log` 에 남지 않는다 |
| 악용 확률·실제 악용이 전부 `—` | 그 grype 버전이 주지 않은 것이다. 0 으로 채우지 않는다 |
| 그 밖에 | [`docs/windows-setup.md` 문제 해결](windows-setup.md#문제-해결) |

---

## 10. 아직 확인하지 못한 것

**`scripts\install-service.ps1` 은 윈도우에서 실행해 보지 못했다.** 개발 환경이
리눅스라 PowerShell 과 작업 스케줄러를 돌릴 수 없었다 — 빌드가 확인한 것은 이
파일의 인코딩(`ScriptEncodingTest`)뿐이다.

그래서 **처음 등록할 때 이 셋을 직접 확인하라.**

```powershell
(Get-ScheduledTaskInfo -TaskName SBOMSight).LastTaskResult   # 0
Get-Content .\logs\service.log -Tail 30                      # Started SbomSightApplication
Restart-Computer                                              # 재부팅 뒤 저절로 열리는가
```

세 번째가 핵심이다 — 재부팅해도 올라오는 것이 이 스크립트의 유일한 목적이다.
안 되면 등록을 지우고(`-Remove`) `run-server.ps1` 로 돌리면서 이유를 찾으면
된다. 그 사이에도 도구는 그대로 쓸 수 있다.

**7 · 8절의 PowerShell 백업 · 되살리기 줄도 윈도우에서 돌려 보지 못했다.** 같은
옵션을 리눅스의 MariaDB 10.11 클라이언트로 확인했다. `>` 로 받은 파일과
`--result-file` 로 받은 파일이 같았고, `<` 와 `source` 로 되살린 DB 도 같았다.
**V15 는 MySQL 8 에서 돌려 보지 못했다.** MySQL 8 을 쓴다면 업그레이드한 뒤
기록의 V15 줄(`Successfully applied 1 migration`)과 대응 화면의 목표 버전을 먼저
보고, 이상하면 8절의 되돌리기로 돌아간다.
