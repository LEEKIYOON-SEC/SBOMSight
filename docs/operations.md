# 운영 가이드

설치가 끝난 PC 에서 **서비스로 띄우고, 날마다 무엇을 하는지**를 적는다.
설치 절차 자체는 [`docs/windows-setup.md`](windows-setup.md)(Linux 는
[`docs/linux-setup.md`](linux-setup.md)) 에 있다.

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

그다음 자산마다 검사 이력의 **`다시 검사`** 를 누른다. 단추는 **최신 검사 줄과
실패한 줄에만** 있다 — 옛 SBOM 을 새 DB 로 돌릴 까닭이 없다.

- **SBOM 을 다시 업로드할 필요가 없다.** 보관해 둔 원본을 그대로 다시 읽는다.
- 누를 때마다 검사 이력에 **새 줄이 하나** 생긴다 — 원본 검사는 그대로 남는다.
  패키지 목록은 자산마다 최신 검사 것만 남는다.
- **SBOM 생성 시각은 바뀌지 않는다.** 다시 검사는 검사 시각만 새것이다. 그래서
  `30일 넘은 자산` 에서 빠지지 않고, 구역 보고서는 그 자산을 `이 기간에 다시 검사만
  한 자산` 으로 센다 — 서버를 새로 본 것이 아니다.
- **그 자산의 검사가 도는 동안에는 업로드 · 다시 검사를 받지 않는다.** 단추가
  닫히고, 끝나면 열린다. 같은 자산의 검사 둘이 겹치면 끝날 때 서로가 담아 둔
  패키지 목록을 지웠다.
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
| 서버 담당자 | `syft dir:/ --source-name web-01 -o cyclonedx-json > web-01.sbom.json` → 파일만 넘긴다 |
| 이 PC | 자산 상세 → **SBOM 업로드** → **검사 시작** |

SBOM 에는 그 서버에 설치된 패키지 목록과 파일 경로가 담긴다. **반출 승인 절차가
있다면 이 파일이 그 대상이다.**

**`--source-name` 에는 이 도구에 등록한 자산 이름을 넣는다.** 자산 상세의 `SBOM 생성
가이드` 가 그 자산의 이름을 넣은 명령을 낸다. 넣지 않으면 SBOM 대상이 모든 서버에서
`/` 라서, 엉뚱한 자산에 올려도 가를 길이 없다. 넣으면 SBOM 대상이 자산 이름과 다를
때 검사 뒤에 경고가 뜬다 — 막지는 않는다.

보고서 문서 정보의 `SBOM 생성 시각` 은 SBOM 안에 적힌 시각이다(CycloneDX · SPDX).
syft JSON 에는 그 칸이 없어 업로드 시각을 쓰고, 그렇다고 옆에 적는다. 최신 검사도
이 시각으로 고른다 — 예전에 떠 둔 SBOM 을 늦게 올려도 최신 검사가 바뀌지 않고,
자산 개요가 그렇다고 알린다. 이 기능 전(V17 전)에 올린 검사는 SBOM 을 다시 읽지
않아 `업로드 시각으로 대체 (SBOM 생성 시각 확인되지 않음)` 으로 적히고, 해시 · 생성
도구 · 대상은 `확인되지 않음` 이다. 새 SBOM 을 올리면 그때부터 채워진다.

검사가 끝나면 자산 상세의 `취약점` 탭에서 본다. 전사 기준으로 보려면 기둥의
**취약점**, 무엇이 어디 깔려 있나는 **패키지** 다.

엉뚱한 자산에 올렸으면 검사 이력에서 그 검사를 지운다. 지운 것이 그 자산의
최신 검사였으면 **그 전 검사의 보관 SBOM 에서 패키지 목록을 다시 담는다** —
안내에 몇 개를 다시 담았는지 나온다. 다시 담지 못하면(그 전 검사의 보관 SBOM
이 없을 때 등) 까닭이 오류로 나오고, 검사는 그래도 지워진다. 패키지 목록은
다음 검사 때 다시 채워진다.

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

완료로 닫았는데 자산의 최신 완료 검사에 그 패키지의 **해소 건수**(수정 버전이 있는
탐지 · 해당 없음 · 오탐 제외)가 남아 있으면 셋 중 하나로 적는다 — 조치 목록 · 자산의
조치 탭 · 조치 상세 · 취약점 표 · 조치 CSV 가 보고서(자산 5장 · 구역 6장)와 같은
규칙이다. 둘 이상에 해당하면 위의 것이다.

| 적는 말 | 언제 | 그다음 |
|---|---|---|
| `완료 · 검증 대기` | 그 검사의 SBOM 생성 시각이 조치 완료보다 앞 — 고치기 전의 서버를 보고 있다 | 고친 뒤에 뜬 SBOM 을 업로드한다. 그 검사로 다시 가른다 |
| `완료 · 탐지 남음` | 고친 뒤의 SBOM 에 **조치 대상**(등록할 때 그 패키지에 걸려 있던 취약점)이 남았다 | 조치가 덜 됐다. 잘못 닫았으면 대기 · 진행으로 되돌린다(다시 열기) |
| `완료 · 신규 탐지` | 남은 것이 조치 대상이 아니다 — 조치는 됐고 새 취약점이 나왔다 | 옆의 `조치 등록` 으로 다음 회차를 연다 |

조치 대상을 모르는 옛 조치(V19 전에 등록했고 그 검사를 지웠다)는 남은 것을
`완료 · 탐지 남음` 으로 적는다 — 새 것인지 가를 근거가 없다. 등록할 때 그 패키지에
탐지가 없던 조치(조치 상세에 `등록 당시 탐지 없음`)는 남은 것이 모두 조치 대상이
아니므로 `완료 · 신규 탐지` 다. 상태를 저절로 바꾸지는 않는다 — 무엇을 할지는 담당이
정한다.

**조치 회차.** 열린 조치는 (자산, 패키지)에 하나다. 완료한 패키지에서 `조치 등록` 을
누르면 새 조치가 다음 회차로 열리고 `이전 조치` 가 앞 조치를 가리킨다 — 앞 조치의
완료는 그대로 남는다. 구역 보고서의 `기간 중 완료` 는 이력의 완료 줄로 센다. 다시
열기는 잘못 닫은 것을 바로잡을 때만 쓴다 — 다음 회차가 이은 조치는 다시 열거나 지울
수 없다(이은 회차에서 이어서 한다).

**이력.** 바뀐 칸마다 앞뒤 값이 남는다 — 조치는 조치 상태와 담당 · 기한 · 설명, 검토
결과는 고르는 칸과 설명 · 추가 보안 통제 · 결재 문서 번호. 적는 칸은 V19 부터 남는다
— 그 전에 만든 조치 · 검토 결과의 상세는 언제부터인지 각주로 밝힌다.

---

## 6. 보고서와 CSV

| 무엇 | 어디 |
|---|---|
| 자산 한 대 | 보고서 → `자산별 · 최신 검사` 에서 고른다. 6장 · 부록 |
| 구역 · 기간 | 보고서 → 구역·기간. **기간 안에 검사되지 않은 자산을 먼저 이름까지 밝힌다** · 부록 |
| 부록 | 실제 악용 · 심각 취약점과 그 설명의 원문 첫 문장. 해당 없음 · 오탐은 뺀다(목록 장과 같다) |
| CSV | 취약점 · 대응 · 감사 로그 · 패키지 화면 머리. 화면의 필터가 그대로 적용된다 |

인쇄하면 그대로 PDF 가 된다. 산문이 없고 표와 각주뿐이다.

**결재에 올리는 것은 발행본이다.** 보고서는 열 때마다 지금 데이터로 계산한다 — 그래서
문서 머리에 `초안 (발행 전)` 이 찍히고, 문서 정보의 사람 · 시각은 `출력자` · `출력 시각`
(연 계정 · 연 시각)이다. 머리의 **발행**(관리자)을 누르면 그 순간의 문서가 발행본으로
저장된다.

| 발행본에 | |
|---|---|
| 발행 번호 | `2026-0001` — 연도와 그해의 일련번호. 동시에 눌려도 겹치지 않는다 |
| 문서 | 그때 그린 문서 그대로 — 문서 정보에 발행 번호 · 발행 시각 · 발행자. 그 뒤 검토 결과를 적거나 자산을 운영 종료해도 바뀌지 않는다 |
| 발행본 해시 | 문서의 SHA-256. 머리에 찍히고 인쇄에도 나간다. 볼 때마다 다시 대조해, 맞지 않으면 문서를 보이지 않는다 |
| 결재 문서 번호 | 발행한 뒤에 적는다(관리자). 바꾼 것은 이력과 감사 로그에 남는다. 문서 밖이라 해시는 그대로다 |
| 계산 결과 | 그때의 계산(JSON)도 함께 저장한다. 화면으로 내보내지는 않는다 |

- 찾는 곳 — **보고서** 화면의 `발행본`(최근 다섯 개)과 `발행본 전체`, 그리고 지금
  보고서 머리의 `발행본` 줄(같은 검사, 같은 구역 · 기간을 발행한 것).
- **발행본이 가리키는 검사는 지우지 못한다** — 자산 보고서는 그 검사와 6장(이전 검사 ·
  최근 검사 추이)의 검사, 구역 보고서는 3장의 자산마다 기준이 된 검사와 7장 대조에 쓴
  기준선이다. 검사 이력에서 그 줄에 `발행본` 표시가 붙고 `삭제` 단추가 없다.
- **자산을 지워도 발행본은 남는다** — 대상 이름은 발행 때의 것이다. 발행본을 지우는
  길은 없다.
- 인쇄 · PDF 는 초안과 같이 브라우저 인쇄다. 발행본 화면에서 인쇄하면 발행 번호 ·
  결재 문서 번호 · 발행본 해시가 맨 위에 찍힌다.

---

## 7. 백업

| 무엇 | 없으면 |
|---|---|
| `sbomsight` 데이터베이스 | 자산·이력·검토 결과·대응·감사 로그가 전부 사라진다 |
| `SBOMSIGHT_DATA_DIR` (기본은 저장소 폴더의 `data`) | 옛 SBOM 과 grype 원본이 사라져 **다시 검사** 를 못 한다 |
| `config` 의 `keystore.p12` · `env.ps1` (Linux 는 `config/env`) | 다시 만들면 된다 |

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
# Linux — 먼저 내린다: sudo systemctl stop sbomsight (창에서 띄웠다면 Ctrl+C)
cd /경로/SBOMSight
mariadb-dump -u root -p --single-transaction --routines sbomsight --result-file=/backup/before-upgrade.sql
cp target/sbomsight-1.0.0.jar /backup/sbomsight-before-upgrade.jar

git pull
./mvnw clean package -DskipTests
sudo systemctl start sbomsight      # 창에서 띄운다면 ./scripts/run-server.sh
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

### V16 — 조치의 현재 버전을 다시 모은다

현재 버전도 하나(CVSS 가 가장 높은 건의 설치 버전)였다 — 같은 패키지가 두 벌
깔린 자산(서로 다른 앱의 log4j-core 2.14.1 · 2.9.1)에서 한 벌이 조치 어디에도
없었다. V16 은 그 칸을 넓히고(255 → 4000자), 조치를 등록한 검사에서 그 패키지로
탐지된 건의 **설치 버전 전부**를 글자 순으로 다시 모아 덮어쓴다. 검토 결과로
거르지 않는다 — 깔려 있는 버전은 검토와 상관없는 사실이다. 그대로 두는 것:
등록한 검사가 지워졌거나 모르는 조치, 모은 것이 4,000자를 넘는 조치. 기록에
`Migrating schema ... to version "16 - remediation from versions"` 가 한 번 찍힌다.
화면은 둘 이상이면 `현재 버전 N가지` 와 그 목록, CSV 는 `현재 버전 N가지: a · b` 로 적는다.

### V18 — 둘로 갈린 검토 결과를 하나로 합친다

앞서 검토 결과를 찾는 순서가 화면마다 달랐다 — 취약점 표는 CVE 번호를 먼저, 목록 ·
보고서는 주 식별자(GHSA)를 먼저 찾았다. 그래서 GHSA 로 적어 둔 건에 나중에 CVE 가
붙은 뒤 표에서 고치면 같은 취약점의 검토 결과가 두 줄이 됐고, 표와 목록 · 보고서가
서로 다른 결정을 말했다. 이제 모든 화면이 한 규칙으로 찾는다 — 두 번호 중 어느
쪽으로 적혔든 그 탐지의 것이고, 둘 다 있으면 나중에 고친 것이다. V18 은 이미 갈린
두 줄을 합친다.

- **남는 줄** — 나중에 고친 쪽. 지금 값은 그대로다. `처음 기록` 만 둘 중 이른 시각으로
  맞춘다 — 옮겨 온 이력이 처음 기록보다 앞서지 않게.
- **지우는 줄** — 그 이력은 남는 줄로 옮긴다(그때의 시각 그대로). 그 결정(번호 ·
  검토 상태 · 근거 · 대응 방안 · 재검토일)은 남는 줄 이력에 `검토 결과 합침` 한 줄로
  남는다. 설명 · 추가 보안 통제 · 결재 문서 번호는 그때(V19 전) 이력에 담지 않던 칸이라
  감사 로그의 `검토 결과 합침` 에 함께 남는다. 둘 다 계정은 `—` 다 — 사람이 한 일이 아니다.
- **합치지 않는 것** — 같은 취약점이라는 근거(두 번호를 함께 가진 탐지)가 DB 에
  남아 있지 않은 줄, 셋 이상이 엮인 줄. 그대로 두어도 화면은 나중에 고친 것을
  고르므로 서로 어긋나지 않는다.

기록에 `Migrating schema ... to version "18 - merge split analysis"` 가 한 번 찍힌다.
합친 것이 있었는지는 감사 로그의 행위를 `검토 결과 합침` 으로 골라 본다.

### V19 — 조치 회차 · 조치 대상 · 이력

앞서 조치는 (자산, 패키지)에 하나뿐이라, 완료한 패키지에 새 취약점이 나오면 완료된
조치를 다시 열 수밖에 없었고 다시 열면 그 완료가 `기간 중 완료` 에서 사라졌다. 조치가
무엇을 고치려던 것인지도 몰라, 완료 뒤 남은 탐지가 덜 된 것인지 새 것인지 가를 수
없었다(5절의 세 갈래).

- **조치 회차** — (자산, 패키지)의 유일 키를 풀고 회차 · 이전 조치 칸을 더한다. 있던
  조치는 모두 1회차다. 열린 조치가 하나인 것은 앱이 지킨다.
- **조치 대상** — 조치를 등록한 검사에서 그 패키지의 탐지(번호 · 함께 온 CVE · 설치
  버전 · 수정 버전)를 채운다(V15 · V16 과 같은 방식). 등록한 검사가 지워졌거나 모르는
  조치는 비워 둔다 — 조치 상세에 `등록 당시 탐지 — 확인되지 않음` 으로 뜨고, 완료 뒤
  남은 것은 `완료 · 탐지 남음` 으로 적는다.
- **이력** — 조치 이력에 바뀐 칸의 이름과 앞뒤 값을 더하고, 검토 결과 이력의 앞뒤 값
  칸을 255자에서 2,000자로 넓힌다. 그 전에 바뀐 담당 · 기한 · 설명 · 추가 보안 통제 ·
  결재 문서 번호는 이력에 없다 — 지어내 채우지 않는다. 언제부터 남겼는지를 설정 표
  (`app_settings` 의 `history_fields_since`, UTC)에 적고, 그 전에 만든 것의 상세가
  각주로 밝힌다.

기록에 `Migrating schema ... to version "19 - remediation rounds and history"` 가 한 번
찍힌다. V19 를 적용한 뒤 2회차를 연 것이 있으면 옛 jar 만 되돌려서는 안 된다 — 아래
되돌리기대로 DB 도 백업으로 되살린다.

### V20 — 보고서 발행본

보고서를 발행하면 그 순간의 문서 · 계산 결과 · 해시를 저장하는 표 셋(발행본 · 가리키는
검사 · 결재 문서 번호 이력)을 만든다(6절). 옮기는 데이터는 없다 — 업그레이드 전의
보고서에는 발행본이 없고, 그때 결재에 붙인 종이 · PDF 가 그대로 근거다. 자산을 지워도
발행본이 남도록 자산 · 검사에는 FK 를 걸지 않는다.

기록에 `Migrating schema ... to version "20 - report publications"` 가 한 번 찍힌다.
V20 을 적용한 뒤 발행한 것이 있으면 옛 jar 만 되돌려서는 안 된다 — 옛 jar 는 뜨지만
발행본을 볼 화면이 없고, 발행본이 가리키는 검사를 지우는 것도 막지 않는다. 아래
되돌리기대로 DB 도 백업으로 되살린다. 그러면 업그레이드 뒤의 발행본은 사라지므로,
되돌리기 전에 발행본 화면에서 인쇄(PDF)해 둔다.

### V22 — 패키지 유형을 purl 의 이름으로

패키지 화면의 한 줄이 (이름, 유형)이 됐다 — 같은 이름도 npm 과 pypi 면 두 줄이고, 버전
분포와 취약점 수가 서로 섞이지 않는다. 유형은 purl 에서 따는데, purl 이 없는 원소는
syft 의 이름(`java-archive` · `python` …)이 그대로 담겨 같은 패키지가 두 줄로 갈렸다.
V22 는 그런 행만 purl 의 이름(`maven` · `pypi` …)으로 옮긴다. purl 이 있는 행과 표에 없는
유형(`binary` …)은 그대로다. 기록에 `Migrating schema ... to version "22 - component type
purl names"` 가 한 번 찍힌다. 옛 jar 로 되돌려도 뜬다 — 그 jar 는 같은 이름을 다시 한
줄로 합쳐 보인다.

### V23 — 탐지의 수정 버전 · 후보 전부

grype 은 수정 버전 후보를 여럿 줄 때가 있다 — NVD(CPE)로 맞춘 건(binary 로 찾은
openssl · curl …)은 갈래마다 하나씩이다. 진짜 grype(0.115.0)로 openssl 3.0.13 · curl 8.5.0
바이너리를 검사하면 86건 중 49건이 4~7가지였다(CVE-2024-5535 는 1.0.2zk · 1.1.1za ·
3.0.15 · 3.1.7 · 3.2.3 · 3.3.2). 앞서 탐지에는 그중 첫 번째만 담아, 취약점 화면 · 보고서 ·
조치의 목표가 `3.0.13 → 1.0.2zk` 처럼 다른 갈래의 버전 하나를 말했다. 이제 후보 전부를
적는다 — 하나면 그 버전, 여럿이면 `수정 버전 N가지` 와 그 목록(글자 순 — 마지막 것이 가장
높은 버전이라는 뜻이 아니다).

V23 은 칸을 넓히고(255 → 1,000자) 이미 담긴 탐지를 상세(grype 이 준 원문의 fixVersions)에서
다시 모은다. 조치 대상도 그 탐지의 것으로 바꾸고, 조치의 목표 버전은 적혀 있던 것을 지우지
않고 등록 때 세던 탐지의 나머지 후보를 더한다 — 지금 해당 없음 · 오탐으로 적힌 탐지의 것은
더하지 않는다. 그대로 두는 것: 상세가 없거나 읽을 수 없는 탐지, 모은 것이 칸을 넘는 것,
등록한 검사가 지워진 조치, 목표에 따옴표나 역슬래시가 든 조치. 이미 발행한 보고서는 그
순간의 문서라 바뀌지 않는다. 기록에 `Migrating schema ... to version "23 - finding fix
versions"` 가 한 번 찍힌다.

옛 jar 만 되돌리면 뜨기는 하지만, 취약점 화면은 후보를 띄어 쓴 한 줄로 보이고 보고서
3장은 탐지마다 이어진 목록을 버전 하나로 세어 `수정 버전 N가지` 의 수가 틀린다(위의 openssl
은 60가지가 22가지로). 아래 되돌리기대로 DB 도 백업으로 되살린다.

### V24 — 패키지 식별자 · 같은 이름의 다른 패키지를 가른다

같은 패키지인지를 **패키지 식별자** 하나로 가른다 — purl 에서 버전 · 한정자(`?arch=…`) ·
하위 경로(`#…`)를 뗀 것이다(`pkg:maven/com.fasterxml.jackson.core/jackson-databind`).
한정자는 V25 부터 유형마다 가른다 — classifier 처럼 패키지를 가르는 것은 남는다(아래 V25).
네임스페이스(Maven groupId · npm scope · 배포판)는 넣는다. purl 이 없는 원소는
`pkg:<유형>/<이름>`(유형을 모르면 `pkg:/<이름>`)이다 — 네임스페이스를 지어내지 않으므로
groupId 를 모르는 jar 는 purl 이 있는 같은 이름과 합치지 않고 패키지 화면에 따로 선다.
버전을 넣지 않으므로 패치해도 검토 결과와 조치는 그대로 이어진다.

앞서 기준이 셋이었다 — 패키지 화면은 (이름, 유형), 검토 결과와 조치는 이름. 그래서 한
자산에 npm 의 semver 와 PyPI 의 semver 가 함께 있으면 npm 쪽에 적은 `해당 없음` 이 PyPI
쪽의 같은 번호 탐지까지 목록 · 보고서에서 뺐고, 한 쪽에 연 조치가 두 패키지의 탐지를
등록 당시 건수 · 버전에 넣었다. groupId 만 다른 두 jackson-databind 는 유형까지 같아 패키지
화면에서도 한 줄이었다. 이제 탐지 · 패키지 화면 · 검토 결과(자산, 번호, 식별자에 하나) ·
조치(조치 대상은 그 조치를 따른다) · 보고서의 줄 · 부록의 패키지 칸 · 6 · 7장 증감 대조 ·
취약점 화면의 묶은 줄과 링크(`pkg=`) · CSV(`패키지 식별자` 열)가 같은 식별자를 쓴다. 화면은
이름 아래에 식별자를 작게 적는다.

**있던 기록은 근거가 있을 때만 식별자를 받는다.** V24 는 탐지 · 패키지 행의 식별자를
purl 에서 만들고, 이름밖에 없는 검토 결과 · 조치는 그 기록이 **앞서 붙던 탐지**로 가른다.

| 기록 | 식별자를 받는 때 | 아니면 |
|---|---|---|
| 검토 결과 | 그 자산의 검사 전부에서 이름과 번호(주 식별자 또는 함께 온 CVE)가 같은 탐지가 한 패키지다 | 비운다 — 같은 이름의 패키지가 둘 이상이었거나, 그런 탐지가 남아 있지 않다(검사를 지웠다 · 위험 수용에서 옮긴 기록) |
| 조치 | 등록한 검사의 그 이름 탐지가 한 패키지다 | 비운다 — 둘 이상이었거나, 등록한 검사가 지워졌거나 모른다(V15 전의 조치) |

이름이 다른 둘이 한 식별자에 모이면(같은 purl 을 syft 가 다른 이름으로 적은 것) 둘 다
비운다 — 하나를 고르는 것이 곧 합치는 것이다. **비운 기록은 지우지도 아무 패키지에나
붙이지도 않는다.** 어느 탐지에도 붙지 않고, 대응 화면 · 자산의 조치 탭 · 상세에
`패키지 확인 필요` 로 남는다(대응 화면의 탭에 그 건수가 뜬다). 사람이 할 일은 하나다 —
그 패키지의 탐지 줄에서 검토 결과를 다시 적거나 조치를 다시 등록한다. 옛 기록은 근거
문서로 그대로 두어도 되고, 조치는 상세의 `삭제` 로 지워도 된다. 비운 기록을 한 번에 보려면:

```sql
SELECT a.name, fa.cve, fa.package_name, fa.state FROM finding_analysis fa
  JOIN assets a ON a.id = fa.asset_id WHERE fa.package_key IS NULL;
SELECT a.name, r.package_name, r.round_no, r.status FROM remediations r
  JOIN assets a ON a.id = r.asset_id WHERE r.package_key IS NULL;
```

**달라지는 수.** 비운 검토 결과가 빼던 탐지는 목록과 보고서의 목록 장에 다시 보인다 —
다른 패키지의 것까지 빼던 것이 풀린 것이다. 비운 조치는 보고서 3 · 5장의 줄에 붙지 않아
그 패키지가 `미등록` 으로 센다. 이미 발행한 보고서는 그 순간의 문서라 바뀌지 않는다.

V24 는 탐지 · 패키지 행을 한 번씩 다시 쓴다 — 행이 많으면 오래 걸린다(백업 먼저). 기록에
`Migrating schema ... to version "24 - package key"` 가 한 번 찍힌다. 옛 jar 로 되돌리면
옛 jar 는 식별자를 모르고 이름으로 다시 붙인다 — 아래 되돌리기대로 DB 도 백업으로 되살린다.

### V25 — 패키지 식별자 · 한정자를 유형마다 가른다

V24 는 purl 의 한정자(`?…`)를 통째로 버렸다. 그래서 Maven 의 classifier · type 만 다른 아티팩트 —
netty 의 네이티브 jar(`?classifier=linux-x86_64`)와 순수 jar, 라이브러리의 test-jar
(`?type=test-jar`)와 jar — 가 한 식별자였다. 한쪽에 적은 `해당 없음` 이 다른 쪽의 같은 번호 탐지까지
목록 · 보고서에서 뺐고, 한쪽에 연 조치가 다른 쪽의 탐지를 등록 당시 건수 · 버전에 넣었다.

이제 식별자는 purl 을 규격의 참조 구현(packageurl-java 1.5.0)으로 읽은 정규형에서 **버전 · 하위
경로와, 패키지를 가르지 않는 한정자**를 뗀 것이다. 식별자는 버전을 넘어 같은 패키지 — 검토 결과 ·
조치가 붙는 단위 — 이므로 한정자를 이렇게 가른다(purl 규격의 유형 정의를 따른다).

- **남긴다** — 버전이 바뀌어도 이어지는 다른 갈래(Maven classifier · type, OCI arch, Conan user ·
  channel · 설정 · 옵션, nix output, deb 의 `arch=source` — 원천 패키지)와, 같은 이름이 출처마다
  다른 패키지인 유형의 출처(아래 표의 오른쪽).
- **뗀다** — 한 판을 가리키는 것(그 버전의 개정 · 빌드 해시 · 그 판의 파일). 남기면 올릴 때마다
  식별자가 바뀌어 검토 결과 · 조치가 버전을 넘지 못한다. 같은 패키지가 놓인 모양(배포판 패키지의
  arch · distro)과 사본을 받아 온 곳(거울이 흔하다)도 뗀다.

| 유형 | 떼는 한정자 | 남기는 출처 |
|---|---|---|
| 모든 유형 | `repository_url` · `download_url` · `vcs_url` · `file_name` · `checksum` — 받아 온 곳 · 그 판의 파일 | 오른쪽 칸의 유형만 |
| deb | `arch`(`source` 는 남는다) · `distro` · `upstream` | |
| apk · alpm | `arch` · `distro` · `upstream` | |
| rpm | `arch` · `distro` · `epoch` · `upstream` | |
| bitnami | `arch` · `distro` | |
| conda | `build` · `channel` · `subdir` · `type` | |
| gem | `platform` | |
| oci | `tag` | `repository_url` — 이름이 저장소 이름의 마지막 조각뿐이다(`docker.io/library/debian` 과 `ghcr.io/debian` 이 둘 다 `debian`) |
| nix | `outputhash` · `drvpath` | |
| vcpkg | `port_version` · `port_revision`(syft 의 이름) · `repository_revision` · `triplet` · `features` · `vcs_url` 의 git-tree | `repository_url` — 포트를 정의한 레지스트리(기본 레지스트리는 뗀다) · `vcs_url` 의 저장소(그 레지스트리면 뗀다) |
| pub | `hosted_url` | |
| conan | `rrev` · `prev` | |
| generic | `vcs_url` 의 개정(`@…`) | `vcs_url` 의 저장소 · 하위 경로 — 등록소가 없다 |
| yocto | `layer_version` | `repository_url` — 레시피를 낸 레이어 |
| otp | | `repository_url` — 앱 소스의 출처 |
| cpan | `distpath` · `ext` | |

vcpkg 의 git-tree 와 Conan 의 `rrev` · `prev` 는 남기지 않는다. 셋 다 그 버전의 레시피 · 바이너리를
고정하는 값이다 — vcpkg 의 버전 DB 는 (포트, 버전, port-version) 하나에 git-tree 하나를 두고 덮어쓰지
않고, Conan 의 개정은 레시피 · 바이너리 내용의 해시다(줄바꿈만 달라도 바뀐다). 같은 이름 · 버전에서
이것만 다른 purl 은 같은 식별자다. 레시피를 정의한 곳이 다른 것(사내 레지스트리 · 오버레이 포트)은
레지스트리로 가른다.

- Maven 의 `type=jar` 는 기본값이라 뗀다 — `?type=jar` 와 적지 않은 것은 같은 패키지다. classifier
  와 jar 가 아닌 type 은 남는다(`pkg:maven/io.netty/netty-transport-native-epoll?classifier=linux-x86_64`).
- **표에 없는 한정자는 남긴다.** 모르는 것을 버리면 다른 패키지를 합칠 수 있고, 남기면 줄이 갈릴
  뿐이다. 남은 한정자는 키 순으로 적는다.
- 글자는 규격대로 맞춘다 — 유형은 소문자, PyPI 이름은 소문자에 `_` 를 `-` 로(`PyYAML` →
  `pyyaml`), bitbucket · deb · github · golang 의 이름과 bitbucket · deb · github · golang · rpm 의
  네임스페이스는 소문자, 네임스페이스 · 이름의 `@` · 한글 같은 글자는 `%XX`(`pkg:npm/%40types/node`).
  이름 곁에 적는 네임스페이스는 풀어서 적는다(`@types`).
- 규격에 맞지 않는 purl(같은 한정자가 둘 · 깨진 `%XX`)은 적힌 좌표에서 버전을 떼고 **한정자는
  남긴다** — 위 표가 버리는 것만 버리고, 겹친 키는 하나로 줄이지 않는다
  (`pkg:maven/g/a?classifier=x&classifier=y`). 앞서 한정자를 통째로 버려 classifier 없는 순수 jar 와
  한 식별자였다. 같은 purl 은 늘 같은 식별자다. purl 이 없는 원소는 V24 와 같다 —
  `pkg:<유형>/<이름>`, 네임스페이스를 지어내지 않는다.
- 패키지 검색(패키지 화면 · 자산의 `설치된 패키지`)이 이름 말고도 네임스페이스로 찾는다 — groupId
  (`org.apache.logging.log4j`), npm scope(`@types`), Maven 좌표(`groupId:artifactId`).

**있던 기록은 근거가 있을 때만 새 식별자로 옮긴다.** V25 는 SQL 이 아니라 자바 마이그레이션이다 —
앱이 새 탐지에 쓰는 규칙(PackageKey)을 그대로 불러, 같은 SBOM 을 다시 검사한 탐지가 옮긴 기록에
이어진다. 표 구조는 바꾸지 않고 한 트랜잭션으로 돈다.

| 기록 | 새 식별자를 받는 때 | 아니면 |
|---|---|---|
| 탐지 · 패키지 | 언제나 — 행의 purl · 유형 · 이름에서 다시 만든다(purl 이 칸을 꽉 채운 행은 아래 `#truncated`) | — |
| 검토 결과 | 그 자산의 검사 전부에서 옛 식별자 · 번호(주 식별자 또는 함께 온 CVE)가 같은 탐지의 새 식별자가 하나다 | 비운다 — 둘 이상(classifier 만 다른 둘에 붙던 것)이거나, 그런 탐지가 남아 있지 않다 |
| 조치(회차마다) | 등록한 검사의 옛 식별자 탐지의 새 식별자가 하나다 | 비운다 — 둘 이상이거나, 등록한 검사가 지워졌다 |

옛 식별자가 다른 기록들이 한 새 식별자에 모이면(V24 에서 `pkg:pypi/PyYAML` 과 `pkg:pypi/pyyaml`
로 갈렸던 둘) 모두 비운다 — 하나를 남기는 것이 곧 합치는 것이다. **비운 기록은 V24 가 비운 것과
같이 다룬다** — 지우지 않고, 어느 탐지에도 붙지 않으며, `패키지 확인 필요` 로 남는다. 위 V24 의
SQL(`package_key IS NULL`)이 V24 · V25 가 비운 것을 함께 보여 준다. 사람이 할 일도 같다 — 그
패키지(변형)의 탐지 줄에서 다시 적거나 다시 등록한다.

**purl 칸(512자)보다 긴 purl.** 칸에는 잘려 담기지만, 이제 식별자는 자르기 전 purl 로 만든다(탐지 ·
패키지 · SBOM 적재). 앞선 판은 잘린 글자로 만들었다 — 칸 뒤로 잘려 나간 classifier 를 모른 채 순수
jar 와 합쳐질 수 있었다. 그렇게 담긴 행의 원래 purl 은 DB 어디에도 없다(탐지의 상세에도 purl 은 담지
않는다). V25 는 그 행(purl 이 칸을 꽉 채운 행)을 짐작해 다시 가르지 않고, 잘린 글자로 만든 식별자 뒤에
`#truncated` 를 단다(`pkg:maven/org.example/trunc#truncated`) — 어느 정상 식별자와도 겹치지 않아 다른
패키지의 검토 결과 · 조치가 붙지 않는다. 그 행에 붙던 검토 결과 · 조치는 위의 규칙 그대로 가른다 —
붙던 탐지가 잘린 행뿐이면 그 식별자로 따라가고, 순수 jar 처럼 다른 패키지와 함께 붙던 것은 비운다.
꼭 512자인 purl 은 잘리지 않았어도 가를 수 없어 같이 다룬다(드물다).

되살리는 길은 **`다시 검사`** 다 — 보관된 SBOM 에는 원래 purl 이 있어, 새 검사의 탐지 · 패키지는 제
식별자를 받는다. `#truncated` 식별자로 따라간 검토 결과 · 조치는 새 탐지에 붙지 않으므로 그 패키지의
탐지 줄에서 다시 적는다. 그런 행이 있는지는:

```sql
SELECT a.name, f.cve, f.package_name, f.package_version FROM findings f
  JOIN scans s ON s.id = f.scan_id JOIN assets a ON a.id = s.asset_id
  WHERE f.package_key LIKE '%#truncated';
SELECT a.name, fa.cve, fa.package_name FROM finding_analysis fa
  JOIN assets a ON a.id = fa.asset_id WHERE fa.package_key LIKE '%#truncated';
```

조치는 회차마다 가른다. 앞 회차를 등록할 때는 순수 jar 뿐이었고 뒤 회차 때 네이티브 jar 가 들어와
있었다면, 앞 회차는 순수 jar 의 식별자를 받고 뒤 회차만 빈다. 그 패키지에서 조치를 다시 등록하면
식별자를 받은 앞 회차의 다음 회차로 선다 — 비운 뒤 회차와 회차 번호가 겹칠 수 있다.

**달라지는 수.** 패키지 화면 · 취약점 화면의 패키지별 줄 · 보고서의 줄이 classifier · type 마다
갈린다(줄이 는다). 비운 검토 결과가 빼던 탐지는 목록과 보고서에 다시 보이고, 비운 조치의 패키지는
`미등록` 으로 센다. 식별자의 글자만 바뀐 패키지(npm scope 의 `@` → `%40`, PyPI 이름 맞춤)는 탐지 ·
검토 결과 · 조치가 함께 옮겨져 그대로 이어진다. CSV 의 `패키지 식별자` 열 글자도 바뀐다 — 앞서
내려받은 CSV 와 식별자로 맞춰 보던 표는 다시 맞춘다. 이미 발행한 보고서는 그 순간의 문서라 바뀌지
않는다. 패키지 화면의 버전별 취약점 수는 이제 (식별자, 버전)으로 센다 — 같은 purl 을 SBOM 과
grype 이 다른 이름으로 적었거나 자산마다 이름이 달랐던 버전의 수가 늘 수 있다(앞서 줄에 찍힌 이름
하나의 탐지만 셌다). purl 도 유형도 없는 원소의 줄(`pkg:/이름`)은 이름 · 버전이 같은 탐지 가운데
어느 줄도 갖지 않은 것을 받는다 — 이름은 대소문자를 가리지 않는다(`BusyBox` 탐지를 `busybox` 줄이
받는다). 대소문자만 다른 그런 줄이 여럿이면 한 줄(식별자 글자 순으로 첫 줄)만 받는다 — 화면 ·
`취약점 있는 것만` · CSV 가 같은 줄에 같은 수를 센다.

V25 는 탐지 · 패키지 행을 전부 읽고 식별자가 바뀐 행만 고친다 — 행이 많으면 오래 걸린다(백업
먼저). 한꺼번에 메모리에 올리지는 않는다 — 탐지 · 패키지는 5,000행씩, 검토 결과 · 조치는 자산을
5,000건쯤씩 묶어 가른다(한 자산의 기록은 쪼개지 않는다 — 유일 키와 "한 식별자에 모인 기록" 이 자산
안의 일이다). 묶음마다 커밋하지 않는다 — 한 트랜잭션이라 중간에 멈추면 V24 의 상태로 돌아간다. 다시
돌려도 바뀌는 것이 없다. 기록에 `Migrating schema ... to version "25 - package key qualifiers"` 와
`패키지 식별자를 다시 만들었습니다 (V25) — 탐지 · 패키지 · 검토 결과 옮김 / 비움 · 조치 옮김 / 비움 ·
자산 묶음` 의 수가 한 번 찍힌다. 비운 기록이 있으면 그 id(앞 스무 개)가 `WARN` 줄에 함께 찍힌다.

**의존성이 하나 늘었다** — `packageurl-java` 1.5.0(MIT, 의존물 없음). 소스로 빌드하는 오프라인 PC 는
`~\.m2` 에 그것이 있어야 한다. 없으면 빌드가 `Could not resolve dependencies ...
com.github.package-url:packageurl-java:jar:1.5.0` 로 멈춘다 — 인터넷 되는 장비에서 이 판을 한 번
빌드해 `~\.m2` 를 다시 반입하거나, 빌드된 jar 를 반입한다(offline-operations.md).

옛 jar 로 되돌리면 옛 jar 는 새 검사의 탐지에 V24 의 식별자를 단다 — V25 가 옮긴 검토 결과 ·
조치(한정자가 든 것, 글자가 바뀐 것)가 새 탐지에 붙지 않는다. 아래 되돌리기대로 DB 도 백업으로
되살린다.

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
# Linux — 먼저 내린다: sudo systemctl stop sbomsight (창에서 띄웠다면 Ctrl+C)
cd /경로/SBOMSight
mariadb -u root -p -e "DROP DATABASE sbomsight; CREATE DATABASE sbomsight CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
mariadb -u root -p sbomsight < /backup/before-upgrade.sql
cp /backup/sbomsight-before-upgrade.jar target/sbomsight-1.0.0.jar
sudo systemctl start sbomsight      # 창에서 띄운다면 ./scripts/run-server.sh
```

V15 는 이 길을 MariaDB 10.11 에서 끝까지 밟아 보았다. V14 인 DB 를 백업하고, 새
jar 로 V15 를 적용한 뒤 되살렸다. 되살린 DB 는 마이그레이션 14까지로 돌아갔고,
목표 버전과 한글 값도 원래대로였다. 이전 jar 도 그 DB 로 떴다.
V16 은 절반만 밟았다 — V15 인 DB 를 백업하고 새 jar 로 V16 을 적용한 뒤, 그 백업을
다른 DB 에 되살려 마이그레이션 15까지 · 같은 행 수로 돌아가는 것까지 보았다. 이전
jar 로 띄워 보지는 않았다.
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
**MySQL 8 은 리눅스에서만 돌려 보았다.** V1~V23 을 MySQL 8.0.46(Ubuntu 패키지를
풀어서 띄운 것)의 빈 DB 와 데이터가 있는 DB 양쪽에 태웠고(`tests/check-migrations.sh`),
그 스키마 위에서 앱 전체 시험 534개가 통과했다(`tests/check-mariadb.sh`, 2026-10-22). V24 는
MySQL 8 에서 `tests/check-migrations.sh` 만 돌렸다(빈 DB · 데이터가 있는 DB, 2026-10-22) — V24
스키마 위의 앱 전체 시험은 MariaDB 10.11 에서만 돌렸다(554개, 2026-10-23). V25(자바
마이그레이션)도 같다 — `tests/check-migrations.sh` 는 MariaDB 10.11.14 · MySQL 8.0.46 양쪽(빈 DB ·
데이터가 있는 DB, 고친 수까지 같음), 앱 전체 시험은 MariaDB 10.11 에서만(572개, 2026-10-24). 윈도우판
MySQL 8 에서는 돌려 보지 못했다 — 업그레이드한 뒤 기록의 마이그레이션 줄
(`Successfully applied`)과 대응 화면의 현재 · 목표 버전을 먼저 보고, 이상하면 8절의
되돌리기로 돌아간다.
