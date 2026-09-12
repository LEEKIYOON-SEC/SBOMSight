# 오프라인 · 폐쇄망 운영

"폐쇄망" 은 두 가지 다른 이야기다. 섞으면 혼란스러우므로 갈라서 적는다.

1. **검사 대상 서버가 폐쇄망에 있다** — 기본 가정이다. 대상 서버에서 SBOM 만
   반출하면 된다.
2. **SBOMSight 이 도는 PC 자체가 오프라인이다** — grype 취약점 DB 를 미리
   반입해 두어야 한다.

---

## 1. 검사 대상이 폐쇄망에 있는 경우 (기본)

SBOMSight 은 대상 서버에 붙지 않는다. **파일만 받는다.**

```
[폐쇄망 서버]                              [SBOMSight PC]
 syft 로 SBOM 생성
 └─ JSON 반출 ───────── 매체 ────────────→ 자산에 업로드 → grype → 이력·보고서

[폐쇄망 서버]                              [인터넷 되는 구간]
 dnf localinstall  ←──── 매체 ──────────── dnf download --resolve --alldeps
```

### 대상 서버에서 SBOM 만들기

syft 바이너리를 미리 반입해 두고 대상 서버에서 돌린다.

```bash
syft dir:/ -o cyclonedx-json > web-01.sbom.json                  # 파일시스템 전체
syft registry.internal/app:1.2 -o cyclonedx-json > app.sbom.json  # 이미지
```

만든 JSON 만 반출한다. **SBOM 에는 설치 패키지 목록과 파일 경로가 담긴다.**
반출 승인 절차가 있다면 그 대상이 된다.

### 보고서가 주는 것과 주지 않는 것

보고서의 조치 대상 표는 **패키지 · 현재 버전 → 목표 버전 · 해소 건수** 까지다.
전부 grype 이 낸 값이고, 그 이상은 지어내지 않는다.

**패치 명령은 만들어 주지 않는다.** 배포판·아키텍처·사내 리포지터리 구성에 따라
달라지고, 그것을 도구가 짐작해 적으면 틀린 지시가 문서에 실린다. 아래는 RPM
계열의 일반적인 절차이며 **사람이 확인하고 쓰는 참고 자료** 다.

```bash
# 1. 인터넷 가능 구간에서 대상 RPM 과 의존성을 함께 받는다.
#    (대상과 같은 배포판·아키텍처에서 수행해야 한다)
dnf download --resolve --alldeps --destdir ./rpms <package>

# 2. 매체로 반입한다.

# 3. 무결성과 서명을 확인한다.
sha256sum -c checksums.txt
rpm -K ./rpms/*.rpm          # NOT OK 가 나오면 설치하지 않는다
rpm -qa gpg-pubkey           # 벤더 GPG 키 등록 확인

# 4. 설치한다.
dnf localinstall ./rpms/*.rpm
#    다건이거나 반복 배포라면 로컬 리포지터리로:
createrepo_c ./rpms
dnf --disablerepo='*' --enablerepo='local-patch' upgrade <package>

# 5. 결과를 확인하고 필요한 서비스를 재기동한다.
rpm -q <package>             # 기대값: 보고서의 목표 버전 이상
systemctl status <service>
```

### 조치가 실제로 끝났는지 확인하는 방법

**SBOM 을 다시 떠서 올린다.** 그것이 유일한 확인 방법이다.

```bash
syft dir:/ -o cyclonedx-json > web-01.sbom.json   # 패치 후 다시
```

같은 자산에 올리면 보고서의 **지난 검사 대비** 에 해소·신규·유지가 나온다.

> **웹의 `다시 검사` 는 이 목적이 아니다.** 그것은 보관된 옛 SBOM 을 갱신된
> 취약점 DB 로 다시 돌리는 것이다 — *서버는 그대로인데 DB 가 새로 알게 된 것*
> 을 본다. 서버를 패치했으면 SBOM 을 새로 떠야 한다. 둘을 섞으면 패치하지
> 않았는데 해소된 것으로 읽거나 그 반대가 된다.

---

## 2. SBOMSight PC 자체가 오프라인인 경우

오프라인에서 **되는 것** 과 **안 되는 것** 을 먼저 가른다.

| | 인터넷 필요 |
|---|---|
| 화면·보고서·CSV | **아니오** — 글꼴을 저장소에 담아 직접 서비스한다 |
| SBOM 업로드 · grype 검사 | **아니오** — 반입한 취약점 DB 로 돈다 |
| 자산·이력·조치·감사 로그 | **아니오** — 전부 로컬 MySQL |
| grype 취약점 DB 갱신 | **예** — 아래 절차로 반입한다 |
| grype · syft 설치 | **예** — 또는 실행 파일을 반입한다 |

외부로 나가는 통신은 없다. 이 도구는 AI 도, 외부 위협정보 수집도 쓰지 않는다 —
EPSS·KEV 를 포함해 화면에 뜨는 모든 값은 **grype 이 그 출력에 담아 준 것** 이다.

### grype 취약점 DB 반입

**먼저 양쪽 grype 판을 맞춘다.** DB 에는 스키마 번호가 있고 grype 은 자기가 아는
스키마만 읽는다. 판이 다르면 반입해도 안 쓰이거나 갱신을 다시 시도한다.

인터넷 되는 장비에서:

```bash
grype version                    # 판을 적어 둔다
grype db update
grype db status
```

```
Location:  /root/.cache/grype/db/5     ← 이 줄을 본다
Built:     2026-03-09 00:31:20 +0000 UTC
Schema:    5
Status:    valid
```

`Location` 의 **마지막 숫자(스키마) 를 뺀 위쪽 폴더** 가 캐시 디렉터리다. 위
예라면 `/root/.cache/grype/db` 이고, 스키마 폴더째로 통째 담는다.

```bash
tar czf grype-db.tar.gz -C ~/.cache/grype db      # db/5/... 가 들어간다
```

Windows 는 `grype db status` 의 `Location` 이
`C:\Users\<사용자>\AppData\Local\grype\db\5` 처럼 나온다.

```powershell
grype db status
# Location 에서 마지막 \5 를 뺀 경로를 통째로 복사한다
Copy-Item "$env:LOCALAPPDATA\grype\db" -Destination D:\반입\grype-db -Recurse
```

오프라인 장비에 같은 자리로 풀거나 복사한 뒤, `config\env.ps1` 에 아래를 더한다.

```powershell
# 갱신을 시도하지 않는다. 오프라인에서 시도하면 매번 시간 초과를 기다린다.
$env:GRYPE_DB_AUTO_UPDATE           = 'false'
$env:GRYPE_CHECK_FOR_APP_UPDATE     = 'false'
# 반입한 캐시 디렉터리 — 스키마 폴더(\5)의 **부모** 를 적는다
$env:GRYPE_DB_CACHE_DIR             = "$env:LOCALAPPDATA\grype\db"
# DB 가 오래되어도 거부하지 않게 한다 (기본 120h = 5일)
$env:GRYPE_DB_MAX_ALLOWED_BUILT_AGE = '720h'
```

> 경과 시간을 아예 보지 않게 하려면 `$env:GRYPE_DB_VALIDATE_AGE = 'false'` 다.
> 다만 그러면 DB 가 얼마나 낡았는지 grype 이 알려 주지 않는다. 넉넉한 상한을
> 두는 쪽을 권한다.

`run-server.ps1` 이 `config\env.ps1` 을 읽은 뒤 java 를 띄우고, grype 는 그
프로세스의 자식으로 돌아 **이 환경변수를 그대로 물려받는다.** 애플리케이션이
따로 넘기는 것이 아니라 상속이므로, 같은 터미널에서 `grype db status` 로 확인한
결과가 곧 검사에 쓰이는 상태다.

### 확인

```powershell
grype db status
```

`Status: valid` 와 반입한 `Built` 날짜가 나와야 한다. 그 뒤 웹의
**설정 → 도구 상태** 에서도 grype 판이 잡히는지 본다.

> `grype db import <archive>` 를 쓸 수도 있다. grype 버전에 따라 받는 아카이브
> 형식이 다르므로 **반출·반입 양쪽을 같은 버전으로** 맞추는 편이 안전하다.

### DB 기준일은 결과와 함께 저장된다

검사마다 grype 판과 취약점 DB 기준일을 함께 저장한다. 몇 달 뒤 같은 SBOM 의
결과가 달라진 이유를 설명할 수 있어야 하기 때문이다. 화면과 보고서 머리에
그대로 찍힌다.

구역 보고서는 한 걸음 더 간다 — **기간 안의 검사가 서로 다른 grype 판이나 다른
DB 기준일로 돌았으면 그 사실을 보고서에 적는다.** 새 판이 규칙을 더 가지면 같은
서버에서도 탐지가 늘고, 그것을 서버가 나빠진 것으로 읽으면 안 된다.

### 오래된 DB 로 운영할 때

반입 주기가 길어지면 판정의 신선도가 떨어진다. 그 사실을 숨기지 않는 것이
이 도구의 방침이지만, **"DB 가 오래되었다" 를 화면이 경고해 주지는 않는다.**
DB 기준일은 찍히므로 보고서를 받는 사람이 읽을 수 있다. 반입 주기는 운영
규정으로 정해 두는 편이 안전하다.

---

## 반입해야 하는 것 요약

| 무엇 | 크기 | 주기 |
|---|---|---|
| JDK 21 설치 파일 | 약 190MB | 한 번 |
| MySQL 8 설치 파일 | 약 450MB | 한 번 |
| SBOMSight 소스 (또는 빌드된 jar) | 약 10MB / 약 60MB | 갱신할 때마다 |
| Maven 의존성 | 약 80MB | 한 번 (`~\.m2` 를 통째로 반입) |
| grype 실행 파일 | 약 30MB | 판을 올릴 때 |
| syft 실행 파일 (대상 서버용) | 약 30MB | 판을 올릴 때 |
| **grype 취약점 DB** | **약 150MB** | **정기적으로** |

> 오프라인에서 `.\mvnw.cmd package` 를 돌리려면 의존성이 이미 `~\.m2` 에 있어야
> 한다. 인터넷 되는 장비에서 한 번 빌드한 뒤 `%USERPROFILE%\.m2\repository` 를
> 통째로 반입하는 것이 가장 확실하다. 또는 **빌드된 jar 만 반입** 해도 된다 —
> `target\sbomsight-1.0.0.jar` 하나에 의존성이 다 들어 있다.

---

## 환경변수 요약 (오프라인 관련)

| 변수 | 기본값 | 용도 |
|---|---|---|
| `GRYPE_DB_AUTO_UPDATE` | — | `false` 로 두면 DB 갱신을 시도하지 않는다 |
| `GRYPE_CHECK_FOR_APP_UPDATE` | — | `false` 로 두면 버전 확인 요청을 하지 않는다 |
| `GRYPE_DB_CACHE_DIR` | — | 반입한 DB 위치 |
| `GRYPE_DB_MAX_ALLOWED_BUILT_AGE` | `120h` | DB 허용 경과 시간 |
| `GRYPE_DB_VALIDATE_AGE` | `true` | `false` 면 경과 시간을 보지 않는다 |
| `SBOMSIGHT_GRYPE` | `grype` | PATH 에 없을 때 grype 전체 경로 |
| `SBOMSIGHT_GRYPE_TIMEOUT` | `60` | grype 제한 시간(분) |
| `SBOMSIGHT_DATA_DIR` | `./data` | SBOM 원본과 grype 결과 보관 위치 |

설정 전체는 [`README.md`](../README.md) 와
[`scripts/env.example.ps1`](../scripts/env.example.ps1) 에 있다.
