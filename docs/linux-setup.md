# Linux 설치 가이드

Ubuntu 24.04 서버에 SBOMSight 를 처음부터 설치해 **서비스로** 띄우는 절차다. 위에서부터
순서대로 따라간다. 각 단계 끝의 **확인** 을 통과하고 다음으로 넘어간다. 윈도우는
[`docs/windows-setup.md`](windows-setup.md).

이 도구는 **Java(Spring Boot) + MariaDB/MySQL** 로 돌고 **HTTPS** 로만 열린다. 화면을 쓰는
법(구역 · 자산 · 업로드 · 보고서)은 운영체제와 상관없으므로
[윈도우 가이드 12단계](windows-setup.md#12단계--첫-한-바퀴) 를 그대로 따른다.

> **무엇을 실제로 돌려 보았는가는 맨 아래 [확인한 것 · 못 한 것](#확인한-것--못-한-것) 에
> 적었다.** RHEL 계열 명령과 systemd 로 실제로 띄우는 것은 확인하지 못했다.

---

## 배치

계정 둘을 가른다. **소스는 설치하는 사람이, 비밀번호와 쌓이는 자료는 서비스 계정이**
가진다. 서비스 계정은 로그인하지 못한다.

| 무엇 | 어디 | 누구 것 |
|---|---|---|
| 소스 · 빌드한 jar | `/opt/sbomsight/SBOMSight` | 설치하는 사람 |
| 설정(`config/env`) · 인증서 | `/opt/sbomsight/SBOMSight/config` | `sbomsight` · 600 |
| 올린 SBOM · grype 결과 | `/var/lib/sbomsight/data` | `sbomsight` |
| grype 취약점 DB | `/var/lib/sbomsight/grype-db` | `sbomsight` |
| grype · syft | `/usr/local/bin` | root (누구나 실행) |
| 기록 | journald (`journalctl -u sbomsight`) | — |

**디스크 여유 10GB 이상.** 취약점 DB 가 풀리면 커지고 `data` 에 SBOM 원본과 grype
결과가 계속 쌓인다.

---

## 1단계 — 패키지

```bash
sudo apt update
sudo apt install -y openjdk-21-jdk-headless mariadb-server git curl
```

> **JRE 가 아니라 JDK 다.** 빌드에 `javac`, 인증서에 `keytool` 이 든다.
> MariaDB 대신 MySQL 8 을 써도 된다(`mysql-server`) — 접속 드라이버는 MariaDB
> Connector/J 하나로 둘 다 붙는다.

<details>
<summary>RHEL · Rocky 9 (확인하지 못함)</summary>

```bash
sudo dnf install -y java-21-openjdk-devel mariadb-server git curl
sudo systemctl enable --now mariadb
```
</details>

### 확인

```bash
java -version          # openjdk version "21..."
javac -version
systemctl is-enabled mariadb    # enabled — 재부팅하면 DB 가 먼저 올라와야 한다
```

---

## 2단계 — 데이터베이스와 계정

```bash
sudo mariadb
```

```sql
CREATE DATABASE sbomsight CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'sbomsight'@'localhost' IDENTIFIED BY '여기에-DB-비밀번호';
GRANT ALL PRIVILEGES ON sbomsight.* TO 'sbomsight'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

> `utf8mb4` 가 아니면 한글 자산명·비고가 깨진다. 표는 첫 기동 때 Flyway 가 만든다 —
> 손으로 만들지 않는다.

### 확인

```bash
mariadb -u sbomsight -p -e "SELECT DATABASE(), @@character_set_database;" sbomsight
```

`sbomsight` 와 `utf8mb4` 가 나와야 한다.

---

## 3단계 — 서비스 계정과 자리

```bash
sudo useradd --system --create-home --home-dir /var/lib/sbomsight \
             --shell /usr/sbin/nologin sbomsight
sudo -u sbomsight mkdir -p /var/lib/sbomsight/data /var/lib/sbomsight/grype-db
sudo mkdir -p /opt/sbomsight && sudo chown "$USER": /opt/sbomsight
```

---

## 4단계 — 소스 받기와 빌드

```bash
cd /opt/sbomsight
git clone https://github.com/LEEKIYOON-SEC/SBOMSight.git
cd SBOMSight
./mvnw clean package -DskipTests
rm -rf tests
```

처음에는 Maven 과 의존성을 받느라 몇 분 걸린다. `target/sbomsight-1.0.0.jar` 가 생긴다.
시험 코드를 지우는 이유는 윈도우와 같다 —
[운영 시스템에 시험 코드를 두지 않는다](windows-setup.md#시험-코드를-지운다).

### 확인

```bash
ls target/sbomsight-1.0.0.jar     # 있어야 한다
ls tests                          # 없어야 한다
```

---

## 5단계 — grype

```bash
INSTALL_DIR=/usr/local/bin sudo -E ./scripts/install-tools.sh
```

GitHub 릴리스에서 tar.gz 를 받아 **릴리스의 `checksums.txt` 와 SHA-256 을 대조하고,
어긋나면 설치를 멈춘다.** `/usr/local/bin` 에 두는 것은 서비스 계정도 보게 하려는
것이다. 버전을 고정하려면 `GRYPE_VERSION=0.115.0` 을 앞에 붙인다.

취약점 DB 는 **서비스 계정으로, 서비스가 볼 자리에** 받는다(약 150MB).

```bash
sudo -u sbomsight env GRYPE_DB_CACHE_DIR=/var/lib/sbomsight/grype-db grype db update
```

> 프록시를 거쳐야 하는 망이면 `sudo -u sbomsight env HTTPS_PROXY=... GRYPE_DB_CACHE_DIR=...`
> 처럼 넘긴다 — `sudo` 는 환경변수를 넘기지 않는다. 폐쇄망이면
> [`docs/offline-operations.md`](offline-operations.md) 의 반입 절차를 쓴다.

### 확인

```bash
grype version
sudo -u sbomsight env GRYPE_DB_CACHE_DIR=/var/lib/sbomsight/grype-db grype db status
```

`Status: valid` 와 최근 `Built` 날짜가 보이면 된다.

---

## 6단계 — 인증서

```bash
./scripts/make-keystore.sh sbomsight.example.co.kr '여기에-키스토어-비밀번호'
```

`config/keystore.p12` 가 만들어진다. SAN 에 호스트 이름 · `localhost` · 이 서버의 IP 가
들어간다. 정식 인증서를 받으면 이 파일만 바꿔 끼운다 —
[윈도우 가이드 8단계](windows-setup.md#8단계--인증서) 와 같다.

---

## 7단계 — 설정 파일

```bash
cp scripts/env.example.sh config/env
nano config/env
```

채울 것은 셋이다. **값은 작은따옴표로 감싼다** — 셸로 읽으므로 따옴표가 없으면 DB
주소의 `&` 와 비밀번호의 `$` 가 셸 문법으로 풀린다.

```bash
SBOMSIGHT_KEYSTORE_PASSWORD='6단계의 키스토어 비밀번호'
SBOMSIGHT_DB_PASSWORD='2단계의 DB 비밀번호'
SBOMSIGHT_DB_URL='jdbc:mariadb://localhost:3306/sbomsight?sslMode=disable&rewriteBatchedStatements=true&allowPublicKeyRetrieval=true'
```

> **`SBOMSIGHT_DB_URL` 을 지우지 마라.** 비우면 개발용 기본값(`127.0.0.1:13306`)으로
> 붙는다. `allowPublicKeyRetrieval=true` 를 빼면 MySQL 8 이 다시 뜬 다음 날 기동이
> 막힌다 — [윈도우 가이드 문제 해결](windows-setup.md#어제까지-잘-되다가-재부팅한-다음부터-기동이-안-된다-rsa-public-key-).

비밀번호가 든 두 파일은 서비스 계정만 읽게 한다.

```bash
sudo chown sbomsight: config/env config/keystore.p12
sudo chmod 600 config/env config/keystore.p12
```

값 전체와 각각의 뜻은 `scripts/env.example.sh` 의 주석에 있다.

---

## 8단계 — 준비 상태 확인

```bash
sudo -u sbomsight ./scripts/run-server.sh --check
```

```
SBOMSight 준비 상태
------------------------------------------------------------
  OK   Java 21 이상  openjdk version "21.0.10" 2026-01-20
  OK   빌드된 jar  target/sbomsight-1.0.0.jar
  OK   config/env  읽었습니다
  OK   인증서  ./config/keystore.p12
  OK   grype  /usr/local/bin/grype
  OK   DB 비밀번호  SBOMSIGHT_DB_PASSWORD
  OK   키스토어 비밀번호  SBOMSIGHT_KEYSTORE_PASSWORD
  OK   DB 주소  jdbc:mariadb://localhost:3306/sbomsight
------------------------------------------------------------

준비되었습니다.
```

전부 `OK` 면 서비스로 등록한다. `config/env 를 다른 계정도 읽을 수 있습니다` 가 뜨면
7단계의 `chmod 600` 을 빠뜨린 것이다.

---

## 9단계 — 서비스로 등록 (systemd)

`/etc/systemd/system/sbomsight.service`:

```ini
[Unit]
Description=SBOMSight
After=network-online.target mariadb.service mysql.service
Wants=network-online.target

[Service]
User=sbomsight
Group=sbomsight
WorkingDirectory=/opt/sbomsight/SBOMSight
ExecStart=/opt/sbomsight/SBOMSight/scripts/run-server.sh
Environment=LANG=C.UTF-8
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
Restart=on-failure
RestartSec=60
SuccessExitStatus=143

[Install]
WantedBy=multi-user.target
```

| 줄 | 왜 |
|---|---|
| `AmbientCapabilities=CAP_NET_BIND_SERVICE` | **443 을 root 없이 연다.** 리눅스는 1024 미만 포트에 권한이 필요하다. 이 서비스에만 준다 |
| `ExecStart=…/run-server.sh` | `config/env` 를 읽고 준비 상태를 기록에 남긴 뒤 java 를 띄운다 |
| `After=mariadb.service` | DB 가 먼저 올라와야 한다. 없는 이름은 무시된다 |
| `Restart=on-failure` · `RestartSec=60` | 떨어지면 1분 뒤 다시 |
| `SuccessExitStatus=143` | `systemctl stop` 의 SIGTERM 으로 끝난 것을 실패로 세지 않는다 |

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sbomsight
```

### 확인

```bash
systemctl status sbomsight          # active (running)
sudo journalctl -u sbomsight -n 50  # Started SbomSightApplication
curl -sk -o /dev/null -w '%{http_code}\n' https://localhost/login   # 200
```

**그리고 한 번 재부팅해 보라.** 저절로 올라오는 것이 이 단계의 목적이다.

<details>
<summary>systemd 없이 손으로 띄울 때</summary>

```bash
sudo -u sbomsight ./scripts/run-server.sh
```

443 은 root 가 아니면 열리지 않는다. 둘 중 하나다.

- `config/env` 의 `SBOMSIGHT_PORT='8443'` — 가장 간단하다.
- `sudo setcap 'cap_net_bind_service=+ep' $(readlink -f $(which java))` — 그 java 로 도는
  **모든** 프로그램이 낮은 포트를 열 수 있게 된다. 그리고 java 패키지를 올리면 파일이
  새로 깔려 이 설정이 사라진다. 서비스로 돌린다면 위의 `AmbientCapabilities` 가 낫다.

멈추려면 `Ctrl+C`.
</details>

---

## 10단계 — 첫 로그인

**첫 기동 때 관리자 계정과 임시 비밀번호가 기록에 한 번만 찍힌다.** 서비스에는 창이
없으므로 journald 에서 본다.

```bash
sudo journalctl -u sbomsight | grep -A6 '최초 관리자'
```

그 값으로 로그인하면 **비밀번호 변경 화면으로 바로 넘어간다.** 로그인한 뒤 한 번
로그아웃하고 새 비밀번호로 다시 들어가 본다. 놓쳤을 때 다시 만드는 법 · 권한 · 잠금
기본값은 [윈도우 가이드 11단계](windows-setup.md#11단계--첫-로그인) 와 같다(`mysql` 대신
`mariadb`, `run-server.ps1` 대신 `sudo systemctl restart sbomsight`).

> **기록을 읽을 수 있는 계정은 그 줄을 본다**(`adm` · `systemd-journal` 그룹). 등록하고
> 바로 로그인해 바꾼다 — 바꾼 뒤에는 기록에 남은 임시 비밀번호로 들어갈 수 없다.

---

## 11단계 — 내부망에 열기

```bash
sudo ufw allow 443/tcp                                                  # Ubuntu (ufw 를 쓸 때)
sudo firewall-cmd --permanent --add-service=https && sudo firewall-cmd --reload   # RHEL
```

(둘 다 확인하지 못함.) 다른 PC 에서 `https://<이 서버 IP>` 를 연다. 허용 IP 좁히기는
[윈도우 가이드 13단계](windows-setup.md#허용-ip-좁히기) 와 같다 — 화면에서 한다.

---

## 갱신받기

**먼저 내리고, DB 와 지금 jar 를 백업한다.** 마이그레이션이 표 구조를 바꾸고, 되돌리는
길은 그 둘뿐이다.

```bash
sudo systemctl stop sbomsight
cd /opt/sbomsight/SBOMSight
sudo mariadb-dump --single-transaction --routines sbomsight --result-file=/opt/sbomsight/backup-before-upgrade.sql
sudo chmod 600 /opt/sbomsight/backup-before-upgrade.sql     # 자산 · 패키지 목록이 통째로 들어 있다
cp target/sbomsight-1.0.0.jar /opt/sbomsight/sbomsight-before-upgrade.jar

git pull
./mvnw clean package -DskipTests
rm -rf tests                       # `git pull` 이 다시 가져온다
sudo systemctl start sbomsight
```

표 변경은 기동할 때 Flyway 가 적용한다(`journalctl -u sbomsight` 에 `Migrating schema` ·
`Successfully applied`). 올라온 뒤 **로그아웃하고 다시 로그인해 본다.** 되돌리는 절차와
V15 · V16 이 무엇을 바꾸는지는 [`docs/operations.md` 8절](operations.md#8-업그레이드).

---

## 백업 대상

| 무엇 | 어디 | 없으면 |
|---|---|---|
| DB | `sbomsight` 데이터베이스 | 자산·이력·조치·감사 로그가 전부 사라진다 |
| 보관 파일 | `/var/lib/sbomsight/data` | 옛 SBOM 과 grype 원본이 사라져 **다시 검사** 를 못 한다 |
| 인증서 | `config/keystore.p12` | 다시 만들면 된다 (자체 서명) |
| 설정 | `config/env` | 다시 채우면 된다 |

`data` 에는 서버에 설치된 패키지 목록이 통째로 들어 있다. 백업 매체도 같은 등급으로
다룬다. 받는 명령과 되살려 보는 절차는 [`docs/operations.md` 7절](operations.md#7-백업).

---

## 문제 해결

| 증상 | 먼저 볼 곳 |
|---|---|
| `--check` 에서 `grype` 가 `안됨` | 서비스 계정이 그 경로를 못 본다 — 5단계처럼 `/usr/local/bin` 에 두고 `config/env` 의 `SBOMSIGHT_GRYPE` 를 전체 경로로 |
| 검사가 실패하고 오류에 DB 가 없다고 나온다 | `grype db update` 를 **서비스 계정으로** `GRYPE_DB_CACHE_DIR` 을 주고 받았는지 (5단계). 설치한 사람의 `~/.cache/grype` 는 서비스가 보지 않는다 |
| `BindException: Permission denied` | 443 을 root 없이 열려고 했다 — 9단계의 `AmbientCapabilities`, 또는 `SBOMSIGHT_PORT='8443'` |
| DB 에 붙지 못하고 기록에 `13306` 이 보인다 | `config/env` 에 `SBOMSIGHT_DB_URL` 이 없다 (7단계) — `--check` 가 `[!]` 로 먼저 말한다 |
| `RSA public key is not available` | 주소 끝의 `allowPublicKeyRetrieval=true` 가 빠졌다 (7단계) |
| 한글이 `?` 로 저장된다 | DB 문자셋이 `utf8mb4` 가 아니다 (2단계) |
| 그 밖에 | [윈도우 가이드 문제 해결](windows-setup.md#문제-해결) — 화면 · DB 쪽은 같다 |

---

## 확인한 것 · 못 한 것

**Ubuntu 24.04 · MariaDB 10.11 · OpenJDK 21 에서 돌려 보았다 (2026-09-26).**

- 1단계의 패키지 이름(`openjdk-21-jdk-headless` 에 `javac`, `keytool` 은 JRE 쪽).
- 2단계의 SQL 과 그 계정으로 소켓 · `127.0.0.1` 양쪽 접속.
- 5단계 — 스크립트로 grype 0.115.0 · syft 1.50.0 을 받아 해시를 대조해 `/usr/local/bin` 에
  설치했다. 틀린 해시에서는 멈추고 아무것도 깔지 않는다(네트워크 없이 흉내 냄). 서비스
  계정으로 `grype db update` → `db status` 가 `valid`.
- 6 · 7 · 8단계 — 인증서 · `config/env`(작은따옴표 안의 `$` · `"` · `'` 가 든 비밀번호 그대로)
  · `--check`. 권한이 644 면 경고한다.
- 9단계의 권한 줄들 — `User=sbomsight` · `AmbientCapabilities` · `CapabilityBoundingSet` ·
  `NoNewPrivileges` 를 **systemd 없이 같은 상태로**(`setpriv`) 만들어 띄웠다. 비 root 로 443 이
  열리고 `/login` 이 200. 권한 없이 띄우면 경고 뒤 `Permission denied` 로 멈춘다.
- 빈 DB 에 첫 기동 — Flyway 가 V1~V16 을 적용하고 최초 관리자 상자가 기록에 찍혔다.
- `setcap` 을 건 java 로 비 root 443 이 열리는 것(걸지 않은 java 는 막힌다).

**확인하지 못한 것.**

- **systemd 로 실제로 띄우고 재부팅하기** — 이 환경은 systemd 가 PID 1 이 아니다. 유닛
  파일은 `systemd-analyze verify` 로 문법만 보았다. 처음 등록할 때 9단계의 **확인** 과
  재부팅을 직접 해 보라.
- `sudo mariadb` 로 root 가 비밀번호 없이 들어가는 것(Ubuntu 기본값) — 이 환경의 DB 는
  다르게 초기화되어 있었다.
- RHEL · Rocky 9 의 패키지 이름, `ufw` · `firewalld` 명령, `journalctl` 에서 최초 관리자 줄
  찾기.
- 5단계 스크립트의 **최신 버전 알아내기** — 이 환경의 프록시가 `github.com/…/releases/latest`
  를 막았다. 막히면 고정 버전(grype 0.115.0 · syft 1.50.0)으로 받는다 — 그 길은 확인했다.

---

## 다음 읽을거리

| 문서 | 내용 |
|---|---|
| [`docs/operations.md`](operations.md) | 설치한 뒤 — 운영 리듬 · 백업 · 업그레이드 |
| [`docs/windows-setup.md`](windows-setup.md) | 화면 쓰는 법(12단계) · 문제 해결 |
| [`docs/offline-operations.md`](offline-operations.md) | 폐쇄망 · 오프라인 취약점 DB 반입 |
| [`scripts/env.example.sh`](../scripts/env.example.sh) | 설정 값과 각각의 뜻 |
