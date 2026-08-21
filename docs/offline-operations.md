# 오프라인 · 폐쇄망 운영

SBOMSight에서 "폐쇄망"은 두 가지 다른 이야기다. 섞으면 혼란스러우므로 갈라서 적는다.

1. **패치 대상 서버가 폐쇄망에 있다** — 보고서 권고사항에 담기는 패치 방법론.
   이것이 기본 가정이다.
2. **SBOMSight가 도는 PC 자체가 오프라인이다** — 도구와 위협정보 스냅샷을
   미리 반입해 두어야 한다. 선택 사항이다.

---

## 1. 패치 대상이 폐쇄망에 있는 경우 (기본)

SBOMSight는 인터넷이 되는 PC에서 돌고, 폐쇄망에서 반출한 SBOM만 받는다.

```
[폐쇄망]                                    [인터넷 되는 PC]
 syft로 SBOM 생성                           SBOMSight 업로드
 └─ JSON 반출  ─────── 매체 ───────────────→ 탐지 · 보강 · 판정 · 보고서
                                             └─ 보고서에 폐쇄망 패치 절차 포함
[폐쇄망]                                    [인터넷 되는 구간]
 dnf localinstall  ←──── 매체 ───────────── dnf download --resolve --alldeps
```

### 폐쇄망에서 SBOM 생성

```bash
# 폐쇄망 안에서 (syft 바이너리는 미리 반입해 둔다)
syft dir:/ -o cyclonedx-json=asset01.cdx.json          # 파일시스템 전체
syft registry.internal/app:1.2 -o cyclonedx-json=app.cdx.json   # 이미지
```

생성한 JSON만 반출한다. SBOM에는 설치 패키지 목록과 파일 경로가 담기므로
반출 승인 절차가 필요하다면 그 대상이 된다.

### 보고서의 폐쇄망 패치 절차

`rules/playbooks/rpm.json` 이 생성하는 절차는 다음과 같다. AI가 만든 것이 아니라
결정론적 템플릿이므로 명령어가 지어내어질 여지가 없다.

```
1. 인터넷 가능 구간에서 대상 RPM과 의존성을 함께 내려받는다
   (대상과 동일한 배포판·아키텍처에서 수행):
       dnf download --resolve --alldeps --destdir ./rpms <package>

2. 매체로 반입한다.

3. 무결성과 서명을 확인한다:
       sha256sum -c checksums.txt
       rpm -K ./rpms/*.rpm          # NOT OK 가 나오면 설치하지 않는다
       rpm -qa gpg-pubkey           # 벤더 GPG 키 등록 확인

4. 대상 서버에 업로드한 뒤 설치한다.
   ㆍ 단건:  dnf localinstall ./rpms/*.rpm
   ㆍ 다건이거나 반복 배포:
        createrepo_c ./rpms
        cat > /etc/yum.repos.d/local-patch.repo <<'REPO'
        [local-patch]
        name=Local patch repository
        baseurl=file:///path/to/rpms
        enabled=1
        gpgcheck=1
        REPO
        dnf --disablerepo='*' --enablerepo='local-patch' upgrade <package>

5. 설치 결과를 확인하고 필요한 서비스를 재기동한다.
```

검증:

```bash
rpm -q <package>                  # 기대값: Fixed Version 이상
dnf history list | head
systemctl status <service>
# SBOM 재생성 후 재스캔해 해당 CVE가 사라졌는지 확인
syft dir:/ -o cyclonedx-json=after.cdx.json
grype sbom:after.cdx.json -o json | grep CVE-XXXX-XXXXX
```

deb · npm · pip · maven 생태계도 같은 구조의 절차가 `rules/playbooks/` 에 있다.

---

## 2. SBOMSight PC 자체를 오프라인으로 운영하는 경우

기본값은 온라인이다. 오프라인으로 돌리려면 **취약점 DB와 위협정보 스냅샷을
미리 반입**해야 한다.

### Grype 취약점 DB 반입

인터넷 되는 장비에서:

```bash
grype db update
grype db status                              # 캐시 위치와 빌드 시각 확인
# 캐시 디렉터리를 통째로 압축해 반입한다 (기본 ~/.cache/grype/db)
tar czf grype-db.tar.gz -C ~/.cache/grype db
```

오프라인 장비에서:

```bash
mkdir -p ~/.cache/grype
tar xzf grype-db.tar.gz -C ~/.cache/grype

export GRYPE_DB_AUTO_UPDATE=false            # 갱신 시도를 막는다
export GRYPE_CHECK_FOR_APP_UPDATE=false
export GRYPE_DB_CACHE_DIR="$HOME/.cache/grype/db"
# DB가 오래되어도 거부하지 않게 (기본 5일)
export GRYPE_DB_MAX_ALLOWED_BUILT_AGE=720h

grype db status                              # 반입한 DB가 잡히는지 확인
```

> `grype db import <archive>` 를 쓸 수도 있다. Grype 버전에 따라 지원하는 아카이브
> 형식이 다르므로, 반입 전에 **같은 버전**으로 확인하는 편이 안전하다.

### 위협정보 스냅샷 반입

EPSS · CISA KEV · Exploit-DB · Metasploit 인덱스는 `data/cache/*.json` 에 스냅샷
기준일과 함께 캐시된다. 인터넷 되는 장비에서 한 번 스캔을 돌려 캐시를 만든 뒤
그 디렉터리를 반입한다.

```bash
# 인터넷 되는 장비
python3 -m core.cli scan sample.cdx.json --no-store >/dev/null
ls data/cache/                                # epss.json kev.json exploitdb.json metasploit.json
tar czf intel-cache.tar.gz data/cache

# 오프라인 장비
tar xzf intel-cache.tar.gz
export SBOMSIGHT_OFFLINE=1                    # 네트워크를 쓰지 않는다
python3 -m core.cli scan asset01.cdx.json
```

오프라인 모드에서는 캐시가 없는 소스가 **`unknown` 으로 남고**, 보고서에
`unknown_epss` · `unknown_kev` · `unknown_exploit` 플래그로 표기된다.
0으로 채우거나 "없음"으로 처리하지 않는다 — 확인하지 못한 것과 없는 것은
다른 이야기이기 때문이다.

스냅샷이 `SBOMSIGHT_SNAPSHOT_STALE_DAYS`(기본 7일)보다 오래되면
`stale_snapshot` 플래그가 붙고, 보고서에 "최신 데이터로 재확인이 권고된다"는
문장이 들어간다.

### AI

오프라인 장비에서는 AI를 쓸 수 없다. 기본값이 미사용이므로 별도 설정이 필요 없고,
보고서는 룰 기반 서술로 완결된다.

---

## 환경변수 요약

| 변수 | 기본값 | 용도 |
|---|---|---|
| `SBOMSIGHT_OFFLINE` | `0` | 1이면 네트워크를 쓰지 않고 캐시 스냅샷만 사용 |
| `SBOMSIGHT_SNAPSHOT_STALE_DAYS` | `7` | 이보다 오래된 스냅샷에 `stale_snapshot` 표기 |
| `SBOMSIGHT_ENRICH_TTL_HOURS` | `24` | 위협정보 캐시 유효 기간 |
| `GRYPE_DB_AUTO_UPDATE` | — | `false` 로 두면 DB 갱신 시도를 막는다 |
| `GRYPE_CHECK_FOR_APP_UPDATE` | — | `false` 로 두면 버전 확인 요청을 막는다 |
| `GRYPE_DB_CACHE_DIR` | — | 반입한 DB 위치 |
| `GRYPE_DB_MAX_ALLOWED_BUILT_AGE` | `120h` | DB 허용 경과 시간 |
| `SYFT_BIN` · `GRYPE_BIN` | `syft` · `grype` | PATH에 없을 때 경로 지정 |

`SBOMSIGHT_OFFLINE=1` 로 두면 SBOMSight가 Grype를 부를 때
`GRYPE_DB_AUTO_UPDATE=false` 와 `GRYPE_CHECK_FOR_APP_UPDATE=false` 를 자동으로
넘긴다(`core/grype_runner.py`).
