# 시험

**운영 PC 에서는 이 폴더를 통째로 지운다.**

```powershell
Remove-Item -Recurse -Force tests      # 윈도우
```
```bash
rm -rf tests                           # 리눅스
```

지운 뒤에도 빌드는 그대로 돈다 — `mvnw package -DskipTests` 는 시험 코드가
없으면 그냥 지나간다. 저장소에는 남아 있으므로 다음에 고칠 때 다시 받으면
된다.

## 왜 여기 있나

운영 PC 는 소스를 받아 그 자리에서 빌드한다(`docs/windows-setup.md`). 시험이
`src/test` 에 흩어져 있으면 운영 PC 디스크에 시험 코드가 남고, 점검에서
**"운영 시스템에 시험 코드가 있다"** 로 잡힌다. 실행되지 않아도 그 자리에
있다는 것이 지적 사항이다.

한 폴더에 모아 두면 지우는 것이 한 줄이다. 그리고 저장소에는 그대로 남으므로
**시험을 수행했다는 증적을 잃지 않는다** — 점검이 묻는 것은 "시험 코드가
있느냐" 가 아니라 "운영에 시험 코드·데이터가 섞였느냐" 다.

`pom.xml` 의 `<testSourceDirectory>` 가 이 폴더를 가리킨다.

## 무엇이 들어 있나

| | 무엇 |
|---|---|
| `java/` · `resources/` | 시험 코드와 시험 자원. H2(MODE=MySQL)로 돈다 |
| `run.sh` | 전체 시험 — `./mvnw -B test` |
| `check-mariadb.sh` | 진짜 MySQL/MariaDB + Flyway 스키마로 전체 시험 |
| `check-migrations.sh` | 마이그레이션만 — 빈 DB 와 데이터가 있는 DB 양쪽에 |
| `check-table-width.py` | 표가 칸을 넘는지 (브라우저로 실측) |
| `check-rows.py` | 목록의 밑선이 어긋나는지 |
| `check-links.py` | 주소에 빈 값이 붙는지 |
| `check-uniform.py` | 단추·입력칸이 한 모양인지 |
| `check-contrast.py` | 글자 대비 (WCAG 2.1 AA) |

`check-*.py` 는 **서버를 띄운 뒤** 돈다. 브라우저로 실제 픽셀을 재기
때문이다 — HTML 만 봐서는 칸이 화면 밖으로 밀렸는지 알 수 없다.

## 쓰는 법

```bash
./mvnw -B test                                  # 컴파일 + 시험 (H2)
DB_PORT=13306 ./tests/check-mariadb.sh          # 진짜 DB + Flyway 스키마
DB_PORT=13306 ./tests/check-migrations.sh       # 마이그레이션만

./scripts/run-server.sh                         # 띄운 뒤
python3 tests/check-table-width.py 1280
python3 tests/check-rows.py
python3 tests/check-links.py
python3 tests/check-uniform.py
python3 tests/check-contrast.py
```

## 여기 없는 것

`scripts/run-server.sh --check` 는 **기동 전 점검**이다 — 자바·DB·인증서·grype
가 준비됐는지 본다. 시험이 아니라 운영 도구라 `scripts/` 에 남는다.
