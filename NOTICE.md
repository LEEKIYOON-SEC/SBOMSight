<!-- 이 파일은 scripts/make-notice.sh 가 만든다. 손으로 고치지 않는다.
     (2장의 글꼴·화면 바탕은 syft 가 세지 않으므로 그 스크립트 안에 적혀 있다.) -->
# NOTICE — SBOMSight 이 쓰는 것

> **법률 판단이 아니다.** 각 의존물이 자기 배포물에 적어 둔 라이선스를 옮긴
> 것이고, 사내 반입·배포 기준에 맞는지는 법무·보안 검토가 따로 필요하다.

뽑은 날 2026-09-14 · 뽑은 도구 **syft 1.19.0** · 훑은 것
`target/sbomsight-1.0.0.jar` (배포물) · 제3자 78개

```bash
scripts/make-notice.sh          # SBOM 을 다시 뽑아 이 파일을 다시 만든다
```

**의무는 대부분 배포할 때 붙는다.** 사내에서만 쓰면 거의 발동하지 않는다.
그래도 목록을 둔다 — 금융권 OSS 관리 정책이 대개 요구하고, 없으면 그때
손으로 적게 된다.

## 1. 배포물에 들어가는 것

| 이름 | 버전 | 라이선스 |
|---|---|---|
| angus-activation | `2.0.2` | EDL-1.0 |
| antlr4-runtime | `4.13.0` | BSD-3-Clause |
| aspectjweaver | `1.9.24` | EPL-2.0 |
| attoparser | `2.0.7.RELEASE` | Apache-2.0 |
| byte-buddy | `1.14.19` | Apache-2.0 |
| caffeine | `3.1.8` | Apache-2.0 |
| checker-qual | `3.32.0` | MIT |
| classmate | `1.7.0` | Apache-2.0 |
| error_prone_annotations | `2.21.1` | Apache-2.0 |
| flyway-core | `10.10.0` | Apache-2.0 |
| flyway-mysql | `10.10.0` | Apache-2.0 |
| gson | `2.10.1` | Apache-2.0 |
| hibernate-commons-annotations | `6.0.6.Final` | LGPL-2.1-or-later |
| hibernate-core | `6.5.3.Final` | LGPL-2.1-or-later |
| hibernate-validator | `8.0.2.Final` | Apache-2.0 |
| HikariCP | `5.1.0` | Apache-2.0 |
| istack-commons-runtime | `4.1.2` | EDL-1.0 |
| jackson-annotations | `2.18.6` | Apache-2.0 |
| jackson-core | `2.18.6` | Apache-2.0 |
| jackson-databind | `2.18.6` | Apache-2.0 |
| jackson-dataformat-toml | `2.18.6` | Apache-2.0 |
| jackson-datatype-jdk8 | `2.18.6` | Apache-2.0 |
| jackson-datatype-jsr310 | `2.18.6` | Apache-2.0 |
| jackson-module-parameter-names | `2.18.6` | Apache-2.0 |
| jakarta.activation-api | `2.1.3` | EDL-1.0 |
| jakarta.annotation-api | `2.1.1` | EPL-2.0 OR GPL-2.0-with-classpath-exception |
| jakarta.inject-api | `2.0.1` | Apache-2.0 |
| jakarta.persistence-api | `3.1.0` | EPL-2.0 OR EDL-1.0 |
| jakarta.transaction-api | `2.0.1` | EPL-2.0 OR GPL-2.0-with-classpath-exception |
| jakarta.validation-api | `3.0.2` | Apache-2.0 |
| jakarta.xml.bind-api | `4.0.2` | EDL-1.0 |
| jandex | `3.1.2` | Apache-2.0 |
| jaxb-core | `4.0.5` | EDL-1.0 |
| jaxb-runtime | `4.0.5` | EDL-1.0 |
| jboss-logging | `3.5.3.Final` | Apache-2.0 |
| jcl-over-slf4j | `2.0.17` | Apache-2.0 |
| jna | `5.13.0` | LGPL-2.1-or-later OR Apache-2.0 |
| jna-platform | `5.13.0` | LGPL-2.1-or-later OR Apache-2.0 |
| jul-to-slf4j | `2.0.17` | MIT |
| log4j-api | `2.23.1` | Apache-2.0 |
| log4j-to-slf4j | `2.23.1` | Apache-2.0 |
| logback-classic | `1.5.25` | EPL-1.0 OR LGPL-2.1 |
| logback-core | `1.5.25` | EPL-1.0 OR LGPL-2.1 |
| mariadb-java-client | `3.3.4` | LGPL-2.1 |
| micrometer-commons | `1.13.15` | Apache-2.0 |
| micrometer-observation | `1.13.15` | Apache-2.0 |
| slf4j-api | `2.0.17` | MIT |
| snakeyaml | `2.2` | Apache-2.0 |
| spring-aop | `6.1.21` | Apache-2.0 |
| spring-aspects | `6.1.21` | Apache-2.0 |
| spring-beans | `6.1.21` | Apache-2.0 |
| spring-boot | `3.3.13` | Apache-2.0 |
| spring-boot-autoconfigure | `3.3.13` | Apache-2.0 |
| spring-boot-jarmode-tools | `3.3.13` | Apache-2.0 |
| spring-context | `6.1.21` | Apache-2.0 |
| spring-core | `6.1.21` | Apache-2.0 |
| spring-data-commons | `3.3.13` | Apache-2.0 |
| spring-data-jpa | `3.3.13` | Apache-2.0 |
| spring-expression | `6.1.21` | Apache-2.0 |
| spring-jcl | `6.1.21` | Apache-2.0 |
| spring-jdbc | `6.1.21` | Apache-2.0 |
| spring-orm | `6.1.21` | Apache-2.0 |
| spring-security-config | `6.3.10` | Apache-2.0 |
| spring-security-core | `6.3.10` | Apache-2.0 |
| spring-security-crypto | `6.3.10` | Apache-2.0 |
| spring-security-web | `6.3.10` | Apache-2.0 |
| spring-tx | `6.1.21` | Apache-2.0 |
| spring-web | `6.1.21` | Apache-2.0 |
| spring-webmvc | `6.1.21` | Apache-2.0 |
| thymeleaf | `3.1.3.RELEASE` | Apache-2.0 |
| thymeleaf-extras-springsecurity6 | `3.1.3.RELEASE` | Apache-2.0 |
| thymeleaf-spring6 | `3.1.3.RELEASE` | Apache-2.0 |
| tomcat-embed-core | `10.1.49` | Apache-2.0 |
| tomcat-embed-el | `10.1.49` | Apache-2.0 |
| tomcat-embed-websocket | `10.1.49` | Apache-2.0 |
| txw2 | `4.0.5` | EDL-1.0 |
| unbescape | `1.1.6.RELEASE` | Apache-2.0 |
| waffle-jna | `3.3.0` | MIT |

## 2. 글꼴 · 화면 바탕 (저장소에 담아 둔 것)

| 무엇 | 버전 | 라이선스 |
|---|---|---|
| IBM Plex Sans KR · IBM Plex Mono (woff2 292개) | — | SIL OFL 1.1 |
| Tabler (tabler.min.css 한 장) | 1.5.1 | MIT |

**Tabler 는 CSS 한 장만 가져왔다.** 함께 배포되는 `dist/libs/` 는 통째로 뺐다 —
그 안의 ApexCharts 는 5판부터 MIT 가 아니고(이중 라이선스 · 재배포는 별도 OEM
라이선스) 우리는 차트를 쓰지 않는다. JS 도 가져오지 않았다. 원문은
`src/main/resources/static/vendor/tabler/LICENSE` 에 동봉되어 있고, 무엇을
가져오고 무엇을 뺐는지는 같은 폴더의 `README.md` 에 적혀 있다.


Copyright © 2017 IBM Corp. with Reserved Font Name "Plex".
전문은 `src/main/resources/static/fonts/LICENSE.txt` 에 동봉되어 있다.
받은 곳과 이유는 `static/css/fonts.css` 머리에 적혀 있다 — 폐쇄망에서
Google Fonts 로 링크하면 조용히 기본 글꼴로 떨어진다.

> syft 는 글꼴 파일을 패키지로 세지 않는다. 위 한 줄은 손으로 적은 것이고,
> 글꼴을 갈아 끼우면 여기도 함께 고쳐야 한다.

## 3. 따로 설치하는 것 — 저장소에 없다

| 무엇 | 라이선스 | 왜 여기 있나 |
|---|---|---|
| syft | Apache-2.0 | 점검 대상 서버에서 SBOM 을 뽑는다 |
| grype | Apache-2.0 | 이 서버에서 취약점을 찾는다 |
| MariaDB 서버 | GPL-2.0 | 별도 프로그램으로 띄운다 — 우리 배포물에 들어가지 않는다 |

**재배포하지 않는다.** 운영자가 설치하고, 우리는 실행만 한다. grype 의 판정을
그대로 보관·정렬·집계할 뿐 다시 계산하지 않는다.

## 4. 시험에만 쓰는 것 — 배포물에 없다

| 무엇 | 라이선스 |
|---|---|
| H2 | MPL-2.0 OR EPL-1.0 |
| AssertJ · JUnit · Spring Boot Test | Apache-2.0 / EPL-2.0 |

`target/sbomsight-1.0.0.jar` 안에 없다. 그래서 위 1장 목록에도 없다.

## 5. 우리 코드

루트 `LICENSE` — **MIT · Copyright (c) 2026 LEEKIYOON-SEC**.

- 사내 전용이라면 MIT 보다 "사내 전용 · 무단 반출 금지" 가 실제 용도에 맞을 수
  있다. MIT 는 누구나 가져다 팔아도 된다는 뜻이다.
- 회사 업무로 만든 것이면 저작권자가 개인이 아니라 회사일 수 있다
  (업무상 저작물). 사내 규정을 확인할 자리다.

## 6. 짚어 둘 것

**LGPL** — `mariadb-java-client` · `hibernate-core` ·
`hibernate-commons-annotations`. 고치지 않고 jar 그대로 쓰고 있고, 갈아 끼울 수
있게 두면(지금 상태) 의무가 충족된다. **고쳐 쓰기 시작하면 그때 달라진다.**

**이중 라이선스** — `logback`(EPL-1.0 또는 LGPL-2.1) ·
`jakarta.*-api`(EPL-2.0 또는 GPL-2.0+CPE) · `jna`(Apache-2.0 또는 LGPL-2.1).
둘 중 하나를 고르는 것이고, 고른 쪽을 적어 두는 것은 배포할 때 할 일이다.

**~~mysql-connector-j~~** — GPL-2.0 이라 N1 에서 MariaDB
Connector/J 로 교체했다. 지금 배포물에 없다.
