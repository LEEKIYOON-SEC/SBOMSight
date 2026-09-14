"""`NOTICE.md` 를 만든다 — **이 도구로 이 도구의 SBOM 을 뽑아서.**

SBOM 도구가 자기 SBOM 이 없는 것은 이상하다. 손으로 적는 목록은 다음 판올림
때 반드시 어긋나므로, 배포물에서 뽑아 쓴다.

    scripts/make-notice.sh                # SBOM 을 뽑고 이 스크립트를 돌린다
    python3 scripts/make-notice.py <sbom.cdx.json> > NOTICE.md

**무엇을 훑는가 — 빌드된 jar 이다.** `dir:.` 로 저장소를 훑으면 시험에만 쓰는
것(H2 · AssertJ)까지 들어가고, 그것을 "우리가 배포하는 것" 으로 적으면 없는
의무가 생긴다. 배포하는 것은 `target/sbomsight-1.0.0.jar` 하나다.

**라이선스는 그 의존물이 자기 pom 에 적어 둔 것을 읽는다.** syft 가 jar 안에서
찾은 것이 있으면 그것을 쓰고, 둘 다 없으면 **`확인 필요` 로 남긴다** — 아는
척해서 채우면 아무도 확인하지 않은 값이 결재 문서에 실린다.

syft 가 purl 에 적는 groupId 는 jar 이름에서 짐작한 것이라 틀릴 때가 있다
(`org.aspectj.weaver` · `thymeleaf`). 그래서 그 경로에 pom 이 없으면
`~/.m2` 에서 `<이름>/<버전>/<이름>-<버전>.pom` 을 찾아 읽는다.
"""
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import date

M2 = os.path.expanduser("~/.m2/repository")
NS = "{http://maven.apache.org/POM/4.0.0}"
PURL = re.compile(r"pkg:maven/([^/]+)/([^@]+)@(.+?)(?:\?|$)")

# 선언 문구 → SPDX 식별자. **묶는 것이 아니라 옮겨 적는 것이다** — 같은
# 라이선스를 프로젝트마다 다르게 적어 두어서, 그대로 두면 목록이 스무 갈래가
# 된다. 모르는 문구는 그대로 내보낸다.
SPDX = {
    "the apache software license, version 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache-2.0": "Apache-2.0",
    "mit": "MIT",
    "mit license": "MIT",
    "the mit license": "MIT",
    "bsd-3-clause": "BSD-3-Clause",
    "eclipse public license - v 1.0": "EPL-1.0",
    "eclipse public license - v 2.0": "EPL-2.0",
    "eclipse public license v. 2.0": "EPL-2.0",
    "epl 2.0": "EPL-2.0",
    "gpl2 w/ cpe": "GPL-2.0-with-classpath-exception",
    "eclipse distribution license - v 1.0": "EDL-1.0",
    "eclipse distribution license v. 1.0": "EDL-1.0",
    "edl 1.0": "EDL-1.0",
    "gnu lesser general public license": "LGPL-2.1",
    "gnu library general public license v2.1 or later": "LGPL-2.1-or-later",
    "lgpl-2.1": "LGPL-2.1",
    "lgpl-2.1-only": "LGPL-2.1-only",
}


def spdx(name):
    return SPDX.get(name.strip().lower(), name.strip())


def pom_of(group, artifact, version):
    """그 의존물의 pom. purl 의 group 이 틀렸으면 ~/.m2 에서 찾아본다."""
    direct = os.path.join(M2, *group.split('.'), artifact, version,
                          f"{artifact}-{version}.pom")
    if os.path.exists(direct):
        return direct
    found = subprocess.run(
        ["find", M2, "-path", f"*/{artifact}/{version}/{artifact}-{version}.pom"],
        capture_output=True, text=True).stdout.split()
    return found[0] if found else None


def declared(path, depth=0):
    """pom 의 <licenses>. 비어 있으면 부모 pom 으로 올라간다."""
    if path is None or depth > 6:
        return []
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return []
    names = [l.findtext(f"{NS}name", "").strip()
             for l in root.findall(f"{NS}licenses/{NS}license")]
    names = [n for n in names if n]
    if names:
        return names
    parent = root.find(f"{NS}parent")
    if parent is None:
        return []
    return declared(pom_of(parent.findtext(f"{NS}groupId", ""),
                           parent.findtext(f"{NS}artifactId", ""),
                           parent.findtext(f"{NS}version", "")), depth + 1)


def rows(sbom):
    out = []
    for c in json.load(open(sbom, encoding="utf-8"))["components"]:
        match = PURL.match(c.get("purl", ""))
        group, artifact, version = match.groups() if match else (
            "", c["name"], c.get("version", ""))
        names = declared(pom_of(group, artifact, version))
        if not names:
            # syft 가 jar 안에서 읽은 것
            for entry in c.get("licenses", []):
                license = entry.get("license", {})
                name = license.get("id") or license.get("name") or entry.get("expression")
                if name:
                    names.append(name)
        out.append({"name": artifact, "version": version,
                    "licenses": [spdx(n) for n in names]})
    out.sort(key=lambda r: r["name"].lower())
    return out


def table(entries):
    print("| 이름 | 버전 | 라이선스 |")
    print("|---|---|---|")
    for e in entries:
        label = " OR ".join(e["licenses"]) if e["licenses"] else "**확인 필요**"
        print(f"| {e['name']} | `{e['version']}` | {label} |")


if __name__ == "__main__":
    sbom = sys.argv[1]
    meta = json.load(open(sbom, encoding="utf-8")).get("metadata", {})
    tool = ""
    for t in meta.get("tools", {}).get("components", []) or []:
        tool = f"{t.get('name', '')} {t.get('version', '')}".strip()
    entries = rows(sbom)
    ours = [e for e in entries if e["name"] == "sbomsight"]
    third = [e for e in entries if e["name"] != "sbomsight"]
    unknown = [e for e in third if not e["licenses"]]

    print(f"""<!-- 이 파일은 scripts/make-notice.sh 가 만든다. 손으로 고치지 않는다. -->
# NOTICE — SBOMSight 이 쓰는 것

> **법률 판단이 아니다.** 각 의존물이 자기 배포물에 적어 둔 라이선스를 옮긴
> 것이고, 사내 반입·배포 기준에 맞는지는 법무·보안 검토가 따로 필요하다.

뽑은 날 {date.today()} · 뽑은 도구 **{tool or 'syft'}** · 훑은 것
`target/sbomsight-1.0.0.jar` (배포물) · 제3자 {len(third)}개

```bash
scripts/make-notice.sh          # SBOM 을 다시 뽑아 이 파일을 다시 만든다
```

**의무는 대부분 배포할 때 붙는다.** 사내에서만 쓰면 거의 발동하지 않는다.
그래도 목록을 둔다 — 금융권 OSS 관리 정책이 대개 요구하고, 없으면 그때
손으로 적게 된다.

## 1. 배포물에 들어가는 것
""")
    table(third)
    print(f"""
## 2. 글꼴

| 무엇 | 버전 | 라이선스 |
|---|---|---|
| IBM Plex Sans KR · IBM Plex Mono (woff2 292개) | — | SIL OFL 1.1 |

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
""")
    if unknown:
        print("**확인 필요** — 배포물과 pom 어디에도 라이선스 문구가 없다. "
              "없는 값을 채우지 않고 그대로 둔다.\n")
        print("| 이름 | 버전 | 어디서 확인하나 |")
        print("|---|---|---|")
        for e in unknown:
            print(f"| {e['name']} | `{e['version']}` | 프로젝트 저장소의 "
                  "`LICENSE` · 같은 릴리스의 다른 산출물 |")
        print()
    print("""**~~mysql-connector-j~~** — GPL-2.0 이라 N1 에서 MariaDB
Connector/J 로 교체했다. 지금 배포물에 없다.""")
