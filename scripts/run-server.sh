#!/usr/bin/env bash
# SBOMSight 을 띄운다 (Linux).
#
# Windows 는 scripts\run-server.ps1 을 쓴다. 운영 값(DB 비밀번호 · 키스토어
# 비밀번호)은 config/env 에서 읽는다 — 윈도우의 config\env.ps1 과 같은 자리다.
# 그 파일은 저장소에 올라가지 않는다(.gitignore). 없으면 환경변수로 준 것으로 본다.
#
#   cp scripts/env.example.sh config/env && chmod 600 config/env   # 한 번
#   ./scripts/run-server.sh --check     # 띄우지 않고 준비 상태만 본다
#   ./scripts/run-server.sh
set -euo pipefail
cd "$(dirname "$0")/.."

# 셸로 읽는다(작은따옴표로 감싼 KEY='값'). `set -a` 로 읽은 값을 java 에 넘긴다.
# 파일을 먼저 읽어야 아래 기본값(포트 · 인증서 자리)이 그 값을 따른다.
ENV_FILE="config/env"
env_note="없음 — 환경변수를 직접 주는 것으로 봅니다"
if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  . "./$ENV_FILE"
  set +a
  env_note="읽었습니다"
fi

JAR="target/sbomsight-1.0.0.jar"
PORT="${SBOMSIGHT_PORT:-8443}"
KEYSTORE="${SBOMSIGHT_KEYSTORE:-file:./config/keystore.p12}"
GRYPE="${SBOMSIGHT_GRYPE:-grype}"

fail=0
say() { # 상태 한 줄
  if [ "$1" = "ok" ]; then printf '  OK   %s\n' "$2"
  else printf ' 안됨  %s\n' "$2"; fail=1; fi
}

echo
echo "SBOMSight 준비 상태"
printf -- '-%.0s' {1..60}; echo

# java -version 은 버전을 stderr 로 낸다. 오류라서가 아니라 처음부터 그렇다.
# 첫 줄을 그냥 집으면 안 된다 — JAVA_TOOL_OPTIONS 가 설정돼 있으면 JVM 이
# "Picked up JAVA_TOOL_OPTIONS: ..." 를 먼저 찍고, 그걸 버전으로 읽게 된다.
if command -v java >/dev/null 2>&1; then
  ver=$(java -version 2>&1 | grep -m1 'version "')
  major=$(printf '%s' "$ver" | sed -n 's/^[^"]*"\([0-9][0-9]*\).*/\1/p')
  if [ "${major:-0}" -ge 21 ] 2>/dev/null; then say ok "Java 21 이상  $ver"
  else say no "Java 21 이상  $ver"; fi
else
  say no "Java  PATH 에 java 가 없습니다"
fi

[ -f "$JAR" ] && say ok "빌드된 jar  $JAR" || say no "빌드된 jar  $JAR (./mvnw package)"

say ok "config/env  $env_note"
# 비밀번호가 든 파일을 다른 계정이 읽을 수 있으면 말한다(띄우는 것은 막지 않는다).
if [ -f "$ENV_FILE" ] && [ -n "$(find "$ENV_FILE" -perm /077 2>/dev/null)" ]; then
  printf '  [!]  %s\n' "config/env 를 다른 계정도 읽을 수 있습니다 — chmod 600 config/env"
fi

ks="${KEYSTORE#file:}"
[ -f "$ks" ] && say ok "인증서  $ks" || say no "인증서  $ks (scripts/make-keystore.sh)"

command -v "$GRYPE" >/dev/null 2>&1 && say ok "grype  $GRYPE" || say no "grype  $GRYPE"

# 비밀번호에는 기본값이 없다. 안 넣으면 스프링이 자리표시자를 못 풀고
# 스택 트레이스로 멈춘다 — 여기서 한 줄로 먼저 말한다.
[ -n "${SBOMSIGHT_DB_PASSWORD+x}" ] \
  && say ok "DB 비밀번호  SBOMSIGHT_DB_PASSWORD" \
  || say no "DB 비밀번호  SBOMSIGHT_DB_PASSWORD 가 없습니다"
[ -n "${SBOMSIGHT_KEYSTORE_PASSWORD+x}" ] \
  && say ok "키스토어 비밀번호  SBOMSIGHT_KEYSTORE_PASSWORD" \
  || say no "키스토어 비밀번호  SBOMSIGHT_KEYSTORE_PASSWORD 가 없습니다"
# 주소를 안 주면 개발용 기본값(127.0.0.1:13306)으로 붙는다 — 설치한 DB(3306)가
# 아니다. 막지는 않는다(윈도우판과 같다) — 개발 PC 는 그 기본값으로 돈다.
if [ -n "${SBOMSIGHT_DB_URL:-}" ]; then
  say ok "DB 주소  ${SBOMSIGHT_DB_URL%%\?*}"
else
  printf '  [!]  %s\n' "DB 주소  SBOMSIGHT_DB_URL 이 없어 개발용 기본값(127.0.0.1:13306)으로 붙습니다"
fi

printf -- '-%.0s' {1..60}; echo

if [ "${1:-}" = "--check" ]; then
  echo
  [ "$fail" = 0 ] && { echo "준비되었습니다."; exit 0; } || { echo "위의 '안됨' 을 먼저 해결하세요."; exit 1; }
fi
[ "$fail" = 0 ] || { echo; echo "위의 '안됨' 을 먼저 해결하세요."; exit 1; }

# Linux 는 1024 미만 포트에 권한(CAP_NET_BIND_SERVICE)이 필요하다. Windows 는 그렇지
# 않다. 권한이 **있는데도** 없다고 말하지 않게 셋을 본다: root 인가, 이 프로세스가
# 받았는가(systemd 의 AmbientCapabilities), java 파일에 걸려 있는가(setcap).
can_bind_low() {
  [ "$(id -u)" = 0 ] && return 0
  local eff
  eff=$(awk '/^CapEff:/ {print $2}' /proc/$$/status 2>/dev/null || true)
  [ -n "$eff" ] && (( (16#$eff >> 10) & 1 )) && return 0
  command -v getcap >/dev/null 2>&1 \
    && getcap "$(readlink -f "$(command -v java)")" 2>/dev/null | grep -q cap_net_bind_service
}
if [ "$PORT" -lt 1024 ] && ! can_bind_low; then
  echo
  echo "[!] $PORT 는 1024 미만이라 권한이 필요합니다. 셋 중 하나를 쓰세요:"
  echo "      서비스로 돌린다 — systemd 가 권한을 준다 (docs/linux-setup.md)"
  echo "      sudo setcap 'cap_net_bind_service=+ep' \$(readlink -f \$(which java))"
  echo "      SBOMSIGHT_PORT=8443 $0"
fi

echo
echo "접속 주소"
echo "  https://localhost:$PORT"
hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]' | while read -r ip; do
  echo "  https://$ip:$PORT"
done
echo

exec java -Dfile.encoding=UTF-8 -jar "$JAR"
