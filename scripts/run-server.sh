#!/usr/bin/env bash
# SBOMSight 을 띄운다 (Linux).
#
# Windows 는 scripts\run-server.ps1 을 쓴다. 운영 값은 환경변수로 준다 —
# 저장소에 두지 않는다.
#
#   SBOMSIGHT_DB_PASSWORD=... SBOMSIGHT_KEYSTORE_PASSWORD=... ./scripts/run-server.sh
set -euo pipefail
cd "$(dirname "$0")/.."

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

ks="${KEYSTORE#file:}"
[ -f "$ks" ] && say ok "인증서  $ks" || say no "인증서  $ks (scripts/make-keystore.sh)"

command -v "$GRYPE" >/dev/null 2>&1 && say ok "grype  $GRYPE" || say no "grype  $GRYPE"

printf -- '-%.0s' {1..60}; echo

if [ "${1:-}" = "--check" ]; then
  echo
  [ "$fail" = 0 ] && { echo "준비되었습니다."; exit 0; } || { echo "위의 '안됨' 을 먼저 해결하세요."; exit 1; }
fi
[ "$fail" = 0 ] || { echo; echo "위의 '안됨' 을 먼저 해결하세요."; exit 1; }

# Linux 는 1024 미만 포트에 권한이 필요하다. Windows 는 그렇지 않다.
if [ "$PORT" -lt 1024 ] && [ "$(id -u)" != 0 ]; then
  echo
  echo "[!] $PORT 는 1024 미만이라 권한이 필요합니다. 둘 중 하나를 쓰세요:"
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
