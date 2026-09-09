#!/usr/bin/env bash
# 자체 서명 인증서 만들기 (개발·초기 구축용)
#
# 정식 인증서를 받으면 이 파일을 바꿔 끼우기만 하면 된다 — 사내 CA 가 내주는
# .pfx 를 그대로 config/keystore.p12 자리에 놓고 비밀번호만 맞추면 된다.
#
#   ./scripts/make-keystore.sh [호스트이름] [비밀번호]
set -euo pipefail

HOST="${1:-sbomsight.local}"
PASSWORD="${2:-changeit}"
OUT="config/keystore.p12"

mkdir -p config

# SAN 에 호스트이름과 접속에 쓸 IP 를 함께 넣는다. 요즘 브라우저는 CN 을 보지
# 않으므로 SAN 이 없으면 "이름이 맞지 않는다"고 막는다.
IPS=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]' | sed 's/^/ip:/' | paste -sd, -)
SAN="dns:${HOST},dns:localhost,ip:127.0.0.1"
[ -n "$IPS" ] && SAN="${SAN},${IPS}"

keytool -genkeypair \
  -alias sbomsight \
  -keyalg RSA -keysize 3072 \
  -validity 825 \
  -storetype PKCS12 \
  -keystore "$OUT" \
  -storepass "$PASSWORD" \
  -dname "CN=${HOST}, OU=Security, O=SBOMSight, L=Seoul, C=KR" \
  -ext "SAN=${SAN}" \
  -ext "KeyUsage=digitalSignature,keyEncipherment" \
  -ext "ExtendedKeyUsage=serverAuth"

echo
echo "만들었습니다: $OUT"
echo "  호스트   ${HOST}"
echo "  SAN      ${SAN}"
echo
echo "브라우저 경고를 없애려면 이 인증서를 사내 CA 로 신뢰 등록하거나,"
echo "정식 인증서를 받아 같은 자리에 .p12 로 바꿔 끼우세요."
