#!/usr/bin/env bash
# SBOMSight 웹 서버 기동 (Linux / macOS)
#
# 업로드된 SBOM과 스캔 결과에는 내부 자산 정보가 담긴다. 그래서 기본
# 바인딩은 127.0.0.1이며, 외부에 노출하려면 SBOMSIGHT_HOST를 명시적으로
# 바꿔야 한다.
set -euo pipefail

cd "$(dirname "$0")/.."

# .env 를 먼저 읽어야 한다 — 뒤에서 읽으면 .env 의 SBOMSIGHT_HOST 가 무시된다.
if [ -f .env ]; then
  echo "[i] .env 로드"
  set -a; . ./.env; set +a
fi

# --listen 은 내부망에 개방한다. 기본은 이 PC에서만 보인다.
LISTEN=0
ARGS=()
for arg in "$@"; do
  case "$arg" in
    --listen) LISTEN=1 ;;
    *) ARGS+=("$arg") ;;
  esac
done
set -- "${ARGS[@]+"${ARGS[@]}"}"

if [ "$LISTEN" = "1" ]; then
  HOST="0.0.0.0"
else
  HOST="${SBOMSIGHT_HOST:-127.0.0.1}"
fi
PORT="${SBOMSIGHT_PORT:-8000}"

# 가상환경이 있으면 활성화 여부와 무관하게 그 python을 쓴다. 활성화를 잊고
# 실행하면 전역 python에는 의존성이 없어 "먼저 설치하세요"만 반복하게 된다.
PYTHON="python3"
if [ -x .venv/bin/python ]; then
  PYTHON=".venv/bin/python"
  echo "[i] 가상환경 사용: .venv"
fi

if ! "$PYTHON" -c "import fastapi" 2>/dev/null; then
  echo "[!] 의존성이 없습니다. 먼저 실행하세요:"
  echo "    python3 -m venv .venv"
  echo "    . .venv/bin/activate"
  echo "    python -m pip install -r requirements.txt"
  exit 1
fi

if ! command -v "${GRYPE_BIN:-grype}" >/dev/null 2>&1; then
  echo "[!] grype를 찾을 수 없습니다. scripts/install-tools.sh 로 설치하거나"
  echo "    GRYPE_BIN 환경변수로 경로를 지정하세요. (설치 전에는 스캔이 실패합니다)"
fi

if [ "$HOST" != "127.0.0.1" ] && [ "$HOST" != "localhost" ]; then
  echo
  echo "[!] ${HOST} 로 바인딩합니다 — 이 PC 밖에서 접속할 수 있게 됩니다."
  echo "    스캔 결과에는 어떤 서버에 어떤 취약점이 있는지가 그대로 담깁니다."
  echo "    신뢰할 수 있는 내부망에서만 여세요."
  # 0.0.0.0 은 주소가 아니라 '전부'라는 뜻이라 브라우저에 그대로 칠 수 없다.
  if command -v hostname >/dev/null 2>&1; then
    for addr in $(hostname -I 2>/dev/null || true); do
      echo "[i] 접속 주소  http://${addr}:${PORT}"
    done
  fi
  echo
fi

# AI 상태를 미리 알려 준다 — 결과 화면에서 전송 버튼이 안 보이는 이유를
# 그때 가서 찾게 하지 않기 위한 것이다. 키 값 자체는 출력하지 않는다.
if [ "${SBOMSIGHT_AI_ENABLED:-0}" = "1" ] || [ "${SBOMSIGHT_AI_ENABLED:-}" = "true" ]; then
  if [ -n "${GEMINI_API_KEY:-}" ]; then
    echo "[i] AI 사용 가능 · 모델 ${GEMINI_MODEL:-gemini-3.5-flash-lite}"
  else
    echo "[!] SBOMSIGHT_AI_ENABLED=1 이지만 GEMINI_API_KEY 가 없습니다. 룰 기반으로만 동작합니다."
  fi
else
  echo "[i] AI 미사용 (기본값). 보고서는 룰 기반으로 완결됩니다."
fi

echo "[i] http://${HOST}:${PORT}"
exec "$PYTHON" -m uvicorn server.app:app --host "$HOST" --port "$PORT" "$@"
