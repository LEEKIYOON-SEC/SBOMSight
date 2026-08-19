#!/usr/bin/env bash
# 전체 테스트 — Python 과 JavaScript 양쪽.
#
# 이그레스 가드는 두 언어로 구현되어 있고 같은 정책·같은 벡터로 채점받는다.
# 한쪽만 돌리면 두 구현이 갈라진 것을 잡지 못한다.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[1/2] Python"
python3 -m pytest

echo
echo "[2/2] JavaScript (이그레스 가드 적합성)"
POLICY_HASH="$(python3 -c "import sys; sys.path.insert(0,'.'); from core.policy import load; print(load('policy/egress-policy.json').sha256)")"
node tests/js/sanitizer.test.mjs "$POLICY_HASH"
