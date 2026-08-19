#!/usr/bin/env bash
# 전체 테스트 — Python 과 JavaScript 양쪽.
#
# 이그레스 가드와 매칭 엔진은 두 언어로 구현되어 있고, 같은 정책·같은 벡터로
# 채점받는다. 한쪽만 돌리면 두 구현이 갈라진 것을 잡지 못한다.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[1/3] Python"
python3 -m pytest

echo
echo "[2/3] 이그레스 가드 적합성 (JavaScript)"
POLICY_HASH="$(python3 -c "import sys; sys.path.insert(0,'.'); from core.policy import load; print(load('policy/egress-policy.json').sha256)")"
node tests/js/sanitizer.test.mjs "$POLICY_HASH"

echo
echo "[3/3] 파리티 — JavaScript 구현이 Python 구현과 같은 결과를 내는가"
python3 scripts/gen_parity_fixture.py >/dev/null
node tests/js/parity.test.mjs
