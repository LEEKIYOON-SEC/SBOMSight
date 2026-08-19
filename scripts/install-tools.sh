#!/usr/bin/env bash
# Syft·Grype 설치 (Linux / macOS)
#
# 폐쇄망에서는 이 스크립트를 쓸 수 없다. 인터넷 되는 구간에서 바이너리를
# 내려받아 반입한 뒤 PATH에 두거나 SYFT_BIN/GRYPE_BIN으로 경로를 지정한다.
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
mkdir -p "$INSTALL_DIR"

install_tool() {
  local name="$1"
  if command -v "$name" >/dev/null 2>&1; then
    echo "[skip] $name 이미 설치됨: $(command -v "$name") ($("$name" version 2>/dev/null | head -1))"
    return
  fi
  echo "[install] $name → $INSTALL_DIR"
  curl -sSfL "https://get.anchore.io/${name}" | sh -s -- -b "$INSTALL_DIR"
}

install_tool syft
install_tool grype

echo
echo "설치 위치: $INSTALL_DIR"
echo "PATH에 없다면 다음을 셸 프로필에 추가하세요:"
echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
echo
echo "취약점 DB 준비 (인터넷 필요):  grype db update"
echo "오프라인 운영:                 GRYPE_DB_AUTO_UPDATE=false 로 두고 grype db import <archive>"
