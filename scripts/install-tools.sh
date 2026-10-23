#!/usr/bin/env bash
# Syft·Grype 설치 (Linux / macOS)
#
# **릴리스 파일을 직접 받아 checksums.txt 와 SHA-256 을 대조하고, 어긋나면
# 설치를 멈춘다.** 윈도우판(install-tools.ps1)과 같은 규칙이다. 취약점 스캐너를
# 검증 없이 설치하는 것은 앞뒤가 맞지 않는다.
#
# 앞서는 https://get.anchore.io/<이름> 을 받아 `sh` 로 돌렸다. 그 스크립트도
# 해시를 대조하지만, 2026-09-26 에 받은 판은 **어긋나도 오류 한 줄만 찍고 설치를
# 계속했다** — 대조 결과를 확인하지 않고 다음 줄로 넘어간다(download_asset). 그
# 함수를 떼어 내 틀린 해시로 돌려 보고 찾았다.
#
# 폐쇄망에서는 이 스크립트를 쓸 수 없다. 인터넷 되는 구간에서 tar.gz 와
# checksums.txt 를 함께 받아 반입하고, `sha256sum -c` 로 확인한 뒤 풀어서 PATH 에
# 두거나 SBOMSIGHT_GRYPE 로 경로를 지정한다(docs/offline-operations.md).
#
#   ./scripts/install-tools.sh
#   GRYPE_VERSION=0.115.0 SYFT_VERSION=1.50.0 ./scripts/install-tools.sh
#   INSTALL_DIR=/usr/local/bin sudo -E ./scripts/install-tools.sh   # 서비스 계정도 보게
#   FORCE=1 ./scripts/install-tools.sh                               # 있어도 다시 받는다
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

# 최신 태그를 못 알아냈을 때 쓰는 하한선이다. "권장 버전" 이 아니라 "확실히
# 존재하는 버전" 일 뿐이다 — 윈도우판과 같은 값.
declare -A FALLBACK=([syft]=1.50.0 [grype]=0.115.0)

os() {
  case "$(uname -s)" in
    Linux) echo linux ;;
    Darwin) echo darwin ;;
    *) echo "지원하지 않는 운영체제입니다: $(uname -s)" >&2; return 1 ;;
  esac
}

arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) echo "지원하지 않는 아키텍처입니다: $(uname -m)" >&2; return 1 ;;
  esac
}

# GitHub 의 releases/latest 는 실제 태그로 넘겨 준다. API 키가 필요 없다.
latest() {
  local name="$1" url
  url=$(curl -sSfL -o /dev/null -w '%{url_effective}' \
             "https://github.com/anchore/$name/releases/latest" 2>/dev/null || true)
  if [[ "$url" =~ /tag/v([0-9][0-9.]*)$ ]]; then
    echo "${BASH_REMATCH[1]}"
  else
    echo "[!] $name 최신 버전을 알아내지 못했습니다. 고정 버전 ${FALLBACK[$name]} 을 씁니다." >&2
    echo "    최신을 쓰려면: ${name^^}_VERSION=<버전>" >&2
    echo "${FALLBACK[$name]}"
  fi
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# checksums.txt 에서 그 파일의 해시를 찾아 **같을 때만** 0 을 돌려준다.
# 항목이 없어도 실패다 — 대조할 것이 없으면 확인한 것이 아니다.
verify() {
  local file="$1" sums="$2" want got
  want=$(awk -v f="$(basename "$file")" '$2 == f || $2 == "*" f { print tolower($1) }' "$sums")
  if [ -z "$want" ]; then
    echo "checksums.txt 에 $(basename "$file") 항목이 없습니다. 설치를 중단합니다." >&2
    return 1
  fi
  got=$(sha256 "$file")
  if [ "$want" != "$got" ]; then
    printf 'SHA-256 불일치입니다. 설치를 중단합니다.\n  기대: %s\n  실제: %s\n' "$want" "$got" >&2
    return 1
  fi
  echo "[verify] SHA-256 확인 (${want:0:16}…)"
}

# 서브셸로 돈다 — 받은 것을 치우는 EXIT 가 성공 · 실패 어느 쪽이든 이 도구 하나에만 걸린다.
install_tool() (
  name="$1" version="$2"
  existing=$(command -v "$name" 2>/dev/null || true)
  if [ -n "$existing" ] && [ -z "${FORCE:-}" ]; then
    echo "[skip] $name 이미 설치됨: $existing"
    echo "       다시 받으려면 FORCE=1"
    exit 0
  fi

  [ -n "$version" ] || version=$(latest "$name")
  tarball="${name}_${version}_$(os)_$(arch).tar.gz"
  sums="${name}_${version}_checksums.txt"
  base="https://github.com/anchore/$name/releases/download/v$version"
  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT

  echo "[download] $tarball"
  curl -sSfL -o "$work/$tarball" "$base/$tarball"
  curl -sSfL -o "$work/$sums" "$base/$sums"
  verify "$work/$tarball" "$work/$sums"

  tar -xzf "$work/$tarball" -C "$work" "$name"
  mkdir -p "$INSTALL_DIR"
  install -m 0755 "$work/$name" "$INSTALL_DIR/$name"
  echo "[install] $name $version -> $INSTALL_DIR"
)

main() {
  install_tool syft "${SYFT_VERSION:-}"
  install_tool grype "${GRYPE_VERSION:-}"

  echo
  echo "설치 위치: $INSTALL_DIR"
  case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) echo "PATH 에 없습니다. 셸 프로필에 더하거나 SBOMSIGHT_GRYPE 로 경로를 지정하세요:"
       echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
       echo "  SBOMSIGHT_GRYPE=$INSTALL_DIR/grype" ;;
  esac
  echo
  echo "취약점 DB 준비 (인터넷 필요):  grype db update"
  echo "오프라인 운영:                 GRYPE_DB_AUTO_UPDATE=false 로 두고 grype db import <archive>"
}

# 불러오기만 하면(source) 함수만 정의한다 — 대조 규칙을 따로 시험해 볼 수 있게.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi
