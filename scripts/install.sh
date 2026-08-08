#!/usr/bin/env sh
set -e
REPO="luutuankiet/gcpx"
BIN_DIR="${XDG_BIN_HOME:-$HOME/.local/bin}"
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/gcpx"

case "$(uname -s)" in
  Linux)  OS=linux ;;
  Darwin) OS=darwin ;;
  *) echo "unsupported OS: $(uname -s)." >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64 ;;
  arm64|aarch64) ARCH=arm64 ;;
  *) echo "unsupported arch: $(uname -m)." >&2; exit 1 ;;
esac

mkdir -p "$BIN_DIR" "$STATE_DIR"
PIN_ARG="${1:-}"
VERSION="${GCPX_VERSION:-$PIN_ARG}"
if [ -z "$VERSION" ]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p')"
fi
ASSET="gcpx_${VERSION#v}_${OS}_${ARCH}.tar.gz"
URL="https://github.com/$REPO/releases/download/$VERSION/$ASSET"
TMP="$(mktemp -d)"; trap "rm -rf $TMP" EXIT
curl -fsSL "$URL" -o "$TMP/gcpx.tar.gz"
tar -xzf "$TMP/gcpx.tar.gz" -C "$TMP"
install -m 0755 "$TMP/gcpx" "$BIN_DIR/gcpx"
if [ -n "$PIN_ARG" ] || [ -n "$GCPX_VERSION" ]; then
  echo "$VERSION" > "$STATE_DIR/pinned-version"
else
  rm -f "$STATE_DIR/pinned-version"
fi
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "NOTE: $BIN_DIR is not on your PATH." ;;
esac
"$BIN_DIR/gcpx" version
