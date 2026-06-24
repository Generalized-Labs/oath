#!/bin/sh
set -e

REPO="Generalized-Labs/oath"
BIN_DIR="${OATH_INSTALL:-$HOME/.local/bin}"

# Detect platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64) ARCH="x64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) echo "Unsupported arch: $ARCH"; exit 1 ;;
esac

case "$OS" in
  darwin) PLATFORM="darwin" ;;
  linux)  PLATFORM="linux" ;;
  *) echo "Unsupported OS: $OS"; exit 1 ;;
esac

BINARY="oath-${PLATFORM}-${ARCH}"
LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)
URL="https://github.com/${REPO}/releases/download/${LATEST}/${BINARY}"

echo "Installing oath ${LATEST} for ${PLATFORM}-${ARCH}..."
mkdir -p "$BIN_DIR"
curl -fsSL "$URL" -o "$BIN_DIR/oath"
chmod +x "$BIN_DIR/oath"

echo "oath installed to $BIN_DIR/oath"
echo "Add $BIN_DIR to your PATH if not already there:"
echo "  export PATH=\"$BIN_DIR:\$PATH\""
