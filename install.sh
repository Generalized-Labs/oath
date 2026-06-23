#!/bin/sh
# oath installer
# curl -fsSL https://oath.dev/install.sh | sh

set -e

REPO="generalized-labs/oath"
VERSION="latest"

# Detect platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
  darwin) OS="apple-darwin" ;;
  linux) OS="unknown-linux-gnu" ;;
  *) echo "Unsupported OS: $OS"; exit 1 ;;
esac

case "$ARCH" in
  x86_64|amd64) ARCH="x86_64" ;;
  arm64|aarch64) ARCH="aarch64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

TARGET="${ARCH}-${OS}"

if [ "$VERSION" = "latest" ]; then
  DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/oath-${TARGET}.tar.gz"
else
  DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/oath-${TARGET}.tar.gz"
fi

INSTALL_DIR="${OATH_INSTALL_DIR:-/usr/local/bin}"

echo "oath installer"
echo ""
echo "  target:  ${TARGET}"
echo "  install: ${INSTALL_DIR}/oath"
echo ""

# Download
TMP=$(mktemp -d)
curl -fsSL "$DOWNLOAD_URL" -o "$TMP/oath.tar.gz"
tar -xzf "$TMP/oath.tar.gz" -C "$TMP"

# Install
if [ -w "$INSTALL_DIR" ]; then
  mv "$TMP/oath" "$INSTALL_DIR/oath"
else
  sudo mv "$TMP/oath" "$INSTALL_DIR/oath"
fi

chmod +x "$INSTALL_DIR/oath"
rm -rf "$TMP"

echo "  installed oath to ${INSTALL_DIR}/oath"
echo ""
echo "  run: oath --help"
