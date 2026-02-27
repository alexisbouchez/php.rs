#!/usr/bin/env bash
set -euo pipefail

REPO="alexisbouchez/php-rs"
INSTALL_DIR="$HOME/.php-rs/bin"
BINARY_NAME="php-rs"

# Detect OS
OS="$(uname -s)"
case "$OS" in
    Linux)  OS="linux" ;;
    Darwin) OS="darwin" ;;
    *)      echo "Error: Unsupported OS: $OS" >&2; exit 1 ;;
esac

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)  ARCH="x86_64" ;;
    aarch64|arm64) ARCH="aarch64" ;;
    *)             echo "Error: Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

TARGET="${BINARY_NAME}-${OS}-${ARCH}"

# Get latest release tag
echo "Fetching latest release..."
LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$LATEST" ]; then
    echo "Error: Could not determine latest release." >&2
    exit 1
fi

DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST}/${TARGET}.tar.gz"

echo "Downloading php-rs ${LATEST} for ${OS}/${ARCH}..."

# Create install directory
mkdir -p "$INSTALL_DIR"

# Download and extract
curl -fsSL "$DOWNLOAD_URL" | tar -xz -C "$INSTALL_DIR"
chmod +x "${INSTALL_DIR}/${BINARY_NAME}"

echo ""
echo "php-rs ${LATEST} installed to ${INSTALL_DIR}/${BINARY_NAME}"
echo ""

# Check if already in PATH
if command -v "$BINARY_NAME" &>/dev/null; then
    echo "php-rs is ready! Run: php-rs --version"
else
    echo "Add php-rs to your PATH:"
    echo ""
    echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
    echo ""
    echo "To make it permanent, add the line above to your ~/.bashrc or ~/.zshrc"
fi
