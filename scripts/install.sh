#!/usr/bin/env sh
# Sirr installer — downloads the latest sirrd (server) and sirr (CLI) binaries.
# Usage: curl -fsSL https://get.sirr.dev | sh
#        curl -fsSL https://get.sirr.dev | sh -s -- --cli-only
#        curl -fsSL https://get.sirr.dev | sh -s -- --server-only
set -eu

REPO="sirrlock/sirr"
INSTALL_DIR="${SIRR_INSTALL_DIR:-/usr/local/bin}"
INSTALL_CLI=1
INSTALL_SERVER=1

for arg in "$@"; do
  case "$arg" in
    --cli-only)    INSTALL_SERVER=0 ;;
    --server-only) INSTALL_CLI=0 ;;
    --help|-h)
      echo "Usage: curl -fsSL https://get.sirr.dev | sh [-s -- OPTIONS]"
      echo ""
      echo "Options:"
      echo "  --cli-only      Install only the sirr CLI"
      echo "  --server-only   Install only the sirrd server"
      echo ""
      echo "Environment:"
      echo "  SIRR_INSTALL_DIR  Install directory (default: /usr/local/bin)"
      echo "  SIRR_VERSION      Specific version to install (default: latest)"
      exit 0
      ;;
  esac
done

# ── Detect OS and architecture ───────────────────────────────────────────

detect_platform() {
  OS="$(uname -s)"
  ARCH="$(uname -m)"

  case "$OS" in
    Linux)  OS_NAME="linux" ;;
    Darwin) OS_NAME="darwin" ;;
    *)      echo "Error: unsupported OS: $OS"; exit 1 ;;
  esac

  case "$ARCH" in
    x86_64|amd64)  ARCH_NAME="x64" ;;
    aarch64|arm64) ARCH_NAME="arm64" ;;
    *)             echo "Error: unsupported architecture: $ARCH"; exit 1 ;;
  esac

  PLATFORM="${OS_NAME}-${ARCH_NAME}"
}

# ── Resolve latest version ───────────────────────────────────────────────

resolve_version() {
  if [ -n "${SIRR_VERSION:-}" ]; then
    VERSION="$SIRR_VERSION"
    return
  fi

  echo "Fetching latest release..."
  VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

  if [ -z "$VERSION" ]; then
    echo "Error: could not determine latest version"
    exit 1
  fi
}

# ── Download and install a binary ────────────────────────────────────────

install_binary() {
  BINARY_NAME="$1"
  ARCHIVE="${BINARY_NAME}-${PLATFORM}.tar.gz"
  URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE}"
  TMPDIR=$(mktemp -d)

  echo "Downloading ${BINARY_NAME} ${VERSION} for ${PLATFORM}..."
  if ! curl -fsSL "$URL" -o "${TMPDIR}/${ARCHIVE}"; then
    echo "Error: failed to download ${URL}"
    rm -rf "$TMPDIR"
    return 1
  fi

  tar xzf "${TMPDIR}/${ARCHIVE}" -C "$TMPDIR"
  rm -f "${TMPDIR}/${ARCHIVE}"

  # Find the binary (may be at top level or in a subdirectory)
  BINARY=$(find "$TMPDIR" -name "$BINARY_NAME" -type f | head -1)
  if [ -z "$BINARY" ]; then
    echo "Error: ${BINARY_NAME} not found in archive"
    rm -rf "$TMPDIR"
    return 1
  fi

  chmod +x "$BINARY"

  if [ -w "$INSTALL_DIR" ]; then
    mv "$BINARY" "${INSTALL_DIR}/${BINARY_NAME}"
  else
    echo "Installing to ${INSTALL_DIR} (requires sudo)..."
    sudo mv "$BINARY" "${INSTALL_DIR}/${BINARY_NAME}"
  fi

  rm -rf "$TMPDIR"
  echo "  Installed ${BINARY_NAME} to ${INSTALL_DIR}/${BINARY_NAME}"
}

# ── Main ─────────────────────────────────────────────────────────────────

main() {
  detect_platform
  resolve_version

  echo ""
  echo "  Platform: ${PLATFORM}"
  echo "  Version:  ${VERSION}"
  echo "  Install:  ${INSTALL_DIR}"
  echo ""

  if [ "$INSTALL_SERVER" -eq 1 ]; then
    install_binary "sirrd"
  fi

  if [ "$INSTALL_CLI" -eq 1 ]; then
    install_binary "sirr"
  fi

  echo ""
  echo "Done! Run 'sirrd serve' to start the server or 'sirr --help' for CLI usage."
}

main
