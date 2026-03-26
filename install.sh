#!/bin/sh

# devcert installer script
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/melvinotieno/devcert/main/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/melvinotieno/devcert/main/install.sh | sh -s -- 0.1.0
#   curl -fsSL https://raw.githubusercontent.com/melvinotieno/devcert/main/install.sh | sh -s -- v0.1.0
#
# This script:
#   1. Detects OS and architecture
#   2. Downloads the release binary from GitHub
#   3. Downloads and verifies SHA-256 checksum
#   4. Moves the binary into place

set -eu

REPO="melvinotieno/devcert"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="devcert"

# --- Helpers ---

info() {
    printf '[devcert] %s\n' "$1"
}

error() {
    printf '[devcert] ERROR: %s\n' "$1" >&2
    exit 1
}

need_cmd() {
    if ! command -v "$1" > /dev/null 2>&1; then
        error "Required command '$1' not found. Please install it and try again."
    fi
}

# --- Detect OS and Architecture ---

detect_platform() {
    OS="$(uname -s)"
    ARCH="$(uname -m)"

    case "$OS" in
        Linux)                  OS_NAME="linux" ;;
        Darwin)                 OS_NAME="darwin" ;;
        CYGWIN*|MINGW*|MSYS*)   OS_NAME="windows" ;;
        *)                      error "Unsupported operating system: $OS." ;;
    esac

    case "$ARCH" in
        x86_64|amd64)           ARCH_NAME="amd64" ;;
        aarch64|arm64)          ARCH_NAME="arm64" ;;
        *)                      error "Unsupported architecture: $ARCH." ;;
    esac

    ARTIFACT="${BINARY_NAME}-${OS_NAME}-${ARCH_NAME}"
    info "Detected platform: ${OS_NAME}/${ARCH_NAME}"
}

# --- Resolve Version ---

resolve_version() {
    REQUESTED_VERSION="$1"

    if [ -n "$REQUESTED_VERSION" ]; then
        VERSION_RAW="$REQUESTED_VERSION"
        if [ "${VERSION_RAW#v}" != "$VERSION_RAW" ]; then
            VERSION="$VERSION_RAW"
        else
            VERSION="v$VERSION_RAW"
        fi
        info "Using specified version: ${VERSION#v}"
    else
        info "Fetching latest release version..."
        VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
            | grep '"tag_name"' \
            | head -1 \
            | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"

        if [ -z "$VERSION" ]; then
            error "Could not determine latest version. Please specify a version explicitly."
        fi
        info "Latest version: ${VERSION#v}"
    fi

    BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
}

# --- Download ---

download_binary() {
    TMPDIR="$(mktemp -d)"
    trap 'rm -rf "$TMPDIR"' EXIT

    BINARY_URL="${BASE_URL}/${ARTIFACT}"
    CHECKSUM_URL="${BASE_URL}/checksums.txt"

    info "Downloading binary: ${BINARY_URL}"
    curl -fSL --progress-bar -o "${TMPDIR}/${ARTIFACT}" "$BINARY_URL" \
        || error "Failed to download binary. Check that version ${VERSION} exists and has a ${ARTIFACT} asset."

    info "Downloading checksums: ${CHECKSUM_URL}"
    curl -fsSL -o "${TMPDIR}/checksums.txt" "$CHECKSUM_URL" \
        || error "Failed to download checksums file."
}

# --- Verify Checksum ---

verify_checksum() {
    info "Verifying SHA-256 checksum..."

    EXPECTED="$(grep "${ARTIFACT}" "${TMPDIR}/checksums.txt" | awk '{print $1}')"
    if [ -z "$EXPECTED" ]; then
        error "No checksum found for ${ARTIFACT} in checksums.txt"
    fi

    if command -v sha256sum > /dev/null 2>&1; then
        ACTUAL="$(sha256sum "${TMPDIR}/${ARTIFACT}" | awk '{print $1}')"
    elif command -v shasum > /dev/null 2>&1; then
        ACTUAL="$(shasum -a 256 "${TMPDIR}/${ARTIFACT}" | awk '{print $1}')"
    else
        error "Neither sha256sum nor shasum found. Cannot verify checksum."
    fi

    if [ "$EXPECTED" != "$ACTUAL" ]; then
        error "Checksum mismatch!
        Expected: ${EXPECTED}
        Actual:   ${ACTUAL}
        This could indicate a corrupted download or a tampered binary. Aborting."
    fi

    info "Checksum verified."
}

# --- Install ---

install_binary() {
    chmod +x "${TMPDIR}/${ARTIFACT}"

    if [ -w "$INSTALL_DIR" ]; then
        mv "${TMPDIR}/${ARTIFACT}" "${INSTALL_DIR}/${BINARY_NAME}"
    else
        info "Elevated permissions required to install to ${INSTALL_DIR}"
        sudo mv "${TMPDIR}/${ARTIFACT}" "${INSTALL_DIR}/${BINARY_NAME}"
    fi

    info "Installed ${BINARY_NAME} to ${INSTALL_DIR}/${BINARY_NAME}"
}

# --- Main ---

main() {
  if [ "$#" -gt 1 ]; then
    error "Too many arguments. Pass at most one version (e.g. 0.1.0 or v0.1.0)."
  fi

    need_cmd curl
    need_cmd grep
    need_cmd mktemp
    need_cmd uname

    detect_platform
    resolve_version "${1:-}"
    download_binary
    verify_checksum
    install_binary

    printf '\n'
    info "Installation complete."
    info "Run 'devcert install' to set up your local CA."
    printf '\n'
}

main "$@"
