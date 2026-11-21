#!/bin/sh
# Clean Code V12 installer for Linux and macOS.
#
#   curl -fsSL https://github.com/LiquidLava1990/clean-code-v12/releases/latest/download/install.sh | sh
#
# Environment overrides:
#   CC_VERSION      release tag to install (default: latest), e.g. v0.1.0
#   CC_INSTALL_DIR  install directory (default: $HOME/.local/bin)
#   CC_BIN_NAME     installed command name (default: cc, or ccv12 when a
#                   different `cc` — usually the C compiler — is on PATH)
#   CC_REPO         GitHub owner/repo to download from
#   CC_DOWNLOAD_URL base URL holding the release assets (mirrors, air-gapped
#                   installs); overrides CC_REPO and CC_VERSION

set -eu

REPO="${CC_REPO:-LiquidLava1990/clean-code-v12}"
VERSION="${CC_VERSION:-latest}"
INSTALL_DIR="${CC_INSTALL_DIR:-$HOME/.local/bin}"

say() { printf 'cc-install: %s\n' "$*"; }
fail() { printf 'cc-install: error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" > /dev/null 2>&1 || fail "'$1' is required but not installed; install it and re-run."; }

detect_target() {
    os="$(uname -s)"
    arch="$(uname -m)"
    case "$arch" in
        x86_64 | amd64) arch=x86_64 ;;
        arm64 | aarch64) arch=aarch64 ;;
        *) fail "unsupported CPU architecture '$arch'. Build from source: cargo install --git https://github.com/$REPO cc-cli" ;;
    esac
    case "$os" in
        Linux) echo "${arch}-unknown-linux-musl" ;;
        Darwin) echo "${arch}-apple-darwin" ;;
        *) fail "unsupported OS '$os'. On Windows use install.ps1; otherwise build from source with cargo." ;;
    esac
}

download() {
    if command -v curl > /dev/null 2>&1; then
        if [ -n "${CC_DOWNLOAD_URL:-}" ]; then
            curl -fsSL "$1" -o "$2"  # mirror: the user chose the scheme
        else
            curl --proto '=https' --tlsv1.2 -fsSL "$1" -o "$2"
        fi
    elif command -v wget > /dev/null 2>&1; then
        wget -q "$1" -O "$2"
    else
        fail "need curl or wget to download release assets."
    fi
}

verify_checksum() {
    expected="$(awk '{print $1}' "$2")"
    if command -v sha256sum > /dev/null 2>&1; then
        actual="$(sha256sum "$1" | awk '{print $1}')"
    elif command -v shasum > /dev/null 2>&1; then
        actual="$(shasum -a 256 "$1" | awk '{print $1}')"
    else
        say "no sha256sum/shasum found; skipping checksum verification"
        return 0
    fi
    [ "$expected" = "$actual" ] || fail "checksum mismatch for $(basename "$1") (expected $expected, got $actual). Re-run; if it persists, report it."
}

choose_bin_name() {
    if [ -n "${CC_BIN_NAME:-}" ]; then
        echo "$CC_BIN_NAME"
        return
    fi
    existing="$(command -v cc 2>/dev/null || true)"
    if [ -z "$existing" ] || [ "$existing" = "$INSTALL_DIR/cc" ]; then
        echo cc
    else
        echo ccv12
    fi
}

main() {
    need uname
    need tar
    target="$(detect_target)"
    archive="cc-${target}.tar.gz"
    if [ -n "${CC_DOWNLOAD_URL:-}" ]; then
        base="${CC_DOWNLOAD_URL%/}"
    elif [ "$VERSION" = latest ]; then
        base="https://github.com/${REPO}/releases/latest/download"
    else
        base="https://github.com/${REPO}/releases/download/${VERSION}"
    fi

    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT INT TERM

    say "downloading ${archive} (${VERSION})"
    download "${base}/${archive}" "$tmp/$archive"
    download "${base}/${archive}.sha256" "$tmp/$archive.sha256"
    verify_checksum "$tmp/$archive" "$tmp/$archive.sha256"
    tar -xzf "$tmp/$archive" -C "$tmp"

    bin_name="$(choose_bin_name)"
    mkdir -p "$INSTALL_DIR"
    install -m 0755 "$tmp/cc-${target}/cc" "$INSTALL_DIR/$bin_name"
    install -m 0755 "$tmp/cc-${target}/cc-lsp" "$INSTALL_DIR/cc-lsp"

    say "installed $INSTALL_DIR/$bin_name and $INSTALL_DIR/cc-lsp"
    if [ "$bin_name" != cc ]; then
        say "a different 'cc' (usually the C compiler) is already on PATH, so the"
        say "linter was installed as '$bin_name' to avoid shadowing it."
        say "Use '$bin_name check .' wherever the docs say 'cc check .'"
    fi
    case ":$PATH:" in
        *":$INSTALL_DIR:"*) ;;
        *) say "add $INSTALL_DIR to your PATH, e.g.: echo 'export PATH=\"$INSTALL_DIR:\$PATH\"' >> ~/.profile" ;;
    esac
    "$INSTALL_DIR/$bin_name" --version
}

main "$@"
