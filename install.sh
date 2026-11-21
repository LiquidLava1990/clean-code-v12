#!/bin/sh
# Clean Code V12 installer for Linux and macOS — installs `ccv12` + `cc-lsp`.
#
#   curl -fsSL https://github.com/LiquidLava1990/clean-code-v12/releases/latest/download/install.sh | sh
#
# Environment overrides:
#   CCV12_VERSION       release tag to install (default: latest), e.g. v0.1.0
#   CCV12_INSTALL_DIR   install directory (default: $HOME/.local/bin)
#   CCV12_REPO          GitHub owner/repo to download from
#   CCV12_DOWNLOAD_URL  base URL holding the release assets (mirrors,
#                       air-gapped installs); overrides REPO and VERSION

set -eu

REPO="${CCV12_REPO:-LiquidLava1990/clean-code-v12}"
VERSION="${CCV12_VERSION:-latest}"
INSTALL_DIR="${CCV12_INSTALL_DIR:-$HOME/.local/bin}"

say() { printf 'ccv12-install: %s\n' "$*"; }
fail() { printf 'ccv12-install: error: %s\n' "$*" >&2; exit 1; }
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
        if [ -n "${CCV12_DOWNLOAD_URL:-}" ]; then
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

release_base_url() {
    if [ -n "${CCV12_DOWNLOAD_URL:-}" ]; then
        echo "${CCV12_DOWNLOAD_URL%/}"
    elif [ "$VERSION" = latest ]; then
        echo "https://github.com/${REPO}/releases/latest/download"
    else
        echo "https://github.com/${REPO}/releases/download/${VERSION}"
    fi
}

main() {
    need uname
    need tar
    target="$(detect_target)"
    name="ccv12-${target}"
    archive="${name}.tar.gz"
    base="$(release_base_url)"

    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT INT TERM

    say "downloading ${archive} (${VERSION})"
    download "${base}/${archive}" "$tmp/$archive"
    download "${base}/${archive}.sha256" "$tmp/$archive.sha256"
    verify_checksum "$tmp/$archive" "$tmp/$archive.sha256"
    tar -xzf "$tmp/$archive" -C "$tmp"

    mkdir -p "$INSTALL_DIR"
    install -m 0755 "$tmp/$name/ccv12" "$INSTALL_DIR/ccv12"
    install -m 0755 "$tmp/$name/cc-lsp" "$INSTALL_DIR/cc-lsp"
    say "installed $INSTALL_DIR/ccv12 and $INSTALL_DIR/cc-lsp"

    case ":$PATH:" in
        *":$INSTALL_DIR:"*) ;;
        *) say "add $INSTALL_DIR to your PATH, e.g.: echo 'export PATH=\"$INSTALL_DIR:\$PATH\"' >> ~/.profile" ;;
    esac
    "$INSTALL_DIR/ccv12" --version
}

main "$@"
