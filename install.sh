#!/bin/sh
# blackbox installer — downloads a prebuilt binary from GitHub Releases.
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/wanazhar/blackbox/master/install.sh | sh
#   BLACKBOX_VERSION=v1.0.0 curl -fsSL ... | sh
#   INSTALL_DIR=$HOME/.local/bin curl -fsSL ... | sh
set -eu

REPO="${BLACKBOX_REPO:-wanazhar/blackbox}"
VERSION="${BLACKBOX_VERSION:-latest}"
INSTALL_DIR="${INSTALL_DIR:-${HOME}/.local/bin}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: required command not found: $1" >&2
    exit 1
  }
}

need uname
need mktemp

if command -v curl >/dev/null 2>&1; then
  download() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
  download() { wget -qO "$2" "$1"; }
else
  echo "error: need curl or wget" >&2
  exit 1
fi

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$os" in
  linux)  os_tag=unknown-linux-gnu ;;
  darwin) os_tag=apple-darwin ;;
  *)
    echo "error: unsupported OS: $os (use: cargo install blackbox-recorder)" >&2
    exit 1
    ;;
esac
case "$arch" in
  x86_64|amd64) arch_tag=x86_64 ;;
  aarch64|arm64) arch_tag=aarch64 ;;
  *)
    echo "error: unsupported arch: $arch (use: cargo install blackbox-recorder)" >&2
    exit 1
    ;;
esac

asset="blackbox-${arch_tag}-${os_tag}.tar.gz"

if [ "$VERSION" = "latest" ]; then
  url="https://github.com/${REPO}/releases/latest/download/${asset}"
else
  # accept v1.0.0 or 1.0.0
  case "$VERSION" in
    v*) tag="$VERSION" ;;
    *) tag="v${VERSION}" ;;
  esac
  url="https://github.com/${REPO}/releases/download/${tag}/${asset}"
fi

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

echo "Downloading ${url}"
if ! download "$url" "$tmpdir/$asset"; then
  echo "error: download failed. Is there a release asset for ${arch_tag}-${os_tag}?" >&2
  echo "       Fallback: cargo install blackbox-recorder" >&2
  exit 1
fi

tar -xzf "$tmpdir/$asset" -C "$tmpdir"
bin=$(find "$tmpdir" -type f -name blackbox | head -n 1)
if [ -z "$bin" ]; then
  echo "error: blackbox binary not found in archive" >&2
  exit 1
fi

mkdir -p "$INSTALL_DIR"
install -m 755 "$bin" "$INSTALL_DIR/blackbox"
echo "Installed: $INSTALL_DIR/blackbox"
if ! echo ":$PATH:" | grep -q ":$INSTALL_DIR:"; then
  echo "Note: add to PATH →  export PATH=\"$INSTALL_DIR:\$PATH\""
fi
"$INSTALL_DIR/blackbox" --version || true
echo "Next: cd your-project && blackbox enable --install-shell"
