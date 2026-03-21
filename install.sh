#!/usr/bin/env bash
# vigil installer — downloads and installs the latest pre-built release.
#
# Usage:
#   curl -fsSL https://github.com/VectorInstitute/vigil/releases/latest/download/install.sh | sudo bash
#
# Or, from a downloaded tarball:
#   sudo ./install.sh
#
set -euo pipefail

REPO="VectorInstitute/vigil"
INSTALL_BIN="/usr/local/bin/vigil"
INSTALL_LIB="/usr/lib/vigil"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[vigil]${NC} $*"; }
warn()  { echo -e "${YELLOW}[vigil]${NC} $*"; }
error() { echo -e "${RED}[vigil]${NC} $*" >&2; }

# Must run as root
if [ "$(id -u)" -ne 0 ]; then
  error "Run as root: sudo $0"
  exit 1
fi

# ── Detect architecture ───────────────────────────────────────────────────────
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  ARCH_SUFFIX="amd64" ;;
  aarch64) ARCH_SUFFIX="arm64" ;;
  *)
    error "Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

# ── Install from local tarball (if running from extracted tarball) ────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "${SCRIPT_DIR}/vigil" ] && [ -f "${SCRIPT_DIR}/vigil.bpf.o" ]; then
  info "Installing from local files in ${SCRIPT_DIR}..."
  install -m 755 "${SCRIPT_DIR}/vigil" "${INSTALL_BIN}"
  mkdir -p "${INSTALL_LIB}"
  install -m 644 "${SCRIPT_DIR}/vigil.bpf.o" "${INSTALL_LIB}/vigil.bpf.o"
  if [ -d "${SCRIPT_DIR}/profiles" ]; then
    cp -r "${SCRIPT_DIR}/profiles" "${INSTALL_LIB}/profiles"
  fi
  info "Installed vigil $(vigil --version 2>/dev/null || true)"
else
  # ── Download latest release from GitHub ──────────────────────────────────────
  info "Fetching latest release from github.com/${REPO}..."
  if ! command -v curl &>/dev/null; then
    apt-get install -y -qq curl 2>/dev/null || yum install -y curl 2>/dev/null || \
      { error "curl not found — install it and retry"; exit 1; }
  fi

  TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

  if [ -z "$TAG" ]; then
    error "Could not fetch latest release tag. Check your network or visit https://github.com/${REPO}/releases"
    exit 1
  fi

  info "Latest release: ${TAG}"
  BASE_URL="https://github.com/${REPO}/releases/download/${TAG}"

  TMPDIR=$(mktemp -d)
  trap 'rm -rf "$TMPDIR"' EXIT

  info "Downloading vigil binary..."
  curl -fsSL "${BASE_URL}/vigil-linux-${ARCH_SUFFIX}" -o "${TMPDIR}/vigil"

  info "Downloading vigil.bpf.o..."
  curl -fsSL "${BASE_URL}/vigil.bpf.o" -o "${TMPDIR}/vigil.bpf.o"

  info "Downloading profiles..."
  curl -fsSL "${BASE_URL}/vigil-${TAG}-linux-${ARCH_SUFFIX}.tar.gz" -o "${TMPDIR}/vigil.tar.gz"
  tar -xzf "${TMPDIR}/vigil.tar.gz" -C "${TMPDIR}" --strip-components=1

  install -m 755 "${TMPDIR}/vigil" "${INSTALL_BIN}"
  mkdir -p "${INSTALL_LIB}"
  install -m 644 "${TMPDIR}/vigil.bpf.o" "${INSTALL_LIB}/vigil.bpf.o"
  if [ -d "${TMPDIR}/profiles" ]; then
    cp -r "${TMPDIR}/profiles" "${INSTALL_LIB}/profiles"
  fi
  info "Installed vigil ${TAG}"
fi

# ── Check lsm=bpf ────────────────────────────────────────────────────────────
echo ""
if grep -q "lsm=bpf" /proc/cmdline 2>/dev/null; then
  info "lsm=bpf is active — vigil is ready to use."
  echo ""
  echo "  Run:  sudo vigil watch --profile ${INSTALL_LIB}/profiles/claude-code.yaml"
else
  warn "lsm=bpf is NOT active. Blocking requires a one-time kernel boot parameter change."
  echo ""
  echo "  To enable on Ubuntu/Debian:"
  echo "    sudo sed -i 's/^GRUB_CMDLINE_LINUX=\"\(.*\)\"/GRUB_CMDLINE_LINUX=\"\1 lsm=bpf\"/' /etc/default/grub"
  echo "    sudo update-grub && sudo reboot"
  echo ""
  echo "  After reboot, run:"
  echo "    sudo vigil watch --profile ${INSTALL_LIB}/profiles/claude-code.yaml"
fi
echo ""
