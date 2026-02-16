#!/usr/bin/env bash
# ------------------------------------------------------------------
# Servagent - Remote installation script
#
# One-liner installation from a fresh server:
#
#   curl -sSfL https://raw.githubusercontent.com/servagent/servagent/main/install-remote.sh | sudo bash
#   curl -sSfL https://raw.githubusercontent.com/servagent/servagent/main/install-remote.sh | sudo bash -s -- votre-domaine.com
#   curl -sSfL https://raw.githubusercontent.com/servagent/servagent/main/install-remote.sh | sudo bash -s -- --full-access votre-domaine.com
#   curl -sSfL https://raw.githubusercontent.com/servagent/servagent/main/install-remote.sh | sudo bash -s -- --version v0.2.0
#
# This script:
#   1. Downloads the specified (or latest) release from GitHub
#   2. Extracts it to a temporary directory
#   3. Runs the bundled install.sh with all forwarded arguments
# ------------------------------------------------------------------
set -euo pipefail

GITHUB_REPO="servagent/servagent"
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# --- Parse our own flags (--version), forward the rest to install.sh ---
VERSION=""
INSTALL_ARGS=()
for arg in "$@"; do
    case "$arg" in
        --version=*) VERSION="${arg#--version=}" ;;
        --version)   VERSION="__next__" ;;
        *)
            if [[ "$VERSION" == "__next__" ]]; then
                VERSION="$arg"
            else
                INSTALL_ARGS+=("$arg")
            fi
            ;;
    esac
done
[[ "$VERSION" == "__next__" ]] && error "--version requires a value (e.g. --version v0.2.0)"

# --- Pre-flight checks ---
[[ $EUID -ne 0 ]] && error "This script must be run as root (use sudo)."

# Detect download tool
DOWNLOAD_CMD=""
if command -v curl &>/dev/null; then
    DOWNLOAD_CMD="curl"
elif command -v wget &>/dev/null; then
    DOWNLOAD_CMD="wget"
else
    error "curl or wget is required but neither was found. Install one first."
fi

download() {
    local url="$1" dest="$2"
    if [[ "$DOWNLOAD_CMD" == "curl" ]]; then
        curl -fsSL "$url" -o "$dest"
    else
        wget -q "$url" -O "$dest"
    fi
}

download_stdout() {
    local url="$1"
    if [[ "$DOWNLOAD_CMD" == "curl" ]]; then
        curl -fsSL "$url"
    else
        wget -q "$url" -O -
    fi
}

# --- Resolve version ---
if [[ -z "$VERSION" ]]; then
    info "Resolving latest version..."
    # Try GitHub API first, fall back to downloading the redirect URL
    if LATEST_TAG=$(download_stdout "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" 2>/dev/null \
                    | grep '"tag_name"' | head -1 | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/'); then
        if [[ -n "$LATEST_TAG" ]]; then
            VERSION="$LATEST_TAG"
        fi
    fi

    # If no releases exist yet, fall back to main branch
    if [[ -z "$VERSION" ]]; then
        warn "No GitHub releases found. Falling back to main branch."
        VERSION="main"
    fi
fi

info "Version: ${VERSION}"

# --- Download ---
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

TARBALL_URL="https://github.com/${GITHUB_REPO}/archive/refs"
if [[ "$VERSION" == "main" || "$VERSION" == "develop" ]]; then
    TARBALL_URL="${TARBALL_URL}/heads/${VERSION}.tar.gz"
else
    TARBALL_URL="${TARBALL_URL}/tags/${VERSION}.tar.gz"
fi

info "Downloading ${TARBALL_URL}..."
TARBALL="${TMPDIR}/servagent.tar.gz"
download "$TARBALL_URL" "$TARBALL" || error "Download failed. Check that version '${VERSION}' exists."

# --- Extract ---
info "Extracting..."
tar -xzf "$TARBALL" -C "$TMPDIR"

# Find the extracted directory (GitHub names it repo-version/)
EXTRACT_DIR=$(find "$TMPDIR" -mindepth 1 -maxdepth 1 -type d | head -1)
[[ -z "$EXTRACT_DIR" ]] && error "Failed to extract archive."

# --- Run install.sh ---
INSTALLER="${EXTRACT_DIR}/install.sh"
[[ ! -f "$INSTALLER" ]] && error "install.sh not found in archive. The download may be corrupted."

info "Starting installation..."
echo ""
bash "$INSTALLER" "${INSTALL_ARGS[@]+"${INSTALL_ARGS[@]}"}"
