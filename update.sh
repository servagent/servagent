#!/usr/bin/env bash
# ------------------------------------------------------------------
# Servagent - Update script
#
# Two modes:
#   - Git mode  (dev / git clone): pulls latest code from the repo
#   - Tarball mode (production / remote install): downloads from GitHub
#
# Usage:
#   sudo bash update.sh              # Update from current branch (git) or latest release (tarball)
#   sudo bash update.sh develop      # Update from a specific branch
#   sudo bash update.sh --force      # Force reinstall even if already up to date
# ------------------------------------------------------------------
set -euo pipefail

APP_NAME="servagent"
APP_DIR="/opt/${APP_NAME}"
VENV_DIR="${APP_DIR}/.venv"
GITHUB_REPO="servagent/servagent"
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FORCE=false
BRANCH=""
for arg in "$@"; do
    case "$arg" in
        --force|-f) FORCE=true ;;
        *)          BRANCH="$arg" ;;
    esac
done

# --- Pre-flight checks ---
[[ $EUID -ne 0 ]] && error "This script must be run as root (use sudo)."
[[ ! -d "${APP_DIR}" ]] && error "Installation not found at ${APP_DIR}. Run install.sh first."
[[ ! -d "${VENV_DIR}" ]] && error "Virtual environment not found at ${VENV_DIR}. Run install.sh first."

# --- Banner ---
BANNER_FILE="${SCRIPT_DIR}/docs/assets/logo-ascii-art.txt"
if [[ -f "$BANNER_FILE" ]]; then
    echo ""
    cat "$BANNER_FILE"
    echo ""
else
    echo ""
    info "Servagent - Update"
    echo ""
fi

# --- Detect mode: git repo or tarball (production) ---
IS_GIT=false
if git -C "${SCRIPT_DIR}" rev-parse --git-dir &>/dev/null; then
    IS_GIT=true
fi

# --- Get current installed version ---
OLD_VERSION=$("${VENV_DIR}/bin/servagent" --version 2>/dev/null || echo "unknown")

# =====================================================================
# SOURCE DIRECTORY — where we'll copy files from
# =====================================================================
# In git mode: SCRIPT_DIR itself (after git pull)
# In tarball mode: a temp directory with the downloaded archive
SOURCE_DIR="${SCRIPT_DIR}"

if $IS_GIT; then
    # =================================================================
    # GIT MODE
    # =================================================================
    GIT_USER="${SUDO_USER:-$(whoami)}"
    run_git() { sudo -u "${GIT_USER}" git -C "${SCRIPT_DIR}" "$@"; }

    OLD_COMMIT=$(run_git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    CURRENT_BRANCH=$(run_git branch --show-current 2>/dev/null || echo "unknown")

    if [[ -n "$BRANCH" ]]; then
        info "Switching to branch '${BRANCH}'..."
        run_git fetch --all --quiet
        run_git checkout "${BRANCH}"
    fi

    info "Pulling latest changes (branch: ${BRANCH:-$CURRENT_BRANCH})..."
    run_git pull --ff-only || error "Git pull failed. Resolve conflicts manually."

    NEW_COMMIT=$(run_git rev-parse --short HEAD 2>/dev/null || echo "unknown")

    if [[ "$OLD_COMMIT" == "$NEW_COMMIT" ]] && ! $FORCE; then
        info "Already up to date (${OLD_COMMIT}). Nothing to do."
        info "Use --force to reinstall anyway."
        exit 0
    fi

    if [[ "$OLD_COMMIT" != "$NEW_COMMIT" ]]; then
        info "Updating: ${OLD_COMMIT} -> ${NEW_COMMIT}"
        echo ""
        run_git log --oneline "${OLD_COMMIT}..${NEW_COMMIT}" 2>/dev/null || true
        echo ""
    else
        info "Already up to date (${OLD_COMMIT}) — forcing reinstall."
    fi

    # SOURCE_DIR is already SCRIPT_DIR
else
    # =================================================================
    # TARBALL MODE (production — no git repo)
    # =================================================================

    # Detect download tool
    if command -v curl &>/dev/null; then
        _download()       { curl -fsSL "$1" -o "$2"; }
        _download_stdout() { curl -fsSL "$1"; }
    elif command -v wget &>/dev/null; then
        _download()       { wget -q "$1" -O "$2"; }
        _download_stdout() { wget -q "$1" -O -; }
    else
        error "curl or wget is required but neither was found."
    fi

    # Resolve version: branch argument, or latest release, or main
    VERSION="${BRANCH}"
    if [[ -z "$VERSION" ]]; then
        info "Resolving latest version..."
        if LATEST_TAG=$(_download_stdout "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" 2>/dev/null \
                        | grep '"tag_name"' | head -1 | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/'); then
            [[ -n "$LATEST_TAG" ]] && VERSION="$LATEST_TAG"
        fi
        if [[ -z "$VERSION" ]]; then
            warn "No GitHub releases found. Falling back to main branch."
            VERSION="main"
        fi
    fi

    info "Version: ${VERSION}"

    TARBALL_URL="https://github.com/${GITHUB_REPO}/archive/refs"
    if [[ "$VERSION" == "main" || "$VERSION" == "develop" ]]; then
        TARBALL_URL="${TARBALL_URL}/heads/${VERSION}.tar.gz"
    else
        TARBALL_URL="${TARBALL_URL}/tags/${VERSION}.tar.gz"
    fi

    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT

    info "Downloading ${TARBALL_URL}..."
    TARBALL="${TMPDIR}/servagent.tar.gz"
    _download "$TARBALL_URL" "$TARBALL" || error "Download failed. Check that version '${VERSION}' exists."

    info "Extracting..."
    tar -xzf "$TARBALL" -C "$TMPDIR"

    SOURCE_DIR=$(find "$TMPDIR" -mindepth 1 -maxdepth 1 -type d | head -1)
    [[ -z "$SOURCE_DIR" ]] && error "Failed to extract archive."
fi

# =====================================================================
# INSTALL — common to both modes
# =====================================================================

# --- Copy sources ---
info "Copying sources to ${APP_DIR}..."
cp -r "${SOURCE_DIR}/src" "${SOURCE_DIR}/pyproject.toml" "${APP_DIR}/"

# Update shell scripts
for _script in install.sh uninstall.sh update.sh generate-oauth-credentials.sh; do
    [[ -f "${SOURCE_DIR}/${_script}" ]] && cp "${SOURCE_DIR}/${_script}" "${APP_DIR}/"
done

chown -R "${APP_NAME}:${APP_NAME}" "${APP_DIR}/src" "${APP_DIR}/pyproject.toml"

# Ensure global symlink exists
ln -sf "${VENV_DIR}/bin/servagent" /usr/local/bin/servagent

# --- Reinstall package ---
info "Reinstalling package..."
"${VENV_DIR}/bin/pip" install --quiet --upgrade pip hatchling
"${VENV_DIR}/bin/pip" install --quiet --no-cache-dir -e "${APP_DIR}"

# --- Migrate .env: add new settings as comments if missing ---
ENV_FILE="${APP_DIR}/.env"
if [[ -f "${ENV_FILE}" ]]; then
    if ! grep -q "SERVAGENT_OAUTH_ISSUER_URL" "${ENV_FILE}" 2>/dev/null; then
        info "Adding OAuth settings (commented) to .env..."
        cat >> "${ENV_FILE}" <<'ENVEOF'

# OAuth 2.0 — Uncomment to enable OAuth for the /mcp endpoint.
# The URL MUST include the /mcp path. The simple Bearer token (API_KEY)
# continues to work for /sse, /messages/, and /upload endpoints.
# SERVAGENT_OAUTH_ISSUER_URL=https://your-domain.com/mcp
# SERVAGENT_OAUTH_DB_PATH=
ENVEOF
        chown "${APP_NAME}:${APP_NAME}" "${ENV_FILE}"
    fi
fi

# --- Restart service ---
info "Restarting ${APP_NAME}..."
systemctl restart "${APP_NAME}"

# --- Verify ---
sleep 2
if systemctl is-active --quiet "${APP_NAME}"; then
    info "Service is running."
else
    error "Service failed to start! Check: sudo journalctl -u ${APP_NAME} -n 50"
fi

# --- Summary ---
NEW_VERSION=$("${VENV_DIR}/bin/servagent" --version 2>/dev/null || echo "unknown")
echo ""
info "============================================="
info " Update complete! ${OLD_VERSION} -> ${NEW_VERSION}"
info "============================================="
echo ""
info "Commands:"
info "  Status:  servagent status"
info "  Logs:    sudo journalctl -u ${APP_NAME} -f"
