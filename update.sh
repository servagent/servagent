#!/usr/bin/env bash
# ------------------------------------------------------------------
# Servagent - Update script
#
# Pulls the latest code from git and updates the running installation.
#
# Usage:
#   sudo bash update.sh            # Update from current branch
#   sudo bash update.sh develop    # Update from a specific branch
#   sudo bash update.sh --force    # Force reinstall even if already up to date
# ------------------------------------------------------------------
set -euo pipefail

APP_NAME="servagent"
APP_DIR="/opt/${APP_NAME}"
VENV_DIR="${APP_DIR}/.venv"
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

# Git commands run as the invoking user (who has SSH keys), not root
GIT_USER="${SUDO_USER:-$(whoami)}"
run_git() { sudo -u "${GIT_USER}" git -C "${SCRIPT_DIR}" "$@"; }
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

# --- Get current version (before update) ---
OLD_COMMIT=$(run_git rev-parse --short HEAD 2>/dev/null || echo "unknown")
CURRENT_BRANCH=$(run_git branch --show-current 2>/dev/null || echo "unknown")

# --- Git pull (as the invoking user who has SSH keys) ---
if [[ -n "$BRANCH" ]]; then
    info "Switching to branch '${BRANCH}'..."
    run_git fetch --all --quiet
    run_git checkout "${BRANCH}"
fi

info "Pulling latest changes (branch: ${BRANCH:-$CURRENT_BRANCH})..."
run_git pull --ff-only || error "Git pull failed. Resolve conflicts manually."

NEW_COMMIT=$(run_git rev-parse --short HEAD 2>/dev/null || echo "unknown")

if [[ "$OLD_COMMIT" == "$NEW_COMMIT" ]]; then
    if ! $FORCE; then
        info "Already up to date (${OLD_COMMIT}). Nothing to do."
        info "Use --force to reinstall anyway."
        exit 0
    fi
    info "Already up to date (${OLD_COMMIT}) — forcing reinstall."
else
    info "Updating: ${OLD_COMMIT} -> ${NEW_COMMIT}"
    echo ""
    run_git log --oneline "${OLD_COMMIT}..${NEW_COMMIT}" 2>/dev/null || true
    echo ""
fi

# --- Copy sources ---
info "Copying sources to ${APP_DIR}..."
cp -r "${SCRIPT_DIR}/src" "${SCRIPT_DIR}/pyproject.toml" "${APP_DIR}/"
chown -R "${APP_NAME}:${APP_NAME}" "${APP_DIR}/src" "${APP_DIR}/pyproject.toml"

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

echo ""
info "============================================="
info " Update complete! ${OLD_COMMIT} -> ${NEW_COMMIT}"
info "============================================="
echo ""
info "Commands:"
info "  Status:  sudo systemctl status ${APP_NAME}"
info "  Logs:    sudo journalctl -u ${APP_NAME} -f"
info "  Rollback: git -C ${SCRIPT_DIR} checkout ${OLD_COMMIT} && sudo bash ${SCRIPT_DIR}/update.sh"
