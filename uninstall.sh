#!/usr/bin/env bash
# ------------------------------------------------------------------
# Servagent - Uninstall script for Linux servers
#
# Reverses everything done by install.sh:
#   - Stops and removes systemd services/timers
#   - Removes Nginx configuration
#   - Removes sudoers file
#   - Deletes application directory (/opt/servagent)
#   - Removes system user
#   - Optionally revokes Let's Encrypt certificates
#
# Usage:
#   sudo bash uninstall.sh              # Interactive (confirmation required)
#   sudo bash uninstall.sh -y           # Non-interactive (skip confirmation)
#   sudo bash uninstall.sh --yes        # Same as -y
#   sudo bash uninstall.sh --keep-certs # Keep Let's Encrypt certificates
# ------------------------------------------------------------------
set -euo pipefail

APP_NAME="servagent"
APP_DIR="/opt/${APP_NAME}"
SERVICE_USER="servagent"
VENV_DIR="${APP_DIR}/.venv"
ENV_FILE="${APP_DIR}/.env"
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

AUTO_YES=false
KEEP_CERTS=false

for arg in "$@"; do
    case "$arg" in
        --yes|-y)       AUTO_YES=true ;;
        --keep-certs)   KEEP_CERTS=true ;;
        --*)            error "Unknown option: $arg" ;;
    esac
done

# --- Pre-flight checks ---
[[ $EUID -ne 0 ]] && error "This script must be run as root (use sudo)."

# --- Detect what's installed ---
echo ""
warn "============================================="
warn " Servagent - Uninstall"
warn "============================================="
echo ""

ITEMS_FOUND=()

# Systemd service
if systemctl list-unit-files "${APP_NAME}.service" &>/dev/null && \
   systemctl list-unit-files "${APP_NAME}.service" 2>/dev/null | grep -q "${APP_NAME}"; then
    ITEMS_FOUND+=("Systemd service: ${APP_NAME}.service")
fi

# Certbot renewal timer/service
if systemctl list-unit-files "certbot-renew-mcp.timer" &>/dev/null && \
   systemctl list-unit-files "certbot-renew-mcp.timer" 2>/dev/null | grep -q "certbot-renew-mcp"; then
    ITEMS_FOUND+=("Certbot renewal timer: certbot-renew-mcp.timer")
fi
if [[ -f /etc/systemd/system/certbot-renew-mcp.service ]]; then
    ITEMS_FOUND+=("Certbot renewal service: certbot-renew-mcp.service")
fi

# Nginx config
NGINX_CONF_SITES="/etc/nginx/sites-available/${APP_NAME}.conf"
NGINX_LINK_SITES="/etc/nginx/sites-enabled/${APP_NAME}.conf"
NGINX_CONF_CONFD="/etc/nginx/conf.d/${APP_NAME}.conf"
NGINX_FOUND=false
if [[ -f "$NGINX_CONF_SITES" ]] || [[ -L "$NGINX_LINK_SITES" ]]; then
    ITEMS_FOUND+=("Nginx config: ${NGINX_CONF_SITES}")
    NGINX_FOUND=true
fi
if [[ -f "$NGINX_CONF_CONFD" ]]; then
    ITEMS_FOUND+=("Nginx config: ${NGINX_CONF_CONFD}")
    NGINX_FOUND=true
fi

# Sudoers
SUDOERS_FILE="/etc/sudoers.d/${SERVICE_USER}"
if [[ -f "$SUDOERS_FILE" ]]; then
    ITEMS_FOUND+=("Sudoers file: ${SUDOERS_FILE}")
fi

# Application directory
if [[ -d "$APP_DIR" ]]; then
    ITEMS_FOUND+=("Application directory: ${APP_DIR}")
fi

# System user
if id "${SERVICE_USER}" &>/dev/null; then
    ITEMS_FOUND+=("System user: ${SERVICE_USER}")
fi

# Certkeys group
if getent group certkeys &>/dev/null; then
    ITEMS_FOUND+=("System group: certkeys")
fi

# Let's Encrypt certificates (detect domain from Nginx config or .env)
DOMAIN=""
if [[ -f "$NGINX_CONF_SITES" ]]; then
    DOMAIN=$(grep -oP 'server_name\s+\K[^;]+' "$NGINX_CONF_SITES" 2>/dev/null | head -1 || true)
elif [[ -f "$NGINX_CONF_CONFD" ]]; then
    DOMAIN=$(grep -oP 'server_name\s+\K[^;]+' "$NGINX_CONF_CONFD" 2>/dev/null | head -1 || true)
elif [[ -f "$ENV_FILE" ]]; then
    # Try to detect from TLS cert path in .env
    CERT_PATH=$(grep -oP 'SERVAGENT_TLS_CERTFILE=.*/live/\K[^/]+' "$ENV_FILE" 2>/dev/null || true)
    if [[ -n "$CERT_PATH" ]]; then
        DOMAIN="$CERT_PATH"
    fi
fi

CERT_DIR=""
if [[ -n "$DOMAIN" ]] && [[ -d "/etc/letsencrypt/live/${DOMAIN}" ]]; then
    CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"
    if $KEEP_CERTS; then
        ITEMS_FOUND+=("Let's Encrypt certificate: ${CERT_DIR} (KEPT)")
    else
        ITEMS_FOUND+=("Let's Encrypt certificate: ${CERT_DIR}")
    fi
fi

# --- Show summary ---
if [[ ${#ITEMS_FOUND[@]} -eq 0 ]]; then
    info "Nothing to uninstall. Servagent does not appear to be installed."
    exit 0
fi

info "The following will be removed:"
echo ""
for item in "${ITEMS_FOUND[@]}"; do
    echo -e "  ${RED}•${NC} ${item}"
done
echo ""

# --- Confirmation ---
if ! $AUTO_YES; then
    warn "This action is IRREVERSIBLE. All data in ${APP_DIR} will be lost."
    echo ""
    read -rp "Are you sure you want to uninstall Servagent? [y/N] : " confirm
    case "${confirm}" in
        [yY]) ;;
        *)    info "Uninstall cancelled."; exit 0 ;;
    esac
    echo ""
fi

# =====================================================================
# 1. STOP AND REMOVE SYSTEMD SERVICES
# =====================================================================

# Stop and disable certbot renewal timer
if systemctl is-active --quiet certbot-renew-mcp.timer 2>/dev/null; then
    info "Stopping certbot renewal timer..."
    systemctl stop certbot-renew-mcp.timer
fi
if systemctl is-enabled --quiet certbot-renew-mcp.timer 2>/dev/null; then
    systemctl disable certbot-renew-mcp.timer
fi

# Stop and disable main service
if systemctl is-active --quiet "${APP_NAME}" 2>/dev/null; then
    info "Stopping ${APP_NAME} service..."
    systemctl stop "${APP_NAME}"
fi
if systemctl is-enabled --quiet "${APP_NAME}" 2>/dev/null; then
    systemctl disable "${APP_NAME}"
fi

# Remove systemd unit files
info "Removing systemd unit files..."
rm -f "/etc/systemd/system/${APP_NAME}.service"
rm -f "/etc/systemd/system/certbot-renew-mcp.service"
rm -f "/etc/systemd/system/certbot-renew-mcp.timer"
systemctl daemon-reload

# =====================================================================
# 2. REMOVE NGINX CONFIGURATION
# =====================================================================
if $NGINX_FOUND; then
    info "Removing Nginx configuration..."
    rm -f "$NGINX_LINK_SITES"
    rm -f "$NGINX_CONF_SITES"
    rm -f "$NGINX_CONF_CONFD"

    # Reload Nginx if it's running
    if systemctl is-active --quiet nginx 2>/dev/null; then
        info "Reloading Nginx..."
        nginx -t 2>/dev/null && systemctl reload nginx
    fi
fi

# =====================================================================
# 3. REMOVE SUDOERS FILE
# =====================================================================
if [[ -f "$SUDOERS_FILE" ]]; then
    info "Removing sudoers file..."
    rm -f "$SUDOERS_FILE"
fi

# =====================================================================
# 4. REVOKE CERTIFICATES (optional)
# =====================================================================
if [[ -n "$CERT_DIR" ]] && [[ -d "$CERT_DIR" ]] && ! $KEEP_CERTS; then
    if command -v certbot &>/dev/null; then
        info "Revoking Let's Encrypt certificate for ${DOMAIN}..."
        certbot delete --cert-name "${DOMAIN}" --non-interactive 2>/dev/null || \
            warn "Could not revoke certificate. You may need to remove it manually."
    else
        warn "certbot not found — skipping certificate removal."
        warn "To remove manually: sudo rm -rf /etc/letsencrypt/live/${DOMAIN}"
    fi
fi

# =====================================================================
# 5. REMOVE APPLICATION DIRECTORY
# =====================================================================
if [[ -d "$APP_DIR" ]]; then
    info "Removing application directory ${APP_DIR}..."
    rm -rf "$APP_DIR"
fi

# =====================================================================
# 6. REMOVE SYSTEM USER
# =====================================================================
if id "${SERVICE_USER}" &>/dev/null; then
    info "Removing system user '${SERVICE_USER}'..."
    userdel "${SERVICE_USER}" 2>/dev/null || \
        warn "Could not remove user '${SERVICE_USER}'. You may need to remove it manually."
fi

# =====================================================================
# 7. REMOVE CERTKEYS GROUP (if no other members)
# =====================================================================
if getent group certkeys &>/dev/null; then
    MEMBERS=$(getent group certkeys | cut -d: -f4)
    if [[ -z "$MEMBERS" ]]; then
        info "Removing empty group 'certkeys'..."
        groupdel certkeys 2>/dev/null || true
    else
        warn "Group 'certkeys' still has members (${MEMBERS}), skipping removal."
    fi
fi

# =====================================================================
# DONE
# =====================================================================
echo ""
info "============================================="
info " Servagent has been completely uninstalled."
info "============================================="
echo ""
if $KEEP_CERTS && [[ -n "$CERT_DIR" ]]; then
    warn "Let's Encrypt certificates were kept at: ${CERT_DIR}"
    echo ""
fi
info "The following packages were NOT removed (they may be used by other services):"
info "  - certbot"
info "  - python3"
info "  - nginx"
echo ""
