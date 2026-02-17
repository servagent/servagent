#!/usr/bin/env bash
# ------------------------------------------------------------------
# Servagent - Installation script for Linux servers
#
# Usage:
#   sudo bash install.sh                                  # HTTP on port 8765
#   sudo bash install.sh votre-domaine.com                # HTTPS via Let's Encrypt
#   sudo bash install.sh --full-access                    # HTTP + sudo privileges
#   sudo bash install.sh --full-access votre-domaine.com  # HTTPS + sudo privileges
#   sudo bash install.sh -y                               # Non-interactive (skip confirmation)
#   sudo bash install.sh --yes                            # Same as -y
#
# If Nginx is running → uses Nginx reverse proxy + certbot webroot
# If Nginx is absent  → uses built-in TLS + certbot standalone
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

FULL_ACCESS=false
AUTO_YES=false
DOMAIN=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for arg in "$@"; do
    case "$arg" in
        --full-access) FULL_ACCESS=true ;;
        --yes|-y)      AUTO_YES=true ;;
        --*)           error "Unknown option: $arg" ;;
        *)             DOMAIN="$arg" ;;
    esac
done

# --- Banner ---
BANNER_FILE="${SCRIPT_DIR}/docs/assets/logo-ascii-art.txt"
if [[ -f "$BANNER_FILE" ]]; then
    echo ""
    cat "$BANNER_FILE"
    echo ""
else
    echo ""
    info "Servagent - Installation"
    echo ""
fi

if ! $AUTO_YES; then
    read -rp "Lancer l'installation de Servagent ? [y/N] : " confirm
    case "${confirm}" in
        [yY]) ;;
        *)    info "Installation annulée."; exit 0 ;;
    esac
    echo ""
fi

# --- Pre-flight checks ---
[[ $EUID -ne 0 ]] && error "This script must be run as root (use sudo)."

command -v python3 >/dev/null 2>&1 || error "python3 is required but not found."

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)
if [[ "$PYTHON_MAJOR" -lt 3 ]] || [[ "$PYTHON_MAJOR" -eq 3 && "$PYTHON_MINOR" -lt 10 ]]; then
    error "Python >= 3.10 required. Found: python${PYTHON_VERSION}"
fi
info "Python ${PYTHON_VERSION} found."

# Detect Nginx
NGINX_ACTIVE=false
if systemctl is-active --quiet nginx 2>/dev/null; then
    NGINX_ACTIVE=true
fi

# Detect Nginx config directory layout
# Debian/Ubuntu: sites-available + sites-enabled (symlinks)
# RHEL/CentOS/other: conf.d (drop-in files)
detect_nginx_conf() {
    if [[ -d /etc/nginx/sites-available ]]; then
        NGINX_CONF="/etc/nginx/sites-available/${APP_NAME}.conf"
        NGINX_LINK="/etc/nginx/sites-enabled/${APP_NAME}.conf"
        NGINX_STYLE="sites"
    else
        mkdir -p /etc/nginx/conf.d
        NGINX_CONF="/etc/nginx/conf.d/${APP_NAME}.conf"
        NGINX_LINK=""
        NGINX_STYLE="confd"
    fi
}

enable_nginx_conf() {
    if [[ "$NGINX_STYLE" == "sites" ]]; then
        ln -sf "${NGINX_CONF}" "${NGINX_LINK}"
    fi
    nginx -t && systemctl reload nginx
}

if [[ -n "$DOMAIN" ]]; then
    info "Domain provided: ${DOMAIN} — will configure HTTPS with Let's Encrypt."
    if $NGINX_ACTIVE; then
        info "Nginx detected — will use Nginx as reverse proxy (recommended)."
    else
        info "Nginx not detected — will use built-in TLS on port 443."
    fi
else
    info "No domain provided — will configure HTTP on port 8765."
    warn "To enable HTTPS later, run: sudo bash install.sh <your-domain>"
fi

# --- Full access prompt ---
if ! $FULL_ACCESS && ! $AUTO_YES; then
    echo ""
    warn "Souhaitez-vous donner les droits d'administration complets (sudo) à ${SERVICE_USER} ?"
    warn "Cela permet l'exécution de commandes avec des privilèges root."
    read -rp "[y/N] : " answer
    case "${answer}" in
        [yY]) FULL_ACCESS=true; info "Full access enabled." ;;
        *)    info "Standard access (no sudo)." ;;
    esac
    echo ""
elif ! $FULL_ACCESS; then
    info "Standard access (no sudo) — mode non-interactif."
fi

# =====================================================================
# 1. APPLICATION INSTALL
# =====================================================================

# --- Create system user ---
if ! id "${SERVICE_USER}" &>/dev/null; then
    info "Creating system user '${SERVICE_USER}'..."
    useradd --system --shell /usr/sbin/nologin --home-dir "${APP_DIR}" "${SERVICE_USER}"
else
    info "User '${SERVICE_USER}' already exists."
fi

# --- Configure sudo access ---
SUDOERS_FILE="/etc/sudoers.d/${SERVICE_USER}"
if $FULL_ACCESS; then
    info "Configuring sudo access for '${SERVICE_USER}'..."
    echo "${SERVICE_USER} ALL=(ALL) NOPASSWD: ALL" > "${SUDOERS_FILE}.tmp"
    if visudo -cf "${SUDOERS_FILE}.tmp" &>/dev/null; then
        mv "${SUDOERS_FILE}.tmp" "${SUDOERS_FILE}"
        chmod 440 "${SUDOERS_FILE}"
        info "Sudoers file installed: ${SUDOERS_FILE}"
    else
        rm -f "${SUDOERS_FILE}.tmp"
        error "Sudoers syntax validation failed. Aborting."
    fi
else
    # Remove sudoers file if it exists from a previous install
    rm -f "${SUDOERS_FILE}"
fi

# --- Install application ---
info "Installing to ${APP_DIR}..."
mkdir -p "${APP_DIR}"
cp -r "${SCRIPT_DIR}/src" "${SCRIPT_DIR}/pyproject.toml" "${APP_DIR}/"

# Copy shell scripts so CLI subcommands (status, uninstall, update) work
for _script in install.sh uninstall.sh update.sh generate-oauth-credentials.sh; do
    [[ -f "${SCRIPT_DIR}/${_script}" ]] && cp "${SCRIPT_DIR}/${_script}" "${APP_DIR}/"
done

# Ensure skills directory exists
mkdir -p "${APP_DIR}/skills"

# --- Create virtual environment ---
info "Creating virtual environment..."
python3 -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/pip" install --upgrade pip hatchling
"${VENV_DIR}/bin/pip" install -e "${APP_DIR}"

# --- Create global symlink ---
info "Creating global command symlink..."
ln -sf "${VENV_DIR}/bin/servagent" /usr/local/bin/servagent

# --- Generate API key & .env ---
if [[ ! -f "${ENV_FILE}" ]]; then
    API_KEY=$("${VENV_DIR}/bin/python" -c "import secrets; print(secrets.token_urlsafe(48))")
    info "Generating .env with new API key..."
    cat > "${ENV_FILE}" <<EOF
SERVAGENT_HOST=127.0.0.1
SERVAGENT_PORT=8765
SERVAGENT_API_KEY=${API_KEY}
SERVAGENT_LOG_LEVEL=INFO
SERVAGENT_COMMAND_TIMEOUT=300

# OAuth 2.0 — Uncomment to enable OAuth for the /mcp endpoint.
# The URL MUST include the /mcp path. The simple Bearer token (API_KEY)
# continues to work for all endpoints (/mcp, /sse, /messages/, /upload).
# SERVAGENT_OAUTH_ISSUER_URL=https://your-domain.com/mcp

# Registration credentials — protects POST /mcp/register with HTTP Basic Auth.
# Generate with: bash generate-oauth-credentials.sh
# SERVAGENT_OAUTH_CLIENT_ID=
# SERVAGENT_OAUTH_CLIENT_SECRET=
EOF
    chmod 600 "${ENV_FILE}"
    echo ""
    warn "============================================="
    warn " YOUR API KEY (save this, it won't be shown again):"
    warn " ${API_KEY}"
    warn "============================================="
    echo ""
else
    info ".env already exists, skipping generation."
fi

# If no domain and no Nginx, bind on all interfaces so it's reachable
if [[ -z "$DOMAIN" ]] && ! $NGINX_ACTIVE; then
    sed -i 's/^SERVAGENT_HOST=.*/SERVAGENT_HOST=0.0.0.0/' "$ENV_FILE"
fi

# --- Set ownership ---
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${APP_DIR}"

# --- Create systemd service ---
info "Installing systemd service..."
if $FULL_ACCESS; then
    NO_NEW_PRIVS="false"
else
    NO_NEW_PRIVS="true"
fi
cat > /etc/systemd/system/${APP_NAME}.service <<EOF
[Unit]
Description=Servagent - Remote Server Administration
After=network.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${APP_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${VENV_DIR}/bin/servagent
Restart=on-failure
RestartSec=5

# Hardening
NoNewPrivileges=${NO_NEW_PRIVS}
ProtectSystem=false
ProtectHome=false
ReadWritePaths=/

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${APP_NAME}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "${APP_NAME}"

# =====================================================================
# 2. TLS SETUP (only if a domain was provided)
# =====================================================================
if [[ -n "$DOMAIN" ]]; then
    info "--- Setting up HTTPS for ${DOMAIN} ---"

    # ----- Install certbot -----
    if ! command -v certbot &>/dev/null; then
        info "Installing certbot..."
        if command -v apt-get &>/dev/null; then
            if $NGINX_ACTIVE; then
                apt-get update -qq && apt-get install -y -qq certbot python3-certbot-nginx
            else
                apt-get update -qq && apt-get install -y -qq certbot
            fi
        elif command -v dnf &>/dev/null; then
            dnf install -y -q certbot
        elif command -v yum &>/dev/null; then
            yum install -y -q certbot
        else
            error "Could not install certbot. Install it manually: https://certbot.eff.org"
        fi
    fi

    CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"

    if $NGINX_ACTIVE; then
        # =============================================================
        # MODE A: Nginx is running → webroot challenge + reverse proxy
        # =============================================================
        info "Using Nginx webroot mode for certificate..."

        # Create webroot directory
        WEBROOT="/var/www/certbot"
        mkdir -p "${WEBROOT}"

        # Detect Nginx config layout
        detect_nginx_conf

        # Temporary Nginx config for ACME challenge
        cat > "${NGINX_CONF}" <<NGINX
server {
    listen 80;
    server_name ${DOMAIN};

    # Let's Encrypt ACME challenge
    location /.well-known/acme-challenge/ {
        root ${WEBROOT};
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}
NGINX
        enable_nginx_conf

        # Obtain certificate via webroot (no downtime)
        if [[ ! -d "$CERT_DIR" ]]; then
            info "Requesting certificate for ${DOMAIN}..."
            certbot certonly \
                --webroot \
                --webroot-path "${WEBROOT}" \
                --non-interactive \
                --agree-tos \
                --register-unsafely-without-email \
                --domain "${DOMAIN}"
        else
            info "Certificate already exists for ${DOMAIN}."
        fi

        [[ ! -f "${CERT_DIR}/fullchain.pem" ]] && error "Certificate not found at ${CERT_DIR}/fullchain.pem"
        info "Certificate OK."

        # Full Nginx config with TLS + reverse proxy
        cat > "${NGINX_CONF}" <<NGINX
# Servagent — Nginx reverse proxy with TLS
# Auto-generated by install.sh

server {
    listen 443 ssl http2;
    server_name ${DOMAIN};

    ssl_certificate     ${CERT_DIR}/fullchain.pem;
    ssl_certificate_key ${CERT_DIR}/privkey.pem;

    # Modern TLS
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # Proxy all MCP endpoints: /mcp (streamable-http), /sse, /messages/
    location / {
        proxy_pass http://127.0.0.1:8765;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # Streaming support (SSE / Streamable HTTP)
        proxy_set_header Connection '';
        proxy_buffering off;
        proxy_cache off;
        chunked_transfer_encoding on;
        proxy_read_timeout 300s;
    }
}

server {
    listen 80;
    server_name ${DOMAIN};

    location /.well-known/acme-challenge/ {
        root ${WEBROOT};
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}
NGINX
        enable_nginx_conf
        info "Nginx reverse proxy configured."

        # MCP stays on 127.0.0.1:8765 (Nginx handles TLS)
        sed -i 's/^SERVAGENT_HOST=.*/SERVAGENT_HOST=127.0.0.1/' "$ENV_FILE"

        # Auto-renewal (certbot renew uses webroot, reloads Nginx)
        cat > /etc/systemd/system/certbot-renew-mcp.service <<EOF
[Unit]
Description=Certbot renewal for Servagent

[Service]
Type=oneshot
ExecStart=/usr/bin/certbot renew --quiet --deploy-hook "systemctl reload nginx"
EOF

    else
        # =============================================================
        # MODE B: No Nginx → standalone challenge + built-in TLS
        # =============================================================
        info "Using standalone mode for certificate..."

        if [[ ! -d "$CERT_DIR" ]]; then
            info "Requesting certificate for ${DOMAIN} (port 80 must be free)..."
            certbot certonly \
                --standalone \
                --non-interactive \
                --agree-tos \
                --register-unsafely-without-email \
                --domain "${DOMAIN}" \
                --preferred-challenges http
        else
            info "Certificate already exists for ${DOMAIN}."
        fi

        [[ ! -f "${CERT_DIR}/fullchain.pem" ]] && error "Certificate not found at ${CERT_DIR}/fullchain.pem"
        info "Certificate OK."

        # Grant read access to the service user
        if ! getent group certkeys &>/dev/null; then
            groupadd certkeys
        fi
        usermod -aG certkeys "${SERVICE_USER}"
        chown root:certkeys "${CERT_DIR}/privkey.pem"
        chmod 640 "${CERT_DIR}/privkey.pem"
        chmod 750 /etc/letsencrypt/live /etc/letsencrypt/archive
        chown root:certkeys /etc/letsencrypt/live /etc/letsencrypt/archive

        # Update .env: switch to port 443 + built-in TLS
        sed -i '/^SERVAGENT_PORT=/d' "$ENV_FILE"
        sed -i '/^SERVAGENT_TLS_CERTFILE=/d' "$ENV_FILE"
        sed -i '/^SERVAGENT_TLS_KEYFILE=/d' "$ENV_FILE"
        sed -i 's/^SERVAGENT_HOST=.*/SERVAGENT_HOST=0.0.0.0/' "$ENV_FILE"
        cat >> "$ENV_FILE" <<EOF
SERVAGENT_PORT=443
SERVAGENT_TLS_CERTFILE=${CERT_DIR}/fullchain.pem
SERVAGENT_TLS_KEYFILE=${CERT_DIR}/privkey.pem
EOF

        # Allow binding to port 443 without root
        REAL_PYTHON=$(readlink -f "${VENV_DIR}/bin/python3")
        setcap 'cap_net_bind_service=+ep' "$REAL_PYTHON" 2>/dev/null || \
            warn "setcap failed — the service may need to run as root for port 443."

        # Auto-renewal (standalone needs to stop server briefly)
        cat > /etc/systemd/system/certbot-renew-mcp.service <<EOF
[Unit]
Description=Certbot renewal for Servagent

[Service]
Type=oneshot
ExecStart=/usr/bin/certbot renew --quiet --deploy-hook "systemctl restart ${APP_NAME}"
EOF
    fi

    # ----- Renewal timer (shared by both modes) -----
    cat > /etc/systemd/system/certbot-renew-mcp.timer <<EOF
[Unit]
Description=Twice-daily certbot renewal check

[Timer]
OnCalendar=*-*-* 02,14:30:00
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now certbot-renew-mcp.timer
fi

# --- Persist public base URL in .env ---
# Used by `servagent oauth setup` to derive the issuer URL.
if [[ -n "$DOMAIN" ]]; then
    sed -i '/^SERVAGENT_BASE_URL=/d' "$ENV_FILE"
    echo "SERVAGENT_BASE_URL=https://${DOMAIN}" >> "$ENV_FILE"
fi

# =====================================================================
# 3. START
# =====================================================================
info "Starting ${APP_NAME}..."
systemctl restart "${APP_NAME}"

echo ""
info "============================================="
info " Installation complete!"
info "============================================="
echo ""
if $FULL_ACCESS; then
    warn "Full access enabled: ${SERVICE_USER} has sudo privileges (NOPASSWD)."
    echo ""
fi
info "Commands:"
info "  Status:  sudo systemctl status ${APP_NAME}"
info "  Logs:    sudo journalctl -u ${APP_NAME} -f"
info "  Stop:    sudo systemctl stop ${APP_NAME}"
info "  Restart: sudo systemctl restart ${APP_NAME}"
echo ""

if [[ -n "$DOMAIN" ]]; then
    info "Endpoint: https://${DOMAIN}/mcp"
    echo ""
    if $NGINX_ACTIVE; then
        info "Mode: Nginx reverse proxy (TLS handled by Nginx)"
        info "  MCP server listens on 127.0.0.1:8765 (internal)"
        info "  Nginx terminates TLS on port 443"
    else
        info "Mode: Built-in TLS on port 443"
    fi
    echo ""
    warn "Make sure ports 80 and 443 are open in your firewall:"
    warn "  ufw allow 80/tcp && ufw allow 443/tcp"
else
    info "Endpoint: http://<your-server-ip>:8765/mcp"
    echo ""
    warn "Make sure port 8765 is open in your firewall:"
    warn "  ufw allow 8765/tcp"
    warn ""
    warn "To enable HTTPS later, re-run:"
    warn "  sudo bash install.sh votre-domaine.com"
fi
