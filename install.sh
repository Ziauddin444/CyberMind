#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  CyberMind Sentinel — Enterprise One-Command Installer
#  Supports: Ubuntu 20.04+, Debian 11+, CentOS/RHEL 8+, macOS 12+
#
#  Usage:
#    sudo bash install.sh              # Interactive install
#    sudo bash install.sh --silent     # Non-interactive with defaults
#
#  After installation:
#    - Dashboard: http://<server-ip>:5173
#    - API:       http://localhost:5000
#    - Logs:      /var/log/cybermind/
#    - Config:    /etc/cybermind/.env
# ═══════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Constants ───────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/cybermind"
CONFIG_DIR="/etc/cybermind"
LOG_DIR="/var/log/cybermind"
CYBERMIND_USER="cybermind"
PYTHON_MIN="3.9"
NODE_MIN="18"
VERSION="1.0.0"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SILENT=false
[[ "${1:-}" == "--silent" ]] && SILENT=true

# ── Helpers ─────────────────────────────────────────────────────────────────
log()  { echo -e "${GREEN}[✔]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✘]${NC} $*" >&2; exit 1; }
step() { echo -e "\n${BOLD}${CYAN}══ $* ══${NC}"; }

banner() {
cat << 'EOF'
  ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ███╗██╗███╗   ██╗██████╗
 ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗████╗ ████║██║████╗  ██║██╔══██╗
 ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██╔████╔██║██║██╔██╗ ██║██║  ██║
 ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║╚██╔╝██║██║██║╚██╗██║██║  ██║
 ╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║ ╚═╝ ██║██║██║ ╚████║██████╔╝
  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═════╝
               Sentinel IDS — Enterprise Installer v1.0.0
EOF
}

# ── OS Detection ─────────────────────────────────────────────────────────────
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        PKG_MANAGER="brew"
    elif [ -f /etc/os-release ]; then
        source /etc/os-release
        case "$ID" in
            ubuntu|debian)   OS="debian";  PKG_MANAGER="apt" ;;
            centos|rhel|rocky|almalinux) OS="rhel"; PKG_MANAGER="dnf" ;;
            *)               err "Unsupported OS: $ID. Supported: Ubuntu, Debian, CentOS/RHEL, macOS." ;;
        esac
    else
        err "Cannot detect OS. Supported: Ubuntu 20.04+, Debian 11+, CentOS/RHEL 8+, macOS 12+"
    fi
    log "Detected OS: $OS (package manager: $PKG_MANAGER)"
}

# ── Privilege Check ──────────────────────────────────────────────────────────
check_privileges() {
    if [[ "$OS" != "macos" ]] && [[ $EUID -ne 0 ]]; then
        err "This installer must be run as root on Linux. Use: sudo bash install.sh"
    fi
}

# ── Dependency Installation ───────────────────────────────────────────────────
install_system_deps() {
    step "Installing System Dependencies"

    case "$PKG_MANAGER" in
        apt)
            apt-get update -qq
            apt-get install -y -qq \
                python3 python3-pip python3-venv python3-dev \
                curl wget git build-essential libssl-dev libffi-dev \
                net-tools tcpdump libpcap-dev
            ;;
        dnf)
            dnf install -y -q \
                python3 python3-pip python3-devel \
                curl wget git gcc openssl-devel libffi-devel \
                net-tools tcpdump libpcap-devel
            ;;
        brew)
            command -v brew &>/dev/null || err "Homebrew not found. Install from https://brew.sh"
            brew install python3 curl wget git libpcap 2>/dev/null || true
            ;;
    esac

    log "System dependencies installed"
}

install_node() {
    step "Installing Node.js ${NODE_MIN}+"

    if command -v node &>/dev/null; then
        NODE_VER=$(node --version | sed 's/v//' | cut -d. -f1)
        if [[ "$NODE_VER" -ge "$NODE_MIN" ]]; then
            log "Node.js $(node --version) already installed — skipping"
            return
        fi
        warn "Node.js version too old ($(node --version)). Upgrading..."
    fi

    case "$PKG_MANAGER" in
        apt|dnf)
            curl -fsSL https://deb.nodesource.com/setup_20.x | bash - 2>/dev/null || \
            curl -fsSL https://rpm.nodesource.com/setup_20.x | bash - 2>/dev/null
            ${PKG_MANAGER} install -y nodejs
            ;;
        brew)
            brew install node@20 2>/dev/null || brew upgrade node 2>/dev/null || true
            ;;
    esac

    log "Node.js $(node --version) installed"
}

install_ollama() {
    step "Installing Ollama (Local AI Engine)"

    if command -v ollama &>/dev/null; then
        log "Ollama already installed — skipping"
    else
        curl -fsSL https://ollama.ai/install.sh | sh
        log "Ollama installed"
    fi

    warn "Pulling Mistral AI model (~4GB download, this may take a few minutes)..."
    if [[ "$SILENT" == "false" ]]; then
        read -p "Download Mistral model now? (recommended) [Y/n] " pull_model
        pull_model="${pull_model:-Y}"
    else
        pull_model="Y"
    fi

    if [[ "$pull_model" =~ ^[Yy]$ ]]; then
        ollama pull mistral
        log "Mistral model downloaded"
    else
        warn "Skipping Mistral download. AI translation will use rule-based fallback."
    fi
}

# ── User & Directory Setup ────────────────────────────────────────────────────
setup_directories() {
    step "Setting Up Directories & System User"

    # Create system user (Linux only)
    if [[ "$OS" != "macos" ]]; then
        if ! id "$CYBERMIND_USER" &>/dev/null; then
            useradd --system --no-create-home --shell /bin/false "$CYBERMIND_USER"
            log "Created system user: $CYBERMIND_USER"
        fi
    fi

    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"

    if [[ "$OS" != "macos" ]]; then
        chown -R "$CYBERMIND_USER:$CYBERMIND_USER" "$LOG_DIR"
        chown root:root "$CONFIG_DIR"
        chmod 750 "$CONFIG_DIR"
    fi

    log "Directories created: $INSTALL_DIR, $CONFIG_DIR, $LOG_DIR"
}

# ── Application Installation ──────────────────────────────────────────────────
install_app() {
    step "Installing CyberMind Sentinel"

    # Copy application files
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cp -r "$SCRIPT_DIR/." "$INSTALL_DIR/"
    log "Application files copied to $INSTALL_DIR"

    # Python virtual environment
    step "Setting Up Python Virtual Environment"
    python3 -m venv "$INSTALL_DIR/venv"
    "$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
    "$INSTALL_DIR/venv/bin/pip" install --quiet -r "$INSTALL_DIR/backend_flask/requirements.txt"
    log "Python dependencies installed"

    # Node.js dependencies (backend auth server)
    step "Installing Node.js Dependencies"
    cd "$INSTALL_DIR/backend" && npm install --omit=dev --silent
    log "Node.js auth backend dependencies installed"

    # Node.js dependencies (frontend)
    cd "$INSTALL_DIR/frontend" && npm install --omit=dev --silent
    log "Frontend dependencies installed"
}

# ── Environment Configuration ─────────────────────────────────────────────────
configure_environment() {
    step "Configuring Environment"

    ENV_FILE="$CONFIG_DIR/.env"

    if [[ -f "$ENV_FILE" ]] && [[ "$SILENT" == "false" ]]; then
        read -p "Config file already exists at $ENV_FILE. Overwrite? [y/N] " overwrite
        [[ ! "$overwrite" =~ ^[Yy]$ ]] && { log "Keeping existing config"; return; }
    fi

    # Generate a secure random secret key
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

    # Prompt for network interface (SPAN port monitoring)
    if [[ "$SILENT" == "false" ]]; then
        echo ""
        echo "Available network interfaces:"
        ip link show 2>/dev/null | grep -E "^[0-9]+:" | awk -F': ' '{print "  •", $2}' || \
        ifconfig -l 2>/dev/null | tr ' ' '\n' | awk '{print "  •", $1}'
        echo ""
        read -p "Network interface to monitor (e.g. eth0, ens3, en0): " IFACE
        IFACE="${IFACE:-eth0}"
    else
        IFACE="eth0"
    fi

    cat > "$ENV_FILE" << EOF
# CyberMind Sentinel — Production Configuration
# Generated by install.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# IMPORTANT: Keep this file secure. chmod 600 $ENV_FILE

# ── Flask ─────────────────────────────────────────────────────
FLASK_ENV=production
FLASK_DEBUG=0
FLASK_PORT=5000
SECRET_KEY=${SECRET_KEY}

# ── CORS ──────────────────────────────────────────────────────
CORS_ORIGINS=http://localhost:5173

# ── Packet Capture ────────────────────────────────────────────
SCAN_NETWORK_INTERFACE=${IFACE}
SCAN_PACKET_COUNT=200
SCAN_TIMEOUT_SECONDS=30

# ── Ollama AI Engine ──────────────────────────────────────────
OLLAMA_HOST=http://localhost:11434

# ── Logging ───────────────────────────────────────────────────
LOG_LEVEL=INFO
LOG_FILE=${LOG_DIR}/cybermind.log
EOF

    chmod 600 "$ENV_FILE"

    # Link env file into app directory
    ln -sf "$ENV_FILE" "$INSTALL_DIR/backend_flask/.env"
    log "Environment configured at $ENV_FILE"
}

# ── ML Model Setup ─────────────────────────────────────────────────────────────
setup_ml_model() {
    step "Setting Up AI/ML Model"

    NSL_KDD_DIR="$INSTALL_DIR/backend_flask/data/nsl_kdd"
    MODEL_FILE="$INSTALL_DIR/backend_flask/data/rf_model.pkl"

    if [[ -f "$MODEL_FILE" ]]; then
        log "Pre-trained model already exists — skipping"
        return
    fi

    warn "Downloading NSL-KDD dataset for model training..."
    mkdir -p "$NSL_KDD_DIR"
    curl -fsSL "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt" \
         -o "$NSL_KDD_DIR/KDDTrain+.csv" || warn "Dataset download failed — model will train on first scan"
    curl -fsSL "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt" \
         -o "$NSL_KDD_DIR/KDDTest+.csv" || true

    if [[ -f "$NSL_KDD_DIR/KDDTrain+.csv" ]]; then
        warn "Training Random Forest model (this runs once, takes ~30 seconds)..."
        "$INSTALL_DIR/venv/bin/python3" -c "
import sys
sys.path.insert(0, '$INSTALL_DIR/backend_flask')
from app.services.rf_classifier import RFClassifier
clf = RFClassifier()
clf.train()
print('Model trained and saved.')
" && log "ML model trained successfully" || warn "Model training failed — will retrain on first scan"
    fi
}

# ── Systemd Services (Linux) ──────────────────────────────────────────────────
setup_systemd() {
    [[ "$OS" == "macos" ]] && return
    step "Creating systemd Services"

    # Flask Backend Service
    cat > /etc/systemd/system/cybermind-flask.service << EOF
[Unit]
Description=CyberMind Sentinel — Flask Security Backend
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${INSTALL_DIR}/backend_flask
EnvironmentFile=${CONFIG_DIR}/.env
ExecStart=${INSTALL_DIR}/venv/bin/gunicorn \
    --bind 0.0.0.0:5000 \
    --workers 2 \
    --timeout 120 \
    --access-logfile ${LOG_DIR}/flask-access.log \
    --error-logfile ${LOG_DIR}/flask-error.log \
    "run:create_app()"
Restart=always
RestartSec=5
StandardOutput=append:${LOG_DIR}/flask.log
StandardError=append:${LOG_DIR}/flask-error.log
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF

    # Node.js Auth Backend Service
    cat > /etc/systemd/system/cybermind-auth.service << EOF
[Unit]
Description=CyberMind Sentinel — Auth Backend
After=network.target

[Service]
Type=simple
User=${CYBERMIND_USER}
WorkingDirectory=${INSTALL_DIR}/backend
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=5
Environment=NODE_ENV=production
StandardOutput=append:${LOG_DIR}/auth.log
StandardError=append:${LOG_DIR}/auth-error.log

[Install]
WantedBy=multi-user.target
EOF

    # Ollama Service
    cat > /etc/systemd/system/cybermind-ollama.service << EOF
[Unit]
Description=CyberMind Sentinel — Ollama AI Engine
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ollama serve
Restart=always
RestartSec=10
Environment=OLLAMA_HOST=0.0.0.0:11434
StandardOutput=append:${LOG_DIR}/ollama.log
StandardError=append:${LOG_DIR}/ollama-error.log

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable cybermind-flask cybermind-auth cybermind-ollama
    log "systemd services created and enabled"
}

# ── macOS Launch Services ──────────────────────────────────────────────────────
setup_launchd() {
    [[ "$OS" != "macos" ]] && return
    step "Creating macOS Launch Services"

    PLIST_DIR="$HOME/Library/LaunchAgents"
    mkdir -p "$PLIST_DIR"

    cat > "$PLIST_DIR/com.cybermind.flask.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.cybermind.flask</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/venv/bin/gunicorn</string>
        <string>--bind</string><string>0.0.0.0:5000</string>
        <string>--workers</string><string>2</string>
        <string>--chdir</string><string>${INSTALL_DIR}/backend_flask</string>
        <string>run:create_app()</string>
    </array>
    <key>WorkingDirectory</key><string>${INSTALL_DIR}/backend_flask</string>
    <key>EnvironmentVariables</key>
    <dict><key>DOTENV_FILE</key><string>${CONFIG_DIR}/.env</string></dict>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>${LOG_DIR}/flask.log</string>
    <key>StandardErrorPath</key><string>${LOG_DIR}/flask-error.log</string>
</dict>
</plist>
EOF

    launchctl load "$PLIST_DIR/com.cybermind.flask.plist" 2>/dev/null || true
    log "macOS launch services configured"
}

# ── Start Services ─────────────────────────────────────────────────────────────
start_services() {
    step "Starting CyberMind Services"

    if [[ "$OS" == "macos" ]]; then
        launchctl start com.cybermind.flask 2>/dev/null || true
        cd "$INSTALL_DIR/backend" && node server.js &>/dev/null &
        log "Services started"
    else
        systemctl start cybermind-flask cybermind-auth cybermind-ollama
        sleep 2
        systemctl is-active --quiet cybermind-flask && log "Flask backend: running" || warn "Flask backend: check logs"
        systemctl is-active --quiet cybermind-auth  && log "Auth backend:  running" || warn "Auth backend:  check logs"
        systemctl is-active --quiet cybermind-ollama && log "Ollama AI:     running" || warn "Ollama AI:     check logs"
    fi
}

# ── SPAN Port Configuration Instructions ──────────────────────────────────────
print_span_instructions() {
    echo ""
    echo -e "${BOLD}${YELLOW}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  SPAN Port / Network Monitor Configuration${NC}"
    echo -e "${BOLD}${YELLOW}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "  CyberMind requires access to all network traffic to detect threats."
    echo "  Configure your switch to mirror traffic to this server:"
    echo ""
    echo "  ┌─ Cisco IOS Example: ──────────────────────────────────────────┐"
    echo "  │  monitor session 1 source interface Gi0/1                     │"
    echo "  │  monitor session 1 destination interface Gi0/24               │"
    echo "  └──────────────────────────────────────────────────────────────-┘"
    echo ""
    echo "  ┌─ Or run in 'local host only' mode (monitors THIS machine): ───┐"
    echo "  │  No switch config needed — monitors localhost traffic only     │"
    echo "  └────────────────────────────────────────────────────────────────┘"
    echo ""
}

# ── Final Summary ──────────────────────────────────────────────────────────────
print_summary() {
    SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "your-server-ip")

    echo ""
    echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${GREEN}  ✔  CyberMind Sentinel Installed Successfully!${NC}"
    echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${BOLD}Dashboard:${NC}     http://${SERVER_IP}:5173"
    echo -e "  ${BOLD}API:${NC}           http://${SERVER_IP}:5000/api"
    echo -e "  ${BOLD}Config:${NC}        ${CONFIG_DIR}/.env"
    echo -e "  ${BOLD}Logs:${NC}          ${LOG_DIR}/"
    echo ""
    echo -e "  ${BOLD}Default Login:${NC}"
    echo -e "    Username:  ${CYAN}admin${NC}"
    echo -e "    Password:  ${CYAN}changeme123${NC}"
    echo -e "  ${YELLOW}  ⚠ Change this immediately after first login!${NC}"
    echo ""
    echo -e "  ${BOLD}Manage services (Linux):${NC}"
    echo -e "    sudo systemctl status cybermind-flask"
    echo -e "    sudo systemctl restart cybermind-flask"
    echo -e "    sudo journalctl -u cybermind-flask -f"
    echo ""
    echo -e "  ${BOLD}Uninstall:${NC}"
    echo -e "    sudo bash ${INSTALL_DIR}/uninstall.sh"
    echo ""
    echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════════════════${NC}"
}

# ── Main ───────────────────────────────────────────────────────────────────────
main() {
    banner
    echo ""
    log "Starting CyberMind Sentinel installation..."
    echo ""

    detect_os
    check_privileges
    install_system_deps
    install_node
    setup_directories
    install_app
    configure_environment
    setup_ml_model
    install_ollama

    if [[ "$OS" == "macos" ]]; then
        setup_launchd
    else
        setup_systemd
    fi

    start_services
    print_span_instructions
    print_summary
}

main "$@"
