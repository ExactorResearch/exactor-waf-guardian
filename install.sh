#!/usr/bin/env bash
# ==============================================================================
# Exactor WAF Guardian - Automated Server Installation Script
# Operating Systems: Ubuntu, Debian, RHEL, CentOS, Rocky Linux, Alpine
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE}🛡️  Installing Exactor WAF Guardian Server Component${NC}"
echo -e "${BLUE}   Deterministic SAT Cyber-Defense & Reverse Proxy${NC}"
echo -e "${BLUE}   Engine: EXACTOR Core & https://exactor.tech${NC}"
echo -e "${BLUE}============================================================${NC}"

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root (use sudo).${NC}" 
   exit 1
fi

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/exactor"
SERVICE_FILE="/etc/systemd/system/exactor-waf.service"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 1. Compile or Locate Binary
echo -e "${YELLOW}[1/5] Preparing binary...${NC}"
BINARY_PATH=""

if [[ -f "${SCRIPT_DIR}/target/release/exactor-waf-guardian" ]]; then
    BINARY_PATH="${SCRIPT_DIR}/target/release/exactor-waf-guardian"
elif [[ -f "${SCRIPT_DIR}/../target/release/exactor-waf-guardian" ]]; then
    BINARY_PATH="${SCRIPT_DIR}/../target/release/exactor-waf-guardian"
else
    echo -e "Compiling release binary using cargo..."
    if command -v cargo &> /dev/null; then
        (cd "${SCRIPT_DIR}" && cargo build --release)
        BINARY_PATH="${SCRIPT_DIR}/target/release/exactor-waf-guardian"
    else
        echo -e "${RED}Error: Cargo not found and no precompiled binary available.${NC}"
        echo -e "Please install Rust (curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh) or provide prebuilt binary."
        exit 1
    fi
fi

# 2. Install Binary
echo -e "${YELLOW}[2/5] Installing binary to ${INSTALL_DIR}...${NC}"
install -m 755 "${BINARY_PATH}" "${INSTALL_DIR}/exactor-waf-guardian"
echo -e "${GREEN}✓ Binary installed at ${INSTALL_DIR}/exactor-waf-guardian${NC}"

# 3. Create Configuration
echo -e "${YELLOW}[3/5] Setting up configuration directory ${CONFIG_DIR}...${NC}"
mkdir -p "${CONFIG_DIR}"

if [[ ! -f "${CONFIG_DIR}/waf_config.toml" ]]; then
    if [[ -f "${SCRIPT_DIR}/waf_config.toml" ]]; then
        cp "${SCRIPT_DIR}/waf_config.toml" "${CONFIG_DIR}/waf_config.toml"
    else
        cat << 'EOF' > "${CONFIG_DIR}/waf_config.toml"
listen_addr = "0.0.0.0:8080"
upstream_url = "http://127.0.0.1:3000"
mode = "block"
exactor_api_url = "https://exactor.tech/api/simplify"
database_path = "/etc/exactor/waf_ledger.db"
autonomous_sync_interval_secs = 300
auto_sync_enabled = true
EOF
    fi
    chmod 644 "${CONFIG_DIR}/waf_config.toml"
    echo -e "${GREEN}✓ Created default config at ${CONFIG_DIR}/waf_config.toml${NC}"
else
    echo -e "${BLUE}ℹ️  Existing configuration preserved at ${CONFIG_DIR}/waf_config.toml${NC}"
fi

# 4. Install Systemd Service
echo -e "${YELLOW}[4/5] Installing systemd service...${NC}"
if [[ -d "/etc/systemd/system" ]]; then
    cp "${SCRIPT_DIR}/exactor-waf.service" "${SERVICE_FILE}"
    chmod 644 "${SERVICE_FILE}"
    systemctl daemon-reload
    systemctl enable exactor-waf.service
    echo -e "${GREEN}✓ Systemd service registered and enabled.${NC}"
else
    echo -e "${YELLOW}Warning: systemd not detected. You can run the server with:${NC}"
    echo -e "${GREEN}exactor-waf-guardian proxy --config ${CONFIG_DIR}/waf_config.toml${NC}"
fi

# 5. Start Service
echo -e "${YELLOW}[5/5] Starting service...${NC}"
if command -v systemctl &> /dev/null && systemctl is-system-running &> /dev/null; then
    systemctl restart exactor-waf.service
    sleep 1
    if systemctl is-active --quiet exactor-waf.service; then
        echo -e "${GREEN}✅ Exactor WAF Guardian is ACTIVE and protecting your server!${NC}"
    else
        echo -e "${RED}⚠️  Service failed to start. Check logs with: journalctl -u exactor-waf -e${NC}"
    fi
fi

echo -e "\n${GREEN}============================================================${NC}"
echo -e "${GREEN}🎉 Installation successfully completed!${NC}"
echo -e "   Status command   : systemctl status exactor-waf"
echo -e "   Logs command     : journalctl -u exactor-waf -f"
echo -e "   Config file      : /etc/exactor/waf_config.toml"
echo -e "   CLI inspection   : exactor-waf-guardian inspect --query \"id=1' OR 1=1--\""
echo -e "   Benchmark        : exactor-waf-guardian benchmark"
echo -e "${GREEN}============================================================${NC}"
