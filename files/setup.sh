#!/bin/bash
# ============================================================
#   🦇 ReconFusion M7 – Setup Script
#   Produced by MilkyWay Intelligence
#   For authorized security testing ONLY
# ============================================================

set -e

YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

banner() {
echo -e "${YELLOW}"
cat << 'EOF'
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███████╗██╗   ██╗███████╗██╗ ██████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔════╝██║   ██║██╔════╝██║██╔═══██╗████╗  ██║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║█████╗  ██║   ██║███████╗██║██║   ██║██╔██╗ ██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔══╝  ██║   ██║╚════██║██║██║   ██║██║╚██╗██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║     ╚██████╔╝███████║██║╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝
EOF
echo -e "${NC}"
echo -e "${CYAN}        🦇  M7 BATMAN Edition – Setup Script  🦇${NC}"
echo -e "${CYAN}             Produced by MilkyWay Intelligence${NC}"
echo ""
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[!] Please run as root: sudo bash setup.sh${NC}"
        exit 1
    fi
}

install_python_deps() {
    echo -e "${CYAN}[*] Installing Python dependencies...${NC}"
    pip3 install -r requirements.txt --break-system-packages -q
    echo -e "${GREEN}[✓] Python deps installed${NC}"
}

install_go_tools() {
    echo -e "${CYAN}[*] Setting up Go environment...${NC}"
    
    if ! command -v go &> /dev/null; then
        echo -e "${YELLOW}[*] Installing Go...${NC}"
        apt-get install -y golang-go -q
    fi

    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin

    GO_TOOLS=(
        "github.com/tomnomnom/assetfinder@latest"
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        "github.com/projectdiscovery/katana/cmd/katana@latest"
        "github.com/hahwul/dalfox/v2@latest"
        "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
    )

    for tool in "${GO_TOOLS[@]}"; do
        name=$(basename ${tool%@*})
        echo -e "${YELLOW}  [*] Installing $name...${NC}"
        go install "$tool" 2>/dev/null && \
            echo -e "${GREEN}  [✓] $name installed${NC}" || \
            echo -e "${RED}  [✗] $name failed (may need manual install)${NC}"
    done

    # Add Go bin to PATH permanently
    if ! grep -q "GOPATH" /etc/profile; then
        echo 'export GOPATH=$HOME/go' >> /etc/profile
        echo 'export PATH=$PATH:$GOPATH/bin' >> /etc/profile
    fi
}

install_apt_tools() {
    echo -e "${CYAN}[*] Installing apt tools...${NC}"
    apt-get update -q
    apt-get install -y nmap amass python3-pip -q
    echo -e "${GREEN}[✓] apt tools installed${NC}"
}

setup_nuclei_templates() {
    echo -e "${CYAN}[*] Updating nuclei templates...${NC}"
    if command -v nuclei &> /dev/null; then
        nuclei -update-templates -silent 2>/dev/null || true
        echo -e "${GREEN}[✓] Nuclei templates updated${NC}"
    fi
}

make_executable() {
    chmod +x reconfusion.py
    echo -e "${GREEN}[✓] reconfusion.py is now executable${NC}"
}

banner
check_root

echo -e "${YELLOW}[*] Starting ReconFusion M7 setup...${NC}"
echo ""

install_apt_tools
install_go_tools
install_python_deps
setup_nuclei_templates
make_executable

echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  ✅ ReconFusion M7 Setup Complete!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "${CYAN}Usage:${NC}"
echo -e "  python3 reconfusion.py -d example.com -o my-project"
echo ""
echo -e "${RED}⚠️  For authorized security testing ONLY${NC}"
echo -e "${YELLOW}🦇 Produced by MilkyWay Intelligence${NC}"
