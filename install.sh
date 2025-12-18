#!/bin/bash

# NEXUS Installation Script
# Professional offensive security reconnaissance framework

set -euo pipefail

# Color codes
readonly COLOR_GREEN='\033[0;92m'
readonly COLOR_BLUE='\033[0;94m'
readonly COLOR_YELLOW='\033[0;93m'
readonly COLOR_RED='\033[0;91m'
readonly COLOR_RESET='\033[0m'

# Installation configuration
readonly INSTALL_DIR="/usr/local/bin"
readonly CONFIG_DIR="${HOME}/.nexus"
readonly NEXUS_NAME="nexus"

# Print banner
print_banner() {
    echo -e "${COLOR_BLUE}"
    cat << 'EOF'
    ╔════════════════════════════════════════════════════════════════╗
    ║                                                                ║
    ║        ████████       ██████  ██████  ██████  ██████         ║
    ║            ██         ██         ██    ██         ██         ║
    ║        ██████         ██   ███  ██  ██   ███  ██           ║
    ║            ██         ██    ██  ██  ██    ██  ██           ║
    ║        ████████       ██████  ██████  ██████  ██████        ║
    ║                                                                ║
    ║      ZERO-FALSE-POSITIVE VULNERABILITY RECONNAISSANCE        ║
    ║                                                                ║
    ╚════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${COLOR_RESET}"
    echo -e "${COLOR_BLUE}NEXUS v1.0.0 - Professional Installation${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}============================================${COLOR_RESET}"
    echo
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        echo -e "${COLOR_RED}❌ Please do not run this script as root${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}  Run as regular user, sudo will be used when needed${COLOR_RESET}"
        exit 1
    fi
}

# Check system compatibility
check_system() {
    echo -e "${COLOR_BLUE}📋 Checking system compatibility...${COLOR_RESET}"
    
    # Check Bash version
    local bash_version
    bash_version=${BASH_VERSION%%.*}
    if [[ $bash_version -lt 4 ]]; then
        echo -e "${COLOR_RED}❌ Bash 4.0+ required (found: $BASH_VERSION)${COLOR_RESET}"
        exit 1
    fi
    
    # Check OS
    local os_name
    os_name=$(uname -s)
    case "$os_name" in
        Linux|Darwin)
            echo -e "${COLOR_GREEN}✅ $os_name supported${COLOR_RESET}"
            ;;
        *)
            echo -e "${COLOR_YELLOW}⚠️  $os_name not fully tested${COLOR_RESET}"
            ;;
    esac
    
    echo
}

# Install dependencies
install_dependencies() {
    echo -e "${COLOR_BLUE}📦 Installing system dependencies...${COLOR_RESET}"
    
    local os_name
    os_name=$(uname -s)
    
    case "$os_name" in
        "Linux")
            install_dependencies_linux
            ;;
        "Darwin")
            install_dependencies_macos
            ;;
        *)
            echo -e "${COLOR_YELLOW}⚠️  Manual dependency installation required for $os_name${COLOR_RESET}"
            install_dependencies_manual
            ;;
    esac
}

# Install dependencies on Linux
install_dependencies_linux() {
    local missing_packages=()
    
    # Check for required packages
    for package in curl jq nmap openssl dnsutils coreutils; do
        if ! command -v "$package" >/dev/null 2>&1; then
            missing_packages+=("$package")
        fi
    done
    
    if [[ ${#missing_packages[@]} -gt 0 ]]; then
        echo -e "${COLOR_YELLOW}🔧 Installing: ${missing_packages[*]}${COLOR_RESET}"
        sudo apt-get update -qq
        sudo apt-get install -y "${missing_packages[@]}"
    fi
    
    echo -e "${COLOR_GREEN}✅ All dependencies satisfied${COLOR_RESET}"
}

# Install dependencies on macOS
install_dependencies_macos() {
    local missing_tools=()
    
    # Check for required tools
    for tool in curl jq nmap openssl dig; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        if command -v brew >/dev/null 2>&1; then
            echo -e "${COLOR_YELLOW}🔧 Installing via Homebrew: ${missing_tools[*]}${COLOR_RESET}"
            brew install "${missing_tools[@]}"
        else
            echo -e "${COLOR_RED}❌ Homebrew required. Install from https://brew.sh${COLOR_RESET}"
            exit 1
        fi
    fi
    
    echo -e "${COLOR_GREEN}✅ All dependencies satisfied${COLOR_RESET}"
}

# Manual dependency installation
install_dependencies_manual() {
    echo -e "${COLOR_YELLOW}📋 Required tools:${COLOR_RESET}"
    echo -e "${COLOR_WHITE}  • curl - HTTP client${COLOR_RESET}"
    echo -e "${COLOR_WHITE}  • jq - JSON processor${COLOR_RESET}"
    echo -e "${COLOR_WHITE}  • nmap - Network scanner${COLOR_RESET}"
    echo -e "${COLOR_WHITE}  • openssl - SSL/TLS toolkit${COLOR_RESET}"
    echo -e "${COLOR_WHITE}  • dig - DNS lookup utility${COLOR_RESET}"
    echo -e "${COLOR_WHITE}  • awk, sed, grep - Text processing${COLOR_RESET}"
    echo
    read -p "Press Enter after installing dependencies..."
}

# Install NEXUS framework
install_nexus() {
    echo -e "${COLOR_BLUE}🚀 Installing NEXUS framework...${COLOR_RESET}"
    
    # Get current directory
    local current_dir
    current_dir=$(dirname "$(realpath "$0")")
    
    # Create directories
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$CONFIG_DIR/cache"
    mkdir -p "$CONFIG_DIR/logs"
    
    # Copy main script
    sudo cp "$current_dir/nexus.sh" "$INSTALL_DIR/$NEXUS_NAME"
    sudo chmod +x "$INSTALL_DIR/$NEXUS_NAME"
    
    # Copy libraries
    mkdir -p "$CONFIG_DIR/lib"
    cp -r "$current_dir/lib/"* "$CONFIG_DIR/lib/"
    
    # Copy modules
    mkdir -p "$CONFIG_DIR/modules"
    cp -r "$current_dir/modules/"* "$CONFIG_DIR/modules/"
    
    echo -e "${COLOR_GREEN}✅ NEXUS installed successfully${COLOR_RESET}"
}

# Setup configuration
setup_config() {
    echo -e "${COLOR_BLUE}⚙️  Setting up configuration...${COLOR_RESET}"
    
    # Create default config
    cat > "$CONFIG_DIR/config.sh" << 'EOF'
#!/bin/bash

# NEXUS Configuration
export NEXUS_CONFIG_DIR="$HOME/.nexus"
export NEXUS_CACHE_DIR="$NEXUS_CONFIG_DIR/cache"
export NEXUS_LOG_DIR="$NEXUS_CONFIG_DIR/logs"
export NEXUS_USER_AGENT="Mozilla/5.0 (compatible; NEXUS/1.0)"

# Default options
export NEXUS_STEALTH_MODE="false"
export NEXUS_CONFIDENCE_THRESHOLD="50"
export NEXUS_TIMEOUT="10"
export NEXUS_MAX_RETRIES="2"
EOF
    
    # Create aliases
    cat > "$CONFIG_DIR/aliases.sh" << 'EOF'
#!/bin/bash

# NEXUS aliases
alias nexus='bash /usr/local/bin/nexus.sh'
alias nexus-stealth='nexus --stealth'
alias nexus-json='nexus --output json'
alias nexus-debug='nexus --verbose'
EOF
    
    echo -e "${COLOR_GREEN}✅ Configuration created${COLOR_RESET}"
}

# Test installation
test_installation() {
    echo -e "${COLOR_BLUE}🧪 Testing installation...${COLOR_RESET}"
    
    # Test main command
    if command -v nexus >/dev/null 2>&1; then
        echo -e "${COLOR_GREEN}✅ Command 'nexus' available${COLOR_RESET}"
    else
        echo -e "${COLOR_RED}❌ Command 'nexus' not found${COLOR_RESET}"
        return 1
    fi
    
    # Test version
    local version
    version=$(nexus --version 2>/dev/null | head -1 || echo "Unknown")
    echo -e "${COLOR_GREEN}✅ Version: $version${COLOR_RESET}"
    
    # Test help
    if nexus --help >/dev/null 2>&1; then
        echo -e "${COLOR_GREEN}✅ Help system working${COLOR_RESET}"
    else
        echo -e "${COLOR_YELLOW}⚠️  Help system issue${COLOR_RESET}"
    fi
    
    echo
}

# Print completion message
print_completion() {
    echo -e "${COLOR_GREEN}╔════════════════════════════════════════════════════════════════╗${COLOR_RESET}"
    echo -e "${COLOR_GREEN}║${COLOR_RESET} ${COLOR_BOLD}NEXUS INSTALLATION COMPLETE${COLOR_RESET} $(printf ' %.0s' {1..18}) ${COLOR_GREEN}║${COLOR_RESET}"
    echo -e "${COLOR_GREEN}╠════════════════════════════════════════════════════════════════╣${COLOR_RESET}"
    echo -e "${COLOR_GREEN}║${COLOR_RESET} ${COLOR_WHITE}Framework ready for professional security testing${COLOR_RESET} $(printf ' %.0s' {1..5}) ${COLOR_GREEN}║${COLOR_RESET}"
    echo -e "${COLOR_GREEN}║${COLOR_RESET} ${COLOR_WHITE}Location: $INSTALL_DIR/nexus${COLOR_RESET} $(printf ' %.0s' {1..21}) ${COLOR_GREEN}║${COLOR_RESET}"
    echo -e "${COLOR_GREEN}║${COLOR_RESET} ${COLOR_WHITE}Config: $CONFIG_DIR${COLOR_RESET} $(printf ' %.0s' {1..26}) ${COLOR_GREEN}║${COLOR_RESET}"
    echo -e "${COLOR_GREEN}╠════════════════════════════════════════════════════════════════╣${COLOR_RESET}"
    echo -e "${COLOR_GREEN}║${COLOR_RESET} ${COLOR_YELLOW}QUICK START:${COLOR_RESET} $(printf ' %.0s' {1..31}) ${COLOR_GREEN}║${COLOR_RESET}"
    echo -e "${COLOR_GREEN}║${COLOR_RESET} ${COLOR_WHITE}nexus --help${COLOR_RESET} $(printf ' %.0s' {1..33}) ${COLOR_GREEN}║${COLOR_RESET}"
    echo -e "${COLOR_GREEN}║${COLOR_RESET} ${COLOR_WHITE}nexus https://target.com${COLOR_RESET} $(printf ' %.0s' {1..20}) ${COLOR_GREEN}║${COLOR_RESET}"
    echo -e "${COLOR_GREEN}║${COLOR_RESET} ${COLOR_WHITE}nexus --stealth https://target.com${COLOR_RESET} $(printf ' %.0s' {1..10}) ${COLOR_GREEN}║${COLOR_RESET}"
    echo -e "${COLOR_GREEN}╚════════════════════════════════════════════════════════════════╝${COLOR_RESET}"
    echo
    echo -e "${COLOR_YELLOW}⚠️  LEGAL NOTICE:${COLOR_RESET}"
    echo -e "${COLOR_WHITE}  Use only on systems you own or have explicit written permission to test.${COLOR_RESET}"
    echo -e "${COLOR_WHITE}  Unauthorized scanning is illegal and unethical.${COLOR_RESET}"
    echo
}

# Main installation flow
main() {
    print_banner
    
    check_root
    check_system
    install_dependencies
    install_nexus
    setup_config
    test_installation
    print_completion
}

# Run installation
main "$@"