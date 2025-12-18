#!/bin/bash

# NEXUS - Zero-False-Positive Vulnerability Reconnaissance Framework
# Copyright (c) 2024 Offensive Security Research Division
# Built for passive detection of historic critical RCE vulnerabilities

set -euo pipefail

# Global Configuration
VERSION="1.0.0"
FRAMEWORK_NAME="NEXUS"
CONFIDENCE_THRESHOLD_CONFIRMED=90
CONFIDENCE_THRESHOLD_LIKELY=70
CONFIDENCE_THRESHOLD_POSSIBLE=50

# Color Definitions (256-color safe)
declare -g COLOR_ERROR='\033[0;91m'
declare -g COLOR_SUCCESS='\033[0;92m'
declare -g COLOR_WARNING='\033[0;93m'
declare -g COLOR_INFO='\033[0;94m'
declare -g COLOR_CYAN='\033[0;96m'
declare -g COLOR_MAGENTA='\033[0;95m'
declare -g COLOR_RESET='\033[0m'

# Source Framework Libraries
source "$(dirname "${BASH_SOURCE[0]}")/lib/colors.sh"
source "$(dirname "${BASH_SOURCE[0]}")/lib/ui.sh"
source "$(dirname "${BASH_SOURCE[0]}")/lib/http.sh"
source "$(dirname "${BASH_SOURCE[0]}")/lib/fingerprint.sh"
source "$(dirname "${BASH_SOURCE[0]}")/lib/confidence.sh"
source "$(dirname "${BASH_SOURCE[0]}")/lib/reporting.sh"

# Initialize Framework
nexus_init() {
    print_banner
    check_dependencies
    setup_environment
}

# Main Entry Point
main() {
    local target=""
    local mode="passive"
    local output_format="table"
    local modules="all"
    local stealth=false
    local callback_domain=""
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            --version)
                echo "${FRAMEWORK_NAME} v${VERSION}"
                exit 0
                ;;
            -l|--list)
                shift; target="file:$1"
                ;;
            --module)
                shift; modules="$1"
                ;;
            --all)
                modules="all"
                ;;
            --stealth)
                stealth=true
                ;;
            --callback)
                shift; callback_domain="$1"
                ;;
            --output)
                shift; output_format="$1"
                ;;
            -v|--verbose)
                set -x
                ;;
            *)
                if [[ -z "$target" ]]; then
                    target="$1"
                else
                    echo -e "${COLOR_ERROR}Error: Multiple targets specified${COLOR_RESET}"
                    exit 1
                fi
                ;;
        esac
        shift
    done
    
    if [[ -z "$target" ]]; then
        show_usage
        exit 1
    fi
    
    # Initialize framework
    nexus_init
    
    # Start reconnaissance
    start_reconnaissance "$target" "$modules" "$stealth" "$callback_domain" "$output_format"
}

# Usage Information
show_usage() {
    cat << EOF
${COLOR_CYAN}${FRAMEWORK_NAME}${COLOR_RESET} v${VERSION} - Zero-False-Positive Vulnerability Reconnaissance

${COLOR_MAGENTA}USAGE:${COLOR_RESET}
    nexus [OPTIONS] <TARGET>

${COLOR_MAGENTA}TARGETS:${COLOR_RESET}
    Single URL:           nexus https://target.com
    Target list:          nexus -l targets.txt
    CIDR range:           nexus 192.168.1.0/24:80,443,8080

${COLOR_MAGENTA}OPTIONS:${COLOR_RESET}
    -h, --help           Show this help message
    --version            Show version information
    -l, --list FILE      Load targets from file
    --module NAME        Run specific vulnerability module
    --all               Run all modules (default)
    --stealth           Enable stealth mode (1 req/10sec)
    --callback DOMAIN   Enable DNS callback for Log4Shell/Text4Shell
    --output FORMAT     Output format: table|json|csv (default: table)
    -v, --verbose       Enable verbose debugging

${COLOR_MAGENTA}MODULES:${COLOR_RESET}
    spring4shell, log4shell, text4shell, fastjson, jackson
    struts2, kibana, ghostscript, vm2

${COLOR_MAGENTA}EXAMPLES:${COLOR_RESET}
    nexus --stealth https://target.com
    nexus --module log4shell --callback security.nexus.lol https://target.com
    nexus --output json --all 192.168.1.0/24:80,443,8080
EOF
}

# Start reconnaissance process
start_reconnaissance() {
    local target="$1"
    local modules="$2"
    local stealth="$3"
    local callback_domain="$4"
    local output_format="$5"
    
    print_stage_header "TARGET ANALYSIS"
    
    # Parse and validate targets
    local targets
    targets=$(parse_targets "$target")
    
    if [[ -z "$targets" ]]; then
        print_error "No valid targets found"
        exit 1
    fi
    
    # Initialize results storage
    local results_file
    results_file=$(mktemp)
    echo "[]" > "$results_file"
    
    # Process targets
    local target_count
    target_count=$(echo "$targets" | wc -l)
    
    print_info "Processing $target_count target(s)"
    
    local current_target=0
    while IFS= read -r target_line; do
        ((current_target++))
        
        print_progress "Analyzing target" "$current_target" "$target_count"
        process_target "$target_line" "$modules" "$stealth" "$callback_domain" "$results_file"
        
    done <<< "$targets"
    
    # Generate final report
    print_stage_header "FINAL REPORT"
    generate_final_report "$results_file" "$output_format"
    
    # Cleanup
    rm -f "$results_file"
}

# Process individual target
process_target() {
    local target="$1"
    local modules="$2"
    local stealth="$3"
    local callback_domain="$4"
    local results_file="$5"
    
    print_target_header "$target"
    
    # Determine which modules to run
    local modules_to_run
    if [[ "$modules" == "all" ]]; then
        modules_to_run="spring4shell log4shell text4shell fastjson jackson struts2 kibana ghostscript vm2"
    else
        modules_to_run="$modules"
    fi
    
    # Run vulnerability detection modules
    for module in $modules_to_run; do
        local module_file="modules/detect_${module}.sh"
        if [[ -f "$module_file" ]]; then
            source "$module_file"
            local module_func="detect_${module}"
            if declare -f "$module_func" >/dev/null; then
                eval "$module_func" "$target" "$stealth" "$callback_domain" "$results_file"
            fi
        fi
    done
}

# Check system dependencies
check_dependencies() {
    local missing_deps=()
    
    for dep in curl jq nmap openssl dig awk sed grep; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            missing_deps+=("$dep")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        print_error "Missing dependencies: ${missing_deps[*]}"
        echo "Install with: sudo apt-get install ${missing_deps[*]}"
        exit 1
    fi
}

# Setup environment
setup_environment() {
    # Create temp directories
    export NEXUS_TMP_DIR
    NEXUS_TMP_DIR=$(mktemp -d)
    export NEXUS_CACHE_DIR
    NEXUS_CACHE_DIR="${HOME}/.nexus/cache"
    mkdir -p "$NEXUS_CACHE_DIR"
    
    # Set user agent
    export NEXUS_USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

# Initialize and run
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi