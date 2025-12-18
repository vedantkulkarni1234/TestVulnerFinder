#!/bin/bash

# UI Components for NEXUS framework

# Print cyberpunk-style banner
print_banner() {
    clear
    cat << 'EOF'

    ████████████████████████████████████████████████████████████████
    █                                                              █
    █        ████████       ██████  ██████  ██████  ██████         █
    █            ██         ██         ██    ██         ██         █
    █        ██████         ██   ███  ██  ██   ███  ██           █
    █            ██         ██    ██  ██  ██    ██  ██           █
    █        ████████       ██████  ██████  ██████  ██████        █
    █                                                              █
    █                                                              █
    █  ZERO-FALSE-POSITIVE VULNERABILITY RECONNAISSANCE FRAMEWORK  █
    █                                                              █
    ████████████████████████████████████████████████████████████████

EOF

    # Version and copyright info
    echo -e "${COLOR_CYAN}════════════════════════════════════════════════════════════════${COLOR_RESET}"
    echo -e "${COLOR_WHITE}NEXUS v${VERSION}${COLOR_RESET}"
    echo -e "${COLOR_DIM}Professional Offensive Security Reconnaissance Tool${COLOR_RESET}"
    echo -e "${COLOR_CYAN}════════════════════════════════════════════════════════════════${COLOR_RESET}"
    echo
}

# Print stage header with heavy border
print_stage_header() {
    local stage="$1"
    echo
    echo -e "${COLOR_BRIGHT_MAGENTA}${BOX_DOUBLE_CORNER_TL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_CORNER_TR}${COLOR_RESET}"
    echo -e "${COLOR_BRIGHT_MAGENTA}${BOX_DOUBLE_VERTICAL}${COLOR_RESET} ${COLOR_BOLD}$stage${COLOR_RESET} $(printf ' %.0s' {1..10}) ${COLOR_BRIGHT_MAGENTA}${BOX_DOUBLE_VERTICAL}${COLOR_RESET}"
    echo -e "${COLOR_BRIGHT_MAGENTA}${BOX_DOUBLE_CORNER_BL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_CORNER_BR}${COLOR_RESET}"
    echo
}

# Print target header
print_target_header() {
    local target="$1"
    echo
    echo -e "${COLOR_CYAN}${BOX_T_TOP}${BOX_HORIZONTAL}${BOX_HORIZONTAL}${BOX_HORIZONTAL}${BOX_HORIZONTAL}${BOX_HORIZONTAL}${BOX_HORIZONTAL}${BOX_HORIZONTAL}${BOX_HORIZONTAL}${BOX_HORIZONTAL}${BOX_HORIZONTAL}${BOX_HORIZONTAL}${BOX_HORIZONTAL}${BOX_HORIZONTAL}${BOX_HORIZONTAL}${BOX_HORIZONTAL}${BOX_HORIZONTAL}${BOX_HORIZONTAL}${BOX_HORIZONTAL}${BOX_T_TOP}${COLOR_RESET}"
    echo -e "${COLOR_CYAN}${BOX_VERTICAL}${COLOR_RESET} ${COLOR_BOLD}$target${COLOR_RESET} $(printf ' %.0s' {1..20}) ${COLOR_CYAN}${BOX_VERTICAL}${COLOR_RESET}"
    echo -e "${COLOR_CYAN}${BOX_T_BOTTOM}${BOX_HORIZONTAL}${BOX_HORIZONTAL}${BOX_HORIZONTAL}${BOX_HORIZONTAL}${BOX_HORIZONTAL}${BOX_HORIZONTAL}${BOX_HORIZONTAL}${BOX_HORIZONTAL}${BOX_HORIZONTAL}${BOX_HORIZONTAL}${BOX_HORIZONTAL}${BOX_HORIZONTAL}${BOX_HORIZONTAL}${BOX_HORIZONTAL}${BOX_HORIZONTAL}${BOX_HORIZONTAL}${BOX_HORIZONTAL}${BOX_HORIZONTAL}${BOX_T_BOTTOM}${COLOR_RESET}"
}

# Print progress bar with percentage and ETA
print_progress() {
    local message="$1"
    local current="$2"
    local total="$3"
    
    local percentage=$((current * 100 / total))
    local filled_blocks=$((percentage / 10))
    local empty_blocks=$((10 - filled_blocks))
    
    local filled_bar=$(printf "%${filled_blocks}s" | tr ' ' '█')
    local empty_bar=$(printf "%${empty_blocks}s" | tr ' ' '░')
    
    # Calculate ETA (simplified)
    local elapsed=$((SECONDS))
    local eta_seconds=$((elapsed * (total - current) / current))
    local eta_minutes=$((eta_seconds / 60))
    local eta_rem=$((eta_seconds % 60))
    
    printf "\r${COLOR_CYAN}[${COLOR_BRIGHT_CYAN}${filled_bar}${COLOR_CYAN}${empty_bar}${COLOR_CYAN}] ${percentage}%%${COLOR_RESET} ${COLOR_WHITE}$message${COLOR_RESET} ${COLOR_DIM}(${current}/${total})${COLOR_RESET}"
    
    if [[ $eta_seconds -gt 0 ]]; then
        echo -n " ${COLOR_DIM}ETA: ${eta_minutes}m${eta_rem}s${COLOR_RESET}"
    fi
    
    if [[ $current -eq $total ]]; then
        echo
    fi
}

# Print spinner animation
print_spinner() {
    local message="$1"
    local pid="$2"
    
    local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    
    while kill -0 $pid 2>/dev/null; do
        i=$(( (i+1) %10 ))
        printf "\r${COLOR_CYAN}${spin:$i:1}${COLOR_RESET} ${COLOR_WHITE}$message${COLOR_RESET}"
        sleep 0.1
    done
    printf "\r"
}

# Print error message
print_error() {
    echo -e "${COLOR_BRIGHT_RED}✗ ERROR:${COLOR_RESET} $1" >&2
}

# Print warning message
print_warning() {
    echo -e "${COLOR_YELLOW}⚠ WARNING:${COLOR_RESET} $1" >&2
}

# Print success message
print_success() {
    echo -e "${COLOR_BRIGHT_GREEN}✓ SUCCESS:${COLOR_RESET} $1"
}

# Print info message
print_info() {
    echo -e "${COLOR_BLUE}ℹ INFO:${COLOR_RESET} $1"
}

# Print finding card
print_finding_card() {
    local severity="$1"
    local confidence="$2"
    local vulnerability="$3"
    local evidence="$4"
    local details="$5"
    
    local severity_color=$(severity_color "$severity")
    local confidence_color=$(confidence_color "$confidence")
    
    # Top border
    echo -e "${COLOR_WHITE}┌────────────────────────────────────────────────────────────────┐${COLOR_RESET}"
    
    # Header
    printf "${COLOR_WHITE}│${COLOR_RESET} ${severity_color}%-8s${COLOR_RESET} ${COLOR_WHITE}│${COLOR_RESET} ${confidence_color}[${confidence}%]${COLOR_RESET} ${COLOR_BOLD}$vulnerability${COLOR_RESET}\n"
    
    # Divider
    echo -e "${COLOR_WHITE}├────────────────────────────────────────────────────────────────┤${COLOR_RESET}"
    
    # Evidence
    if [[ -n "$evidence" ]]; then
        echo -e "${COLOR_WHITE}│${COLOR_RESET} ${COLOR_YELLOW}Evidence:${COLOR_RESET} $evidence"
    fi
    
    # Details
    if [[ -n "$details" ]]; then
        echo -e "${COLOR_WHITE}│${COLOR_RESET} ${COLOR_CYAN}Details:${COLOR_RESET} $details"
    fi
    
    # Bottom border
    echo -e "${COLOR_WHITE}└────────────────────────────────────────────────────────────────┘${COLOR_RESET}"
}

# Print summary table
print_summary_table() {
    local results_file="$1"
    
    # Header
    echo
    echo -e "${COLOR_BRIGHT_MAGENTA}${BOX_DOUBLE_HORIZONTAL}${BOX_T_TOP}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_T_BOTTOM}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_CORNER_BR}${COLOR_RESET}"
    
    # Column headers
    printf "${COLOR_BRIGHT_MAGENTA}${BOX_DOUBLE_VERTICAL}${COLOR_RESET} ${COLOR_BOLD}%-15s${COLOR_RESET} ${COLOR_BRIGHT_MAGENTA}${BOX_DOUBLE_VERTICAL}${COLOR_RESET} ${COLOR_BOLD}%-10s${COLOR_RESET} ${COLOR_BRIGHT_MAGENTA}${BOX_DOUBLE_VERTICAL}${COLOR_RESET} ${COLOR_BOLD}%-12s${COLOR_RESET} ${COLOR_BRIGHT_MAGENTA}${BOX_DOUBLE_VERTICAL}${COLOR_RESET} ${COLOR_BOLD}%-10s${COLOR_RESET} ${COLOR_BRIGHT_MAGENTA}${BOX_DOUBLE_VERTICAL}${COLOR_RESET}\n" "VULNERABILITY" "SEVERITY" "CONFIDENCE" "TARGET"
    
    # Separator
    echo -e "${COLOR_BRIGHT_MAGENTA}${BOX_T_LEFT}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_T_INTERSECTION}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_T_INTERSECTION}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_T_INTERSECTION}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_T_INTERSECTION}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_T_INTERSECTION}${BOX_DOUBLE_HORIZONTAL}${BOX_T_RIGHT}${COLOR_RESET}"
    
    # Results (would be populated by jq parsing)
    echo -e "${COLOR_BRIGHT_MAGENTA}${BOX_DOUBLE_VERTICAL}${COLOR_RESET} ${COLOR_WHITE}No findings${COLOR_RESET} $(printf ' %.0s' {1..7}) ${COLOR_BRIGHT_MAGENTA}${BOX_DOUBLE_VERTICAL}${COLOR_RESET} $(printf ' %.0s' {1..4}) ${COLOR_BRIGHT_MAGENTA}${BOX_DOUBLE_VERTICAL}${COLOR_RESET} $(printf ' %.0s' {1..6}) ${COLOR_BRIGHT_MAGENTA}${BOX_DOUBLE_VERTICAL}${COLOR_RESET} $(printf ' %.0s' {1..4}) ${COLOR_BRIGHT_MAGENTA}${BOX_DOUBLE_VERTICAL}${COLOR_RESET}"
    
    # Bottom border
    echo -e "${COLOR_BRIGHT_MAGENTA}${BOX_DOUBLE_CORNER_BL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_T_BOTTOM}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_T_BOTTOM}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_T_BOTTOM}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_T_BOTTOM}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_CORNER_BR}${COLOR_RESET}"
    echo
}