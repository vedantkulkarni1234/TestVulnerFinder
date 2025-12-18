#!/bin/bash

# Color and formatting utilities for NEXUS framework

# Check if terminal supports 256 colors
supports_256_colors() {
    [[ -n "${TERM:-}" ]] && tput colors >/dev/null 2>&1 && [[ $(tput colors) -ge 256 ]]
}

# Color codes (256-color safe)
if supports_256_colors; then
    declare -g COLOR_BOLD='\033[1m'
    declare -g COLOR_DIM='\033[2m'
    declare -g COLOR_RED='\033[0;91m'
    declare -g COLOR_GREEN='\033[0;92m'
    declare -g COLOR_YELLOW='\033[0;93m'
    declare -g COLOR_BLUE='\033[0;94m'
    declare -g COLOR_MAGENTA='\033[0;95m'
    declare -g COLOR_CYAN='\033[0;96m'
    declare -g COLOR_WHITE='\033[0;97m'
    declare -g COLOR_BRIGHT_RED='\033[0;196m'
    declare -g COLOR_BRIGHT_GREEN='\033[0;46m'
    declare -g COLOR_BRIGHT_YELLOW='\033[0;226m'
    declare -g COLOR_BRIGHT_BLUE='\033[0;21m'
    declare -g COLOR_BRIGHT_MAGENTA='\033[0;201m'
    declare -g COLOR_BRIGHT_CYAN='\033[0;51m'
    declare -g COLOR_RESET='\033[0m'
    declare -g COLOR_BG_DARK='\033[48;5;16m'
else
    # Fallback to 16-color
    declare -g COLOR_BOLD='\033[1m'
    declare -g COLOR_DIM='\033[2m'
    declare -g COLOR_RED='\033[0;31m'
    declare -g COLOR_GREEN='\033[0;32m'
    declare -g COLOR_YELLOW='\033[0;33m'
    declare -g COLOR_BLUE='\033[0;34m'
    declare -g COLOR_MAGENTA='\033[0;35m'
    declare -g COLOR_CYAN='\033[0;36m'
    declare -g COLOR_WHITE='\033[0;37m'
    declare -g COLOR_BRIGHT_RED='\033[1;31m'
    declare -g COLOR_BRIGHT_GREEN='\033[1;32m'
    declare -g COLOR_BRIGHT_YELLOW='\033[1;33m'
    declare -g COLOR_BRIGHT_BLUE='\033[1;34m'
    declare -g COLOR_BRIGHT_MAGENTA='\033[1;35m'
    declare -g COLOR_BRIGHT_CYAN='\033[1;36m'
    declare -g COLOR_RESET='\033[0m'
    declare -g COLOR_BG_DARK='\033[40m'
fi

# Box drawing characters (Unicode)
declare -g BOX_HORIZONTAL='─'
declare -g BOX_VERTICAL='│'
declare -g BOX_CORNER_TL='┌'
declare -g BOX_CORNER_TR='┐'
declare -g BOX_CORNER_BL='└'
declare -g BOX_CORNER_BR='┘'
declare -g BOX_INTERSECTION='┼'
declare -g BOX_T_LEFT='├'
declare -g BOX_T_RIGHT='┤'
declare -g BOX_T_TOP='┬'
declare -g BOX_T_BOTTOM='┴'
declare -g BOX_DOUBLE_HORIZONTAL='═'
declare -g BOX_DOUBLE_VERTICAL='║'
declare -g BOX_DOUBLE_CORNER_TL='╔'
declare -g BOX_DOUBLE_CORNER_TR='╗'
declare -g BOX_DOUBLE_CORNER_BL='╚'
declare -g BOX_DOUBLE_CORNER_BR='╝'

# Utility functions
colorize() {
    local color="$1"
    shift
    echo -en "${color}$*${COLOR_RESET}"
}

# Severity color mapping
severity_color() {
    local severity="$1"
    case "$severity" in
        CRITICAL) echo "$COLOR_BRIGHT_RED" ;;
        HIGH) echo "$COLOR_RED" ;;
        MEDIUM) echo "$COLOR_YELLOW" ;;
        LOW) echo "$COLOR_COLOR_CYAN" ;;
        INFO) echo "$COLOR_BLUE" ;;
        *) echo "$COLOR_WHITE" ;;
    esac
}

# Confidence color mapping
confidence_color() {
    local confidence="$1"
    if [[ $confidence -ge 90 ]]; then
        echo "$COLOR_BRIGHT_RED"
    elif [[ $confidence -ge 70 ]]; then
        echo "$COLOR_RED"
    elif [[ $confidence -ge 50 ]]; then
        echo "$COLOR_YELLOW"
    else
        echo "$COLOR_CYAN"
    fi
}