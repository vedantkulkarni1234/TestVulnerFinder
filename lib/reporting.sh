#!/bin/bash

# Final report generation for NEXUS framework
# Generates comprehensive vulnerability assessment reports

# Generate comprehensive final report
generate_final_report() {
    local results_file="$1"
    local output_format="$2"
    
    # Load and parse results
    local results_data
    results_data=$(cat "$results_file" 2>/dev/null || echo "[]")
    
    local total_findings
    total_findings=$(echo "$results_data" | jq '. | length')
    
    if [[ "$total_findings" == "0" ]]; then
        print_no_findings
    else
        # Generate summary statistics
        local summary_stats
        summary_stats=$(generate_summary_statistics "$results_data")
        
        # Generate detailed findings
        generate_detailed_findings "$results_data"
        
        # Generate summary table
        print_summary_table "$results_data"
        
        # Generate final statistics
        print_final_statistics "$summary_stats"
    fi
}

# Generate summary statistics
generate_summary_statistics() {
    local results_data="$1"
    
    local critical_count
    local high_count
    local medium_count
    local low_count
    
    critical_count=$(echo "$results_data" | jq '[.[] | select(.severity == "CRITICAL")] | length')
    high_count=$(echo "$results_data" | jq '[.[] | select(.severity == "HIGH")] | length')
    medium_count=$(echo "$results_data" | jq '[.[] | select(.severity == "MEDIUM")] | length')
    low_count=$(echo "$results_data" | jq '[.[] | select(.severity == "LOW")] | length')
    
    local confirmed_count
    local likely_count
    local possible_count
    
    confirmed_count=$(echo "$results_data" | jq '[.[] | select(.level == "CONFIRMED")] | length')
    likely_count=$(echo "$results_data" | jq '[.[] | select(.level == "HIGHLY_LIKELY")] | length')
    possible_count=$(echo "$results_data" | jq '[.[] | select(.level == "POSSIBLE")] | length')
    
    cat << EOF
{
    "total_findings": $(echo "$results_data" | jq '. | length'),
    "critical": $critical_count,
    "high": $high_count,
    "medium": $medium_count,
    "low": $low_count,
    "confirmed": $confirmed_count,
    "highly_likely": $likely_count,
    "possible": $possible_count
}
EOF
}

# Generate detailed findings display
generate_detailed_findings() {
    local results_data="$1"
    
    print_stage_header "VULNERABILITY FINDINGS"
    
    local findings_count
    findings_count=$(echo "$results_data" | jq '. | length')
    
    echo -e "${COLOR_CYAN}Found $findings_count potential vulnerabilities${COLOR_RESET}\n"
    
    # Process each finding
    local i=0
    while [[ $i -lt $findings_count ]]; do
        local finding
        finding=$(echo "$results_data" | jq -r ".[$i]")
        
        local vulnerability
        vulnerability=$(echo "$finding" | jq -r '.vulnerability')
        local cve
        cve=$(echo "$finding" | jq -r '.cve')
        local severity
        severity=$(echo "$finding" | jq -r '.severity')
        local confidence
        confidence=$(echo "$finding" | jq -r '.confidence')
        local evidence
        evidence=$(echo "$finding" | jq -r '.evidence')
        local explanation
        explanation=$(echo "$finding" | jq -r '.explanation')
        
        print_finding_card "$severity" "$confidence" "$vulnerability ($cve)" "$evidence" "$explanation"
        echo
        
        ((i++))
    done
}

# Print no findings message
print_no_findings() {
    print_stage_header "SCAN COMPLETE"
    
    echo -e "${COLOR_BRIGHT_GREEN}${BOX_DOUBLE_CORNER_TL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_CORNER_TR}${COLOR_RESET}"
    echo -e "${COLOR_BRIGHT_GREEN}${BOX_DOUBLE_VERTICAL}${COLOR_RESET} ${COLOR_BRIGHT_GREEN}NO CRITICAL VULNERABILITIES DETECTED${COLOR_RESET} $(printf ' %.0s' {1..5}) ${COLOR_BRIGHT_GREEN}${BOX_DOUBLE_VERTICAL}${COLOR_RESET}"
    echo -e "${COLOR_BRIGHT_GREEN}${BOX_DOUBLE_CORNER_BL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_CORNER_BR}${COLOR_RESET}"
    echo
    echo -e "${COLOR_WHITE}Target(s) did not meet the strict confidence thresholds for${COLOR_RESET}"
    echo -e "${COLOR_WHITE}zero-false-positive vulnerability reporting.${COLOR_RESET}"
    echo
    echo -e "${COLOR_DIM}This indicates either:${COLOR_RESET}"
    echo -e "${COLOR_DIM}• No vulnerabilities present${COLOR_RESET}"
    echo -e "${COLOR_DIM}• Vulnerabilities below detection threshold${COLOR_RESET}"
    echo -e "${COLOR_DIM}• Target employing security controls${COLOR_RESET}"
    echo
}

# Print comprehensive summary table
print_summary_table() {
    local results_data="$1"
    
    print_stage_header "VULNERABILITY SUMMARY"
    
    # Enhanced header
    echo -e "${COLOR_BRIGHT_MAGENTA}${BOX_DOUBLE_HORIZONTAL}${BOX_T_TOP}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_T_BOTTOM}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_T_BOTTOM}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_CORNER_BR}${COLOR_RESET}"
    
    # Column headers
    printf "${COLOR_BRIGHT_MAGENTA}${BOX_DOUBLE_VERTICAL}${COLOR_RESET} ${COLOR_BOLD}%-15s${COLOR_RESET} ${COLOR_BRIGHT_MAGENTA}${BOX_DOUBLE_VERTICAL}${COLOR_RESET} ${COLOR_BOLD}%-10s${COLOR_RESET} ${COLOR_BRIGHT_MAGENTA}${BOX_DOUBLE_VERTICAL}${COLOR_RESET} ${COLOR_BOLD}%-10s${COLOR_RESET} ${COLOR_BRIGHT_MAGENTA}${BOX_DOUBLE_VERTICAL}${COLOR_RESET} ${COLOR_BOLD}%-25s${COLOR_RESET} ${COLOR_BRIGHT_MAGENTA}${BOX_DOUBLE_VERTICAL}${COLOR_RESET}\n" "VULNERABILITY" "SEVERITY" "CONFIDENCE" "TARGET"
    
    # Separator
    echo -e "${COLOR_BRIGHT_MAGENTA}${BOX_T_LEFT}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_T_INTERSECTION}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_T_INTERSECTION}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_T_INTERSECTION}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_T_BOTTOM}${BOX_DOUBLE_HORIZONTAL}${BOX_T_BOTTOM}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_T_BOTTOM}${BOX_DOUBLE_HORIZONTAL}${BOX_T_RIGHT}${COLOR_RESET}"
    
    # Process findings
    local findings_count
    findings_count=$(echo "$results_data" | jq '. | length')
    
    local i=0
    while [[ $i -lt $findings_count ]]; do
        local finding
        finding=$(echo "$results_data" | jq -r ".[$i]")
        
        local vulnerability
        vulnerability=$(echo "$finding" | jq -r '.vulnerability')
        local cve
        cve=$(echo "$finding" | jq -r '.cve')
        local severity
        severity=$(echo "$finding" | jq -r '.severity')
        local confidence
        confidence=$(echo "$finding" | jq -r '.confidence')
        local target
        target=$(echo "$finding" | jq -r '.target')
        
        # Colorize severity and confidence
        local severity_color
        severity_color=$(severity_color "$severity")
        local confidence_color
        confidence_color=$(confidence_color "$confidence")
        
        printf "${COLOR_WHITE}${BOX_VERTICAL}${COLOR_RESET} ${COLOR_BOLD}%-15s${COLOR_RESET} ${COLOR_WHITE}${BOX_VERTICAL}${COLOR_RESET} ${severity_color}%-10s${COLOR_RESET} ${COLOR_WHITE}${BOX_VERTICAL}${COLOR_RESET} ${confidence_color}%-10s${COLOR_RESET} ${COLOR_WHITE}${BOX_VERTICAL}${COLOR_RESET} ${COLOR_CYAN}%-25s${COLOR_RESET} ${COLOR_WHITE}${BOX_VERTICAL}${COLOR_RESET}\n" "$vulnerability" "$severity" "${confidence}%" "$target"
        
        # Vulnerability details row
        printf "${COLOR_WHITE}${BOX_VERTICAL}${COLOR_RESET} ${COLOR_DIM}%-15s${COLOR_RESET} ${COLOR_WHITE}${BOX_VERTICAL}${COLOR_RESET} ${COLOR_DIM}%-10s${COLOR_RESET} ${COLOR_WHITE}${BOX_VERTICAL}${COLOR_RESET} ${COLOR_DIM}%-10s${COLOR_RESET} ${COLOR_WHITE}${BOX_VERTICAL}${COLOR_RESET} ${COLOR_DIM}%-25s${COLOR_RESET} ${COLOR_WHITE}${BOX_VERTICAL}${COLOR_RESET}\n" "$cve" "" "" "${target}"
        
        ((i++))
    done
    
    # Bottom border
    echo -e "${COLOR_BRIGHT_MAGENTA}${BOX_DOUBLE_CORNER_BL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_T_BOTTOM}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_T_BOTTOM}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_T_BOTTOM}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_T_BOTTOM}${BOX_DOUBLE_HORIZONTAL}${BOX_T_BOTTOM}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_HORIZONTAL}${BOX_T_BOTTOM}${BOX_DOUBLE_HORIZONTAL}${BOX_DOUBLE_CORNER_BR}${COLOR_RESET}"
}

# Print final statistics
print_final_statistics() {
    local summary_stats="$1"
    
    print_stage_header "SCAN STATISTICS"
    
    # Extract statistics
    local total_findings
    total_findings=$(echo "$summary_stats" | jq -r '.total_findings')
    local critical
    critical=$(echo "$summary_stats" | jq -r '.critical')
    local high
    high=$(echo "$summary_stats" | jq -r '.high')
    local medium
    medium=$(echo "$summary_stats" | jq -r '.medium')
    local low
    low=$(echo "$summary_stats" | jq -r '.low')
    local confirmed
    confirmed=$(echo "$summary_stats" | jq -r '.confirmed')
    local highly_likely
    highly_likely=$(echo "$summary_stats" | jq -r '.highly_likely')
    local possible
    possible=$(echo "$summary_stats" | jq -r '.possible')
    
    # Print statistics grid
    echo -e "${COLOR_WHITE}╔══════════════════════════════════════════════════════════════╗${COLOR_RESET}"
    echo -e "${COLOR_WHITE}║${COLOR_RESET} ${COLOR_BOLD}VULNERABILITY SEVERITY DISTRIBUTION${COLOR_RESET} $(printf ' %.0s' {1..20}) ${COLOR_WHITE}║${COLOR_RESET}"
    echo -e "${COLOR_WHITE}╠══════════════════════════════════════════════════════════════╣${COLOR_RESET}"
    echo -e "${COLOR_WHITE}║${COLOR_RESET} ${COLOR_BRIGHT_RED}CRITICAL:${COLOR_RESET} $critical $(printf ' %.0s' {1..30}) ${COLOR_WHITE}║${COLOR_RESET}"
    echo -e "${COLOR_WHITE}║${COLOR_RESET} ${COLOR_RED}HIGH:${COLOR_RESET} $high $(printf ' %.0s' {1..34}) ${COLOR_WHITE}║${COLOR_RESET}"
    echo -e "${COLOR_WHITE}║${COLOR_RESET} ${COLOR_YELLOW}MEDIUM:${COLOR_RESET} $medium $(printf ' %.0s' {1..32}) ${COLOR_WHITE}║${COLOR_RESET}"
    echo -e "${COLOR_WHITE}║${COLOR_RESET} ${COLOR_CYAN}LOW:${COLOR_RESET} $low $(printf ' %.0s' {1..35}) ${COLOR_WHITE}║${COLOR_RESET}"
    echo -e "${COLOR_WHITE}╠══════════════════════════════════════════════════════════════╣${COLOR_RESET}"
    echo -e "${COLOR_WHITE}║${COLOR_RESET} ${COLOR_BOLD}CONFIDENCE LEVEL DISTRIBUTION${COLOR_RESET} $(printf ' %.0s' {1..20}) ${COLOR_WHITE}║${COLOR_RESET}"
    echo -e "${COLOR_WHITE}╠══════════════════════════════════════════════════════════════╣${COLOR_RESET}"
    echo -e "${COLOR_WHITE}║${COLOR_RESET} ${COLOR_BRIGHT_RED}CONFIRMED (≥90%):${COLOR_RESET} $confirmed $(printf ' %.0s' {1..20}) ${COLOR_WHITE}║${COLOR_RESET}"
    echo -e "${COLOR_WHITE}║${COLOR_RESET} ${COLOR_RED}HIGHLY LIKELY (70-89%):${COLOR_RESET} $highly_likely $(printf ' %.0s' {1..12}) ${COLOR_WHITE}║${COLOR_RESET}"
    echo -e "${COLOR_WHITE}║${COLOR_RESET} ${COLOR_YELLOW}POSSIBLE (50-69%):${COLOR_RESET} $possible $(printf ' %.0s' {1..16}) ${COLOR_WHITE}║${COLOR_RESET}"
    echo -e "${COLOR_WHITE}╚══════════════════════════════════════════════════════════════╝${COLOR_RESET}"
    
    # Risk assessment
    echo
    local risk_level="LOW"
    if [[ $critical -gt 0 ]]; then
        risk_level="CRITICAL"
    elif [[ $high -gt 0 ]]; then
        risk_level="HIGH"
    elif [[ $medium -gt 0 ]]; then
        risk_level="MEDIUM"
    fi
    
    local risk_color
    case "$risk_level" in
        "CRITICAL") risk_color="$COLOR_BRIGHT_RED" ;;
        "HIGH") risk_color="$COLOR_RED" ;;
        "MEDIUM") risk_color="$COLOR_YELLOW" ;;
        "LOW") risk_color="$COLOR_BRIGHT_GREEN" ;;
        *) risk_color="$COLOR_WHITE" ;;
    esac
    
    echo -e "${COLOR_WHITE}Overall Risk Assessment: ${risk_color}${BOLD}$risk_level${COLOR_RESET}"
    echo
    
    # Completion timestamp
    echo -e "${COLOR_DIM}Scan completed at: $(date)${COLOR_RESET}"
    echo -e "${COLOR_DIM}Framework: NEXUS v${VERSION}${COLOR_RESET}"
    echo -e "${COLOR_DIM}Zero-False-Positive Detection Methodology${COLOR_RESET}"
}

# Export function for main script
export -f generate_final_report
export -f generate_summary_statistics
export -f generate_detailed_findings
export -f print_no_findings
export -f print_summary_table
export -f print_final_statistics