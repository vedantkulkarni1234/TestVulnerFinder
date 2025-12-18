#!/bin/bash

# Apache Struts 2 RCE (CVE-2017-5638) Detection Module
# OGNL injection via Content-Type header manipulation

# Main detection function
detect_struts2() {
    local target="$1"
    local stealth="$2"
    local callback_domain="$3"
    local results_file="$4"
    
    print_info "Running Struts2 detection module"
    
    # Initialize confidence tracking
    local confidence_data
    confidence_data=$(init_confidence_tracking "$target" "struts2")
    
    # Collect detection signals
    confidence_data=$(collect_struts2_signals "$target" "$stealth" "$confidence_data")
    
    # Apply advanced correlation
    confidence_data=$(apply_advanced_correlation "struts2" "$confidence_data")
    
    # Calculate final confidence
    confidence_data=$(calculate_confidence "$confidence_data")
    
    # Validate for reporting
    if validate_final_confidence "$confidence_data"; then
        # Render finding
        render_struts2_finding "$confidence_data" "$results_file"
    else
        print_info "Struts2: Below confidence threshold, not reporting"
    fi
}

# Collect Struts2 specific signals
collect_struts2_signals() {
    local target="$1"
    local stealth="$2"
    local confidence_data="$3"
    
    # Signal 1: Struts2 framework fingerprint
    local struts2_detected=false
    local response
    response=$(make_http_request "$target" "GET" "" "$stealth")
    
    # Check for Struts2 in various places
    local struts2_patterns=(
        "Struts-Version"
        "X-Powered-By.*Struts"
        "org\.apache\.struts"
        "struts2"
        "Struts2"
        "struts-tags"
    )
    
    for pattern in "${struts2_patterns[@]}"; do
        if echo "$response" | grep -Eq "$pattern" 2>/dev/null; then
            confidence_data=$(add_confidence_signal "$confidence_data" "struts2_fingerprint" 1.0 "struts2")
            struts2_detected=true
            break
        fi
    done
    
    # Signal 2: Check for vulnerable Struts2 versions
    local version_detected=false
    local vulnerable_versions=("2.3.5" "2.3.31" "2.5.0" "2.5.10")
    
    # Check for version in headers and response
    local server_headers
    server_headers=$(get_response_headers "$target" "GET" "" "$stealth")
    
    # Extract version from headers
    local struts_version
    struts_version=$(echo "$server_headers" | jq -r '.["Struts-Version"] // .["X-Powered-By"] // ""' | grep -Eo "[0-9]+\.[0-9]+(\.[0-9]+)?" || echo "")
    
    if [[ -n "$struts_version" ]]; then
        for vulnerable_version in "${vulnerable_versions[@]}"; do
            if [[ "$struts_version" == "$vulnerable_version" || "$struts_version" =~ ^$vulnerable_version\. ]]; then
                confidence_data=$(add_confidence_signal "$confidence_data" "struts2_version_vulnerable" 1.0 "struts2")
                version_detected=true
                break
            fi
        done
    fi
    
    # Check actuator/management endpoints for version info
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
        
        # Look for Struts2 version in management endpoints
        if echo "$version_response" | grep -Eq "struts2|Struts.*[0-9]+\.[0-9]+" 2>/dev/null; then
            local found_struts_version
            found_struts_version=$(echo "$version_response" | grep -Eo "Struts.*[0-9]+\.[0-9]+\.[0-9]+" | grep -Eo "[0-9]+\.[0-9]+\.[0-9]+" | head -1)
            
            for vulnerable_version in "${vulnerable_versions[@]}"; do
                if [[ "$found_struts_version" == "$vulnerable_version" || "$found_struts_version" =~ ^$vulnerable_version\. ]]; then
                    confidence_data=$(add_confidence_signal "$confidence_data" "struts2_version_vulnerable" 1.0 "struts2")
                    version_detected=true
                    break 2
                fi
            done
        fi
    done
    
    # Signal 3: OGNL expression patterns
    local ognl_patterns=false
    
    # Look for OGNL expressions in responses or error pages
    local ognl_indicators=(
        "#"
        "%{"
        "%{"
        "${"
        "\\$\\{"
        "ognl"
    )
    
    for indicator in "${ognl_indicators[@]}"; do
        if echo "$response" | grep -Eq "$indicator" 2>/dev/null; then
            confidence_data=$(add_confidence_signal "$confidence_data" "struts2_ognl_patterns" 1.0 "struts2")
            ognl_patterns=true
            break
        fi
    done
    
    # Signal 4: Content-Type header vulnerability assessment
    local content_type_vuln=false
    
    # Check if application accepts various content types (potential injection surface)
    local accept_headers
    accept_headers=$(get_response_headers "$target" "GET" "" "$stealth")
    
    local vulnerable_content_types=(
        "multipart/form-data"
        "application/x-www-form-urlencoded"
        "text/xml"
        "application/xml"
        "application/json"
        "text/plain"
    )
    
    local accept_header
    accept_header=$(echo "$accept_headers" | jq -r '.Accept // .accept // ""')
    
    for content_type in "${vulnerable_content_types[@]}"; do
        if [[ -n "$accept_header" ]] && echo "$accept_header" | grep -q "$content_type" 2>/dev/null; then
            confidence_data=$(add_confidence_signal "$confidence_data" "struts2_content_type" 1.0 "struts2")
            content_type_vuln=true
            break
        fi
    done
    
    # Signal 5: Struts2-specific URL patterns
    local struts2_urls=false
    
    # Common Struts2 URL patterns
    local struts2_patterns=(
        "/action/"
        "/struts/"
        "/.action"
        "/.do"
        "/!/"
    )
    
    for pattern in "${struts2_patterns[@]}"; do
        local test_url="${target%/}${pattern}test"
        local test_response
        test_response=$(make_full_request "$test_url" "GET" "" "$stealth")
        
        local status_code
        status_code=$(echo "$test_response" | jq -r '.status_code')
        
        # If endpoint responds (not 404), might be Struts2
        if [[ ! "$status_code" =~ ^(404|410)$ ]]; then
            confidence_data=$(add_confidence_signal "$confidence_data" "struts2_url_patterns" 0.8 "struts2")
            struts2_urls=true
            break
        fi
    done
    
    # Signal 6: Error page analysis for Struts2-specific errors
    local error_analysis=false
    
    # Try to trigger error pages that might reveal Struts2 stack traces
    local error_endpoints=(
        "/error"
        "/404"
        "/500"
        "/invalid.action"
        "/test.do"
    )
    
    for endpoint in "${error_endpoints[@]}"; do
        local error_url="${target%/}${endpoint}"
        local error_response
        error_response=$(make_http_request "$error_url" "GET" "" "$stealth")
        
        # Look for Struts2-specific error patterns
        if echo "$error_response" | grep -Eq "struts2|Struts|OGNL|Dispatcher" 2>/dev/null; then
            confidence_data=$(add_confidence_signal "$confidence_data" "struts2_error_page" 1.0 "struts2")
            error_analysis=true
            break
        fi
    done
    
    # Signal 7: HTTP Response header analysis
    local header_analysis=false
    
    # Check for specific Struts2 response headers
    if echo "$server_headers" | jq -e 'keys | contains(["Struts-Version", "X-Powered-By"])' >/dev/null 2>&1; then
        confidence_data=$(add_confidence_signal "$confidence_data" "struts2_headers" 0.9 "struts2")
        header_analysis=true
    fi
    
    echo "$confidence_data"
}

# Test for OGNL injection indicators (without exploitation)
test_ognl_injection() {
    local target="$1"
    local confidence_data="$2"
    
    # Test OGNL injection points without actual exploitation
    # Using benign expressions that won't cause harm but might reveal processing
    
    local ognl_test_payloads=(
        "%{2+2}"
        "%{1+1}"
        "#{2+2}"
    )
    
    local test_endpoints=(
        "/login.action"
        "/test.action"
        "/action/test"
        "/test.do"
    )
    
    for endpoint in "${test_endpoints[@]}"; do
        local test_url="${target%/}${endpoint}"
        
        # Test with custom Content-Type header containing OGNL
        for payload in "${ognl_test_payloads[@]}"; do
            # Use curl with custom Content-Type header
            local response
            response=$(curl -s -X POST \
                -H "Content-Type: %{(2+2)}multipart/form-data" \
                -H "User-Agent: ${NEXUS_USER_AGENT}" \
                "$test_url" 2>/dev/null || echo "")
            
            # Check if OGNL was processed (result might be 4 if calculation happened)
            if echo "$response" | grep -Eq "4|#response" 2>/dev/null; then
                confidence_data=$(add_confidence_signal "$confidence_data" "struts2_ognl_processing" 1.0 "struts2")
                break 2
            fi
        done
    done
    
    echo "$confidence_data"
}

# Render Struts2 finding
render_struts2_finding() {
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
        evidence+="Struts2 framework detected; "
    fi
    if echo "$signals_detected" | grep -q "version_vulnerable"; then
        evidence+="Vulnerable Struts2 version; "
    fi
    if echo "$signals_detected" | grep -q "content_type"; then
        evidence+="Vulnerable Content-Type handling; "
    fi
    if echo "$signals_detected" | grep -q "error_page"; then
        evidence+="Struts2 error traces detected"
    fi
    
    # Calculate technical severity
    local technical_severity="CRITICAL"
    if [[ $confidence -ge 95 ]]; then
        technical_severity="CRITICAL"
    elif [[ $confidence -ge 85 ]]; then
        technical_severity="CRITICAL"
    elif [[ $confidence -ge 70 ]]; then
        technical_severity="HIGH"
    else
        technical_severity="HIGH"
    fi
    
    # Render visual finding card
    print_finding_card "$technical_severity" "$confidence" "Apache Struts2 RCE (CVE-2017-5638)" "$evidence" "$explanation"
    
    # Save to results file
    local finding_data
    finding_data=$(cat << EOF
{
    "target": "$target",
    "vulnerability": "Apache Struts2 RCE",
    "cve": "CVE-2017-5638",
    "severity": "$technical_severity",
    "confidence": $confidence,
    "level": "$level",
    "evidence": "$evidence",
    "explanation": $(echo "$explanation" | jq -Rs '.'),
    "timestamp": "$(date -Iseconds)",
    "category": "Remote Code Execution",
    "description": "Critical Apache Struts2 OGNL injection RCE vulnerability allowing arbitrary code execution through malformed Content-Type headers."
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
export -f detect_struts2
export -f collect_struts2_signals
export -f test_ognl_injection
export -f render_struts2_finding