#!/bin/bash

# Jackson Databind RCE (CVE-2019-12384 et al.) Detection Module
# Polymorphic type handling + gadget chain exploitation

# Main detection function
detect_jackson() {
    local target="$1"
    local stealth="$2"
    local callback_domain="$3"
    local results_file="$4"
    
    print_info "Running Jackson Databind detection module"
    
    # Initialize confidence tracking
    local confidence_data
    confidence_data=$(init_confidence_tracking "$target" "jackson")
    
    # Collect detection signals
    confidence_data=$(collect_jackson_signals "$target" "$stealth" "$confidence_data")
    
    # Apply advanced correlation
    confidence_data=$(apply_advanced_correlation "jackson" "$confidence_data")
    
    # Calculate final confidence
    confidence_data=$(calculate_confidence "$confidence_data")
    
    # Validate for reporting
    if validate_final_confidence "$confidence_data"; then
        # Render finding
        render_jackson_finding "$confidence_data" "$results_file"
    else
        print_info "Jackson: Below confidence threshold, not reporting"
    fi
}

# Collect Jackson specific signals
collect_jackson_signals() {
    local target="$1"
    local stealth="$2"
    local confidence_data="$3"
    
    # Signal 1: Jackson library fingerprint
    local jackson_detected=false
    local response
    response=$(make_http_request "$target" "GET" "" "$stealth")
    
    # Check for Jackson in various places
    local jackson_patterns=(
        "com\.fasterxml\.jackson"
        "jackson"
        "Jackson"
        "jackson\.databind"
        "ObjectMapper"
        "JsonMappingException"
    )
    
    for pattern in "${jackson_patterns[@]}"; do
        if echo "$response" | grep -Eq "$pattern" 2>/dev/null; then
            confidence_data=$(add_confidence_signal "$confidence_data" "jackson_fingerprint" 1.0 "jackson")
            jackson_detected=true
            break
        fi
    done
    
    # Signal 2: Check for vulnerable Jackson versions
    local version_detected=false
    local vulnerable_versions=("2.9.0" "2.9.1" "2.9.2" "2.9.3" "2.9.4" "2.9.5" "2.9.6" "2.9.7" "2.9.8" "2.9.9" "2.9.10" "2.10.0" "2.10.1" "2.10.2" "2.10.3" "2.10.4" "2.10.5")
    
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
        
        # Extract potential Jackson versions
        local found_versions
        found_versions=$(echo "$version_response" | grep -Eo "[0-9]+\.[0-9]+\.[0-9]+" | sort -u)
        
        for version in $found_versions; do
            for vulnerable_version in "${vulnerable_versions[@]}"; do
                if [[ "$version" == "$vulnerable_version" || "$version" =~ ^$vulnerable_version\. ]]; then
                    confidence_data=$(add_confidence_signal "$confidence_data" "jackson_version_vulnerable" 1.0 "jackson")
                    version_detected=true
                    break 2
                fi
            done
        done
    done
    
    # Signal 3: JSON API endpoints (potential deserialization surface)
    local json_api=false
    
    # Common JSON API endpoints
    local json_api_patterns=(
        "/api/"
        "/rest/"
        "/json/"
        "/ws/"
        "/ajax/"
        "/auth/"
    )
    
    for pattern in "${json_api_patterns[@]}"; do
        local test_url="${target%/}${pattern}"
        local test_response
        test_response=$(make_full_request "$test_url" "GET" "" "$stealth")
        
        local status_code
        status_code=$(echo "$test_response" | jq -r '.status_code')
        
        # If endpoint exists and likely handles JSON
        if [[ "$status_code" =~ ^(200|400|401|404)$ ]]; then
            confidence_data=$(add_confidence_signal "$confidence_data" "jackson_json_api" 0.8 "jackson")
            json_api=true
            break
        fi
    done
    
    # Signal 4: Polymorphic type handling detection
    local polymorphic=false
    
    # Look for polymorphic type handling patterns
    local polymorphic_patterns=(
        "@JsonTypeInfo"
        "JsonTypeInfo"
        "Polymorphic"
        "typeProperty"
        "defaultImpl"
        "include"
    )
    
    for pattern in "${polymorphic_patterns[@]}"; do
        if echo "$response" | grep -Eq "$pattern" 2>/dev/null; then
            confidence_data=$(add_confidence_signal "$confidence_data" "jackson_polymorphic" 1.0 "jackson")
            polymorphic=true
            break
        fi
    done
    
    # Signal 5: Java deserialization indicators
    local deserialization=false
    
    # Look for Java deserialization indicators
    local java_patterns=(
        "java\."
        "ObjectInputStream"
        "ObjectOutputStream"
        "Serializable"
        "Externalizable"
        "readObject"
        "writeObject"
    )
    
    for pattern in "${java_patterns[@]}"; do
        if echo "$response" | grep -Eq "$pattern" 2>/dev/null; then
            confidence_data=$(add_confidence_signal "$confidence_data" "jackson_deserialization" 0.9 "jackson")
            deserialization=true
            break
        fi
    done
    
    # Signal 6: Content-Type header analysis
    local content_type_handling=false
    
    # Check if application accepts JSON content types
    local accept_headers=(
        "application/json"
        "application/*+json"
        "text/json"
    )
    
    local server_headers
    server_headers=$(get_response_headers "$target" "GET" "" "$stealth")
    
    for accept_type in "${accept_headers[@]}"; do
        if echo "$server_headers" | jq -e ".Accept | select(contains(\"$accept_type\"))" >/dev/null 2>&1; then
            confidence_data=$(add_confidence_signal "$confidence_data" "jackson_content_type" 0.6 "jackson")
            content_type_handling=true
            break
        fi
    done
    
    # Signal 7: Error message analysis for Jackson-specific errors
    local error_analysis=false
    
    # Try to trigger error pages that might reveal Jackson stack traces
    local error_endpoints=(
        "/error"
        "/404"
        "/500"
        "/test-error"
    )
    
    for endpoint in "${error_endpoints[@]}"; do
        local error_url="${target%/}${endpoint}"
        local error_response
        error_response=$(make_http_request "$error_url" "GET" "" "$stealth")
        
        # Look for Jackson-specific error patterns
        if echo "$error_response" | grep -Eq "jackson|Jackson|JsonMapping|ObjectMapper" 2>/dev/null; then
            confidence_data=$(add_confidence_signal "$confidence_data" "jackson_error_trace" 0.8 "jackson")
            error_analysis=true
            break
        fi
    done
    
    echo "$confidence_data"
}

# Test for Jackson JSON processing indicators
test_jackson_indicators() {
    local target="$1"
    local confidence_data="$2"
    
    # Test JSON parsing behavior without actual exploitation
    local json_test_payloads=(
        '{"type":"java.lang.String","value":"test"}'
        '{"type":"java.util.HashMap","value":"test"}'
        '{"@class":"java.lang.String","value":"test"}'
        '["java.lang.String","test"]'
    )
    
    local json_endpoints=(
        "/api/login"
        "/api/user"
        "/api/auth"
        "/login"
        "/auth"
    )
    
    for endpoint in "${json_endpoints[@]}"; do
        local json_url="${target%/}${endpoint}"
        
        for payload in "${json_test_payloads[@]}"; do
            # Make request with JSON payload
            local response
            response=$(make_http_request "$json_url" "POST" "$payload" "false")
            
            # Check for indicators of Jackson processing
            if echo "$response" | grep -Eq "jackson|Jackson|ObjectMapper|JsonMapping" 2>/dev/null; then
                confidence_data=$(add_confidence_signal "$confidence_data" "jackson_processing_behavior" 0.7 "jackson")
                break 2
            fi
            
            # Check HTTP status codes that might indicate JSON parsing errors
            local status_code
            status_code=$(echo "$response" | jq -r '.status_code // 000')
            if [[ "$status_code" =~ ^(200|400|401|415|422)$ ]]; then
                confidence_data=$(add_confidence_signal "$confidence_data" "jackson_json_parsing" 0.5 "jackson")
                break
            fi
        done
    done
    
    echo "$confidence_data"
}

# Render Jackson finding
render_jackson_finding() {
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
        evidence+="Jackson library detected; "
    fi
    if echo "$signals_detected" | grep -q "version_vulnerable"; then
        evidence+="Vulnerable Jackson version; "
    fi
    if echo "$signals_detected" | grep -q "polymorphic"; then
        evidence+="Polymorphic type handling enabled; "
    fi
    if echo "$signals_detected" | grep -q "deserialization"; then
        evidence+="Java deserialization patterns detected"
    fi
    
    # Calculate technical severity
    local technical_severity="HIGH"
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
    print_finding_card "$technical_severity" "$confidence" "Jackson Databind RCE (CVE-2019-12384)" "$evidence" "$explanation"
    
    # Save to results file
    local finding_data
    finding_data=$(cat << EOF
{
    "target": "$target",
    "vulnerability": "Jackson Databind RCE",
    "cve": "CVE-2019-12384",
    "severity": "$technical_severity",
    "confidence": $confidence,
    "level": "$level",
    "evidence": "$evidence",
    "explanation": $(echo "$explanation" | jq -Rs '.'),
    "timestamp": "$(date -Iseconds)",
    "category": "Remote Code Execution",
    "description": "Critical Jackson Databind polymorphic type handling RCE vulnerability allowing gadget chain exploitation through malicious JSON deserialization."
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
export -f detect_jackson
export -f collect_jackson_signals
export -f test_jackson_indicators
export -f render_jackson_finding