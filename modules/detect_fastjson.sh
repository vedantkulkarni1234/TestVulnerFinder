#!/bin/bash

# Fastjson RCE (CVE-2017-18349 et al.) Detection Module
# Autotype enabled + polymorphic deserialization

# Main detection function
detect_fastjson() {
    local target="$1"
    local stealth="$2"
    local callback_domain="$3"
    local results_file="$4"
    
    print_info "Running Fastjson detection module"
    
    # Initialize confidence tracking
    local confidence_data
    confidence_data=$(init_confidence_tracking "$target" "fastjson")
    
    # Collect detection signals
    confidence_data=$(collect_fastjson_signals "$target" "$stealth" "$confidence_data")
    
    # Apply advanced correlation
    confidence_data=$(apply_advanced_correlation "fastjson" "$confidence_data")
    
    # Calculate final confidence
    confidence_data=$(calculate_confidence "$confidence_data")
    
    # Validate for reporting
    if validate_final_confidence "$confidence_data"; then
        # Render finding
        render_fastjson_finding "$confidence_data" "$results_file"
    else
        print_info "Fastjson: Below confidence threshold, not reporting"
    fi
}

# Collect Fastjson specific signals
collect_fastjson_signals() {
    local target="$1"
    local stealth="$2"
    local confidence_data="$3"
    
    # Signal 1: Fastjson library fingerprint
    local fastjson_detected=false
    local response
    response=$(make_http_request "$target" "GET" "" "$stealth")
    
    # Check for Fastjson in various places
    local fastjson_patterns=(
        "com.alibaba.fastjson"
        "fastjson"
        "FastJson"
        "alibaba.fastjson"
        "fastjson\.version"
    )
    
    for pattern in "${fastjson_patterns[@]}"; do
        if echo "$response" | grep -Eq "$pattern" 2>/dev/null; then
            confidence_data=$(add_confidence_signal "$confidence_data" "fastjson_fingerprint" 1.0 "fastjson")
            fastjson_detected=true
            break
        fi
    done
    
    # Signal 2: Check for vulnerable Fastjson versions
    local version_detected=false
    local vulnerable_versions=("1.2.0" "1.2.1" "1.2.2" "1.2.3" "1.2.4" "1.2.5" "1.2.6" "1.2.7" "1.2.8" "1.2.9" "1.2.10" "1.2.11" "1.2.12" "1.2.13" "1.2.14" "1.2.15" "1.2.16" "1.2.17" "1.2.18" "1.2.19" "1.2.20" "1.2.21" "1.2.22" "1.2.23" "1.2.24" "1.2.25" "1.2.26" "1.2.27" "1.2.28" "1.2.29" "1.2.30" "1.2.31" "1.2.32" "1.2.33" "1.2.34" "1.2.35" "1.2.36" "1.2.37" "1.2.38" "1.2.39" "1.2.40" "1.2.41" "1.2.42" "1.2.43" "1.2.44" "1.2.45" "1.2.46" "1.2.47")
    
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
        
        # Extract potential Fastjson versions
        local found_versions
        found_versions=$(echo "$version_response" | grep -Eo "[0-9]+\.[0-9]+\.[0-9]+" | sort -u)
        
        for version in $found_versions; do
            for vulnerable_version in "${vulnerable_versions[@]}"; do
                if [[ "$version" == "$vulnerable_version" || "$version" =~ ^$vulnerable_version\. ]]; then
                    confidence_data=$(add_confidence_signal "$confidence_data" "fastjson_version_vulnerable" 1.0 "fastjson")
                    version_detected=true
                    break 2
                fi
            done
        done
    done
    
    # Signal 3: JSON endpoint detection (potential deserialization surface)
    local json_endpoints=false
    
    # Common JSON API endpoints
    local json_api_patterns=(
        "/api/"
        "/rest/"
        "/json/"
        "/ws/"
        "/ajax/"
    )
    
    for pattern in "${json_api_patterns[@]}"; do
        local test_url="${target%/}${pattern}"
        local test_response
        test_response=$(make_full_request "$test_url" "GET" "" "$stealth")
        
        local status_code
        status_code=$(echo "$test_response" | jq -r '.status_code')
        
        # If endpoint exists and likely handles JSON
        if [[ "$status_code" =~ ^(200|400|401|404)$ ]]; then
            confidence_data=$(add_confidence_signal "$confidence_data" "fastjson_json_endpoint" 0.8 "fastjson")
            json_endpoints=true
            break
        fi
    done
    
    # Signal 4: Check for Java deserialization patterns
    local deserialization=false
    
    # Look for Java serialization indicators
    local java_patterns=(
        "java\."
        "ObjectInputStream"
        "ObjectOutputStream"
        "Serializable"
        "Externalizable"
    )
    
    for pattern in "${java_patterns[@]}"; do
        if echo "$response" | grep -Eq "$pattern" 2>/dev/null; then
            confidence_data=$(add_confidence_signal "$confidence_data" "fastjson_deserialization" 0.9 "fastjson")
            deserialization=true
            break
        fi
    done
    
    # Signal 5: Autotype feature detection (key vulnerability indicator)
    local autotype=false
    
    # Check for autotype-related configurations or patterns
    local autotype_patterns=(
        "autoTypeSupport"
        "AutoTypeSupport"
        "typeAction"
        "@type"
        "\"@type\""
    )
    
    for pattern in "${autotype_patterns[@]}"; do
        if echo "$response" | grep -Eq "$pattern" 2>/dev/null; then
            confidence_data=$(add_confidence_signal "$confidence_data" "fastjson_autotype_enabled" 1.0 "fastjson")
            autotype=true
            break
        fi
    done
    
    # Signal 6: Java version compatibility check
    local java_version="Unknown"
    local jdk_compatible=false
    
    # Try to get Java version from various sources
    local java_endpoints=(
        "/actuator/env"
        "/management/env"
        "/error"
    )
    
    for endpoint in "${java_endpoints[@]}"; do
        local java_url="${target%/}${endpoint}"
        local java_response
        java_response=$(make_http_request "$java_url" "GET" "" "$stealth")
        
        # Extract Java version
        if echo "$java_response" | grep -Eq "java\.version|jdk|java\.vm\.version" 2>/dev/null; then
            java_version=$(echo "$java_response" | grep -Eo "java\.version[^,}]*|\"java\.version\"[^,}]*" | grep -Eo "[0-9]+\.[0-9]+" | head -1)
            
            # Fastjson vulnerabilities typically affect Java 6+
            if [[ -n "$java_version" ]] && [[ "${java_version%%.*}" -ge 6 ]]; then
                confidence_data=$(add_confidence_signal "$confidence_data" "fastjson_java_compatible" 0.7 "fastjson")
                jdk_compatible=true
                break
            fi
        fi
    done
    
    echo "$confidence_data"
}

# Test for Fastjson deserialization indicators (without exploitation)
test_fastjson_indicators() {
    local target="$1"
    local confidence_data="$2"
    
    # Test JSON parsing behavior without actual exploitation
    local json_test_payloads=(
        '{"@type":"java.lang.String","val":"test"}'
        '{"@type":"java.util.HashMap","val":"test"}'
        '{"name":"test","value":"@type"}'
    )
    
    local json_endpoints=(
        "/api/login"
        "/api/user"
        "/login"
        "/search"
    )
    
    for endpoint in "${json_endpoints[@]}"; do
        local json_url="${target%/}${endpoint}"
        
        for payload in "${json_test_payloads[@]}"; do
            # Make request with JSON payload
            local response
            response=$(make_http_request "$json_url" "POST" "$payload" "false")
            
            # Check for indicators of JSON processing
            if echo "$response" | grep -Eq "@type|com\.alibaba\.fastjson|fastjson" 2>/dev/null; then
                confidence_data=$(add_confidence_signal "$confidence_data" "fastjson_parsing_behavior" 0.6 "fastjson")
                break 2
            fi
            
            # Check HTTP status codes that might indicate JSON parsing
            local status_code
            status_code=$(echo "$response" | jq -r '.status_code // 000')
            if [[ "$status_code" =~ ^(200|400|401|415)$ ]]; then
                confidence_data=$(add_confidence_signal "$confidence_data" "fastjson_json_parsing" 0.4 "fastjson")
                break
            fi
        done
    done
    
    echo "$confidence_data"
}

# Render Fastjson finding
render_fastjson_finding() {
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
        evidence+="Fastjson library detected; "
    fi
    if echo "$signals_detected" | grep -q "version_vulnerable"; then
        evidence+="Vulnerable Fastjson version; "
    fi
    if echo "$signals_detected" | grep -q "autotype_enabled"; then
        evidence+="Autotype feature enabled; "
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
    print_finding_card "$technical_severity" "$confidence" "Fastjson RCE (CVE-2017-18349)" "$evidence" "$explanation"
    
    # Save to results file
    local finding_data
    finding_data=$(cat << EOF
{
    "target": "$target",
    "vulnerability": "Fastjson RCE",
    "cve": "CVE-2017-18349",
    "severity": "$technical_severity",
    "confidence": $confidence,
    "level": "$level",
    "evidence": "$evidence",
    "explanation": $(echo "$explanation" | jq -Rs '.'),
    "timestamp": "$(date -Iseconds)",
    "category": "Remote Code Execution",
    "description": "Critical Fastjson autotype enabled deserialization RCE vulnerability allowing malicious object injection via polymorphic type handling."
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
export -f detect_fastjson
export -f collect_fastjson_signals
export -f test_fastjson_indicators
export -f render_fastjson_finding