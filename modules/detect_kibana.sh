#!/bin/bash

# Kibana Prototype Pollution RCE (CVE-2019-7609) Detection Module
# Timelion canvas shell injection

# Main detection function
detect_kibana() {
    local target="$1"
    local stealth="$2"
    local callback_domain="$3"
    local results_file="$4"
    
    print_info "Running Kibana detection module"
    
    # Initialize confidence tracking
    local confidence_data
    confidence_data=$(init_confidence_tracking "$target" "kibana")
    
    # Collect detection signals
    confidence_data=$(collect_kibana_signals "$target" "$stealth" "$confidence_data")
    
    # Apply advanced correlation
    confidence_data=$(apply_advanced_correlation "kibana" "$confidence_data")
    
    # Calculate final confidence
    confidence_data=$(calculate_confidence "$confidence_data")
    
    # Validate for reporting
    if validate_final_confidence "$confidence_data"; then
        # Render finding
        render_kibana_finding "$confidence_data" "$results_file"
    else
        print_info "Kibana: Below confidence threshold, not reporting"
    fi
}

# Collect Kibana specific signals
collect_kibana_signals() {
    local target="$1"
    local stealth="$2"
    local confidence_data="$3"
    
    # Signal 1: Kibana application fingerprint
    local kibana_detected=false
    local response
    response=$(make_http_request "$target" "GET" "" "$stealth")
    
    # Check for Kibana in various places
    local kibana_patterns=(
        "kibana"
        "Kibana"
        "Elastic Kibana"
        "elasticsearch"
        "kibana\.yml"
        "kibana\.index"
        "x-pack"
    )
    
    for pattern in "${kibana_patterns[@]}"; do
        if echo "$response" | grep -Eq "$pattern" 2>/dev/null; then
            confidence_data=$(add_confidence_signal "$confidence_data" "kibana_fingerprint" 1.0 "kibana")
            kibana_detected=true
            break
        fi
    done
    
    # Signal 2: Check for vulnerable Kibana versions
    local version_detected=false
    local vulnerable_versions=("6.0.0" "6.0.1" "6.0.2" "6.0.3" "6.0.4" "6.1.0" "6.1.1" "6.1.2" "6.1.3" "6.1.4" "6.2.0" "6.2.1" "6.2.2" "6.2.3" "6.2.4" "6.3.0" "6.3.1" "6.3.2" "6.4.0" "6.4.1" "6.4.2" "6.4.3" "6.5.0" "6.5.1" "6.5.2" "6.5.3" "6.5.4" "6.6.0" "6.6.1")
    
    # Check for version in various places
    local server_headers
    server_headers=$(get_response_headers "$target" "GET" "" "$stealth")
    
    # Extract version from headers
    local kibana_version
    kibana_version=$(echo "$server_headers" | jq -r '.["Kbn-Version"] // .["kbn-version"] // .["kibana"] // ""' | grep -Eo "[0-9]+\.[0-9]+\.[0-9]+" || echo "")
    
    if [[ -n "$kibana_version" ]]; then
        for vulnerable_version in "${vulnerable_versions[@]}"; do
            if [[ "$kibana_version" == "$vulnerable_version" || "$kibana_version" =~ ^$vulnerable_version\. ]]; then
                confidence_data=$(add_confidence_signal "$confidence_data" "kibana_version_vulnerable" 1.0 "kibana")
                version_detected=true
                break
            fi
        done
    fi
    
    # Check common Kibana endpoints for version info
    local version_endpoints=(
        "/api/status"
        "/api/kibana/settings"
        "/app/kibana"
        "/app/canvas"
        "/status"
    )
    
    for endpoint in "${version_endpoints[@]}"; do
        local version_url="${target%/}${endpoint}"
        local version_response
        version_response=$(make_http_request "$version_url" "GET" "" "$stealth")
        
        # Look for Kibana version in API responses
        if echo "$version_response" | grep -Eq "kibana|kibana.*[0-9]+\.[0-9]+\.[0-9]+" 2>/dev/null; then
            local found_version
            found_version=$(echo "$version_response" | grep -Eo "[0-9]+\.[0-9]+\.[0-9]+" | head -1)
            
            for vulnerable_version in "${vulnerable_versions[@]}"; do
                if [[ "$found_version" == "$vulnerable_version" || "$found_version" =~ ^$vulnerable_version\. ]]; then
                    confidence_data=$(add_confidence_signal "$confidence_data" "kibana_version_vulnerable" 1.0 "kibana")
                    version_detected=true
                    break 2
                fi
            done
        fi
    done
    
    # Signal 3: Timelion endpoint detection
    local timelion_detected=false
    
    # Check for Timelion endpoint
    local timelion_endpoints=(
        "/timelion"
        "/app/timelion"
        "/api/timelion"
    )
    
    for endpoint in "${timelion_endpoints[@]}"; do
        local timelion_url="${target%/}${endpoint}"
        local timelion_response
        timelion_response=$(make_full_request "$timelion_url" "GET" "" "$stealth")
        
        local status_code
        status_code=$(echo "$timelion_response" | jq -r '.status_code')
        
        # Timelion should return 200 if accessible
        if [[ "$status_code" == "200" ]]; then
            confidence_data=$(add_confidence_signal "$confidence_data" "kibana_timelion" 1.0 "kibana")
            timelion_detected=true
            break
        fi
    done
    
    # Signal 4: Canvas endpoint detection
    local canvas_detected=false
    
    # Check for Canvas endpoint
    local canvas_endpoints=(
        "/app/canvas"
        "/api/canvas"
        "/canvas"
    )
    
    for endpoint in "${canvas_endpoints[@]}"; do
        local canvas_url="${target%/}${endpoint}"
        local canvas_response
        canvas_response=$(make_full_request "$canvas_url" "GET" "" "$stealth")
        
        local status_code
        status_code=$(echo "$canvas_response" | jq -r '.status_code')
        
        # Canvas should return 200 if accessible
        if [[ "$status_code" == "200" ]]; then
            confidence_data=$(add_confidence_signal "$confidence_data" "kibana_canvas" 0.9 "kibana")
            canvas_detected=true
            break
        fi
    done
    
    # Signal 5: Elasticsearch integration indicators
    local elasticsearch_detected=false
    
    # Check for Elasticsearch backend
    local elasticsearch_endpoints=(
        "/api/console/proxy"
        "/elasticsearch/"
        "/.kibana"
    )
    
    for endpoint in "${elasticsearch_endpoints[@]}"; do
        local es_url="${target%/}${endpoint}"
        local es_response
        es_response=$(make_full_request "$es_url" "GET" "" "$stealth")
        
        local status_code
        status_code=$(echo "$es_response" | jq -r '.status_code')
        
        # Elasticsearch endpoints should respond
        if [[ ! "$status_code" =~ ^(404|410)$ ]]; then
            confidence_data=$(add_confidence_signal "$confidence_data" "kibana_elasticsearch" 0.8 "kibana")
            elasticsearch_detected=true
            break
        fi
    done
    
    # Signal 6: X-Pack security features
    local xpack_detected=false
    
    # Check for X-Pack features
    local xpack_patterns=(
        "x-pack"
        "xpack"
        "License"
        "security"
        "watcher"
        "ml"
    )
    
    for pattern in "${xpack_patterns[@]}"; do
        if echo "$response" | grep -Eq "$pattern" 2>/dev/null; then
            confidence_data=$(add_confidence_signal "$confidence_data" "kibana_xpack" 0.6 "kibana")
            xpack_detected=true
            break
        fi
    done
    
    # Signal 7: Prototype pollution patterns in responses
    local prototype_pollution=false
    
    # Look for JavaScript prototype pollution indicators
    local js_patterns=(
        "__proto__"
        "prototype"
        "__constructor"
        "__proto__"
    )
    
    for pattern in "${js_patterns[@]}"; do
        if echo "$response" | grep -Eq "$pattern" 2>/dev/null; then
            confidence_data=$(add_confidence_signal "$confidence_data" "kibana_prototype_pollution" 1.0 "kibana")
            prototype_pollution=true
            break
        fi
    done
    
    # Signal 8: Error page analysis for Kibana-specific errors
    local error_analysis=false
    
    # Try to trigger error pages that might reveal Kibana stack traces
    local error_endpoints=(
        "/error"
        "/404"
        "/500"
        "/api/console/invalid"
        "/app/nonexistent"
    )
    
    for endpoint in "${error_endpoints[@]}"; do
        local error_url="${target%/}${endpoint}"
        local error_response
        error_response=$(make_http_request "$error_url" "GET" "" "$stealth")
        
        # Look for Kibana-specific error patterns
        if echo "$error_response" | grep -Eq "kibana|Kibana|elasticsearch|Elasticsearch" 2>/dev/null; then
            confidence_data=$(add_confidence_signal "$confidence_data" "kibana_error_trace" 0.8 "kibana")
            error_analysis=true
            break
        fi
    done
    
    echo "$confidence_data"
}

# Test for prototype pollution indicators
test_prototype_pollution() {
    local target="$1"
    local confidence_data="$2"
    
    # Test prototype pollution vectors without exploitation
    # Using safe expressions that indicate processing
    
    local test_endpoints=(
        "/api/console/proxy"
        "/timelion"
        "/app/canvas"
    )
    
    # Test with prototype pollution vectors
    local test_payloads=(
        '{"__proto__": {"admin": true}}'
        '{"constructor": {"prototype": {"admin": true}}}'
        '.es(*).label(__proto__="admin")'
    )
    
    for endpoint in "${test_endpoints[@]}"; do
        local test_url="${target%/}${endpoint}"
        
        for payload in "${test_payloads[@]}"; do
            # Test with POST data
            local response
            response=$(make_http_request "$test_url" "POST" "$payload" "false")
            
            # Check for indicators of prototype pollution processing
            if echo "$response" | grep -Eq "__proto__|prototype|constructor" 2>/dev/null; then
                confidence_data=$(add_confidence_signal "$confidence_data" "kibana_prototype_pollution_active" 1.0 "kibana")
                break 2
            fi
        done
    done
    
    echo "$confidence_data"
}

# Test for Timelion/Canvas shell injection points
test_shell_injection() {
    local target="$1"
    local confidence_data="$2"
    
    # Test for Timelion shell injection points
    local timelion_endpoints=(
        "/api/timelion"
        "/app/timelion"
    )
    
    # Test with safe expressions that might trigger processing
    local test_expressions=(
        ".es(1)"
        ".world(1)"
        ".info()"
        ".split()"
    )
    
    for endpoint in "${timelion_endpoints[@]}"; do
        local test_url="${target%/}${endpoint}"
        
        for expression in "${test_expressions[@]}"; do
            # Test with GET parameters
            local response
            response=$(make_http_request "${test_url}?input=${expression}" "GET" "" "false")
            
            # Check if Timelion expression was processed
            if echo "$response" | grep -Eq "timelion|Timelion|canvas|expression" 2>/dev/null; then
                confidence_data=$(add_confidence_signal "$confidence_data" "kibana_shell_injection_surface" 1.0 "kibana")
                break 2
            fi
        done
    done
    
    echo "$confidence_data"
}

# Render Kibana finding
render_kibana_finding() {
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
        evidence+="Kibana application detected; "
    fi
    if echo "$signals_detected" | grep -q "version_vulnerable"; then
        evidence+="Vulnerable Kibana version; "
    fi
    if echo "$signals_detected" | grep -q "timelion"; then
        evidence+="Timelion endpoint accessible; "
    fi
    if echo "$signals_detected" | grep -q "prototype_pollution"; then
        evidence+="Prototype pollution patterns detected"
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
    print_finding_card "$technical_severity" "$confidence" "Kibana Prototype Pollution RCE (CVE-2019-7609)" "$evidence" "$explanation"
    
    # Save to results file
    local finding_data
    finding_data=$(cat << EOF
{
    "target": "$target",
    "vulnerability": "Kibana Prototype Pollution RCE",
    "cve": "CVE-2019-7609",
    "severity": "$technical_severity",
    "confidence": $confidence,
    "level": "$level",
    "evidence": "$evidence",
    "explanation": $(echo "$explanation" | jq -Rs '.'),
    "timestamp": "$(date -Iseconds)",
    "category": "Remote Code Execution",
    "description": "Critical Kibana prototype pollution vulnerability in Timelion/Canvas functionality allowing remote code execution via prototype pollution and shell injection."
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
export -f detect_kibana
export -f collect_kibana_signals
export -f test_prototype_pollution
export -f test_shell_injection
export -f render_kibana_finding