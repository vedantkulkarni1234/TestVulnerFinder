#!/bin/bash

# vm2 Sandbox Escape (CVE-2023-37466) Detection Module
# Node.js JavaScript sandbox escape vulnerability

# Main detection function
detect_vm2() {
    local target="$1"
    local stealth="$2"
    local callback_domain="$3"
    local results_file="$4"
    
    print_info "Running vm2 detection module"
    
    # Initialize confidence tracking
    local confidence_data
    confidence_data=$(init_confidence_tracking "$target" "vm2")
    
    # Collect detection signals
    confidence_data=$(collect_vm2_signals "$target" "$stealth" "$confidence_data")
    
    # Apply advanced correlation
    confidence_data=$(apply_advanced_correlation "vm2" "$confidence_data")
    
    # Calculate final confidence
    confidence_data=$(calculate_confidence "$confidence_data")
    
    # Validate for reporting
    if validate_final_confidence "$confidence_data"; then
        # Render finding
        render_vm2_finding "$confidence_data" "$results_file"
    else
        print_info "vm2: Below confidence threshold, not reporting"
    fi
}

# Collect vm2 specific signals
collect_vm2_signals() {
    local target="$1"
    local stealth="$2"
    local confidence_data="$3"
    
    # Signal 1: Node.js application fingerprint
    local nodejs_detected=false
    local response
    response=$(make_http_request "$target" "GET" "" "$stealth")
    
    # Check for Node.js in various places
    local nodejs_patterns=(
        "node"
        "Node"
        "Node.js"
        "express"
        "Express"
        "X-Powered-By.*Express"
        "X-Response-Time"
        "Server: cloudd"
        "Served-By"
    )
    
    for pattern in "${nodejs_patterns[@]}"; do
        if echo "$response" | grep -Eq "$pattern" 2>/dev/null; then
            confidence_data=$(add_confidence_signal "$confidence_data" "vm2_nodejs" 1.0 "vm2")
            nodejs_detected=true
            break
        fi
    done
    
    # Signal 2: vm2 library detection
    local vm2_detected=false
    
    # Check for vm2 library in various sources
    local vm2_patterns=(
        "vm2"
        "VM2"
        "require.*vm2"
        "import.*vm2"
        "sandbox"
        "Sandbox"
        "eval"
        "Function"
    )
    
    for pattern in "${vm2_patterns[@]}"; do
        if echo "$response" | grep -Eq "$pattern" 2>/dev/null; then
            confidence_data=$(add_confidence_signal "$confidence_data" "vm2_fingerprint" 1.0 "vm2")
            vm2_detected=true
            break
        fi
    done
    
    # Signal 3: Check for vulnerable vm2 versions
    local version_detected=false
    local vulnerable_versions=("3.9.0" "3.9.1" "3.9.2" "3.9.3" "3.9.4" "3.9.5" "3.9.6" "3.9.7" "3.9.8" "3.9.9" "3.9.10" "3.9.11" "3.9.12" "3.9.13" "3.9.14" "3.9.15" "3.9.16" "3.9.17" "3.9.18")
    
    # Check package.json or other sources for version
    local version_sources=(
        "/package.json"
        "/api/info"
        "/api/version"
        "/api/status"
    )
    
    for endpoint in "${version_sources[@]}"; do
        local version_url="${target%/}${endpoint}"
        local version_response
        version_response=$(make_http_request "$version_url" "GET" "" "$stealth")
        
        # Look for vm2 version in API responses
        if echo "$version_response" | grep -Eq "vm2|vm2.*[0-9]+\.[0-9]+" 2>/dev/null; then
            local found_version
            found_version=$(echo "$version_response" | grep -Eo "[0-9]+\.[0-9]+\.[0-9]+" | head -1)
            
            for vulnerable_version in "${vulnerable_versions[@]}"; do
                if [[ "$found_version" == "$vulnerable_version" || "$found_version" =~ ^$vulnerable_version\. ]]; then
                    confidence_data=$(add_confidence_signal "$confidence_data" "vm2_version_vulnerable" 1.0 "vm2")
                    version_detected=true
                    break 2
                fi
            done
        fi
    done
    
    # Signal 4: JavaScript API endpoints
    local js_api=false
    
    # Check for JavaScript processing endpoints
    local js_endpoints=(
        "/api/eval"
        "/api/execute"
        "/api/run"
        "/api/sandbox"
        "/eval"
        "/execute"
        "/run"
        "/sandbox"
        "/api/js"
        "/api/javascript"
        "/js"
        "/javascript"
    )
    
    for endpoint in "${js_endpoints[@]}"; do
        local js_url="${target%/}${endpoint}"
        local js_response
        js_response=$(make_full_request "$js_url" "GET" "" "$stealth")
        
        local status_code
        status_code=$(echo "$js_response" | jq -r '.status_code')
        
        # If endpoint exists, might process JavaScript
        if [[ ! "$status_code" =~ ^(404|410)$ ]]; then
            confidence_data=$(add_confidence_signal "$confidence_data" "vm2_js_api" 0.9 "vm2")
            js_api=true
            break
        fi
    done
    
    # Signal 5: Sandbox-related endpoints
    local sandbox_surface=false
    
    # Check for sandbox-related functionality
    local sandbox_endpoints=(
        "/api/sandbox"
        "/sandbox"
        "/api/code"
        "/code"
        "/api/snippet"
        "/snippet"
        "/api/repl"
        "/repl"
    )
    
    for endpoint in "${sandbox_endpoints[@]}";
    do
        local sandbox_url="${target%/}${endpoint}"
        local sandbox_response
        sandbox_response=$(make_full_request "$sandbox_url" "GET" "" "$stealth")
        
        local status_code
        status_code=$(echo "$sandbox_response" | jq -r '.status_code')
        
        # If endpoint exists, might be sandbox surface
        if [[ ! "$status_code" =~ ^(404|410)$ ]]; then
            confidence_data=$(add_confidence_signal "$confidence_data" "vm2_sandbox_escape" 1.0 "vm2")
            sandbox_surface=true
            break
        fi
    done
    
    # Signal 6: Error message analysis for vm2-specific errors
    local error_analysis=false
    
    # Try to trigger error pages that might reveal vm2 stack traces
    local error_endpoints=(
        "/error"
        "/404"
        "/500"
        "/eval/error"
        "/api/eval/error"
    )
    
    for endpoint in "${error_endpoints[@]}"; do
        local error_url="${target%/}${endpoint}"
        local error_response
        error_response=$(make_http_request "$error_url" "GET" "" "$stealth")
        
        # Look for vm2-specific error patterns
        if echo "$error_response" | grep -Eq "vm2|VM2|sandbox|Sandbox|eval|Function" 2>/dev/null; then
            confidence_data=$(add_confidence_signal "$confidence_data" "vm2_error_trace" 0.8 "vm2")
            error_analysis=true
            break
        fi
    done
    
    # Signal 7: Content-Type and Accept header analysis
    local content_type_handling=false
    
    # Check if application accepts JavaScript content types
    local accept_headers
    accept_headers=$(get_response_headers "$target" "GET" "" "$stealth")
    
    local js_content_types=(
        "application/javascript"
        "text/javascript"
        "application/json"
        "text/js"
        "application/ecmascript"
    )
    
    local accept_header
    accept_header=$(echo "$accept_headers" | jq -r '.Accept // .accept // ""')
    
    for content_type in "${js_content_types[@]}"; do
        if [[ -n "$accept_header" ]] && echo "$accept_header" | grep -q "$content_type" 2>/dev/null; then
            confidence_data=$(add_confidence_signal "$confidence_data" "vm2_content_type" 0.7 "vm2")
            content_type_handling=true
            break
        fi
    done
    
    # Signal 8: Security and isolation patterns
    local isolation=false
    
    # Look for security/isolation indicators
    local isolation_patterns=(
        "isolation"
        "restricted"
        "permission"
        "access-control"
        "cors"
        "origin"
    )
    
    for pattern in "${isolation_patterns[@]}"; do
        if echo "$response" | grep -Eq "$pattern" 2>/dev/null; then
            confidence_data=$(add_confidence_signal "$confidence_data" "vm2_isolation" 0.6 "vm2")
            isolation=true
            break
        fi
    done
    
    # Signal 9: Process and system access attempts
    local process_access=false
    
    # Look for process-related JavaScript patterns
    local process_patterns=(
        "process\."
        "global\."
        "__dirname"
        "__filename"
        "require"
        "import"
    )
    
    for pattern in "${process_patterns[@]}"; do
        if echo "$response" | grep -Eq "$pattern" 2>/dev/null; then
            confidence_data=$(add_confidence_signal "$confidence_data" "vm2_process_access" 0.8 "vm2")
            process_access=true
            break
        fi
    done
    
    # Signal 10: Code execution endpoints
    local code_execution=false
    
    # Check for endpoints that might execute code
    local code_endpoints=(
        "/api/exec"
        "/exec"
        "/api/cmd"
        "/cmd"
        "/api/system"
        "/system"
        "/api/shell"
        "/shell"
    )
    
    for endpoint in "${code_endpoints[@]}"; do
        local code_url="${target%/}${endpoint}"
        local code_response
        code_response=$(make_full_request "$code_url" "GET" "" "$stealth")
        
        local status_code
        status_code=$(echo "$code_response" | jq -r '.status_code')
        
        # If endpoint exists, might execute code
        if [[ ! "$status_code" =~ ^(404|410)$ ]]; then
            confidence_data=$(add_confidence_signal "$confidence_data" "vm2_code_execution" 0.9 "vm2")
            code_execution=true
            break
        fi
    done
    
    echo "$confidence_data"
}

# Test for vm2 sandbox escape indicators
test_vm2_escape() {
    local target="$1"
    local confidence_data="$2"
    
    # Test for vm2 processing without exploitation
    # Using safe JavaScript expressions that might reveal processing
    
    local test_endpoints=(
        "/api/eval"
        "/eval"
        "/api/sandbox"
        "/sandbox"
        "/api/execute"
        "/execute"
    )
    
    # Test with safe JavaScript expressions
    local test_payloads=(
        '1+1'
        '"test"'
        'console.log'
        'null'
        'undefined'
        '{}.constructor.name'
    )
    
    for endpoint in "${test_endpoints[@]}"; do
        local test_url="${target%/}${endpoint}"
        
        for payload in "${test_payloads[@]}"; do
            # Test with POST data
            local response
            response=$(make_http_request "$test_url" "POST" "$payload" "false")
            
            # Check for indicators of JavaScript processing
            if echo "$response" | grep -Eq "vm2|VM2|sandbox|Function|eval" 2>/dev/null; then
                confidence_data=$(add_confidence_signal "$confidence_data" "vm2_processing_behavior" 1.0 "vm2")
                break 2
            fi
            
            # Check for JavaScript evaluation indicators
            local status_code
            status_code=$(echo "$response" | jq -r '.status_code // 000')
            if [[ "$status_code" =~ ^(200|400|401)$ ]]; then
                confidence_data=$(add_confidence_signal "$confidence_data" "vm2_js_evaluation" 0.8 "vm2")
                break
            fi
        done
    done
    
    echo "$confidence_data"
}

# Render vm2 finding
render_vm2_finding() {
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
        evidence+="vm2 library detected; "
    fi
    if echo "$signals_detected" | grep -q "version_vulnerable"; then
        evidence+="Vulnerable vm2 version; "
    fi
    if echo "$signals_detected" | grep -q "sandbox_escape"; then
        evidence+="Sandbox escape surface detected; "
    fi
    if echo "$signals_detected" | grep -q "js_evaluation"; then
        evidence+="JavaScript evaluation endpoints detected"
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
    print_finding_card "$technical_severity" "$confidence" "vm2 Sandbox Escape (CVE-2023-37466)" "$evidence" "$explanation"
    
    # Save to results file
    local finding_data
    finding_data=$(cat << EOF
{
    "target": "$target",
    "vulnerability": "vm2 Sandbox Escape",
    "cve": "CVE-2023-37466",
    "severity": "$technical_severity",
    "confidence": $confidence,
    "level": "$level",
    "evidence": "$evidence",
    "explanation": $(echo "$explanation" | jq -Rs '.'),
    "timestamp": "$(date -Iseconds)",
    "category": "Remote Code Execution",
    "description": "Critical vm2 JavaScript sandbox escape vulnerability allowing arbitrary code execution through constructor manipulation and prototype poisoning."
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
export -f detect_vm2
export -f collect_vm2_signals
export -f test_vm2_escape
export -f render_vm2_finding