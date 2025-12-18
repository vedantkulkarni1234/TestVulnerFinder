#!/bin/bash

# Spring4Shell (CVE-2022-22965) Detection Module
# Strict precondition matrix for zero false positives

# Main detection function
detect_spring4shell() {
    local target="$1"
    local stealth="$2"
    local callback_domain="$3"
    local results_file="$4"
    
    print_info "Running Spring4Shell detection module"
    
    # Initialize confidence tracking
    local confidence_data
    confidence_data=$(init_confidence_tracking "$target" "spring4shell")
    
    # Collect detection signals
    confidence_data=$(collect_spring4shell_signals "$target" "$stealth" "$confidence_data")
    
    # Apply advanced correlation
    confidence_data=$(apply_advanced_correlation "spring4shell" "$confidence_data")
    
    # Calculate final confidence
    confidence_data=$(calculate_confidence "$confidence_data")
    
    # Validate for reporting
    if validate_final_confidence "$confidence_data"; then
        # Render finding
        render_spring4shell_finding "$confidence_data" "$results_file"
    else
        print_info "Spring4Shell: Below confidence threshold, not reporting"
    fi
}

# Collect Spring4Shell specific signals
collect_spring4shell_signals() {
    local target="$1"
    local stealth="$2"
    local confidence_data="$3"
    
    # Signal 1: Spring Framework fingerprint
    local spring_detected=false
    local response
    response=$(make_http_request "$target" "GET" "" "$stealth")
    
    if echo "$response" | grep -Eq "Spring-Framework|SpringBoot|spring\.web\.|X-Application-Context" 2>/dev/null; then
        confidence_data=$(add_confidence_signal "$confidence_data" "spring4shell_fingerprint" 1.0 "spring4shell")
        spring_detected=true
    fi
    
    # Signal 2: JDK 9+ version confirmation
    local jdk_version="Unknown"
    local jdk_detected=false
    
    # Try actuator endpoints for version info
    local actuator_endpoints=(
        "/actuator/env"
        "/management/env" 
        "/env"
    )
    
    for endpoint in "${actuator_endpoints[@]}"; do
        local env_url="${target%/}${endpoint}"
        local env_response
        env_response=$(make_http_request "$env_url" "GET" "" "$stealth")
        
        if echo "$env_response" | grep -q "java.version\|jdk\|java.vm.version" 2>/dev/null; then
            jdk_version=$(echo "$env_response" | grep -Eo "java\.version[^\"]*\"|\"java\.version\"[^,}]*" | grep -Eo "[0-9]+\.[0-9]+" | head -1)
            
            # Check if JDK 9+ (major version >= 9)
            if [[ -n "$jdk_version" ]] && [[ "${jdk_version%%.*}" -ge 9 ]]; then
                confidence_data=$(add_confidence_signal "$confidence_data" "spring4shell_jdk_version" 1.0 "spring4shell")
                jdk_detected=true
                break
            fi
        fi
    done
    
    # Signal 3: WAR deployment confirmation
    local war_detected=false
    local war_indicators=(
        "/WEB-INF/"
        "/WEB-INF/web.xml"
        "/classes/"
        "/META-INF/"
    )
    
    for indicator in "${war_indicators[@]}"; do
        local war_url="${target%/}${indicator}"
        local war_response
        war_response=$(make_full_request "$war_url" "GET" "" "$stealth")
        
        local status_code
        status_code=$(echo "$war_response" | jq -r '.status_code')
        
        # 403 means directory exists but access denied (typical for WEB-INF)
        # 200 means accessible
        if [[ "$status_code" == "403" ]] || [[ "$status_code" == "200" ]]; then
            confidence_data=$(add_confidence_signal "$confidence_data" "spring4shell_deployment_war" 1.0 "spring4shell")
            war_detected=true
            break
        fi
    done
    
    # Signal 4: Apache Tomcat detection
    local tomcat_detected=false
    local server_header
    server_header=$(get_response_headers "$target" "GET" "" "$stealth" | jq -r '.Server // ""')
    
    if echo "$server_header" | grep -Eq "Apache-Coyote|Tomcat" 2>/dev/null; then
        confidence_data=$(add_confidence_signal "$confidence_data" "spring4shell_tomcat" 1.0 "spring4shell")
        tomcat_detected=true
    fi
    
    # Signal 5: ClassLoader manipulation surface (actuator endpoints)
    local actuator_detected=false
    local actuator_endpoints=(
        "/actuator"
        "/actuator/heapdump"
        "/actuator/loggers"
        "/actuator/mappings"
    )
    
    for endpoint in "${actuator_endpoints[@]}"; do
        local actuator_url="${target%/}${endpoint}"
        local actuator_response
        actuator_response=$(make_full_request "$actuator_url" "GET" "" "$stealth")
        
        local status_code
        status_code=$(echo "$actuator_response" | jq -r '.status_code')
        
        # Spring Boot actuator endpoints typically return 200 or 401/403, not 404
        if [[ "$status_code" =~ ^(200|401|403)$ ]]; then
            confidence_data=$(add_confidence_signal "$confidence_data" "spring4shell_actuator_env" 1.0 "spring4shell")
            actuator_detected=true
            break
        fi
    done
    
    echo "$confidence_data"
}

# Render Spring4Shell finding
render_spring4shell_finding() {
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
        evidence+="Spring Framework detected; "
    fi
    if echo "$signals_detected" | grep -q "jdk_version"; then
        evidence+="JDK 9+ confirmed; "
    fi
    if echo "$signals_detected" | grep -q "deployment_war"; then
        evidence+="WAR deployment confirmed; "
    fi
    if echo "$signals_detected" | grep -q "tomcat"; then
        evidence+="Apache Tomcat detected; "
    fi
    if echo "$signals_detected" | grep -q "actuator_env"; then
        evidence+="Spring Boot actuator endpoints accessible"
    fi
    
    # Calculate technical severity
    local technical_severity="HIGH"
    if [[ $confidence -ge 95 ]]; then
        technical_severity="CRITICAL"
    elif [[ $confidence -ge 85 ]]; then
        technical_severity="HIGH"
    else
        technical_severity="MEDIUM"
    fi
    
    # Render visual finding card
    print_finding_card "$technical_severity" "$confidence" "Spring4Shell (CVE-2022-22965)" "$evidence" "$explanation"
    
    # Save to results file
    local finding_data
    finding_data=$(cat << EOF
{
    "target": "$target",
    "vulnerability": "Spring4Shell",
    "cve": "CVE-2022-22965",
    "severity": "$technical_severity",
    "confidence": $confidence,
    "level": "$level",
    "evidence": "$evidence",
    "explanation": $(echo "$explanation" | jq -Rs '.'),
    "timestamp": "$(date -Iseconds)",
    "category": "Remote Code Execution",
    "description": "Spring Framework RCE vulnerability allowing arbitrary file upload and code execution via ClassLoader manipulation in Spring4Shell vulnerable applications."
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
export -f detect_spring4shell
export -f collect_spring4shell_signals
export -f render_spring4shell_finding