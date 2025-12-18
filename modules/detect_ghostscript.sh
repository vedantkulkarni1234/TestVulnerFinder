#!/bin/bash

# Ghostscript RCE via ImageMagick (CVE-2018-16509) Detection Module
# Ghostscript -dSAFER bypass through PostScript injection

# Main detection function
detect_ghostscript() {
    local target="$1"
    local stealth="$2"
    local callback_domain="$3"
    local results_file="$4"
    
    print_info "Running Ghostscript detection module"
    
    # Initialize confidence tracking
    local confidence_data
    confidence_data=$(init_confidence_tracking "$target" "ghostscript")
    
    # Collect detection signals
    confidence_data=$(collect_ghostscript_signals "$target" "$stealth" "$confidence_data")
    
    # Apply advanced correlation
    confidence_data=$(apply_advanced_correlation "ghostscript" "$confidence_data")
    
    # Calculate final confidence
    confidence_data=$(calculate_confidence "$confidence_data")
    
    # Validate for reporting
    if validate_final_confidence "$confidence_data"; then
        # Render finding
        render_ghostscript_finding "$confidence_data" "$results_file"
    else
        print_info "Ghostscript: Below confidence threshold, not reporting"
    fi
}

# Collect Ghostscript specific signals
collect_ghostscript_signals() {
    local target="$1"
    local stealth="$2"
    local confidence_data="$3"
    
    # Signal 1: ImageMagick fingerprint
    local imagemagick_detected=false
    local response
    response=$(make_http_request "$target" "GET" "" "$stealth")
    
    # Check for ImageMagick in various places
    local imagemagick_patterns=(
        "ImageMagick"
        "imagick"
        "convert"
        "identify"
        "magick"
        "IM_MOD_*"
    )
    
    for pattern in "${imagemagick_patterns[@]}"; do
        if echo "$response" | grep -Eq "$pattern" 2>/dev/null; then
            confidence_data=$(add_confidence_signal "$confidence_data" "ghostscript_imagemagick" 1.0 "ghostscript")
            imagemagick_detected=true
            break
        fi
    done
    
    # Signal 2: Ghostscript library detection
    local ghostscript_detected=false
    
    # Check for Ghostscript in headers or responses
    local server_headers
    server_headers=$(get_response_headers "$target" "GET" "" "$stealth")
    
    # Look for Ghostscript in headers
    if echo "$server_headers" | jq -e '.Server' | grep -iE "ghostscript|gpl|afpl" >/dev/null 2>&1; then
        confidence_data=$(add_confidence_signal "$confidence_data" "ghostscript_fingerprint" 1.0 "ghostscript")
        ghostscript_detected=true
    fi
    
    # Check response body for Ghostscript indicators
    local ghostscript_patterns=(
        "ghostscript"
        "Ghostscript"
        "gs"
        "PostScript"
        "PDF"
        "Encapsulated PostScript"
    )
    
    for pattern in "${ghostscript_patterns[@]}"; do
        if echo "$response" | grep -Eq "$pattern" 2>/dev/null; then
            confidence_data=$(add_confidence_signal "$confidence_data" "ghostscript_fingerprint" 0.8 "ghostscript")
            ghostscript_detected=true
            break
        fi
    done
    
    # Signal 3: Check for vulnerable Ghostscript versions
    local version_detected=false
    local vulnerable_versions=("9.22" "9.23" "9.24" "9.25")
    
    # Extract version from various sources
    local found_versions
    found_versions=$(echo "$response" | grep -Eo "[0-9]+\.[0-9]+" | grep -E "^(9\.(22|23|24|25))" || echo "")
    
    if [[ -n "$found_versions" ]]; then
        confidence_data=$(add_confidence_signal "$confidence_data" "ghostscript_version_vulnerable" 1.0 "ghostscript")
        version_detected=true
    fi
    
    # Check for version in headers
    local server_version
    server_version=$(echo "$server_headers" | jq -r '.Server // ""' | grep -Eo "[0-9]+\.[0-9]+" | head -1)
    
    for vulnerable_version in "${vulnerable_versions[@]}"; do
        if [[ "$server_version" == "$vulnerable_version" || "$server_version" =~ ^$vulnerable_version\. ]]; then
            confidence_data=$(add_confidence_signal "$confidence_data" "ghostscript_version_vulnerable" 1.0 "ghostscript")
            version_detected=true
            break
        fi
    done
    
    # Signal 4: Image processing endpoint detection
    local image_processing=false
    
    # Check for image upload/processing endpoints
    local image_endpoints=(
        "/upload"
        "/api/upload"
        "/convert"
        "/api/convert"
        "/process"
        "/api/process"
        "/image"
        "/api/image"
    )
    
    for endpoint in "${image_endpoints[@]}"; do
        local image_url="${target%/}${endpoint}"
        local image_response
        image_response=$(make_full_request "$image_url" "GET" "" "$stealth")
        
        local status_code
        status_code=$(echo "$image_response" | jq -r '.status_code')
        
        # If endpoint responds, might be image processing service
        if [[ ! "$status_code" =~ ^(404|410)$ ]]; then
            confidence_data=$(add_confidence_signal "$confidence_data" "ghostscript_image_processing" 0.9 "ghostscript")
            image_processing=true
            break
        fi
    done
    
    # Signal 5: PDF processing indicators
    local pdf_processing=false
    
    # Check for PDF processing functionality
    local pdf_endpoints=(
        "/pdf"
        "/api/pdf"
        "/convert-to-pdf"
        "/generate-pdf"
    )
    
    for endpoint in "${pdf_endpoints[@]}"; do
        local pdf_url="${target%/}${endpoint}"
        local pdf_response
        pdf_response=$(make_full_request "$pdf_url" "GET" "" "$stealth")
        
        local status_code
        status_code=$(echo "$pdf_response" | jq -r '.status_code')
        
        # If endpoint exists, might process PDFs
        if [[ ! "$status_code" =~ ^(404|410)$ ]]; then
            confidence_data=$(add_confidence_signal "$confidence_data" "ghostscript_pdf_processing" 0.8 "ghostscript")
            pdf_processing=true
            break
        fi
    done
    
    # Signal 6: File format support indicators
    local file_formats=false
    
    # Check for support of various file formats that might be processed by Ghostscript
    local format_patterns=(
        "image/jpeg"
        "image/png"
        "image/gif"
        "image/tiff"
        "application/pdf"
        "image/svg+xml"
        "EPS"
        "PS"
        "PDF"
    )
    
    for pattern in "${format_patterns[@]}"; do
        if echo "$response" | grep -Eq "$pattern" 2>/dev/null; then
            confidence_data=$(add_confidence_signal "$confidence_data" "ghostscript_file_formats" 0.7 "ghostscript")
            file_formats=true
            break
        fi
    done
    
    # Signal 7: PostScript content type headers
    local postscript_headers=false
    
    # Check for PostScript-related content types
    if echo "$server_headers" | jq -e '.["Content-Type"]' | grep -iE "postscript|eps|ps" >/dev/null 2>&1; then
        confidence_data=$(add_confidence_signal "$confidence_data" "ghostscript_postscript" 1.0 "ghostscript")
        postscript_headers=true
    fi
    
    # Signal 8: Error page analysis for Ghostscript-specific errors
    local error_analysis=false
    
    # Try to trigger error pages that might reveal Ghostscript processing
    local error_endpoints=(
        "/error"
        "/404"
        "/500"
        "/upload/error"
        "/convert/error"
    )
    
    for endpoint in "${error_endpoints[@]}"; do
        local error_url="${target%/}${endpoint}"
        local error_response
        error_response=$(make_http_request "$error_url" "GET" "" "$stealth")
        
        # Look for Ghostscript-specific error patterns
        if echo "$error_response" | grep -Eq "ghostscript|Ghostscript|PostScript|eps|gs\." 2>/dev/null; then
            confidence_data=$(add_confidence_signal "$confidence_data" "ghostscript_error_trace" 0.8 "ghostscript")
            error_analysis=true
            break
        fi
    done
    
    # Signal 9: Command injection patterns in responses
    local command_injection=false
    
    # Look for command injection indicators in responses
    local cmd_patterns=(
        "\$\("
        "`"
        "system\("
        "exec\("
        "shell_exec"
    )
    
    for pattern in "${cmd_patterns[@]}"; do
        if echo "$response" | grep -Eq "$pattern" 2>/dev/null; then
            confidence_data=$(add_confidence_signal "$confidence_data" "ghostscript_command_injection" 0.9 "ghostscript")
            command_injection=true
            break
        fi
    done
    
    echo "$confidence_data"
}

# Test for Ghostscript processing indicators
test_ghostscript_processing() {
    local target="$1"
    local confidence_data="$2"
    
    # Test for Ghostscript processing without exploitation
    # Using safe test files and endpoints
    
    local test_endpoints=(
        "/upload"
        "/convert"
        "/api/upload"
        "/api/convert"
        "/process"
    )
    
    # Test with various image formats
    local test_formats=(
        "eps"
        "ps"
        "pdf"
        "svg"
    )
    
    for endpoint in "${test_endpoints[@]}"; do
        local test_url="${target%/}${endpoint}"
        
        for format in "${test_formats[@]}"; do
            # Test with format extension
            local response
            response=$(make_http_request "${test_url}/test.${format}" "GET" "" "false")
            
            # Check if format is processed
            if echo "$response" | grep -Eq "postscript|eps|ghostscript|PDF" 2>/dev/null; then
                confidence_data=$(add_confidence_signal "$confidence_data" "ghostscript_processing_format" 0.8 "ghostscript")
                break 2
            fi
        done
    done
    
    echo "$confidence_data"
}

# Render Ghostscript finding
render_ghostscript_finding() {
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
    if echo "$signals_detected" | grep -q "imagemagick"; then
        evidence+="ImageMagick detected; "
    fi
    if echo "$signals_detected" | grep -q "fingerprint"; then
        evidence+="Ghostscript library detected; "
    fi
    if echo "$signals_detected" | grep -q "version_vulnerable"; then
        evidence+="Vulnerable Ghostscript version; "
    fi
    if echo "$signals_detected" | grep -q "pdf_processing"; then
        evidence+="PDF processing functionality detected"
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
    print_finding_card "$technical_severity" "$confidence" "Ghostscript RCE (CVE-2018-16509)" "$evidence" "$explanation"
    
    # Save to results file
    local finding_data
    finding_data=$(cat << EOF
{
    "target": "$target",
    "vulnerability": "Ghostscript RCE via ImageMagick",
    "cve": "CVE-2018-16509",
    "severity": "$technical_severity",
    "confidence": $confidence,
    "level": "$level",
    "evidence": "$evidence",
    "explanation": $(echo "$explanation" | jq -Rs '.'),
    "timestamp": "$(date -Iseconds)",
    "category": "Remote Code Execution",
    "description": "Critical Ghostscript -dSAFER bypass vulnerability allowing PostScript injection and remote code execution through malicious image/PDF processing."
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
export -f detect_ghostscript
export -f collect_ghostscript_signals
export -f test_ghostscript_processing
export -f render_ghostscript_finding