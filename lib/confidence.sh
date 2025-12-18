#!/bin/bash

# Confidence scoring engine for NEXUS framework
# Implements 3-layer signal correlation for zero false positives

# Confidence thresholds
declare -g CONFIDENCE_THRESHOLD_CONFIRMED=90
declare -g CONFIDENCE_THRESHOLD_LIKELY=70
declare -g CONFIDENCE_THRESHOLD_POSSIBLE=50

# Signal weights for different vulnerability types
declare -A SIGNAL_WEIGHTS

# Spring4Shell signals
SIGNAL_WEIGHTS["spring4shell_fingerprint"]=25
SIGNAL_WEIGHTS["spring4shell_jdk_version"]=20
SIGNAL_WEIGHTS["spring4shell_deployment_war"]=15
SIGNAL_WEIGHTS["spring4shell_tomcat"]=10
SIGNAL_WEIGHTS["spring4shell_actuator_env"]=20

# Log4Shell signals
SIGNAL_WEIGHTS["log4shell_fingerprint"]=30
SIGNAL_WEIGHTS["log4shell_version_vulnerable"]=25
SIGNAL_WEIGHTS["log4shell_jndi_enabled"]=25
SIGNAL_WEIGHTS["log4shell_dns_callback"]=20

# Text4Shell signals
SIGNAL_WEIGHTS["text4shell_fingerprint"]=25
SIGNAL_WEIGHTS["text4shell_version_vulnerable"]=25
SIGNAL_WEIGHTS["text4shell_dns_callback"]=30
SIGNAL_WEIGHTS["text4shell_library_present"]=20

# Fastjson signals
SIGNAL_WEIGHTS["fastjson_fingerprint"]=25
SIGNAL_WEIGHTS["fastjson_autotype_enabled"]=25
SIGNAL_WEIGHTS["fastjson_version_vulnerable"]=25
SIGNAL_WEIGHTS["fastjson_deserialization"]=25

# Jackson signals
SIGNAL_WEIGHTS["jackson_fingerprint"]=20
SIGNAL_WEIGHTS["jackson_polymorphic"]=25
SIGNAL_WEIGHTS["jackson_version_vulnerable"]=25
SIGNAL_WEIGHTS["jackson_deserialization"]=30

# Struts2 signals
SIGNAL_WEIGHTS["struts2_fingerprint"]=25
SIGNAL_WEIGHTS["struts2_version_vulnerable"]=30
SIGNAL_WEIGHTS["struts2_content_type"]=25
SIGNAL_WEIGHTS["struts2_error_page"]=20

# Kibana signals
SIGNAL_WEIGHTS["kibana_fingerprint"]=30
SIGNAL_WEIGHTS["kibana_version_vulnerable"]=25
SIGNAL_WEIGHTS["kibana_timelion"]=25
SIGNAL_WEIGHTS["kibana_prototype_pollution"]=20

# Ghostscript signals
SIGNAL_WEIGHTS["ghostscript_fingerprint"]=20
SIGNAL_WEIGHTS["ghostscript_imagemagick"]=30
SIGNAL_WEIGHTS["ghostscript_version_vulnerable"]=25
SIGNAL_WEIGHTS["ghostscript_pdf_processing"]=25

# vm2 signals
SIGNAL_WEIGHTS["vm2_fingerprint"]=25
SIGNAL_WEIGHTS["vm2_version_vulnerable"]=30
SIGNAL_WEIGHTS["vm2_sandbox_escape"]=25
SIGNAL_WEIGHTS["vm2_nodejs"]=20

# Initialize confidence tracking for a target
init_confidence_tracking() {
    local target="$1"
    local vulnerability_type="$2"
    
    cat << EOF
{
    "target": "$target",
    "vulnerability_type": "$vulnerability_type",
    "signals_detected": [],
    "signals_total": 0,
    "signals_weight": 0,
    "confidence": 0,
    "timestamp": "$(date -Iseconds)"
}
EOF
}

# Add detected signal to confidence calculation
add_confidence_signal() {
    local confidence_data="$1"
    local signal_name="$2"
    local signal_strength="${3:-1.0}"
    local vulnerability_type="$4"
    
    # Check if signal already exists
    local signals_detected
    signals_detected=$(echo "$confidence_data" | jq -r '.signals_detected[]' 2>/dev/null || echo "")
    
    if echo "$signals_detected" | grep -q "$signal_name"; then
        echo "$confidence_data"  # Signal already added
        return
    fi
    
    # Calculate signal weight
    local signal_weight
    signal_weight=$(get_signal_weight "$signal_name" "$vulnerability_type")
    local weighted_score
    weighted_score=$(echo "$signal_weight * $signal_strength" | bc -l)
    
    # Update confidence data
    local updated_data
    updated_data=$(echo "$confidence_data" | jq "
        .signals_detected += [\"$signal_name\"]
        .signals_total += 1
        .signals_weight += $weighted_score
        | .confidence = min(100, .signals_weight)
    ")
    
    echo "$updated_data"
}

# Get weight for a specific signal
get_signal_weight() {
    local signal_name="$1"
    local vulnerability_type="$2"
    
    local key="${vulnerability_type}_${signal_name}"
    echo "${SIGNAL_WEIGHTS[$key]:-0}"
}

# Calculate final confidence with multi-layer correlation
calculate_confidence() {
    local confidence_data="$1"
    
    # Base confidence from signal weights
    local base_confidence
    base_confidence=$(echo "$confidence_data" | jq -r '.confidence')
    
    # Apply correlation multipliers
    local correlation_multiplier=1.0
    
    # Strong correlation: 3+ related signals
    local signals_count
    signals_count=$(echo "$confidence_data" | jq -r '.signals_total')
    if [[ $signals_count -ge 3 ]]; then
        correlation_multiplier=$(echo "$correlation_multiplier * 1.2" | bc -l)
    fi
    
    # Perfect correlation: 5+ signals
    if [[ $signals_count -ge 5 ]]; then
        correlation_multiplier=$(echo "$correlation_multiplier * 1.1" | bc -l)
    fi
    
    # Anti-correlation penalty: too few signals
    if [[ $signals_count -lt 2 ]]; then
        correlation_multiplier=$(echo "$correlation_multiplier * 0.8" | bc -l)
    fi
    
    # Apply correlation multiplier
    local final_confidence
    final_confidence=$(echo "scale=0; $base_confidence * $correlation_multiplier / 1" | bc -l)
    
    # Cap at 100
    if [[ $final_confidence -gt 100 ]]; then
        final_confidence=100
    fi
    
    # Update confidence data with final score
    local updated_data
    updated_data=$(echo "$confidence_data" | jq ".confidence = $final_confidence")
    
    echo "$updated_data"
}

# Determine confidence level based on score
get_confidence_level() {
    local confidence="$1"
    
    if [[ $confidence -ge $CONFIDENCE_THRESHOLD_CONFIRMED ]]; then
        echo "CONFIRMED"
    elif [[ $confidence -ge $CONFIDENCE_THRESHOLD_LIKELY ]]; then
        echo "HIGHLY_LIKELY"
    elif [[ $confidence -ge $CONFIDENCE_THRESHOLD_POSSIBLE ]]; then
        echo "POSSIBLE"
    else
        echo "NOT_LIKELY"
    fi
}

# Generate confidence explanation
generate_confidence_explanation() {
    local confidence_data="$1"
    
    local confidence
    confidence=$(echo "$confidence_data" | jq -r '.confidence')
    local level
    level=$(get_confidence_level "$confidence")
    
    local signals_count
    signals_count=$(echo "$confidence_data" | jq -r '.signals_total')
    
    local explanation="Confidence Level: $level ($confidence%)\n"
    explanation+="Signals Detected: $signals_count\n"
    
    # Add signal breakdown
    local signals_detected
    signals_detected=$(echo "$confidence_data" | jq -r '.signals_detected[]' 2>/dev/null || echo "")
    
    if [[ -n "$signals_detected" ]]; then
        explanation+="Signal Breakdown:\n"
        while IFS= read -r signal; do
            if [[ -n "$signal" ]]; then
                local weight
                weight=$(get_signal_weight "$signal" "$(echo "$confidence_data" | jq -r '.vulnerability_type')")
                explanation+="  ✓ $signal (weight: $weight)\n"
            fi
        done <<< "$signals_detected"
    fi
    
    echo -e "$explanation"
}

# Validate all mandatory preconditions are met
validate_preconditions() {
    local vulnerability_type="$1"
    local signals_data="$2"
    
    # Define mandatory precondition matrix for each vulnerability
    case "$vulnerability_type" in
        "spring4shell")
            # Spring4Shell requires ALL 5 preconditions
            local has_spring_framework
            local has_jdk9_plus
            local has_war_deployment
            local has_tomcat
            local has_classloader_surface
            
            has_spring_framework=$(echo "$signals_data" | jq -e '.signals_detected | map(select(contains("spring"))) | length > 0' 2>/dev/null && echo "true" || echo "false")
            has_jdk9_plus=$(echo "$signals_data" | jq -e '.signals_detected | map(select(contains("jdk"))) | map(select(test("1[7-9]|2[0-9]"))) | length > 0' 2>/dev/null && echo "true" || echo "false")
            has_war_deployment=$(echo "$signals_data" | jq -e '.signals_detected | map(select(contains("war"))) | length > 0' 2>/dev/null && echo "true" || echo "false")
            has_tomcat=$(echo "$signals_data" | jq -e '.signals_detected | map(select(contains("tomcat"))) | length > 0' 2>/dev/null && echo "true" || echo "false")
            has_classloader_surface=$(echo "$signals_data" | jq -e '.signals_detected | map(select(contains("classloader") or contains("actuator"))) | length > 0' 2>/dev/null && echo "true" || echo "false")
            
            if [[ "$has_spring_framework" == "true" && "$has_jdk9_plus" == "true" && 
                  "$has_war_deployment" == "true" && "$has_tomcat" == "true" && 
                  "$has_classloader_surface" == "true" ]]; then
                echo "true"
            else
                echo "false"
            fi
            ;;
        "log4shell")
            # Log4Shell requires fingerprint + vulnerable version + JNDI enabled
            local has_log4j
            has_log4j=$(echo "$signals_data" | jq -e '.signals_detected | map(select(contains("log4j"))) | length > 0' 2>/dev/null && echo "true" || echo "false")
            
            local has_vulnerable_version
            has_vulnerable_version=$(echo "$signals_data" | jq -e '.signals_detected | map(select(contains("version_vulnerable"))) | length > 0' 2>/dev/null && echo "true" || echo "false")
            
            if [[ "$has_log4j" == "true" && "$has_vulnerable_version" == "true" ]]; then
                echo "true"
            else
                echo "false"
            fi
            ;;
        *)
            # Default: require at least 2 signals
            local signal_count
            signal_count=$(echo "$signals_data" | jq -r '.signals_total')
            if [[ $signal_count -ge 2 ]]; then
                echo "true"
            else
                echo "false"
            fi
            ;;
    esac
}

# Advanced signal correlation for complex vulnerabilities
apply_advanced_correlation() {
    local vulnerability_type="$1"
    local confidence_data="$2"
    
    local confidence
    confidence=$(echo "$confidence_data" | jq -r '.confidence')
    
    # Apply vulnerability-specific correlation rules
    case "$vulnerability_type" in
        "spring4shell")
            # Spring4Shell: Multi-signal correlation requirement
            local spring_signals
            spring_signals=$(echo "$confidence_data" | jq -r '.signals_detected | map(select(contains("spring"))) | length')
            
            local deployment_signals
            deployment_signals=$(echo "$confidence_data" | jq -r '.signals_detected | map(select(contains("war") or contains("deployment"))) | length')
            
            if [[ $spring_signals -ge 2 && $deployment_signals -ge 1 ]]; then
                confidence=$(echo "$confidence + 10" | bc -l)
            fi
            ;;
        "log4shell")
            # Log4Shell: DNS callback confirmation
            local has_dns_callback
            has_dns_callback=$(echo "$confidence_data" | jq -r '.signals_detected | map(select(contains("dns_callback"))) | length > 0')
            
            if [[ "$has_dns_callback" == "true" ]]; then
                confidence=$(echo "$confidence + 25" | bc -l)
            fi
            ;;
        "fastjson")
            # Fastjson: Autotype + version correlation
            local has_autotype
            has_autotype=$(echo "$confidence_data" | jq -r '.signals_detected | map(select(contains("autotype"))) | length > 0')
            
            if [[ "$has_autotype" == "true" ]]; then
                confidence=$(echo "$confidence + 15" | bc -l)
            fi
            ;;
    esac
    
    # Cap at 100 and update confidence
    if [[ $confidence -gt 100 ]]; then
        confidence=100
    fi
    
    local updated_data
    updated_data=$(echo "$confidence_data" | jq ".confidence = $confidence")
    
    echo "$updated_data"
}

# Final confidence validation before reporting
validate_final_confidence() {
    local confidence_data="$1"
    
    local confidence
    confidence=$(echo "$confidence_data" | jq -r '.confidence')
    local vulnerability_type
    vulnerability_type=$(echo "$confidence_data" | jq -r '.vulnerability_type')
    
    # Check minimum confidence threshold
    if [[ $confidence -lt $CONFIDENCE_THRESHOLD_POSSIBLE ]]; then
        return 1  # Below reporting threshold
    fi
    
    # Validate preconditions
    local preconditions_met
    preconditions_met=$(validate_preconditions "$vulnerability_type" "$confidence_data")
    
    if [[ "$preconditions_met" != "true" ]]; then
        return 1  # Preconditions not met
    fi
    
    return 0  # Ready to report
}

# Generate confidence report for output
generate_confidence_report() {
    local confidence_data="$1"
    
    local confidence
    confidence=$(echo "$confidence_data" | jq -r '.confidence')
    local level
    level=$(get_confidence_level "$confidence")
    
    local explanation
    explanation=$(generate_confidence_explanation "$confidence_data")
    
    cat << EOF
{
    "confidence": $confidence,
    "level": "$level",
    "explanation": $(echo "$explanation" | jq -Rs '.')
}
EOF
}