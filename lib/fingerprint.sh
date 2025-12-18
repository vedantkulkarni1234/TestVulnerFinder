#!/bin/bash

# Universal technology fingerprinting for NEXUS framework

# Fingerprint database (tech signatures)
declare -A FINGERPRINT_SIGNATURES

# Web Server fingerprints
FINGERPRINT_SIGNATURES["apache"]="Server: Apache"
FINGERPRINT_SIGNATURES["nginx"]="Server: nginx"
FINGERPRINT_SIGNATURES["tomcat"]="Server: Apache-Coyote"
FINGERPRINT_SIGNATURES["jetty"]="Server: Jetty"
FINGERPRINT_SIGNATURES["undertow"]="Server: Undertow"

# Java Framework fingerprints  
FINGERPRINT_SIGNATURES["spring"]="X-Application-Context\|Spring-Version\|spring\.web\."
FINGERPRINT_SIGNATURES["struts2"]="Struts-Version\|X-Powered-By.*Struts"
FINGERPRINT_SIGNATURES["hibernate"]="HibernateSession\|HibernateStatistics"
FINGERPRINT_SIGNATURES["mybatis"]="MyBatis\|ibatis"

# Java Version detection
FINGERPRINT_SIGNATURES["jdk8"]="Java/1\.8\|java\.version.*1\.8"
FINGERPRINT_SIGNATURES["jdk11"]="Java/11\|java\.version.*11"
FINGERPRINT_SIGNATURES["jdk17"]="Java/17\|java\.version.*17"

# JavaScript/Node.js fingerprints
FINGERPRINT_SIGNATURES["nodejs"]="X-Powered-By.*Express\|Server: cloudd\|X-Served-By"
FINGERPRINT_SIGNATURES["express"]="X-Powered-By.*Express"
FINGERPRINT_SIGNATURES["react"]="react\|__NEXT_DATA__"
FINGERPRINT_SIGNATURES["vue"]="__VUE__\|vue"
FINGERPRINT_SIGNATURES["angular"]="__ngContext__\|angular"

# Library fingerprints
FINGERPRINT_SIGNATURES["jackson"]="com\.fasterxml\.jackson\|X-Jackson"
FINGERPRINT_SIGNATURES["fastjson"]="com\.alibaba\.fastjson\|fastjson"
FINGERPRINT_SIGNATURES["log4j"]="log4j\.version\|log4j\."
FINGERPRINT_SIGNATURES["logback"]="logback\."
FINGERPRINT_SIGNATURES["slf4j"]="slf4j\."

# Framework version patterns
FINGERPRINT_SIGNATURES["tomcat_version"]="Apache-Coyote/[0-9]\.[0-9]+"
FINGERPRINT_SIGNATURES["spring_version"]="Spring-Version: [0-9]+\.[0-9]+\.[0-9]+"
FINGERPRINT_SIGNATURES["log4j_version"]="log4j\.version: [0-9]+\.[0-9]+\.[0-9]+"

# Parse target URL and extract components
parse_targets() {
    local target="$1"
    
    # Handle file input
    if [[ "$target" == file:* ]]; then
        local file_path="${target#file:}"
        if [[ -f "$file_path" ]]; then
            cat "$file_path"
        fi
        return
    fi
    
    # Handle CIDR ranges with port specification
    if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+: ]]; then
        local cidr="${target%%:*}"
        local port_list="${target##*:}"
        local hosts
        hosts=$(nmap -sn "$cidr" -oG - 2>/dev/null | grep "Up" | awk '{print $2}' || true)
        
        for host in $hosts; do
            for port in $(echo "$port_list" | tr ',' '\n'); do
                echo "http://${host}:${port}"
            done
        done
        return
    fi
    
    # Handle CIDR without port specification
    if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+ ]]; then
        local cidr="$target"
        local hosts
        hosts=$(nmap -sn "$cidr" -oG - 2>/dev/null | grep "Up" | awk '{print $2}' || true)
        
        for host in $hosts; do
            for port in 80 443 8080 8443; do
                echo "http://${host}:${port}"
            done
        done
        return
    fi
    
    # Handle domain:port format
    if [[ "$target" =~ ^[a-zA-Z0-9.-]+:[0-9]+$ ]]; then
        echo "http://${target}"
        return
    fi
    
    # Handle domain or IP
    if [[ "$target" =~ ^https?:// ]]; then
        echo "$target"
    else
        echo "http://${target}"
    fi
}

# Perform technology fingerprinting
fingerprint_target() {
    local target="$1"
    local stealth="$2"
    
    # Make initial request to get basic headers
    local response_headers
    response_headers=$(get_response_headers "$target" "GET" "" "$stealth")
    
    # Extract key information
    local server_header
    server_header=$(echo "$response_headers" | jq -r '.Server // ""')
    
    local content_type
    content_type=$(echo "$response_headers" | jq -r '.["Content-Type"] // ""')
    
    local powered_by
    powered_by=$(echo "$response_headers" | jq -r '.["X-Powered-By"] // ""')
    
    local framework_context
    framework_context=$(echo "$response_headers" | jq -r '.["X-Application-Context"] // ""')
    
    # Try to get HTML body for additional fingerprinting
    local response_body
    response_body=$(make_http_request "$target" "GET" "" "$stealth")
    
    # Build fingerprint result
    local result="{"
    result+='"target": "'"$target"'",'
    result+='"server": "'"$server_header"'",'
    result+='"content_type": "'"$content_type"'",'
    result+='"powered_by": "'"$powered_by"'",'
    result+='"framework_context": "'"$framework_context"'",'
    result+='"technologies": []'
    
    # Check for technology signatures
    local technologies=()
    
    # Check each signature
    for tech in "${!FINGERPRINT_SIGNATURES[@]}"; do
        local pattern="${FINGERPRINT_SIGNATURES[$tech]}"
        
        # Check headers first
        if echo "$response_headers" | jq -e "to_entries | map(select(.key == \"$tech\")) | length" >/dev/null 2>&1; then
            technologies+=("$tech")
            continue
        fi
        
        # Check individual header fields
        if echo "$server_header" | grep -Eq "$pattern" 2>/dev/null; then
            technologies+=("$tech")
            continue
        fi
        
        if echo "$powered_by" | grep -Eq "$pattern" 2>/dev/null; then
            technologies+=("$tech")
            continue
        fi
        
        if echo "$framework_context" | grep -Eq "$pattern" 2>/dev/null; then
            technologies+=("$tech")
            continue
        fi
        
        # Check response body for patterns
        if echo "$response_body" | grep -Eq "$pattern" 2>/dev/null; then
            technologies+=("$tech")
            continue
        fi
    done
    
    # Add technologies to result
    if [[ ${#technologies[@]} -gt 0 ]]; then
        local tech_json=$(printf '"%s",' "${technologies[@]}")
        tech_json="${tech_json%,}"  # Remove trailing comma
        result="${result%,}"  # Remove trailing comma
        result+=',"technologies": ['"$tech_json"']'
    fi
    
    result+="}"
    echo "$result"
}

# Extract specific version information
extract_version_info() {
    local target="$1"
    local technology="$2"
    local stealth="$3"
    
    local response
    response=$(make_http_request "$target" "GET" "" "$stealth")
    
    case "$technology" in
        "spring")
            echo "$response" | grep -Eo "Spring-Version: [0-9]+\.[0-9]+\.[0-9]+" | cut -d' ' -f2
            echo "$response" | grep -Eo "spring\.web\.context-path.*[0-9]+\.[0-9]+\.[0-9]+" | grep -Eo "[0-9]+\.[0-9]+\.[0-9]+" | head -1
            ;;
        "log4j")
            echo "$response" | grep -Eo "log4j\.version: [0-9]+\.[0-9]+\.[0-9]+" | cut -d' ' -f2
            echo "$response" | grep -Eo "log4j.*[0-9]+\.[0-9]+\.[0-9]+" | grep -Eo "[0-9]+\.[0-9]+\.[0-9]+" | head -1
            ;;
        "tomcat")
            echo "$response" | grep -Eo "Apache-Coyote/[0-9]+\.[0-9]+" | cut -d'/' -f2
            ;;
        *)
            echo ""
            ;;
    esac
}

# Check for specific Java versions via actuator endpoints
check_java_version_actuator() {
    local target="$1"
    local stealth="$2"
    
    # Common Spring Boot actuator endpoints
    local actuator_endpoints=(
        "/actuator"
        "/actuator/env"
        "/actuator/info"
        "/management"
        "/management/env"
    )
    
    for endpoint in "${actuator_endpoints[@]}"; do
        local url="${target%/}${endpoint}"
        local response
        response=$(make_http_request "$url" "GET" "" "$stealth")
        
        if echo "$response" | grep -q "java.version\|jdk\|java.vm.version" 2>/dev/null; then
            echo "$response" | grep -Eo "java\.version[^,}]*" | cut -d'"' -f3
            echo "$response" | grep -Eo "java\.vm\.version[^,}]*" | cut -d'"' -f3
            return 0
        fi
    done
    
    return 1
}

# Detect deployment type (WAR vs JAR)
detect_deployment_type() {
    local target="$1"
    local stealth="$2"
    
    # Check for WAR deployment indicators
    local war_indicators=(
        "/WEB-INF/"
        "/META-INF/"
        "/classes/"
        "/lib/"
    )
    
    for indicator in "${war_indicators[@]}"; do
        local url="${target%/}${indicator}"
        local response
        response=$(make_http_request "$url" "GET" "" "$stealth")
        local status_code
        status_code=$(echo "$response" | jq -r '.status_code // 404')
        
        # 403 means directory exists but access denied (typical for WEB-INF)
        # 200 means accessible
        # 404 means doesn't exist
        if [[ "$status_code" == "403" ]] || [[ "$status_code" == "200" ]]; then
            echo "WAR"
            return 0
        fi
    done
    
    # Check for JAR deployment indicators
    local jar_indicators=(
        "/BOOT-INF/"
        "/org/springframework/boot/"
    )
    
    for indicator in "${jar_indicators[@]}"; do
        local url="${target%/}${indicator}"
        local response
        response=$(make_http_request "$url" "GET" "" "$stealth")
        local status_code
        status_code=$(echo "$response" | jq -r '.status_code // 404')
        
        if [[ "$status_code" == "200" ]] || [[ "$status_code" == "403" ]]; then
            echo "JAR"
            return 0
        fi
    done
    
    echo "UNKNOWN"
}

# Comprehensive target analysis
analyze_target() {
    local target="$1"
    local stealth="$2"
    
    # Fingerprint technologies
    local fingerprint
    fingerprint=$(fingerprint_target "$target" "$stealth")
    
    # Extract version info
    local java_version
    java_version=$(check_java_version_actuator "$target" "$stealth")
    
    # Detect deployment type
    local deployment_type
    deployment_type=$(detect_deployment_type "$target" "$stealth")
    
    # Build comprehensive analysis
    local analysis="{"
    analysis+='"fingerprint": '"$fingerprint"','
    analysis+='"java_version": "'"$java_version"'",'
    analysis+='"deployment_type": "'"$deployment_type"'",'
    analysis+='"timestamp": "'"$(date -Iseconds)"'"'
    analysis+="}"
    
    echo "$analysis"
}

# Cache fingerprint results for performance
get_cached_fingerprint() {
    local target="$1"
    local cache_key
    cache_key=$(echo "$target" | md5sum | cut -d' ' -f1)
    local cache_file="${NEXUS_CACHE_DIR}/${cache_key}.json"
    
    if [[ -f "$cache_file" ]]; then
        # Check if cache is less than 1 hour old
        local cache_age
        cache_age=$(($(date +%s) - $(stat -c %Y "$cache_file" 2>/dev/null || echo 0)))
        if [[ $cache_age -lt 3600 ]]; then
            cat "$cache_file"
            return 0
        fi
    fi
    
    return 1
}

# Save fingerprint to cache
save_fingerprint() {
    local target="$1"
    local fingerprint="$2"
    local cache_key
    cache_key=$(echo "$target" | md5sum | cut -d' ' -f1)
    local cache_file="${NEXUS_CACHE_DIR}/${cache_key}.json"
    
    echo "$fingerprint" > "$cache_file"
}