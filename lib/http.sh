#!/bin/bash

# HTTP request engine with stealth capabilities for NEXUS framework

# Global HTTP configuration
readonly NEXUS_HTTP_TIMEOUT=10
readonly NEXUS_HTTP_RETRIES=2
readonly NEXUS_STEALTH_DELAY=10

# HTTP headers for stealth mode
STEALTH_HEADERS=(
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
    "Accept-Language: en-US,en;q=0.5"
    "Accept-Encoding: gzip, deflate"
    "Connection: keep-alive"
    "Upgrade-Insecure-Requests: 1"
    "Sec-Fetch-Dest: document"
    "Sec-Fetch-Mode: navigate"
    "Sec-Fetch-Site: none"
    "Cache-Control: max-age=0"
)

# Regular headers
REGULAR_HEADERS=(
    "User-Agent: ${NEXUS_USER_AGENT:-Mozilla/5.0 (compatible; NEXUS/1.0)}"
    "Accept: */*"
)

# Make HTTP request with stealth options
make_http_request() {
    local url="$1"
    local method="${2:-GET}"
    local data="$3"
    local stealth="${4:-false}"
    local headers=()
    
    # Select header set
    if [[ "$stealth" == "true" ]]; then
        headers=("${STEALTH_HEADERS[@]}")
        # Add random delay in stealth mode
        sleep $((RANDOM % NEXUS_STEALTH_DELAY + 5))
    else
        headers=("${REGULAR_HEADERS[@]}")
    fi
    
    # Build curl command
    local curl_args=(
        "--silent" "--show-error" "--fail"
        "--connect-timeout" "$NEXUS_HTTP_TIMEOUT"
        "--max-time" "$((NEXUS_HTTP_TIMEOUT * 2))"
        "--location" "--location-trusted"
        "--user-agent" "${NEXUS_USER_AGENT:-NEXUS/1.0}"
        "--header" "X-NEXUS-Request: 1"
    )
    
    # Add method and data
    if [[ "$method" == "POST" ]]; then
        curl_args+=("--request" "POST" "--data" "$data")
    fi
    
    # Add custom headers
    for header in "${headers[@]}"; do
        curl_args+=("--header" "$header")
    done
    
    # Execute request
    local response
    response=$(curl "${curl_args[@]}" "$url" 2>/dev/null || true)
    
    echo "$response"
}

# Make HTTP request with full response details
make_full_request() {
    local url="$1"
    local method="${2:-GET}"
    local data="$3"
    local stealth="${4:-false}"
    
    # Temporary files for response
    local body_file=$(mktemp)
    local headers_file=$(mktemp)
    
    # Select header set
    local headers=()
    if [[ "$stealth" == "true" ]]; then
        headers=("${STEALTH_HEADERS[@]}")
        sleep $((RANDOM % NEXUS_STEALTH_DELAY + 5))
    else
        headers=("${REGULAR_HEADERS[@]}")
    fi
    
    # Build curl command for full response
    local curl_args=(
        "--silent" "--show-error"
        "--connect-timeout" "$NEXUS_HTTP_TIMEOUT"
        "--max-time" "$((NEXUS_HTTP_TIMEOUT * 2))"
        "--location" "--location-trusted"
        "--user-agent" "${NEXUS_USER_AGENT:-NEXUS/1.0}"
        "--write-out" "%{http_code}|%{content_type}|%{ssl_verify_result}|%{time_total}|%{size_download}"
        "--output" "$body_file"
        "--dump-header" "$headers_file"
    )
    
    # Add method and data
    if [[ "$method" == "POST" ]]; then
        curl_args+=("--request" "POST" "--data" "$data")
    fi
    
    # Add custom headers
    for header in "${headers[@]}"; do
        curl_args+=("--header" "$header")
    done
    
    # Execute request
    local response_info
    response_info=$(curl "${curl_args[@]}" "$url" 2>/dev/null || echo "000|unknown|0|0|0")
    
    # Parse response info
    local http_code="${response_info%%|*}"
    local remaining="${response_info#*|}"
    local content_type="${remaining%%|*}"; remaining="${remaining#*|}"
    local ssl_verify="${remaining%%|*}"; remaining="${remaining#*|}"
    local time_total="${remaining%%|*}"; remaining="${remaining#*|}"
    local size_download="${remaining}"
    
    # Read response body and headers
    local body
    local headers_content
    body=$(cat "$body_file" 2>/dev/null || echo "")
    headers_content=$(cat "$headers_file" 2>/dev/null || echo "")
    
    # Cleanup
    rm -f "$body_file" "$headers_file"
    
    # Return structured data
    cat << EOF
{
    "status_code": $http_code,
    "content_type": "$content_type",
    "ssl_verify": $ssl_verify,
    "time_total": $time_total,
    "size_download": $size_download,
    "headers": $(echo "$headers_content" | jq -Rs 'split("\n")[:-1] | map(select(length > 0))'),
    "body": $(echo "$body" | jq -Rs '.')
}
EOF
}

# Check if URL is reachable
check_url_reachable() {
    local url="$1"
    local stealth="$2"
    
    local response
    response=$(make_http_request "$url" "GET" "" "$stealth")
    
    if [[ $? -eq 0 ]] && [[ -n "$response" ]]; then
        return 0
    else
        return 1
    fi
}

# Extract HTTP response headers as JSON
get_response_headers() {
    local url="$1"
    local method="${2:-GET}"
    local data="$3"
    local stealth="${4:-false}"
    
    local headers_file=$(mktemp)
    
    # Select header set
    local headers=()
    if [[ "$stealth" == "true" ]]; then
        headers=("${STEALTH_HEADERS[@]}")
        sleep $((RANDOM % NEXUS_STEALTH_DELAY + 5))
    else
        headers=("${REGULAR_HEADERS[@]}")
    fi
    
    # Build curl command
    local curl_args=(
        "--silent" "--head"
        "--connect-timeout" "$NEXUS_HTTP_TIMEOUT"
        "--max-time" "$NEXUS_HTTP_TIMEOUT"
        "--location"
        "--user-agent" "${NEXUS_USER_AGENT:-NEXUS/1.0}"
        "--dump-header" "$headers_file"
    )
    
    # Add method and data for HEAD if needed
    if [[ "$method" == "POST" ]]; then
        curl_args+=("--request" "POST" "--data" "$data")
    fi
    
    # Add custom headers
    for header in "${headers[@]}"; do
        curl_args+=("--header" "$header")
    done
    
    # Execute request
    curl "${curl_args[@]}" "$url" >/dev/null 2>&1
    
    # Process headers
    local headers_processed
    headers_processed=$(cat "$headers_file" 2>/dev/null | jq -Rs 'split("\n")[:-1] | map(select(length > 0)) | map(split(": ")) | map({key: .[0], value: .[1]}) | from_entries' 2>/dev/null || echo '{}')
    
    # Cleanup
    rm -f "$headers_file"
    
    echo "$headers_processed"
}

# Perform DNS lookup for callback verification
dns_lookup() {
    local domain="$1"
    local record_type="${2:-A}"
    
    dig "$domain" "$record_type" +short +time=5 +tries=1 2>/dev/null || echo ""
}

# Test for DNS callback (for Log4Shell/Text4Shell verification)
test_dns_callback() {
    local callback_domain="$1"
    local timestamp="$2"
    
    # Generate unique callback subdomain
    local callback_subdomain
    callback_subdomain="${timestamp}.${callback_domain}"
    
    # Wait for potential DNS lookup
    sleep 15
    
    # Check for DNS lookup
    local dns_result
    dns_result=$(dns_lookup "$callback_subdomain")
    
    if [[ -n "$dns_result" ]]; then
        return 0  # Callback detected
    else
        return 1  # No callback
    fi
}

# Parse target URL and extract components
parse_target_url() {
    local target="$1"
    
    # Handle file input
    if [[ "$target" == file:* ]]; then
        local file_path="${target#file:}"
        if [[ -f "$file_path" ]]; then
            cat "$file_path"
        fi
        return
    fi
    
    # Handle CIDR ranges
    if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+ ]]; then
        local cidr="$target"
        local port_list="${target##*:}"
        if [[ "$port_list" == "$target" ]]; then
            port_list="80,443,8080,8443"
        fi
        
        # Use nmap to enumerate hosts
        local hosts
        hosts=$(nmap -sn "$cidr" -oG - | grep "Up" | awk '{print $2}' || true)
        
        for host in $hosts; do
            for port in $(echo "$port_list" | tr ',' '\n'); do
                echo "http://${host}:${port}"
            done
        done
        return
    fi
    
    # Handle single URL or domain
    if [[ "$target" =~ ^https?:// ]]; then
        echo "$target"
    else
        # Assume it's a domain
        local port_list="${target##*:}"
        if [[ "$port_list" == "$target" ]]; then
            echo "http://${target}"
        else
            local host="${target%:*}"
            echo "http://${host}:${port_list}"
        fi
    fi
}

# Validate URL format
validate_url() {
    local url="$1"
    
    if [[ "$url" =~ ^https?://[a-zA-Z0-9.-]+([.:][a-zA-Z0-9.-]+)*(/.*)?$ ]]; then
        return 0
    else
        return 1
    fi
}