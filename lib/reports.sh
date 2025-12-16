#!/bin/bash

# Report Generation Module for StackScan
# Handles JSON and HTML report generation

# Global report statistics
STATS_OPEN_PORTS=0
STATS_VULNERABILITIES=0
STATS_CVES=0

# API rate limiting configuration
readonly API_CALLS_FILE="/tmp/stackscan_api_calls"
readonly API_RATE_LIMIT=30

# Function to check rate limit for API calls
check_rate_limit() {
    local current_time=$(date +%s)
    local minute_ago=$((current_time - 60))

    touch "$API_CALLS_FILE" 2>/dev/null
    sed -i "/$minute_ago/d" "$API_CALLS_FILE" 2>/dev/null
    local recent_calls=$(wc -l < "$API_CALLS_FILE" 2>/dev/null || echo "0")

    if [ "$recent_calls" -ge "$API_RATE_LIMIT" ]; then
        return 1
    fi

    echo "$current_time" >> "$API_CALLS_FILE" 2>/dev/null
    return 0
}

# Function to lookup CVE details from NVD
lookup_cve_details() {
   local cve_id="$1"
   print_verbose "Looking up CVE details for $cve_id"

   # Check rate limit before making API call
   if ! check_rate_limit; then
       print_verbose "Rate limit hit, waiting 2s before retry"
       sleep 2
       if ! check_rate_limit; then
           print_warning "Rate limit exceeded for NVD API"
           echo "N/A,N/A" # Return placeholder values
           return 1
       fi
   fi

   # Use curl to query NVD API
   local nvd_url="https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$cve_id"
   local api_response
   api_response=$(curl -s --connect-timeout 10 --max-time 30 -A "StackScan/1.0" "$nvd_url" 2>/dev/null)

   if [ -z "$api_response" ]; then
       echo "N/A,N/A"
       return 1
   fi

   # Parse JSON response (simplified parsing without jq for compatibility)
   local cvss_score
   local description
   
   # Extract CVSS score
   cvss_score=$(echo "$api_response" | grep -o '"cvssV3_1":{[^}]*}' | grep -o '"baseScore":[0-9.]*' | cut -d: -f2 | tr -d '"' || echo "N/A")
   
   # Extract description (first 100 chars)
   description=$(echo "$api_response" | grep -o '"description":{[^}]*}' | head -1 | grep -o '"value":"[^"]*"' | cut -d'"' -f4 | cut -c1-100 || echo "N/A")

   if [ -z "$cvss_score" ]; then
       cvss_score="N/A"
   fi

   if [ -z "$description" ]; then
       description="N/A"
   fi

   echo "$cvss_score,$description"
   return 0
}

# Function to generate JSON report
generate_json_report() {
    local target="${TARGET:-unknown}"
    local target_type="${TARGET_TYPE:-unknown}"
    local scan_start_time="${scan_start_time:-$(date +%s)}"
    local scan_end_time="${scan_end_time:-$(date +%s)}"
    local scan_duration="${scan_duration:-0}"
    local formatted_scan_duration="${formatted_scan_duration:-00:00:00}"
    
    local json_file="${STACKSCAN_DATA_DIR:-/var/lib/stackscan}/reports/${TARGET_SAFE:-target}_${DATE_TIME:-$(date +'%Y%m%d_%H%M%S')}_scan_report.json"

    print_status "$(date '+[%Y-%m-%d %H:%M:%S]') Generating JSON report..."

    # Create JSON structure
    cat > "$json_file" <<EOF
{
  "scan_metadata": {
    "target": "$target",
    "target_type": "$target_type",
    "scan_date": "$(date '+%Y-%m-%d %H:%M:%S')",
    "scan_start_time": "$scan_start_time",
    "scan_end_time": "$scan_end_time",
    "scan_duration": "$formatted_scan_duration",
    "scan_duration_seconds": $scan_duration
  },
  "statistics": {
    "nmap_scans": {
      "web": ${STATS_NMAP_SCANS[web]:-0},
      "auth": ${STATS_NMAP_SCANS[auth]:-0},
      "database": ${STATS_NMAP_SCANS[database]:-0},
      "common": ${STATS_NMAP_SCANS[common]:-0},
      "vuln": ${STATS_NMAP_SCANS[vuln]:-0},
      "custom": ${STATS_NMAP_SCANS[custom]:-0}
    },
    "third_party_scans": {
      "wapiti": ${STATS_WAPITI_SCANS:-0},
      "nikto": ${STATS_NIKTO_SCANS:-0},
      "wpscan": ${STATS_WPSCAN_SCANS:-0},
      "sqlmap": ${STATS_SQLMAP_SCANS:-0}
    },
    "findings": {
      "open_ports": ${STATS_OPEN_PORTS:-0},
      "vulnerabilities": ${STATS_VULNERABILITIES:-0},
      "cves": ${STATS_CVES:-0},
      "cves_with_exploits": ${STATS_CVES_WITH_EXPLOITS:-0},
      "total_public_exploits": ${STATS_TOTAL_EXPLOITS:-0}
    },
    "owasp_top_10_2021": {
      "A01_Broken_Access_Control": ${OWASP_FINDINGS[A01_Broken_Access_Control]:-0},
      "A02_Cryptographic_Failures": ${OWASP_FINDINGS[A02_Cryptographic_Failures]:-0},
      "A03_Injection": ${OWASP_FINDINGS[A03_Injection]:-0},
      "A04_Insecure_Design": ${OWASP_FINDINGS[A04_Insecure_Design]:-0},
      "A05_Security_Misconfiguration": ${OWASP_FINDINGS[A05_Security_Misconfiguration]:-0},
      "A06_Vulnerable_Components": ${OWASP_FINDINGS[A06_Vulnerable_Components]:-0},
      "A07_Auth_Failures": ${OWASP_FINDINGS[A07_Auth_Failures]:-0},
      "A08_Data_Integrity_Failures": ${OWASP_FINDINGS[A08_Data_Integrity_Failures]:-0},
      "A09_Logging_Failures": ${OWASP_FINDINGS[A09_Logging_Failures]:-0},
      "A10_SSRF": ${OWASP_FINDINGS[A10_SSRF]:-0},
      "total_owasp_findings": ${OWASP_TOTAL_FINDINGS:-0}
    },
    "total_scans": $((STATS_NMAP_SCANS[web] + STATS_NMAP_SCANS[auth] + STATS_NMAP_SCANS[database] + STATS_NMAP_SCANS[common] + STATS_NMAP_SCANS[vuln] + STATS_NMAP_SCANS[custom] + STATS_WAPITI_SCANS + STATS_NIKTO_SCANS + STATS_WPSCAN_SCANS + STATS_SQLMAP_SCANS)),
    "failed_scans": ${STATS_FAILED_SCANS:-0}
  },
  "log_file": "${LOG_FILE:-}",
  "html_report_file": "${HTML_REPORT_FILE:-}"
}
EOF

    # Set secure permissions
    chmod 644 "$json_file" 2>/dev/null
    if [ -n "$SUDO_USER" ]; then
        chown "$SUDO_USER":"$SUDO_USER" "$json_file" 2>/dev/null
    fi

    log_message "INFO" "$(date '+[%Y-%m-%d %H:%M:%S]') JSON Report saved to: $json_file"

    # If --json flag was used, output JSON to console
    if [ "${OUTPUT_JSON:-false}" = "true" ]; then
        cat "$json_file"
    fi

    return 0
}

# Function to generate HTML report
generate_html_report() {
    local target="${TARGET:-unknown}"
    local target_type="${TARGET_TYPE:-unknown}"
    local scan_duration="${formatted_scan_duration:-00:00:00}"
    
    local html_file="${HTML_REPORT_FILE:-${STACKSCAN_DATA_DIR:-/var/lib/stackscan}/reports/${TARGET_SAFE:-target}_${DATE_TIME:-$(date +'%Y%m%d_%H%M%S')}_scan_report.html}"

    print_status "$(date '+[%Y-%m-%d %H:%M:%S]') Generating HTML report..."

    # Create HTML structure
    cat > "$html_file" <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>StackScan Security Assessment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; border-bottom: 2px solid #007bff; padding-bottom: 20px; margin-bottom: 30px; }
        .section { margin-bottom: 30px; }
        .section h2 { color: #007bff; border-bottom: 2px solid #007bff; padding-bottom: 10px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .stat-card { background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 6px; padding: 20px; }
        .stat-card h3 { margin-top: 0; color: #495057; }
        .vulnerability { background: #f8d7da; border-left: 4px solid #dc3545; padding: 10px; margin: 10px 0; }
        .critical { background: #f8d7da; border-left-color: #dc3545; }
        .high { background: #fff3cd; border-left-color: #ffc107; }
        .medium { background: #d1ecf1; border-left-color: #17a2b8; }
        .low { background: #d4edda; border-left-color: #28a745; }
        .owasp-section { background: #e9ecef; border-radius: 6px; padding: 15px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #dee2e6; padding: 12px; text-align: left; }
        th { background-color: #007bff; color: white; }
        .severity-critical { color: #dc3545; font-weight: bold; }
        .severity-high { color: #ffc107; font-weight: bold; }
        .severity-medium { color: #17a2b8; font-weight: bold; }
        .severity-low { color: #28a745; font-weight: bold; }
        .footer { text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #dee2e6; color: #6c757d; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 StackScan Security Assessment Report</h1>
            <p><strong>Target:</strong> TARGET_PLACEHOLDER</p>
            <p><strong>Target Type:</strong> TARGET_TYPE_PLACEHOLDER</p>
            <p><strong>Scan Date:</strong> SCAN_DATE_PLACEHOLDER</p>
            <p><strong>Scan Duration:</strong> SCAN_DURATION_PLACEHOLDER</p>
        </div>

EOF

    # Replace placeholders with actual values
    sed -i "s/TARGET_PLACEHOLDER/$target/g" "$html_file"
    sed -i "s/TARGET_TYPE_PLACEHOLDER/$target_type/g" "$html_file"
    sed -i "s/SCAN_DATE_PLACEHOLDER/$(date '+%Y-%m-%d %H:%M:%S')/g" "$html_file"
    sed -i "s/SCAN_DURATION_PLACEHOLDER/$scan_duration/g" "$html_file"

    # Add scan statistics section
    cat >> "$html_file" <<'EOF'
        <div class="section">
            <h2>📊 Scan Statistics</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>Network Scans</h3>
                    <p><strong>Nmap Web:</strong> NMAP_WEB_PLACEHOLDER</p>
                    <p><strong>Nmap Auth:</strong> NMAP_AUTH_PLACEHOLDER</p>
                    <p><strong>Nmap Database:</strong> NMAP_DATABASE_PLACEHOLDER</p>
                    <p><strong>Nmap Common:</strong> NMAP_COMMON_PLACEHOLDER</p>
                    <p><strong>Nmap Vuln:</strong> NMAP_VULN_PLACEHOLDER</p>
                </div>
                <div class="stat-card">
                    <h3>Web Application Scans</h3>
                    <p><strong>Wapiti:</strong> WAPITI_PLACEHOLDER</p>
                    <p><strong>Nikto:</strong> NIKTO_PLACEHOLDER</p>
                    <p><strong>WPScan:</strong> WPSCAN_PLACEHOLDER</p>
                    <p><strong>SQLMap:</strong> SQLMAP_PLACEHOLDER</p>
                </div>
                <div class="stat-card">
                    <h3>Findings Summary</h3>
                    <p><strong>Open Ports:</strong> OPEN_PORTS_PLACEHOLDER</p>
                    <p><strong>Vulnerabilities:</strong> VULNERABILITIES_PLACEHOLDER</p>
                    <p><strong>CVEs Found:</strong> CVES_PLACEHOLDER</p>
                    <p><strong>Failed Scans:</strong> FAILED_SCANS_PLACEHOLDER</p>
                </div>
            </div>
        </div>

EOF

    # Replace statistics placeholders
    sed -i "s/NMAP_WEB_PLACEHOLDER/${STATS_NMAP_SCANS[web]:-0}/g" "$html_file"
    sed -i "s/NMAP_AUTH_PLACEHOLDER/${STATS_NMAP_SCANS[auth]:-0}/g" "$html_file"
    sed -i "s/NMAP_DATABASE_PLACEHOLDER/${STATS_NMAP_SCANS[database]:-0}/g" "$html_file"
    sed -i "s/NMAP_COMMON_PLACEHOLDER/${STATS_NMAP_SCANS[common]:-0}/g" "$html_file"
    sed -i "s/NMAP_VULN_PLACEHOLDER/${STATS_NMAP_SCANS[vuln]:-0}/g" "$html_file"
    sed -i "s/WAPITI_PLACEHOLDER/${STATS_WAPITI_SCANS:-0}/g" "$html_file"
    sed -i "s/NIKTO_PLACEHOLDER/${STATS_NIKTO_SCANS:-0}/g" "$html_file"
    sed -i "s/WPSCAN_PLACEHOLDER/${STATS_WPSCAN_SCANS:-0}/g" "$html_file"
    sed -i "s/SQLMAP_PLACEHOLDER/${STATS_SQLMAP_SCANS:-0}/g" "$html_file"
    sed -i "s/OPEN_PORTS_PLACEHOLDER/${STATS_OPEN_PORTS:-0}/g" "$html_file"
    sed -i "s/VULNERABILITIES_PLACEHOLDER/${STATS_VULNERABILITIES:-0}/g" "$html_file"
    sed -i "s/CVES_PLACEHOLDER/${STATS_CVES:-0}/g" "$html_file"
    sed -i "s/FAILED_SCANS_PLACEHOLDER/${STATS_FAILED_SCANS:-0}/g" "$html_file"

    # Add OWASP section if there are findings
    if [ ${OWASP_TOTAL_FINDINGS:-0} -gt 0 ]; then
        cat >> "$html_file" <<'EOF'
        <div class="section">
            <h2>🛡️ OWASP Top 10 Analysis</h2>
            <div class="owasp-section">
                <p>Scan findings mapped to OWASP Top 10 2021 categories:</p>
                <ul>
OWASP_PLACEHOLDER
                </ul>
            </div>
        </div>

EOF
        
        # Generate OWASP findings list
        local owasp_html=""
        for category in A01_Broken_Access_Control A02_Cryptographic_Failures A03_Injection A04_Insecure_Design A05_Security_Misconfiguration A06_Vulnerable_Components A07_Auth_Failures A08_Data_Integrity_Failures A09_Logging_Failures A10_SSRF; do
            local count=${OWASP_FINDINGS[$category]:-0}
            if [ $count -gt 0 ]; then
                local category_name=$(echo "$category" | sed 's/_/ /g')
                owasp_html+="                    <li><strong>$category_name:</strong> $count finding(s)</li>\n"
            fi
        done
        
        sed -i "s/OWASP_PLACEHOLDER/$owasp_html/g" "$html_file"
    fi

    # Add footer
    cat >> "$html_file" <<'EOF'
        <div class="footer">
            <p>Generated by StackScan - https://github.com/intuitionamiga/stackscan</p>
            <p>MIT License - Use at your own risk!</p>
        </div>
    </div>
</body>
</html>
EOF

    # Set secure permissions
    chmod 644 "$html_file" 2>/dev/null
    if [ -n "$SUDO_USER" ]; then
        chown "$SUDO_USER":"$SUDO_USER" "$html_file" 2>/dev/null
    fi

    log_message "INFO" "$(date '+[%Y-%m-%d %H:%M:%S]') HTML Report saved to: $html_file"

    return 0
}

# Function to print scan statistics summary to console
print_scan_summary() {
    local target="${TARGET:-unknown}"
    local formatted_scan_duration="${formatted_scan_duration:-00:00:00}"

    local total_nmap=$((STATS_NMAP_SCANS[web] + STATS_NMAP_SCANS[auth] + STATS_NMAP_SCANS[database] + STATS_NMAP_SCANS[common] + STATS_NMAP_SCANS[vuln] + STATS_NMAP_SCANS[custom]))
    local total_third_party=$((STATS_WAPITI_SCANS + STATS_NIKTO_SCANS + STATS_WPSCAN_SCANS + STATS_SQLMAP_SCANS))
    local total_scans=$((total_nmap + total_third_party))

    echo ""
    echo "=========================================="
    echo "           SCAN STATISTICS SUMMARY        "
    echo "=========================================="
    echo ""
    echo "Target: $target (${TARGET_TYPE:-unknown})"
    echo "Scan Duration: $formatted_scan_duration"
    echo ""
    echo "Nmap Scans:"
    echo "  - Web:      ${STATS_NMAP_SCANS[web]:-0}"
    echo "  - Auth:     ${STATS_NMAP_SCANS[auth]:-0}"
    echo "  - Database: ${STATS_NMAP_SCANS[database]:-0}"
    echo "  - Common:   ${STATS_NMAP_SCANS[common]:-0}"
    echo "  - Vuln:     ${STATS_NMAP_SCANS[vuln]:-0}"
    echo "  - Custom:   ${STATS_NMAP_SCANS[custom]:-0}"
    echo "  Total Nmap: $total_nmap"
    echo ""
    echo "Third-Party Scans:"
    echo "  - Wapiti:   ${STATS_WAPITI_SCANS:-0}"
    echo "  - Nikto:    ${STATS_NIKTO_SCANS:-0}"
    echo "  - WPScan:   ${STATS_WPSCAN_SCANS:-0}"
    echo "  - SQLMap:   ${STATS_SQLMAP_SCANS:-0}"
    echo "  Total:      $total_third_party"
    echo ""
    echo "Findings:"
    echo "  - Open Ports:      ${STATS_OPEN_PORTS:-0}"
    echo "  - Vulnerabilities: ${STATS_VULNERABILITIES:-0}"
    echo "  - CVEs:            ${STATS_CVES:-0}"
    if [ ${STATS_CVES_WITH_EXPLOITS:-0} -gt 0 ]; then
        echo "  - CVEs with Public Exploits: ${STATS_CVES_WITH_EXPLOITS:-0} (⚠️  High Priority!)"
    fi
    echo ""

    # Display OWASP Top 10 summary
    if [ ${OWASP_TOTAL_FINDINGS:-0} -gt 0 ]; then
        echo "OWASP Top 10 (2021) Findings:"
        for category in A01_Broken_Access_Control A02_Cryptographic_Failures A03_Injection A04_Insecure_Design A05_Security_Misconfiguration A06_Vulnerable_Components A07_Auth_Failures A08_Data_Integrity_Failures A09_Logging_Failures A10_SSRF; do
            local count=${OWASP_FINDINGS[$category]:-0}
            if [ $count -gt 0 ]; then
                local display_name=$(echo "$category" | sed 's/_/ /g')
                echo "  - $display_name: $count"
            fi
        done
        echo "  Total OWASP Findings: ${OWASP_TOTAL_FINDINGS:-0}"
        echo ""
    fi

    echo "Scan Status:"
    echo "  - Total Scans:     $total_scans"
    echo "  - Failed Scans:    ${STATS_FAILED_SCANS:-0}"
    echo "=========================================="
    echo ""
}

# Function to generate all reports
generate_reports() {
    if [ "${GENERATE_HTML_REPORT:-true}" = "true" ]; then
        generate_html_report
    fi
    
    generate_json_report
    
    return 0
}

# Initialize reports module
init_reports() {
    # Create reports directory if needed
    local reports_dir="${STACKSCAN_DATA_DIR:-/var/lib/stackscan}/reports"
    if [ ! -d "$reports_dir" ]; then
        mkdir -p "$reports_dir" 2>/dev/null || {
            print_error "Failed to create reports directory: $reports_dir"
            return 1
        }
        chmod 775 "$reports_dir" 2>/dev/null
        
        if [ -n "$SUDO_USER" ]; then
            chown "$SUDO_USER":"$SUDO_USER" "$reports_dir" 2>/dev/null
        fi
    fi
    
    print_verbose "Reports module initialized"
    return 0
}