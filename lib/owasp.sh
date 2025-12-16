#!/bin/bash

# OWASP Analysis Module for StackScan
# Handles OWASP Top 10 mapping and educational content

# Global OWASP tracking variables
declare -A OWASP_FINDINGS=(
    [A01_Broken_Access_Control]=0
    [A02_Cryptographic_Failures]=0
    [A03_Injection]=0
    [A04_Insecure_Design]=0
    [A05_Security_Misconfiguration]=0
    [A06_Vulnerable_Components]=0
    [A07_Auth_Failures]=0
    [A08_Data_Integrity_Failures]=0
    [A09_Logging_Failures]=0
    [A10_SSRF]=0
)
OWASP_TOTAL_FINDINGS=0

# Global exploit tracking variables
STATS_CVES_WITH_EXPLOITS=0
STATS_TOTAL_EXPLOITS=0
declare -A CVE_EXPLOIT_DATA

# OWASP Top 10 mapping function
map_to_owasp() {
    local finding="$1"
    local finding_lower=$(echo "$finding" | tr '[:upper:]' '[:lower:]')

    # A01: Broken Access Control
    if [[ "$finding_lower" =~ (access.*control|authorization|privilege.*escalation|idor|path.*traversal|directory.*traversal|forced.*browsing|insecure.*direct.*object) ]]; then
        ((OWASP_FINDINGS[A01_Broken_Access_Control]++))
        ((OWASP_TOTAL_FINDINGS++))
        return 0
    fi

    # A02: Cryptographic Failures
    if [[ "$finding_lower" =~ (weak.*cipher|ssl|tls|crypto|encryption|cleartext|plaintext|weak.*hash|md5|sha1|des|rc4|heartbleed|poodle) ]]; then
        ((OWASP_FINDINGS[A02_Cryptographic_Failures]++))
        ((OWASP_TOTAL_FINDINGS++))
        return 0
    fi

    # A03: Injection
    if [[ "$finding_lower" =~ (injection|sql.*inject|xss|cross.*site.*script|ldap.*inject|xml.*inject|command.*inject|code.*inject|os.*command|eval) ]]; then
        ((OWASP_FINDINGS[A03_Injection]++))
        ((OWASP_TOTAL_FINDINGS++))
        return 0
    fi

    # A04: Insecure Design
    if [[ "$finding_lower" =~ (rate.*limit|brute.*force|account.*enumeration|predictable|business.*logic|workflow|trust.*boundary) ]]; then
        ((OWASP_FINDINGS[A04_Insecure_Design]++))
        ((OWASP_TOTAL_FINDINGS++))
        return 0
    fi

    # A05: Security Misconfiguration
    if [[ "$finding_lower" =~ (misconfigur|default.*credential|default.*password|directory.*listing|verbose.*error|debug.*mode|unnecessary.*feature|unpatched|outdated.*software|missing.*header|security.*header|cors|csp) ]]; then
        ((OWASP_FINDINGS[A05_Security_Misconfiguration]++))
        ((OWASP_TOTAL_FINDINGS++))
        return 0
    fi

    # A06: Vulnerable and Outdated Components
    if [[ "$finding_lower" =~ (cve-|vulnerable.*component|outdated.*library|known.*vulnerability|vulnerable.*version|end.*of.*life|eol) ]]; then
        ((OWASP_FINDINGS[A06_Vulnerable_Components]++))
        ((OWASP_TOTAL_FINDINGS++))
        return 0
    fi

    # A07: Identification and Authentication Failures
    if [[ "$finding_lower" =~ (authentication|session|cookie|jwt|token|password|credential|login|logout|session.*fixation|session.*hijack) ]]; then
        ((OWASP_FINDINGS[A07_Auth_Failures]++))
        ((OWASP_TOTAL_FINDINGS++))
        return 0
    fi

    # A08: Software and Data Integrity Failures
    if [[ "$finding_lower" =~ (deserialization|insecure.*deserialization|update.*mechanism|ci.*cd|plugin|integrity.*check|untrusted.*source) ]]; then
        ((OWASP_FINDINGS[A08_Data_Integrity_Failures]++))
        ((OWASP_TOTAL_FINDINGS++))
        return 0
    fi

    # A09: Security Logging and Monitoring Failures
    if [[ "$finding_lower" =~ (logging|monitoring|audit|alerting|intrusion.*detection|siem) ]]; then
        ((OWASP_FINDINGS[A09_Logging_Failures]++))
        ((OWASP_TOTAL_FINDINGS++))
        return 0
    fi

    # A10: Server-Side Request Forgery (SSRF)
    if [[ "$finding_lower" =~ (ssrf|server.*side.*request|url.*fetch|remote.*fetch|internal.*service) ]]; then
        ((OWASP_FINDINGS[A10_SSRF]++))
        ((OWASP_TOTAL_FINDINGS++))
        return 0
    fi

    return 1
}

# Function to analyze scan outputs for OWASP mapping
analyze_scan_outputs_for_owasp() {
    local scan_dir="$1"

    if [ ! -d "$scan_dir" ]; then
        return 0
    fi

    print_status "$(date '+[%Y-%m-%d %H:%M:%S]') Analyzing findings for OWASP Top 10 mapping..."

    # Analyze all scan output files
    for output_file in "$scan_dir"/*_output.txt "$scan_dir"/*_scan_output.txt; do
        if [ -f "$output_file" ]; then
            # Read file line by line and map findings
            while IFS= read -r line; do
                # Skip empty lines
                [ -z "$line" ] && continue

                # Map findings to OWASP categories
                map_to_owasp "$line"
            done < "$output_file"
        fi
    done

    # Display OWASP mapping results if in educational mode
    if [ "${EDUCATIONAL_MODE:-false}" = "true" ]; then
        echo ""
        echo -e "${GREEN}OWASP Top 10 Mapping Results:${RESET}"
        for category in "${!OWASP_FINDINGS[@]}"; do
            local count=${OWASP_FINDINGS[$category]}
            if [ $count -gt 0 ]; then
                local category_name=$(echo "$category" | tr '_' ' ')
                echo "  • $category_name: $count finding(s)"
            fi
        done
        echo "  Total OWASP-classified findings: $OWASP_TOTAL_FINDINGS"
        echo ""
    fi

    return 0
}

# Function to analyze CVEs for public exploits
analyze_cve_exploits() {
    local scan_dir="$1"

    if [ ! -d "$scan_dir" ]; then
        return 0
    fi

    print_status "$(date '+[%Y-%m-%d %H:%M:%S]') Checking for public exploits..."

    # Extract CVEs from all scan output files
    local cve_list=""
    for output_file in "$scan_dir"/*_output.txt "$scan_dir"/*_scan_output.txt; do
        if [ -f "$output_file" ]; then
            local file_cves
            file_cves=$(grep -oE "CVE-[0-9]+-[0-9]+" "$output_file" 2>/dev/null || echo "")
            cve_list+="$file_cves"$'\n'
        fi
    done

    # Get unique CVEs
    local unique_cves
    unique_cves=$(echo "$cve_list" | sort -u | grep "CVE-" || echo "")

    if [ -z "$unique_cves" ]; then
        print_verbose "No CVEs found to check for exploits"
        return 0
    fi

    # Check each CVE for exploits
    while IFS= read -r cve; do
        if [ -n "$cve" ]; then
            check_cve_exploit "$cve"
        fi
    done <<< "$unique_cves"

    # Display exploit summary
    if [ $STATS_CVES_WITH_EXPLOITS -gt 0 ]; then
        print_warning "Found $STATS_CVES_WITH_EXPLOITS CVE(s) with public exploits!"
        print_warning "Total public exploits available: $STATS_TOTAL_EXPLOITS"
    fi

    return 0
}

# Function to check a specific CVE for exploits
check_cve_exploit() {
    local cve_id="$1"
    local exploit_count=0

    print_verbose "Checking exploits for $cve_id"

    # Use curl to check ExploitDB (with rate limiting)
    if command -v curl &> /dev/null; then
        local exploit_db_url="https://www.exploit-db.com/search?cve=${cve_id}"
        local exploit_check_result
        exploit_check_result=$(curl -s --connect-timeout 10 --max-time 30 -A "StackScan/1.0" "$exploit_db_url" 2>/dev/null | grep -ic "exploit" | wc -l)

        if [ "$exploit_check_result" -gt 0 ]; then
            exploit_count=$exploit_check_result
            ((STATS_CVES_WITH_EXPLOITS++))
            ((STATS_TOTAL_EXPLOITS += exploit_count))
            CVE_EXPLOIT_DATA["$cve_id"]="exploits:$exploit_count"
        fi
    fi

    return 0
}

# Function to display OWASP Top 10 educational information
display_owasp_educational_info() {
    if [ "${EDUCATIONAL_MODE:-false}" != "true" ]; then
        return 0
    fi

    if [ $OWASP_TOTAL_FINDINGS -eq 0 ]; then
        return 0
    fi

    cat <<'EOF'

 🛡️  OWASP TOP 10 - Web Application Security Risks (2021)

The Open Web Application Security Project (OWASP) Top 10 represents the
most critical security risks to web applications, updated every 3-4 years.

A01:2021 – Broken Access Control
   • Users can act outside their intended permissions
   • Example: Accessing other users' data by changing URL parameters

A02:2021 – Cryptographic Failures
   • Sensitive data exposed due to lack of encryption
   • Example: Passwords transmitted over HTTP instead of HTTPS

A03:2021 – Injection
   • Untrusted data sent to interpreter as part of command/query
   • Example: SQL injection, command injection, LDAP injection

A04:2021 – Insecure Design
   • Missing or ineffective security controls by design
   • Example: No rate limiting on password resets

A05:2021 – Security Misconfiguration
   • Missing security hardening, unnecessary features enabled
   • Example: Default credentials, directory listings enabled

A06:2021 – Vulnerable and Outdated Components
   • Using components with known vulnerabilities
   • Example: WordPress plugins with unpatched CVEs

A07:2021 – Identification and Authentication Failures
   • Broken authentication and session management
   • Example: Weak passwords, session fixation

A08:2021 – Software and Data Integrity Failures
   • Code/infrastructure without integrity verification
   • Example: Unverified updates, deserialization attacks

A09:2021 – Security Logging and Monitoring Failures
   • Insufficient logging allows attacks to go undetected
   • Example: No alerts for failed login attempts

A10:2021 – Server-Side Request Forgery (SSRF)
   • Application fetches remote resources without validation
   • Example: Accessing internal services via crafted URLs

WHY THIS MATTERS FOR CEH:
The CEH exam expects you to recognize these categories and understand
how to test for and remediate each type of vulnerability.

EOF
}

# Function to display educational info about CVE analysis
display_cve_educational_info() {
    if [ "${EDUCATIONAL_MODE:-false}" != "true" ]; then
        return 0
    fi

    cat <<'EOF'

 🔐 CVE - Common Vulnerabilities and Exposures

WHAT IS A CVE:
   CVEs are standardized identifiers for publicly known security vulnerabilities.
   Format: CVE-YEAR-NUMBER (e.g., CVE-2024-12345)

WHY THEY MATTER:
   • Vendors use CVEs to coordinate patches
   • Security teams prioritize fixes based on CVE severity
   • Attackers search for systems vulnerable to known CVEs

CVSS SCORING (0-10):
   • 0.0: Informational
   • 0.1-3.9: Low severity
   • 4.0-6.9: Medium severity
   • 7.0-8.9: High severity
   • 9.0-10.0: Critical severity

WHAT WE'RE DOING:
   For each CVE found, we query the National Vulnerability Database (NVD)
   to get detailed descriptions, CVSS scores, and remediation guidance.

ATTACKER PERSPECTIVE:
   - Search exploit databases for proof-of-concept code
   - Look for "exploit in the wild" indicators
   - Prioritize high-value, low-difficulty exploits

DEFENDER PERSPECTIVE:
   - Prioritize critical/high CVEs with known exploits
   - Patch or mitigate before attackers weaponize
   - Monitor threat intelligence for active exploitation

EOF
}

# Function to reset OWASP counters
reset_owasp_counters() {
    for category in "${!OWASP_FINDINGS[@]}"; do
        OWASP_FINDINGS[$category]=0
    done
    OWASP_TOTAL_FINDINGS=0
    
    # Reset exploit counters
    STATS_CVES_WITH_EXPLOITS=0
    STATS_TOTAL_EXPLOITS=0
    for cve in "${!CVE_EXPLOIT_DATA[@]}"; do
        unset CVE_EXPLOIT_DATA["$cve"]
    done

    print_verbose "OWASP and exploit counters reset"
    return 0
}

# Function to get OWASP summary
get_owasp_summary() {
    local summary="OWASP Top 10 (2021) Findings:\n"
    
    for category in A01_Broken_Access_Control A02_Cryptographic_Failures A03_Injection A04_Insecure_Design A05_Security_Misconfiguration A06_Vulnerable_Components A07_Auth_Failures A08_Data_Integrity_Failures A09_Logging_Failures A10_SSRF; do
        local count=${OWASP_FINDINGS[$category]}
        if [ $count -gt 0 ]; then
            local display_name=$(echo "$category" | sed 's/_/ /g')
            summary+="  - $display_name: $count\n"
        fi
    done
    summary+="  Total OWASP Findings: $OWASP_TOTAL_FINDINGS\n"
    
    echo -e "$summary"
}

# Initialize OWASP module
init_owasp() {
    reset_owasp_counters
    print_verbose "OWASP analysis module initialized"
    return 0
}