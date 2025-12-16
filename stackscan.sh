#!/bin/bash

# StackScan - Comprehensive Security Scanner (Modular Version)
# Main entry point that orchestrates all modules

# Check Bash version requirement
if ((BASH_VERSINFO[0] < 4)); then
    echo "Error: Bash 4.0 or higher required" >&2
    exit 1
fi

# Global directories (can be overridden by environment)
readonly STACKSCAN_LOG_DIR="${STACKSCAN_LOG_DIR:-/var/log/stackscan}"
readonly STACKSCAN_DATA_DIR="${STACKSCAN_DATA_DIR:-/var/lib/stackscan}"
readonly STACKSCAN_TMP_DIR="${STACKSCAN_TMP_DIR:-/tmp/stackscan}"
readonly SCAN_DIR="."

# Global scan tracking variables
scan_start_time=$(date +%s)
declare -A SCAN_STAGE_STATUS=(
    [initialization]="PENDING"
    [nmap_ipv4]="PENDING"
    [nmap_ipv6]="PENDING"
    [port_detection]="PENDING"
    [third_party_scans]="PENDING"
    [vulnerability_analysis]="PENDING"
    [report_generation]="PENDING"
)
CURRENT_SCAN_STAGE=""
TOTAL_SCAN_STAGES=7

# Source all modules
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/config.sh"
source "$SCRIPT_DIR/lib/logging.sh"
source "$SCRIPT_DIR/lib/utils.sh"
source "$SCRIPT_DIR/lib/nmap.sh"
source "$SCRIPT_DIR/lib/scanners.sh"
source "$SCRIPT_DIR/lib/owasp.sh"
source "$SCRIPT_DIR/lib/reports.sh"

# Main execution function
main() {
    # Check for --help before requiring root
    if [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
        show_help
        exit 0
    else
        check_root_privileges || exit 1
    fi

    # Initialize all modules
    init_config || exit 1
    init_logging || exit 1
    init_utils || exit 1
    init_nmap || exit 1
    init_scanners || exit 0  # Don't fail for optional scanners
    init_owasp || exit 1
    init_reports || exit 1

    # Parse command line arguments
    parse_arguments "$@" || exit 1

    # Validate target
    validate_target "$TARGET" || exit 1

    # Set up global variables for file paths
    readonly DATE_TIME=$(date +"%Y%m%d_%H%M%S")
    readonly LOG_FILE="${STACKSCAN_LOG_DIR}/${TARGET_SAFE}_${DATE_TIME}_scan.log"
    readonly HTML_REPORT_FILE="${STACKSCAN_DATA_DIR}/reports/${TARGET_SAFE}_${DATE_TIME}_scan_report.html"

    # Setup secure permissions with new paths
    setup_secure_permissions

    # Print banner and start scanning
    print_banner
    log_message "INFO" "$(date '+[%Y-%m-%d %H:%M:%S]') Scan Date: $(date)"

    # Educational mode introduction
    print_educational_info "SCAN_START"

    # Log verbosity status
    if [ "$LOG_LEVEL" = "VERBOSE" ]; then
        log_message "VERBOSE" "$(date '+[%Y-%m-%d %H:%M:%S]') Verbose mode enabled. Detailed logs will be printed."
    else
        log_message "WARNING" "$(date '+[%Y-%m-%d %H:%M:%S]') Verbose mode disabled. Only important logs will be printed."
    fi

    # Check system requirements
    check_required_commands || exit 1
    check_ipv6_support || exit 1

    # Phase 1: Initialization
    update_scan_stage "initialization" "IN_PROGRESS"
    validate_configuration || exit 1
    update_scan_stage "initialization" "COMPLETED"

    # Educational info about Nmap
    print_educational_info "NMAP_SCANNING"

    # Phase 2: Nmap IPv4 scans
    update_scan_stage "nmap_ipv4" "IN_PROGRESS"
    local scan_pids
    read -ra scan_pids <<< "$(run_scan_groups "IPv4" "$TARGET")"
    local web_scan_pid_v4=${scan_pids[0]}
    local database_scan_pid_v4=${scan_pids[2]}

    # Phase 3: Nmap IPv6 scans (if applicable)
    if [ "$IPV6_SUPPORTED" = true ] && [ "$TARGET_TYPE" != "IPv4" ]; then
        update_scan_stage "nmap_ipv6" "IN_PROGRESS"
        local ipv6_scan_pids
        read -ra ipv6_scan_pids <<< "$(run_scan_groups "IPv6" "$TARGET")"
        local web_scan_pid_v6=${ipv6_scan_pids[0]}
        local database_scan_pid_v6=${ipv6_scan_pids[2]}
        
        # Wait for IPv4 web scan to complete for port detection
        wait "$web_scan_pid_v4" || true
        wait "$web_scan_pid_v6" || true
    else
        update_scan_stage "nmap_ipv6" "COMPLETED"
        # Wait for IPv4 web scan to complete for port detection
        wait "$web_scan_pid_v4" || true
    fi

    update_scan_stage "nmap_ipv4" "COMPLETED"
    if [ "$IPV6_SUPPORTED" = true ] && [ "$TARGET_TYPE" != "IPv4" ]; then
        update_scan_stage "nmap_ipv6" "COMPLETED"
    fi

    # Phase 4: Port detection and service discovery
    update_scan_stage "port_detection" "IN_PROGRESS"
    local open_ports
    open_ports=$(get_open_web_ports "$TARGET")
    
    # Remove duplicate ports
    declare -A unique_ports
    for port in $open_ports; do
        unique_ports["$port"]=1
    done
    open_ports="${!unique_ports[@]}"
    
    # Track open ports statistic
    STATS_OPEN_PORTS=$(echo "$open_ports" | wc -w)
    update_scan_stage "port_detection" "COMPLETED"

    # Wait for database scans to complete
    wait "$database_scan_pid_v4" || true
    if [ -n "$database_scan_pid_v6" ]; then
        wait "$database_scan_pid_v6" || true
    fi

    # Detect services
    local services_detection
    services_detection=$(detect_services "$TARGET")
    local wp_detected=$(echo "$services_detection" | awk '{print $1}')
    local sql_detected=$(echo "$services_detection" | awk '{print $2}')

    # Educational info about web scanning
    print_educational_info "WEB_SCANNING"

    # Phase 5: Third-party scans
    update_scan_stage "third_party_scans" "IN_PROGRESS"
    run_third_party_scans "$TARGET" "$open_ports" "$wp_detected" "$sql_detected"
    update_scan_stage "third_party_scans" "COMPLETED"

    # Phase 6: Vulnerability analysis
    update_scan_stage "vulnerability_analysis" "IN_PROGRESS"
    count_findings "$TARGET"
    
    # Analyze findings for OWASP Top 10 mapping
    analyze_scan_outputs_for_owasp "${STACKSCAN_DATA_DIR}/reports"
    
    # Show OWASP educational info if findings exist
    if [ "$EDUCATIONAL_MODE" = "true" ] && [ $OWASP_TOTAL_FINDINGS -gt 0 ]; then
        print_educational_info "OWASP_TOP_10"
    fi
    
    # Check for public exploits if CVEs found
    if [ $STATS_CVES -gt 0 ]; then
        analyze_cve_exploits "${STACKSCAN_DATA_DIR}/reports"
    fi
    
    update_scan_stage "vulnerability_analysis" "COMPLETED"

    # Calculate scan duration
    local scan_end_time=$(date +%s)
    local scan_duration=$((scan_end_time - scan_start_time))
    local formatted_scan_duration=$(printf "%02d:%02d:%02d" $((scan_duration/3600)) $((scan_duration%3600/60)) $((scan_duration%60)))

    # Phase 7: Report generation
    update_scan_stage "report_generation" "IN_PROGRESS"
    generate_reports
    update_scan_stage "report_generation" "COMPLETED"

    # Print final summary
    print_status "$(date '+[%Y-%m-%d %H:%M:%S]') Scanning complete for $TARGET."
    log_message "INFO" "$(date '+[%Y-%m-%d %H:%M:%S]') Log saved to: $LOG_FILE"
    
    print_scan_summary

    return 0
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi