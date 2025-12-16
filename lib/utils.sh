#!/bin/bash

# Utility Functions Module for StackScan
# Handles validation, cleanup, error handling, and other utilities

# Global variables for error handling
STATS_FAILED_SCANS=0
BACKGROUND_PIDS=()

# Function to run command with timeout
run_with_timeout() {
    local timeout=$1
    shift
    print_verbose "Running command with ${timeout}s timeout: $*"
    timeout "$timeout" "$@"
    local exit_code=$?
    if [ $exit_code -eq 124 ]; then
        log_message "WARNING" "Command timed out after ${timeout} seconds: $*"
        return 124
    fi
    return $exit_code
}

# Enhanced input validation and sanitization function
validate_target() {
    local target="$1"
    
    # Comprehensive input sanitization
    TARGET=$(printf '%s' "$target" | tr -cd 'a-zA-Z0-9.-')
    
    # Additional security checks
    if [ -z "$TARGET" ]; then
        print_error "Target cannot be empty."
        return 1
    fi
    
    # Check for suspicious patterns
    if [[ "$TARGET" =~ [\;\|\&\|\$\|\`\|] ]]; then
        print_error "Target contains potentially dangerous characters."
        return 1
    fi
    
    # Length validation
    if [ ${#TARGET} -gt 253 ]; then
        print_error "Target exceeds maximum length (253 characters)."
        return 1
    fi
    
    # Prevent localhost scanning unless explicitly allowed
    if [[ "$TARGET" =~ ^(localhost|127\.|::1) ]] && [ "${ALLOW_LOCALHOST:-false}" != "true" ]; then
        print_error "Localhost scanning is not allowed. Use ALLOW_LOCALHOST=true to override."
        return 1
    fi
    
    # Prevent private network scanning unless explicitly allowed
    if [[ "$TARGET" =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.) ]] && [ "${ALLOW_PRIVATE_NETWORKS:-false}" != "true" ]; then
        print_error "Private network scanning is not allowed. Use ALLOW_PRIVATE_NETWORKS=true to override."
        return 1
    fi

    # Enhanced validation regexes with better error detection
    local domain_regex="^([a-zA-Z0-9](-*[a-zA-Z0-9])*(\.[a-zA-Z0-9](-*[a-zA-Z0-9])*)*[a-zA-Z]{2,})$"
    local ipv4_regex="^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    local ipv6_regex="^(([0-9a-fA-F]{1,4}:){1,7}([0-9a-fA-F]{1,4})?|::([0-9a-fA-F]{1,4}:){0,7}([0-9a-fA-F]{1,4})?)$"

    # Validate with detailed error messages
    if [[ $TARGET =~ $ipv4_regex ]]; then
        # Additional IPv4 validation
        local octets=(${TARGET//./ })
        for octet in "${octets[@]}"; do
            if [ "$octet" -gt 255 ] || [ "$octet" -lt 0 ]; then
                print_error "Invalid IPv4 address: octet $octet out of range (0-255)."
                return 1
            fi
        done
        TARGET_TYPE="IPv4"
    elif [[ $TARGET =~ $ipv6_regex ]]; then
        TARGET_TYPE="IPv6"
    elif [[ $TARGET =~ $domain_regex ]]; then
        # Additional domain validation
        local tld="${TARGET##*.}"
        if [ ${#tld} -lt 2 ] || [ ${#tld} -gt 63 ]; then
            print_error "Invalid domain: TLD '$tld' must be 2-63 characters."
            return 1
        fi
        TARGET_TYPE="DOMAIN"
    else
        print_error "Invalid target: $TARGET"
        print_error "Please provide a valid:"
        print_error "  - Domain name (e.g., example.com)"
        print_error "  - IPv4 address (e.g., 192.168.1.1)"
        print_error "  - IPv6 address (e.g., 2001:db8::1)"
        return 1
    fi
    
    # Set safe version for filenames with additional encoding
    readonly TARGET_SAFE=$(printf '%q' "$TARGET" | sed 's/[^a-zA-Z0-9._-]/_/g')
    
    print_verbose "Target validation passed: $TARGET ($TARGET_TYPE)"
    return 0
}

# Function to check if IPv6 is supported
check_ipv6_support() {
    # Only check IPv6 support if the target is specifically identified as an IPv6 address
    if [ "${TARGET_TYPE:-}" = "IPv6" ]; then
        if ping6 -c 1 -W 1 "$TARGET" &> /dev/null; then
            IPV6_SUPPORTED=true
            print_verbose "IPv6 is supported and reachable for $TARGET."
        else
            IPV6_SUPPORTED=false
            print_error "IPv6 is not supported or not reachable for $TARGET. Exiting."
            return 1
        fi
    else
        IPV6_SUPPORTED=false
        print_verbose "IPv6 check skipped as the target is not an IPv6 address."
    fi
    return 0
}

# Function to check if script is run as root
check_root_privileges() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "\033[31mError: This script must be run as root.\033[0m" >&2
        echo "Usage: sudo $0 [OPTIONS] <domain_or_ip>" >&2
        echo "Use --help for more information" >&2
        exit 1
    fi
    return 0
}

# Function to check required system commands
check_required_commands() {
    local cmds=("nmap" "dig" "ping6" "jq" "curl" "bash")
    local optional_cmds=("nikto" "wapiti" "wpscan" "sqlmap")
    
    # Check required commands
    local missing_required=()
    for cmd in "${cmds[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_required+=("$cmd")
        fi
    done

    # Check optional commands (warn but don't fail)
    local missing_optional=()
    for cmd in "${optional_cmds[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_optional+=("$cmd")
        fi
    done

    # Report missing required commands
    if [ ${#missing_required[@]} -gt 0 ]; then
        print_error "Required commands not found: ${missing_required[*]}"
        print_error "Please install these commands and try again."
        return 1
    fi

    # Report missing optional commands
    if [ ${#missing_optional[@]} -gt 0 ]; then
        print_warning "Optional commands not found: ${missing_optional[*]}"
        print_warning "Some features may be limited without these commands."
    fi

    print_verbose "All required commands are available"
    return 0
}

# Enhanced directory setup with improved security validation
setup_directories() {
    local log_dir="${STACKSCAN_LOG_DIR:-/var/log/stackscan}"
    local data_dir="${STACKSCAN_DATA_DIR:-/var/lib/stackscan}"
    local tmp_dir="${STACKSCAN_TMP_DIR:-/tmp/stackscan}"

    # Security check: ensure running in controlled environment
    if [ "${SECURE_MODE:-true}" = "true" ]; then
        # Validate parent directory permissions
        for dir_path in "$log_dir" "$data_dir" "$tmp_dir"; do
            local parent_dir=$(dirname "$dir_path")
            if [ -d "$parent_dir" ]; then
                local parent_perms=$(stat -c "%a" "$parent_dir" 2>/dev/null)
                if [ -n "$parent_perms" ] && [[ "$parent_perms" =~ [02367] ]]; then
                    print_warning "Parent directory $parent_dir has permissive permissions: $parent_perms"
                fi
            fi
        done
    fi

    # Create log directory with enhanced security
    if [ ! -d "$log_dir" ]; then
        mkdir -p "$log_dir" 2>/dev/null || {
            print_error "Failed to create log directory: $log_dir"
            return 1
        }
        chmod 750 "$log_dir"  # More restrictive: drwxr-x---
        # Set proper ownership
        if [ -n "$SUDO_USER" ]; then
            chown root:"$SUDO_USER" "$log_dir" 2>/dev/null
        fi
    fi

    # Create data directory with proper permissions
    if [ ! -d "$data_dir" ]; then
        mkdir -p "$data_dir" 2>/dev/null || {
            print_error "Failed to create data directory: $data_dir"
            return 1
        }
        chmod 750 "$data_dir"  # More restrictive: drwxr-x---
        
        # Create a reports subdirectory
        mkdir -p "$data_dir/reports" 2>/dev/null
        chmod 750 "$data_dir/reports"
        
        # Set proper ownership
        if [ -n "$SUDO_USER" ]; then
            chown -R "$SUDO_USER":"$SUDO_USER" "$data_dir" 2>/dev/null
        fi
    fi
    
    # Create temporary directory with enhanced security
    if [ ! -d "$tmp_dir" ]; then
        mkdir -p "$tmp_dir" 2>/dev/null || {
            print_error "Failed to create temp directory: $tmp_dir"
            return 1
        }
        chmod 700 "$tmp_dir"  # drwx------
        
        # Add additional temp security measures
        if [ -n "$SUDO_USER" ]; then
            chown "$SUDO_USER":"$SUDO_USER" "$tmp_dir" 2>/dev/null
        fi
        
        # Set sticky bit if supported
        chmod +t "$tmp_dir" 2>/dev/null || true
    fi

    # Verify directory creation and permissions
    for dir_path in "$log_dir" "$data_dir" "$tmp_dir"; do
        if [ ! -d "$dir_path" ]; then
            print_error "Directory creation failed: $dir_path"
            return 1
        fi
        
        # Test write permissions
        local test_file="$dir_path/.stackscan_write_test_$$"
        if ! touch "$test_file" 2>/dev/null; then
            print_error "Cannot write to directory: $dir_path"
            return 1
        fi
        rm -f "$test_file" 2>/dev/null
    done

    print_verbose "Directory structure setup complete with enhanced security"
    return 0
}

# Function to set secure permissions
setup_secure_permissions() {
    local log_dir="${STACKSCAN_LOG_DIR:-/var/log/stackscan}"
    local data_dir="${STACKSCAN_DATA_DIR:-/var/lib/stackscan}"
    local log_file="${LOG_FILE:-}"
    local html_report_file="${HTML_REPORT_FILE:-}"

    # Set secure umask
    umask 077

    # Ensure log directory has secure permissions
    chmod 755 "$log_dir" 2>/dev/null

    # Ensure data directory has secure permissions
    chmod 775 "$data_dir" 2>/dev/null
    chmod 775 "$data_dir/reports" 2>/dev/null

    # Ensure log file has secure permissions from the start
    if [ -n "$log_file" ]; then
        touch "$log_file" 2>/dev/null
        chmod 600 "$log_file" 2>/dev/null
    fi

    # Ensure HTML report file has secure permissions
    if [ -n "$html_report_file" ]; then
        touch "$html_report_file" 2>/dev/null
        chmod 644 "$html_report_file" 2>/dev/null
    fi

    # Set ownership if SUDO_USER is set
    if [ -n "$SUDO_USER" ]; then
        chown -R "$SUDO_USER":"$SUDO_USER" "$data_dir" 2>/dev/null
        chown "$SUDO_USER":"$SUDO_USER" "$log_file" 2>/dev/null
        chown "$SUDO_USER":"$SUDO_USER" "$html_report_file" 2>/dev/null
    fi

    print_verbose "Secure permissions setup complete"
    return 0
}

# Function to set resource limits
setup_resource_limits() {
    # Set maximum number of concurrent processes
    local max_procs=1000
    ulimit -u "$max_procs" 2>/dev/null || print_warning "Could not set process limit"

    # Set maximum file size (500MB)
    ulimit -f 512000 2>/dev/null || print_warning "Could not set file size limit"

    # Check available disk space (need at least 1GB free)
    local data_dir="${STACKSCAN_DATA_DIR:-/var/lib/stackscan}"
    local free_space
    free_space=$(df -P "$data_dir" | awk 'NR==2 {print $4}' 2>/dev/null || echo "0")
    
    if [ "$free_space" -lt 1048576 ]; then
        print_error "Insufficient disk space. Need at least 1GB free."
        return 1
    fi

    print_verbose "Resource limits setup complete"
    return 0
}

# Enhanced error handling with recovery mechanisms
handle_error() {
    local exit_code=$?
    local cmd="${BASH_COMMAND}"
    local line_number="${BASH_LINENO[0]}"
    local function_name="${FUNCNAME[0]:-main}"
    local error_context="ERROR"

    # Categorize error type for better handling
    case $exit_code in
        124)
            error_context="TIMEOUT"
            log_message "ERROR" "Command timed out after timeout period: ${cmd}"
            ;;
        127)
            error_context="COMMAND_NOT_FOUND"
            log_message "ERROR" "Command not found: ${cmd}"
            ;;
        2)
            error_context="PERMISSION_DENIED"
            log_message "ERROR" "Permission denied: ${cmd}"
            ;;
        125)
            error_context="COMMAND_FAILED"
            log_message "ERROR" "Command execution failed: ${cmd}"
            ;;
        130)
            error_context="INTERRUPTED"
            log_message "ERROR" "Command interrupted by user: ${cmd}"
            ;;
        *)
            error_context="UNKNOWN"
            log_message "ERROR" "Command failed with exit code ${exit_code}: ${cmd}"
            ;;
    esac

    # Enhanced stack trace with context
    local i=0
    local stack_size=${#FUNCNAME[@]}
    log_message "ERROR" "=== ERROR ANALYSIS ==="
    log_message "ERROR" "Error Type: $error_context"
    log_message "ERROR" "Exit Code: $exit_code"
    log_message "ERROR" "Command: ${cmd}"
    log_message "ERROR" "Function: $function_name"
    log_message "ERROR" "Line: $line_number"
    log_message "ERROR" "Stack Trace:"
    
    while [ $i -lt $stack_size ]; do
        if [ $i -lt $stack_size ]; then
            local source_file="${BASH_SOURCE[$i]}"
            local source_line="${BASH_LINENO[$i]}"
            local stack_function="${FUNCNAME[$i]}"
            
            # Truncate long file paths for readability
            if [ ${#source_file} -gt 50 ]; then
                source_file="...${source_file: -50}"
            fi
            
            log_message "ERROR" "  [$i] ${source_file}:${source_line} ${stack_function}"
        fi
        i=$((i + 1))
    done
    log_message "ERROR" "========================"

    # Attempt error recovery based on type
    attempt_error_recovery "$error_context" "$exit_code" "$cmd"

    # Cleanup and exit
    cleanup_handler "$exit_code"
    exit "$exit_code"
}

# Enhanced error recovery function
attempt_error_recovery() {
    local error_context="$1"
    local exit_code="$2"
    local failed_cmd="$3"

    print_verbose "Attempting error recovery for: $error_context"

    case "$error_context" in
        "TIMEOUT")
            # Recovery from timeout - adjust timeouts and retry if possible
            log_message "INFO" "Recovery: Increasing timeout for subsequent operations"
            export STACKSCAN_TIMEOUT_MULTIPLIER=${STACKSCAN_TIMEOUT_MULTIPLIER:-1.5}
            ;;
            
        "COMMAND_NOT_FOUND")
            # Recovery from missing command - suggest installation
            log_message "INFO" "Recovery: Checking for alternative tools..."
            suggest_alternative_tools "$failed_cmd"
            ;;
            
        "PERMISSION_DENIED")
            # Recovery from permission issues - check SUDO and file permissions
            log_message "INFO" "Recovery: Checking file permissions and SUDO status..."
            check_and_fix_permissions
            ;;
            
        "INTERRUPTED")
            # Recovery from interruption - graceful shutdown
            log_message "INFO" "Recovery: Graceful shutdown initiated"
            export STACKSCAN_INTERRUPTED=true
            ;;
            
        "COMMAND_FAILED")
            # Generic command failure - log system state
            log_message "INFO" "Recovery: Logging system state for debugging..."
            log_system_state
            ;;
    esac
}

# Function to suggest alternative tools
suggest_alternative_tools() {
    local failed_cmd="$1"
    
    case "$failed_cmd" in
        "nmap")
            log_message "INFO" "Alternative: Install nmap with: apt install nmap (Ubuntu) or yum install nmap (CentOS)"
            ;;
        "curl")
            log_message "INFO" "Alternative: Use wget or install curl with: apt install curl"
            ;;
        "jq")
            log_message "INFO" "Alternative: Parse JSON manually or install jq with: apt install jq"
            ;;
        *)
            log_message "INFO" "Alternative: Check package manager for $failed_cmd"
            ;;
    esac
}

# Function to check and fix permissions
check_and_fix_permissions() {
    # Check critical directories
    local critical_dirs=(
        "${STACKSCAN_LOG_DIR:-/var/log/stackscan}"
        "${STACKSCAN_DATA_DIR:-/var/lib/stackscan}"
        "${STACKSCAN_TMP_DIR:-/tmp/stackscan}"
    )
    
    for dir in "${critical_dirs[@]}"; do
        if [ -d "$dir" ]; then
            local current_perms=$(stat -c "%a" "$dir" 2>/dev/null)
            local current_owner=$(stat -c "%U" "$dir" 2>/dev/null)
            
            # Fix ownership issues
            if [ "$current_owner" != "$SUDO_USER" ] && [ "$current_owner" != "root" ]; then
                log_message "INFO" "Fixing ownership for $dir"
                chown -R "$SUDO_USER":"$SUDO_USER" "$dir" 2>/dev/null || true
            fi
            
            # Fix permission issues
            case "$(basename "$dir")" in
                "stackscan")
                    # Data directory needs write access
                    if [ "$current_perms" != "750" ]; then
                        log_message "INFO" "Fixing permissions for $dir"
                        chmod -R 750 "$dir" 2>/dev/null || true
                    fi
                    ;;
                "reports")
                    # Reports need readable by web server
                    if [ "$current_perms" != "750" ]; then
                        log_message "INFO" "Fixing permissions for $dir"
                        chmod -R 750 "$dir" 2>/dev/null || true
                    fi
                    ;;
                *)
                    # Default secure permissions
                    if [ "$current_perms" != "700" ]; then
                        log_message "INFO" "Fixing permissions for $dir"
                        chmod -R 700 "$dir" 2>/dev/null || true
                    fi
                    ;;
            esac
        fi
    done
}

# Function to log system state for debugging
log_system_state() {
    log_message "INFO" "=== SYSTEM STATE ==="
    log_message "INFO" "User: $(whoami)"
    log_message "INFO" "SUDO_USER: ${SUDO_USER:-not set}"
    log_message "INFO" "Working Directory: $(pwd)"
    log_message "INFO" "Disk Space: $(df -h / | tail -1)"
    log_message "INFO" "Memory Usage: $(free -h | grep Mem)"
    log_message "INFO" "Load Average: $(uptime | awk -F'load average:' '{print $4}')"
    log_message "INFO" "Environment Variables:"
    env | grep -E '^STACKSCAN|^TARGET|^LOG_LEVEL' | while read line; do
        log_message "INFO" "  $line"
    done
    log_message "INFO" "==================="
}

# Cleanup handler function
cleanup_handler() {
    local exit_code=${1:-0}

    print_verbose "Starting cleanup process..."

    # Kill all background processes
    for pid in "${BACKGROUND_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done

    # Clean up temporary files
    local tmp_dir="${STACKSCAN_TMP_DIR:-/tmp/stackscan}"
    if [ -d "$tmp_dir" ]; then
        rm -rf "$tmp_dir"/* 2>/dev/null || true
    fi

    # Clean up scan output files based on patterns
    local cleanup_patterns=(
        "*_scan_output.txt"
        "*_output.txt"
        "*_log.txt"
    )

    for pattern in "${cleanup_patterns[@]}"; do
        rm -f "${STACKSCAN_DATA_DIR:-/var/lib/stackscan}/reports"/$pattern 2>/dev/null || true
    done

    print_verbose "Cleanup completed with exit code: $exit_code"
    return $exit_code
}

# Function to parse command line arguments
parse_arguments() {
    # Initialize global variables
    OUTPUT_JSON=false
    EDUCATIONAL_MODE=false
    TARGET=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --json)
                OUTPUT_JSON=true
                shift
                ;;
            --explain|--learn|--educational)
                EDUCATIONAL_MODE=true
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            -*)
                print_error "Unknown option: $1"
                print_error "Usage: $0 [OPTIONS] <domain_or_ip>"
                print_error "Use --help for more information"
                exit 1
                ;;
            *)
                if [ -z "$TARGET" ]; then
                    TARGET="$1"
                else
                    print_error "Error: Multiple targets specified"
                    exit 1
                fi
                shift
                ;;
        esac
    done

    # Check if target was provided
    if [ -z "$TARGET" ]; then
        print_error "Usage: $0 [OPTIONS] <domain_or_ip>"
        print_error "Use --help for more information"
        exit 1
    fi

    return 0
}

# Function to show help
show_help() {
    cat <<'EOF'
StackScan - Comprehensive Security Scanner
==========================================

Usage: sudo $0 [OPTIONS] <domain_or_ip>

OPTIONS:
  --json              Output JSON report to console
  --explain           Enable educational mode with detailed explanations
  --learn             Alias for --explain
  --educational       Alias for --explain
  --help, -h          Show this help message

EXAMPLES:
  sudo $0 192.168.1.1                 # Basic scan
  sudo $0 --explain example.com       # Scan with educational explanations
  sudo $0 --json --explain target.com # JSON output + learning mode

EDUCATIONAL MODE:
  The --explain flag provides detailed explanations about:
  • What each scan does and why
  • How tools work (Nmap, Wapiti, Nikto, etc.)
  • OWASP Top 10 vulnerabilities
  • CVE/CVSS scoring systems
  • Attack vs Defense perspectives
  • CEH exam preparation tips

Perfect for security training and education!

EOF
}

# Function to count vulnerabilities and CVEs from scan results
count_findings() {
    local target_ip="$1"
    local vuln_count=0
    local cve_count=0

    # Count vulnerabilities from all scan output files
    for file in "${target_ip}"_*_scan_output.txt "${target_ip}"_*_wapiti_output.txt "${target_ip}"_*_nikto_output.txt "${target_ip}"_*_wpscan_output.txt "${target_ip}"_*_sqlmap_output.txt; do
        if [ -f "$file" ] && [ -s "$file" ]; then
            # Count lines containing vulnerability indicators
            local file_vuln_count
            file_vuln_count=$(grep -ic -E "vuln|vulnerable|exploit|weakness|security" "$file" 2>/dev/null || echo "0")
            vuln_count=$((vuln_count + file_vuln_count))
        fi
    done

    # Count unique CVEs from all scan output files
    local cve_list=""
    for file in "${target_ip}"_*_scan_output.txt "${target_ip}"_*_wapiti_output.txt "${target_ip}"_*_nikto_output.txt "${target_ip}"_*_wpscan_output.txt "${target_ip}"_*_sqlmap_output.txt; do
        if [ -f "$file" ] && [ -s "$file" ]; then
            cve_list+=$(grep -oE "CVE-[0-9]+-[0-9]+" "$file" 2>/dev/null || echo "")$'\n'
        fi
    done
    cve_count=$(echo "$cve_list" | sort -u | grep -c "CVE-" || echo "0")

    STATS_VULNERABILITIES=$vuln_count
    STATS_CVES=$cve_count

    print_verbose "Found $vuln_count potential vulnerabilities and $cve_count unique CVEs"
    return 0
}

# Set up error handling traps
setup_error_handling() {
    trap 'handle_error ${BASH_SOURCE[0]} ${LINENO} ${FUNCNAME[0]:-main} $?' ERR
    trap 'kill -TERM $$ 2>/dev/null' INT TERM
    trap 'cleanup_handler' EXIT
}

# Initialize utility module
init_utils() {
    setup_error_handling
    setup_directories || return 1
    setup_resource_limits || return 1
    setup_secure_permissions
    print_verbose "Utility module initialized"
    return 0
}