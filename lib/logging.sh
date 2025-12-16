#!/bin/bash

# Logging and Output Module for StackScan
# Handles all logging, output formatting, and banner display

# ANSI color codes
readonly BOLD="\033[1m"
readonly CYAN="\033[36m"
readonly GREEN="\033[32m"
readonly YELLOW="\033[33m"
readonly RED="\033[31m"
readonly RESET="\033[0m"

# Global log file variable (will be set in main script)
LOG_FILE=""

# Function to log messages with timestamps
log_message() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")

    # Only log VERBOSE messages if in verbose mode
    if [ "$level" = "VERBOSE" ] && [ "${LOG_LEVEL:-INFO}" != "VERBOSE" ]; then
        return
    fi

    # Log to file if available
    if [ -n "$LOG_FILE" ]; then
        echo "[$timestamp] $level: $message" >> "$LOG_FILE"
    fi

    # Console output based on log level
    case "$level" in
        ERROR)   echo -e "${RED}$message${RESET}" ;;
        WARNING) [[ "${LOG_LEVEL:-INFO}" != "QUIET" ]] && echo -e "${YELLOW}$message${RESET}" ;;
        INFO)    [[ "${LOG_LEVEL:-INFO}" =~ ^(INFO|VERBOSE)$ ]] && echo -e "${GREEN}$message${RESET}" ;;
        VERBOSE) [[ "${LOG_LEVEL:-INFO}" == "VERBOSE" ]] && echo -e "${CYAN}$message${RESET}" ;;
    esac
}

# Convenience functions for different log levels
print_status() {
    log_message "INFO" "$1"
}

print_verbose() {
    log_message "VERBOSE" "$1"
}

print_warning() {
    log_message "WARNING" "$1"
}

print_error() {
    log_message "ERROR" "$1"
}

# Function to print the StackScan banner
print_banner() {
    local banner_text="
    \e[1;31m  ██████ \e[1;32m▄▄▄█████▓ \e[1;33m▄▄▄       \e[1;34m▄████▄  \e[1;35m ██ ▄█▀  \e[1;36m ██████  \e[1;31m▄████▄  \e[1;32m ▄▄▄       \e[1;33m ███▄    █
    \e[1;31m▒██    ▒ \e[1;32m▓  ██▒ ▓▒\e[1;33m▒████▄    \e[1;34m▒██▀ ▀█  \e[1;35m ██▄█▒  \e[1;36m▒██    ▒ \e[1;31m▒██▀ ▀█  \e[1;32m▒████▄     \e[1;33m ██ ▀█   █
    \e[1;31m░ ▓██▄   \e[1;32m▒ ▓██░ ▒░\e[1;33m▒██  ▀█▄  \e[1;34m▒▓█    ▄ \e[1;35m▓███▄░  \e[1;36m░ ▓██▄   \e[1;31m▒▓█    ▄ \e[1;32m▒██  ▀█▄  \e[1;33m▓██  ▀█ ██▒
    \e[1;31m  ▒   ██▒\e[1;32m░ ▓██▓ ░ \e[1;33m░██▄▄▄▄██ \e[1;34m▒▓▓▄ ▄██▒\e[1;35m▓██ █▄  \e[1;36m  ▒   ██▒\e[1;31m▒▓▓▄ ▄██▒\e[1;32m░██▄▄▄▄██ \e[1;33m▓██▒  ▐▌██▒
    \e[1;31m▒██████▒▒\e[1;32m  ▒██▒ ░  \e[1;33m▓█   ▓██▒\e[1;34m▒ ▓███▀ ░\e[1;35m▒██▒ █▄ \e[1;36m▒██████▒▒\e[1;31m▒ ▓███▀ ░\e[1;32m ▓█   ▓██▒\e[1;33m▓██░   ▓██░
    \e[1;31m▒ ▒▓▒ ▒ ░\e[1;32m  ▒ ░░    \e[1;33m▒▒   ▓▒█░\e[1;34m░ ░▒ ▒  ░\e[1;35m▒ ▒▒ ▓▒\e[1;36m▒ ▒▓▒ ▒ ░\e[1;31m░ ░▒ ▒  ░\e[1;32m  ▒   ▒▒ ░\e[1;33m▒▒   ▓▒█░\e[1;33m░ ▒░   ▒ ▒
    \e[1;31m░ ░▒  ░ ░\e[1;32m    ░      \e[1;33m▒   ▒▒ ░\e[1;34m  ░  ▒   \e[1;35m░ ░▒ ▒░\e[1;36m░ ░▒  ░ ░ \e[1;31m  ░  ▒   \e[1;32m  ▒   ▒▒ ░\e[1;33m░ ░░   ░ ▒░
    \e[1;31m░  ░  ░  \e[1;32m  ░        \e[1;33m▒   ▒   \e[1;34m       ░ \e[1;35m░ ░░ ░ \e[1;36m░  ░  ░   \e[1;31m       ░ \e[1;32m    ░   ▒   \e[1;33m   ░   ░ ░
    \e[1;31m      ░  \e[1;32m             \e[1;33m▒  ░\e[1;34m░ ░      \e[1;35m░  ░   \e[1;36m       ░   \e[1;31m░ ░      \e[1;32m    ░  ░\e[1;33m        ░
                                 ░                        ░

    \e[1;31m                               StackScan (c) 2024 Zayn Otley
    \e[1;32m                         https://github.com/intuitionamiga/stackscan
    \e[1;34m                            MIT License - Use at your own risk!

    "

    # Print with ANSI coloring to the console
    echo -e "${BOLD}${CYAN}$banner_text${RESET}"

    # If target not blank then log the banner to the log file
    if [ -n "${TARGET:-}" ] && [ -n "${TARGET_TYPE:-}" ]; then
        # Strip all ANSI escape codes from the banner and print to the log file
        echo -e "$banner_text" | sed "s,\x1B\[[0-9;]*[a-zA-Z],,g" >> "$LOG_FILE"
    fi
}

# Progress tracking functions
update_scan_stage() {
    local stage="$1"
    local status="$2"  # PENDING, IN_PROGRESS, COMPLETED, FAILED

    SCAN_STAGE_STATUS["$stage"]="$status"
    CURRENT_SCAN_STAGE="$stage"

    # Calculate progress percentage
    local completed_stages=0
    for s in "${!SCAN_STAGE_STATUS[@]}"; do
        if [ "${SCAN_STAGE_STATUS[$s]}" = "COMPLETED" ]; then
            ((completed_stages++))
        fi
    done
    local progress_percent=$((completed_stages * 100 / TOTAL_SCAN_STAGES))

    # Display progress
    local stage_display=$(echo "$stage" | tr '_' ' ' | awk '{for(i=1;i<=NF;i++) $i=toupper(substr($i,1,1)) tolower(substr($i,2));}1')
    if [ "$status" = "IN_PROGRESS" ]; then
        print_status "$(date '+[%Y-%m-%d %H:%M:%S]') [${progress_percent}%] Stage: ${stage_display} - ${status}"
    elif [ "$status" = "COMPLETED" ]; then
        print_status "$(date '+[%Y-%m-%d %H:%M:%S]') [${progress_percent}%] Stage: ${stage_display} - ${status} ✓"
    elif [ "$status" = "FAILED" ]; then
        print_warning "$(date '+[%Y-%m-%d %H:%M:%S]') [${progress_percent}%] Stage: ${stage_display} - ${status} ✗"
    fi
}

show_scan_progress() {
    local completed=0
    local failed=0
    local in_progress=0
    local pending=0

    for stage in "${!SCAN_STAGE_STATUS[@]}"; do
        case "${SCAN_STAGE_STATUS[$stage]}" in
            COMPLETED) ((completed++)) ;;
            FAILED) ((failed++)) ;;
            IN_PROGRESS) ((in_progress++)) ;;
            PENDING) ((pending++)) ;;
        esac
    done

    echo ""
    echo "Scan Progress: $completed/$TOTAL_SCAN_STAGES stages completed"
    if [ $failed -gt 0 ]; then
        echo "Failed stages: $failed"
    fi
}

# Spinner function for long-running processes
spinner() {
    local delay=0.1
    local spinstr='|/-\'

    local scan_name="$1"
    local start_time=$(date +%s)

    while kill -0 $! 2>/dev/null; do
        # Calculate elapsed time
        local current_time=$(date +%s)
        local elapsed_time=$((current_time - start_time))

        # Format elapsed time as HH:MM:SS
        local hours=$((elapsed_time / 3600))
        local minutes=$(( (elapsed_time % 3600) / 60 ))
        local seconds=$((elapsed_time % 60))
        local formatted_time=$(printf "%02d:%02d:%02d" $hours $minutes $seconds)

        # Create the spinner string
        local temp=${spinstr#?}
        local spinner_str=$(printf " [%c] %s (%s)" "$spinstr" "$scan_name" "$formatted_time")
        spinstr=$temp${spinstr%"$temp"}

        # Calculate the padding needed to right-align the spinner
        local terminal_width=$(tput cols 2>/dev/null || echo 80)

        # Display the right-justified spinner
        printf "%*s\r" "$terminal_width" "$spinner_str"
        sleep $delay
    done
    printf "    \r"  # Clear spinner after process is done
}

# Educational mode information display
print_educational_info() {
    local topic="$1"

    if [ "${EDUCATIONAL_MODE:-false}" != "true" ]; then
        return 0
    fi

    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}${GREEN}📚 EDUCATIONAL INFO: $topic${RESET}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${RESET}"

    case "$topic" in
        "SCAN_START")
            cat <<'EOF'

 🎯 WHAT WE'RE DOING:
    StackScan performs a comprehensive security assessment using multiple
    industry-standard tools to discover vulnerabilities in your target.

 🔍 SCAN METHODOLOGY:
    1. Reconnaissance - Gather information about the target
    2. Service Detection - Identify running services and versions
    3. Vulnerability Scanning - Test for known weaknesses
    4. Web Application Testing - Check for web-specific vulnerabilities
    5. Exploitation Verification - Confirm vulnerabilities are real

 📖 WHY THIS MATTERS:
    Security assessments help identify weaknesses BEFORE attackers do.
    Each vulnerability found is an opportunity to strengthen your defenses.

 ⚠️  LEGAL NOTE:
    Only scan systems you own or have explicit written permission to test.
    Unauthorized scanning is illegal in most jurisdictions.

EOF
            ;;
        "NMAP_SCANNING")
            cat <<'EOF'

 🔧 NMAP - The Network Mapper

WHAT IT DOES:
    Nmap is the industry standard for network discovery and security auditing.
    It sends specially crafted packets to determine what ports are open and
    what services are running.

HOW IT WORKS:
    • Port Scanning: Tests which network ports (1-65535) are accepting connections
    • Service Detection: Identifies software/version running on each port
    • OS Fingerprinting: Attempts to determine the operating system
    • Script Scanning: Runs specialized tests for known vulnerabilities

ATTACK PERSPECTIVE:
    Attackers use Nmap to:
    - Find exposed services (potential entry points)
    - Identify outdated software versions (known vulnerabilities)
    - Map network topology (plan multi-stage attacks)

DEFENSIVE VALUE:
    - Discover unnecessary exposed services (reduce attack surface)
    - Find misconfigured systems (fix before attackers find them)
    - Verify firewall rules are working correctly

CEH EXAM TIP:
    Know the different Nmap scan types:
    -sT (TCP Connect), -sS (SYN Stealth), -sU (UDP), -sV (Version Detection)

EOF
            ;;
        "WEB_SCANNING")
            cat <<'EOF'

 🌐 WEB APPLICATION SCANNING

WHY WEB APPS ARE TARGETED:
    70% of attacks target the application layer (OWASP statistics).
    Web apps often have direct access to databases and sensitive data.

TOOLS USED:
    • Wapiti - Automated web vulnerability scanner
    • Nikto - Web server misconfiguration detector
    • WPScan - WordPress-specific security scanner (if detected)
    • SQLMap - SQL injection detection and exploitation (if detected)

COMMON WEB VULNERABILITIES:
    1. SQL Injection (OWASP A03:2021)
       - Attackers inject malicious SQL to access/modify database
       - Can lead to complete database compromise

    2. Cross-Site Scripting/XSS (OWASP A03:2021)
       - Inject malicious JavaScript into pages viewed by other users
       - Can steal sessions, credentials, or redirect to malware

    3. Authentication Flaws (OWASP A07:2021)
       - Weak passwords, session hijacking, broken logout
       - Direct access to user accounts

    4. Security Misconfiguration (OWASP A05:2021)
       - Default credentials, unnecessary features enabled
       - Directory listings, verbose error messages

WHAT ATTACKERS LOOK FOR:
    - Login pages (brute force attempts)
    - File upload functionality (malware upload)
    - User input fields (injection attacks)
    - Admin interfaces (privilege escalation)

EOF
            ;;
        # Add more educational topics as needed...
        *)
            echo "Educational information for '$topic' will be available in future updates."
            ;;
    esac

    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${RESET}"
    echo ""
}

# Initialize logging system
init_logging() {
    local log_dir="${STACKSCAN_LOG_DIR:-/var/log/stackscan}"
    local target_safe="${TARGET_SAFE:-unknown}"
    local date_time="${DATE_TIME:-$(date +'%Y%m%d_%H%M%S')}"
    
    LOG_FILE="${log_dir}/${target_safe}_${date_time}_scan.log"
    
    # Ensure log directory exists
    if [ ! -d "$log_dir" ]; then
        mkdir -p "$log_dir" 2>/dev/null || {
            echo "Warning: Could not create log directory $log_dir"
            return 1
        }
        chmod 755 "$log_dir" 2>/dev/null
    fi
    
    # Create log file with secure permissions
    touch "$LOG_FILE" 2>/dev/null || {
        echo "Warning: Could not create log file $LOG_FILE"
        return 1
    }
    chmod 600 "$LOG_FILE" 2>/dev/null
    
    if [ -n "$SUDO_USER" ]; then
        chown "$SUDO_USER":"$SUDO_USER" "$LOG_FILE" 2>/dev/null
    fi
    
    print_verbose "Logging initialized. Log file: $LOG_FILE"
    return 0
}