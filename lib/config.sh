#!/bin/bash

# Configuration Management Module for StackScan
# Handles loading, validation, and creation of configuration files

# Default configuration values
readonly DEFAULT_NMAP_OPTIONS="-Pn"
readonly DEFAULT_NIKTO_OPTIONS="-timeout 10"
readonly DEFAULT_WAPITI_OPTIONS="--flush-session --scope domain -d 5 --max-links-per-page 100 --flush-attacks --max-scan-time 1800 --timeout 10 -m all --verify-ssl 1"
readonly DEFAULT_WPSCAN_OPTIONS="--random-user-agent --disable-tls-checks --max-threads 10"
readonly DEFAULT_SQLMAP_OPTIONS="--batch --random-agent --level=3 --risk=2"
readonly DEFAULT_LOG_LEVEL="INFO"
readonly DEFAULT_GENERATE_HTML_REPORT="true"

# Load configuration from user's home directory
load_config() {
    local config_file="/home/$SUDO_USER/.stackscan.conf"
    
    if [ -f "$config_file" ]; then
        # Check ownership and permissions
        local owner=$(stat -c '%U' "$config_file" 2>/dev/null)
        local perms=$(stat -c '%a' "$config_file" 2>/dev/null)

        if [ "$owner" != "$SUDO_USER" ] || [ "$perms" != "600" ]; then
            log_message "ERROR" "Configuration file has incorrect ownership or permissions."
            return 1
        fi
        
        if ! source "$config_file"; then
            log_message "ERROR" "Failed to source config: $config_file"
            return 1
        fi
        
        log_message "INFO" "Configuration loaded from: $config_file"
        return 0
    else
        log_message "WARNING" "Configuration file not found. Creating default configuration."
        create_default_config
        return 0
    fi
}

# Create default configuration file
create_default_config() {
    if [ -z "$SUDO_USER" ]; then
        log_message "ERROR" "SUDO_USER is not set. Please run the script with sudo."
        return 1
    fi

    local config_file="/home/$SUDO_USER/.stackscan.conf"
    
    cat > "$config_file" <<EOL
# StackScan Configuration File
# Generated automatically on $(date)

# Default Nmap options
NMAP_OPTIONS="$DEFAULT_NMAP_OPTIONS"

# Group-specific Nmap scripts and their specific arguments

# Web Group
WEB_NMAP_OPTIONS="-sT"
WEB_NMAP_SCRIPTS=(
  "http-enum"
  "http-vuln*"
  "http-wordpress*"
  "http-phpmyadmin-dir-traversal"
  "http-config-backup"
  "http-vhosts"
  "http-sql-injection"
  "service-info"
)
WEB_NMAP_SCRIPT_ARGS=(
  "http-wordpress-enum.threads=10"
  "http-wordpress-brute.threads=10"
  "" "" "" "" "" "" ""
)
WEB_PORTS="80,443,8080,8443,8000,8888,8181,9090,8081,9000,10000,3000,5000,7000,7001,4433,10443,16080,61000,61001"

# Auth Group
AUTH_NMAP_OPTIONS="-sS -sV"
AUTH_NMAP_SCRIPTS=(
  "ssh*"
  "ftp*"
  "auth*"
  "ssh-auth-methods"
  "mysql-brute"
  "pgsql-brute"
  "ms-sql-brute"
  "oracle-brute"
  "mysql-empty-password"
  "ms-sql-empty-password"
)
AUTH_NMAP_SCRIPT_ARGS=(
  "" "" "" "" "" "" "" "" "" "" ""
)
AUTH_PORTS="22,21,389,636"

# Database Group
DATABASE_NMAP_OPTIONS="-sT -sV"
DATABASE_NMAP_SCRIPTS=(
  "mysql-audit"
  "mysql-info"
  "mysql-enum"
  "pgsql-info"
  "pgsql-databases"
  "ms-sql-config"
  "ms-sql-info"
  "ms-sql-dump-hashes"
  "ms-sql-query"
  "ms-sql-tables"
  "oracle-enum-users"
  "oracle-query"
  "oracle-tns-version"
  "oracle-sid-brute"
)
DATABASE_NMAP_SCRIPT_ARGS=(
  "" "" "" "" "" "" "" "" "" "" "" "" "" "" "" ""
)
DATABASE_PORTS="3306,5432,1433,1521,1522,1434,3050,3051"

# VULN Group-specific Nmap scripts and their specific arguments
VULN_NMAP_OPTIONS="-sS -A -sV"
VULN_NMAP_SCRIPTS=(
  "vulners"
  "http-vuln*"
  "ssl-heartbleed"
  "ftp-vsftpd-backdoor"
  "smb-vuln*"
  "http-csrf"
  "dns-zone-transfer"
)
VULN_NMAP_SCRIPT_ARGS=(
  "" "" "" "" "" "" ""
)
VULN_PORTS="21,22,25,53,80,110,443,445,1433,3306,3389"

# Common Group
COMMON_NMAP_OPTIONS="-sS -sV"
COMMON_NMAP_SCRIPTS=(
  "*apache*"
  "dns*"
  "smb*"
  "firewall*"
  "ssl-enum-ciphers"
  "ssl-cert"
  "service-info"
)
COMMON_NMAP_SCRIPT_ARGS=(
  "" "" "" "" "" "" ""
)
COMMON_PORTS="22,21,53,445"

# Custom Group (User-defined)
CUSTOM_NMAP_OPTIONS=""
CUSTOM_NMAP_SCRIPTS=("")
CUSTOM_NMAP_SCRIPT_ARGS=("")
CUSTOM_PORTS=""

# Third-party scanner options
NIKTO_OPTIONS="$DEFAULT_NIKTO_OPTIONS"
WAPITI_OPTIONS="$DEFAULT_WAPITI_OPTIONS"
WPSCAN_OPTIONS="$DEFAULT_WPSCAN_OPTIONS"
SQLMAP_OPTIONS="$DEFAULT_SQLMAP_OPTIONS"

# Report generation
GENERATE_HTML_REPORT="$DEFAULT_GENERATE_HTML_REPORT"

# Log level (VERBOSE, INFO, WARNING, ERROR, QUIET)
LOG_LEVEL="$DEFAULT_LOG_LEVEL"

EOL

    sync
    chown "$SUDO_USER":"$SUDO_USER" "$config_file"
    chmod 600 "$config_file"

    log_message "INFO" "Default configuration file created at: $config_file"
    
    # Source newly created config
    if ! source "$config_file"; then
        log_message "ERROR" "Failed to source the newly created configuration file."
        return 1
    fi
    
    return 0
}

# Set default values for any unset configuration variables
set_config_defaults() {
    # Set default Nmap options if not set
    NMAP_OPTIONS="${NMAP_OPTIONS:-$DEFAULT_NMAP_OPTIONS}"
    WEB_NMAP_OPTIONS="${WEB_NMAP_OPTIONS:--sT}"
    AUTH_NMAP_OPTIONS="${AUTH_NMAP_OPTIONS:--sS -sV}"
    DATABASE_NMAP_OPTIONS="${DATABASE_NMAP_OPTIONS:--sT -sV}"
    VULN_NMAP_OPTIONS="${VULN_NMAP_OPTIONS:--sS -A -sV}"
    COMMON_NMAP_OPTIONS="${COMMON_NMAP_OPTIONS:--sS -sV}"
    
    # Set default scanner options
    NIKTO_OPTIONS="${NIKTO_OPTIONS:-$DEFAULT_NIKTO_OPTIONS}"
    WAPITI_OPTIONS="${WAPITI_OPTIONS:-$DEFAULT_WAPITI_OPTIONS}"
    WPSCAN_OPTIONS="${WPSCAN_OPTIONS:-$DEFAULT_WPSCAN_OPTIONS}"
    SQLMAP_OPTIONS="${SQLMAP_OPTIONS:-$DEFAULT_SQLMAP_OPTIONS}"
    
    # Set default log level
    LOG_LEVEL="${LOG_LEVEL:-$DEFAULT_LOG_LEVEL}"
    
    # Set default report generation flag
    GENERATE_HTML_REPORT="${GENERATE_HTML_REPORT:-$DEFAULT_GENERATE_HTML_REPORT}"
    
    log_message "VERBOSE" "Configuration defaults applied"
}

# Enhanced configuration validation with security checks
validate_configuration() {
    log_message "INFO" "Validating configuration..."
    
    local validation_errors=0
    local validation_warnings=0

    # Security-first validation
    if [ "${SECURE_MODE:-true}" = "true" ]; then
        # Check for insecure defaults
        if [[ "$NMAP_OPTIONS" =~ -A ]] && [[ "$NMAP_OPTIONS" =~ -Pn ]]; then
            log_message "WARNING" "Aggressive Nmap options detected in secure mode"
            ((validation_warnings++))
        fi
        
        # Validate scanner options for security
        for scanner_var in NIKTO_OPTIONS WAPITI_OPTIONS WPSCAN_OPTIONS SQLMAP_OPTIONS; do
            local scanner_options="${!scanner_var}"
            if [[ "$scanner_options" =~ (-random-agent|-user-agent) ]]; then
                log_message "INFO" "User agent randomization detected - good security practice"
            fi
        done
    fi

    # Validate port ranges with enhanced checks
    for group in WEB AUTH DATABASE COMMON VULN; do
        local ports_var="${group}_PORTS"
        local ports="${!ports_var}"
        
        if [ -n "$ports" ]; then
            # Check if ports contain valid numbers and commas
            if ! [[ "$ports" =~ ^[0-9,-]+$ ]]; then
                log_message "ERROR" "Invalid port format in ${group}_PORTS: $ports"
                ((validation_errors++))
                continue
            fi
            
            # Check for dangerous port ranges
            local ports_array=(${ports//,/ })
            for port in "${ports_array[@]}"; do
                # Skip port 0 and >65535
                if [ "$port" -le 0 ] || [ "$port" -gt 65535 ]; then
                    log_message "ERROR" "Invalid port range in ${group}_PORTS: $port (must be 1-65535)"
                    ((validation_errors++))
                fi
                
                # Warn about scanning well-known privileged ports
                if [ "$port" -le 1024 ] && [ "$SECURE_MODE" = "true" ]; then
                    log_message "WARNING" "Scanning privileged port $port in secure mode"
                    ((validation_warnings++))
                fi
            done
        fi
    done

    # Enhanced Nmap script validation
    for group in WEB AUTH DATABASE COMMON VULN; do
        local scripts_var="${group}_NMAP_SCRIPTS[@]}"
        local scripts=("${!scripts_var}")
        
        for script in "${scripts[@]}"; do
            if [ -n "$script" ]; then
                if [[ ! "$script" =~ \* ]]; then
                    # Validate non-wildcard scripts
                    if [ ! -f "/usr/share/nmap/scripts/${script}.nse" ]; then
                        log_message "WARNING" "Nmap script not found: ${script}.nse (will be skipped)"
                        ((validation_warnings++))
                    else
                        # Check script dependencies
                        check_script_dependencies "$script" || ((validation_errors++))
                    fi
                else
                    # Validate wildcard patterns
                    local expanded_count=$(find /usr/share/nmap/scripts/ -name "${script}.nse" 2>/dev/null | wc -l)
                    if [ "$expanded_count" -eq 0 ]; then
                        log_message "WARNING" "Wildcard pattern '$script' matches no scripts"
                        ((validation_warnings++))
                    fi
                fi
            fi
        done
    done

    # Validate third-party scanner options
    validate_scanner_options || ((validation_errors++))

    # Validate log level with enhanced checks
    if ! [[ "$LOG_LEVEL" =~ ^(VERBOSE|INFO|WARNING|ERROR|QUIET)$ ]]; then
        log_message "ERROR" "Invalid LOG_LEVEL: $LOG_LEVEL. Must be one of: VERBOSE, INFO, WARNING, ERROR, QUIET"
        ((validation_errors++))
    elif [ "$LOG_LEVEL" = "VERBOSE" ] && [ "${PRODUCTION_MODE:-false}" = "true" ]; then
        log_message "WARNING" "Verbose mode enabled in production mode"
        ((validation_warnings++))
    fi

    # Validate timeout values
    validate_timeout_values || ((validation_errors++))

    # Output final validation results
    if [ $validation_errors -gt 0 ]; then
        log_message "ERROR" "Configuration validation failed with $validation_errors error(s)"
        if [ $validation_warnings -gt 0 ]; then
            log_message "WARNING" "Additional $validation_warnings warning(s) found"
        fi
        return 1
    fi

    if [ $validation_warnings -gt 0 ]; then
        log_message "WARNING" "Configuration validation passed with $validation_warnings warning(s)"
    else
        log_message "INFO" "Configuration validation passed ✓"
    fi
    
    return 0
}

# Function to validate Nmap script dependencies
check_script_dependencies() {
    local script="$1"
    local script_path="/usr/share/nmap/scripts/${script}.nse"
    
    if [ ! -f "$script_path" ]; then
        return 0
    fi
    
    # Check for common dependency indicators in script content
    local dependencies
    dependencies=$(grep -o -E "(require|nmap\.library|http\.get|ssl\.[a-z])" "$script_path" 2>/dev/null || echo "")
    
    if [ -n "$dependencies" ]; then
        log_message "INFO" "Script $script has dependencies: $dependencies"
        
        # Check if dependency libraries are available
        if [[ "$dependencies" =~ ssl ]] && ! command -v openssl &> /dev/null; then
            log_message "WARNING" "SSL dependency required for $script but openssl not available"
            return 1
        fi
        
        if [[ "$dependencies" =~ http ]] && ! command -v curl &> /dev/null; then
            log_message "WARNING" "HTTP dependency required for $script but curl not available"
            return 1
        fi
    fi
    
    return 0
}

# Function to validate third-party scanner options
validate_scanner_options() {
    local scanner_configs=(
        "NIKTO_OPTIONS:nikto"
        "WAPITI_OPTIONS:wapiti"
        "WPSCAN_OPTIONS:wpscan"
        "SQLMAP_OPTIONS:sqlmap"
    )
    
    for config_pair in "${scanner_configs[@]}"; do
        local options_var="${config_pair%:*}"
        local scanner_name="${config_pair#*:}"
        local options="${!options_var}"
        
        # Check for insecure options
        if [[ "$options" =~ (-no-follow|--insecure) ]] && [ "${SECURE_MODE:-true}" = "true" ]; then
            log_message "ERROR" "Insecure options detected in $scanner_name configuration: $options"
            return 1
        fi
        
        # Validate timeout values
        if [[ "$options" =~ --timeout[[:space:]]*([0-9]+) ]]; then
            local timeout_value="${BASH_REMATCH[1]}"
            if [ "$timeout_value" -gt 7200 ]; then
                log_message "WARNING" "$scanner_name timeout value very high: ${timeout_value}s"
            elif [ "$timeout_value" -lt 30 ]; then
                log_message "WARNING" "$scanner_name timeout value very low: ${timeout_value}s"
            fi
        fi
    done
    
    return 0
}

# Function to validate timeout values
validate_timeout_values() {
    # Validate global timeout multiplier
    local timeout_multiplier="${STACKSCAN_TIMEOUT_MULTIPLIER:-1.0}"
    if [[ "$timeout_multiplier" =~ ^[0-9]+\.?[0-9]*$ ]]; then
        if (( $(echo "$timeout_multiplier < 0.5" 2>/dev/null || echo "1"))); then
            log_message "ERROR" "Timeout multiplier too low: $timeout_multiplier (minimum 0.5)"
            return 1
        elif (( $(echo "$timeout_multiplier > 5.0" 2>/dev/null || echo "1"))); then
            log_message "ERROR" "Timeout multiplier too high: $timeout_multiplier (maximum 5.0)"
            return 1
        fi
    else
        log_message "ERROR" "Invalid timeout multiplier format: $timeout_multiplier"
        return 1
    fi
    
    log_message "VERBOSE" "Timeout multiplier set to: $timeout_multiplier"
    return 0
}

# Initialize configuration system
init_config() {
    load_config || return 1
    set_config_defaults
    validate_configuration || return 1
    return 0
}