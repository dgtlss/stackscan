#!/bin/bash

# Nmap Scanning Module for StackScan
# Handles all Nmap-related operations and script management

# Global Nmap statistics
declare -A STATS_NMAP_SCANS=(
    [web]=0
    [auth]=0
    [database]=0
    [common]=0
    [vuln]=0
    [custom]=0
)

# Function to expand wildcard patterns to actual script names
expand_wildcard_scripts() {
    local script_pattern="$1"
    local expanded_scripts=()

    # Expand wildcard pattern to actual script names
    readarray -t expanded_scripts < <(find /usr/share/nmap/scripts/ -name "${script_pattern}.nse" -exec basename {} .nse \; 2>/dev/null)

    # Return the expanded script names as array
    echo "${expanded_scripts[@]}"
}

# Function to execute a single Nmap scan with scripts
run_nmap_with_scripts() {
    local group_name="$1"
    local target_ip="$2"
    local ip_version="$3"
    
    # Get group-specific configuration
    local nmap_options_var="${group_name^^}_NMAP_OPTIONS"
    local nmap_options="${!nmap_options_var}"
    
    local scripts_var="${group_name}_NMAP_SCRIPTS[@]"
    local scripts=("${!scripts_var}")
    
    local script_args_var="${group_name}_NMAP_SCRIPT_ARGS[@]"
    local script_args=("${!script_args_var}")
    
    local ports_var="${group_name}_PORTS"
    local ports="${!ports_var}"

    # Add IPv6 flag if needed
    if [ "$ip_version" == "IPv6" ]; then
        nmap_options="$nmap_options -6"
    fi

    local output_file="${target_ip}_${group_name}_${ip_version}_scan_output.txt"

    print_status "$(date '+[%Y-%m-%d %H:%M:%S]') Starting Nmap $group_name scan on $target_ip ($ip_version)..."

    # Loop through each script and apply its specific arguments
    for i in "${!scripts[@]}"; do
        local script="${scripts[$i]}"
        local args="${script_args[$i]}"

        # Expand wildcard patterns to actual script names
        local expanded_scripts=($(expand_wildcard_scripts "$script"))

        # Loop through each expanded script name
        for expanded_script in "${expanded_scripts[@]}"; do
            local individual_nmap_command="nmap $nmap_options -p $ports $target_ip --min-rate=100 --randomize-hosts >> $output_file -vv"

            if [ -n "$args" ]; then
                individual_nmap_command+=" --script=\"$expanded_script\" --script-args=\"$args\""
            else
                individual_nmap_command+=" --script=\"$expanded_script\""
            fi

            # Execute the Nmap command and append command and its output to the output file
            echo "Executing Nmap Command: $individual_nmap_command" >> "$output_file"
            eval run_with_timeout 3600 $individual_nmap_command >> "$output_file" 2>&1

            # Add a dividing line after each command's output
            echo " " >> "$output_file"
            echo "------------------------------------------------------------------" >> "$output_file"
            echo " " >> "$output_file"

            (spinner "Nmap $group_name scan - Script: $expanded_script") &
            print_verbose "Nmap command executed for $group_name ($ip_version), Script: $expanded_script: $individual_nmap_command"
        done
    done

    # Track statistics: count executed Nmap commands
    if [ -f "$output_file" ]; then
        local nmap_cmd_count
        nmap_cmd_count=$(grep -c "Executing Nmap Command" "$output_file" 2>/dev/null || echo "0")
        STATS_NMAP_SCANS[$group_name]=$((STATS_NMAP_SCANS[$group_name] + nmap_cmd_count))
    fi

    print_status "$(date '+[%Y-%m-%d %H:%M:%S]') Nmap $group_name scan on $target_ip ($ip_version) completed."
    print_verbose "$(date '+[%Y-%m-%d %H:%M:%S]') Nmap $group_name scan on $target_ip ($ip_version) completed."
}

# Function to run all scan groups for a specific IP version with optimized parallelism
run_scan_groups() {
    local ip_version="$1"
    local target_ip="$2"

    # Calculate optimal parallel jobs based on CPU cores
    local cpu_cores=$(nproc 2>/dev/null || echo "4")
    local max_parallel_jobs=$((cpu_cores > 8 ? 8 : cpu_cores))
    
    print_verbose "Running Nmap scans with up to $max_parallel_jobs parallel jobs"

    # Use job control for parallel execution
    set -m  # Enable job control
    
    # Function to run scan group with load balancing
    run_scan_with_priority() {
        local group="$1"
        local target="$2"
        local ip_version="$3"
        local priority="$4"
        
        # Add delay for lower priority scans to balance load
        if [ "$priority" = "low" ]; then
            sleep 2
        elif [ "$priority" = "medium" ]; then
            sleep 1
        fi
        
        run_nmap_with_scripts "$group" "$target" "$ip_version"
    }
    
    # Launch high priority scans first (web, auth)
    run_scan_with_priority "web" "$target_ip" "$ip_version" "high" &
    local web_scan_pid=$!
    
    run_scan_with_priority "auth" "$target_ip" "$ip_version" "high" &
    local auth_scan_pid=$!
    
    # Wait for high priority to start before medium priority
    sleep 0.5
    
    # Launch medium priority scans (database, vuln)
    run_scan_with_priority "database" "$target_ip" "$ip_version" "medium" &
    local database_scan_pid=$!
    
    run_scan_with_priority "vuln" "$target_ip" "$ip_version" "medium" &
    local vuln_scan_pid=$!
    
    # Launch common scan (low priority)
    run_scan_with_priority "common" "$target_ip" "$ip_version" "low" &
    local common_scan_pid=$!

    # Run custom group if defined
    local custom_scan_pid=""
    if [ -n "${CUSTOM_NMAP_SCRIPTS[0]}" ]; then
        if nmap --script-help="${CUSTOM_NMAP_SCRIPTS[0]}" > /dev/null 2>&1; then
            run_scan_with_priority "custom" "$target_ip" "$ip_version" "low" &
            custom_scan_pid=$!
        else
            print_warning "Custom scripts not found or invalid: ${CUSTOM_NMAP_SCRIPTS[0]}"
        fi
    fi

    # Monitor parallel jobs and prevent system overload
    local active_jobs=0
    while [ $active_jobs -lt $max_parallel_jobs ]; do
        # Check running jobs
        local running_jobs=($(jobs -r -p))
        active_jobs=${#running_jobs[@]}
        
        if [ $active_jobs -ge $max_parallel_jobs ]; then
            print_verbose "Max parallel jobs reached, waiting..."
            wait -n  # Wait for any job to finish
        fi
        
        # Check if specific scans are still running
        for pid_var in web_scan_pid auth_scan_pid database_scan_pid vuln_scan_pid common_scan_pid custom_scan_pid; do
            local pid_value="${!pid_var}"
            if [ -n "$pid_value" ] && ! kill -0 "$pid_value" 2>/dev/null; then
                print_verbose "Scan group completed, PID: $pid_value"
            fi
        done
    done

    # Return PIDs for wait tracking
    echo "$web_scan_pid $auth_scan_pid $database_scan_pid $common_scan_pid $vuln_scan_pid $custom_scan_pid"
}

# Function to extract open web ports from scan results
get_open_web_ports() {
    local target_ip="$1"
    local ipv4_file="${target_ip}_web_IPv4_scan_output.txt"
    local ipv6_file="${target_ip}_web_IPv6_scan_output.txt"
    local open_ports=""
    local retry_count=0
    local max_retries=3

    while [ "$retry_count" -lt "$max_retries" ]; do
        # Check and extract from the IPv4 scan output
        if [ -f "$ipv4_file" ]; then
            local ipv4_ports
            ipv4_ports=$(awk '
            /^[0-9]+\/tcp\s+open/ {
                if ($3 ~ /^http/) {
                    split($1, port_info, "/")
                    print port_info[1]
                }
            }' "$ipv4_file" 2>/dev/null)

            open_ports+="$ipv4_ports "
        fi

        # Check and extract from the IPv6 scan output if available
        if [ -f "$ipv6_file" ]; then
            local ipv6_ports
            ipv6_ports=$(awk '
            /^[0-9]+\/tcp\s+open/ {
                if ($3 ~ /^http/) {
                    split($1, port_info, "/")
                    print port_info[1]
                }
            }' "$ipv6_file" 2>/dev/null)

            open_ports+="$ipv6_ports "
        fi

        open_ports=$(echo "$open_ports" | xargs)

        if [ -n "$open_ports" ]; then
            break
        fi

        ((retry_count++))
        if [ $retry_count -lt $max_retries ]; then
            print_verbose "Retrying to detect open web ports ($retry_count/$max_retries)..."
            run_nmap_with_scripts "web" "$target_ip" "IPv4"
            wait $web_scan_pid
        fi
    done

    if [ $retry_count -eq $max_retries ] && [ -z "$open_ports" ]; then
        print_warning "Failed to detect open web ports after $max_retries attempts."
        return 1
    fi

    echo "$open_ports"
    return 0
}

# Function to detect specific services from scan results
detect_services() {
    local target_ip="$1"
    local wp_detected=false
    local sql_detected=false

    # Check Nmap IPv4 output for web services (WordPress)
    local nmap_web_output_v4="${target_ip}_web_IPv4_scan_output.txt"
    if [ -f "$nmap_web_output_v4" ]; then
        if grep -qis '<meta name="generator" content="WordPress"' "$nmap_web_output_v4"; then
            wp_detected=true
        fi
    fi

    # Check Nmap IPv6 output for web services (WordPress)
    local nmap_web_output_v6="${target_ip}_web_IPv6_scan_output.txt"
    if [ -f "$nmap_web_output_v6" ]; then
        if grep -qis '<meta name="generator" content="WordPress"' "$nmap_web_output_v6"; then
            wp_detected=true
        fi
    fi

    # Check Nmap IPv4 output for database services
    local nmap_db_output_v4="${target_ip}_database_IPv4_scan_output.txt"
    if [ -f "$nmap_db_output_v4" ]; then
        if grep -qis -e "mysql" -e "postgresql" -e "mssql" -e "mariadb" -e "oracle" -e "sybase" -e "db2" -e "sqlite" -e "access" -e "firebird" -e "informix" -e "teradata" -e "memsql" -e "dynamodb" -e "arangodb" -e "couchdb" -e "mongodb" -e "monetdb" -e "mckoi" -e "presto" -e "altibase" -e "cubrid" -e "intersystems cache" -e "tibero" -e "columnstore" -e "vertica" -e "mimer" -e "hana" -e "redshift" -e "clickhouse" -e "cockroachdb" -e "greenplum" -e "nuodb" -e "oceanbase" "$nmap_db_output_v4"; then
            sql_detected=true
        fi
    fi

    # Check Nmap IPv6 output for database services
    local nmap_db_output_v6="${target_ip}_database_IPv6_scan_output.txt"
    if [ -f "$nmap_db_output_v6" ]; then
        if grep -qis -e "mysql" -e "postgresql" -e "mssql" -e "mariadb" -e "oracle" -e "sybase" -e "db2" -e "sqlite" -e "access" -e "firebird" -e "informix" -e "teradata" -e "memsql" -e "dynamodb" -e "arangodb" -e "couchdb" -e "mongodb" -e "monetdb" -e "mckoi" -e "presto" -e "altibase" -e "cubrid" -e "intersystems cache" -e "tibero" -e "columnstore" -e "vertica" -e "mimer" -e "hana" -e "redshift" -e "clickhouse" -e "cockroachdb" -e "greenplum" -e "nuodb" -e "oceanbase" "$nmap_db_output_v6"; then
            sql_detected=true
        fi
    fi

    # Return results
    echo "$wp_detected $sql_detected"
}

# Function to validate Nmap installation and required scripts
check_nmap_requirements() {
    # Check if Nmap is installed
    if ! command -v nmap &> /dev/null; then
        print_error "Nmap is not installed. Please install it and try again."
        return 1
    fi

    # Check if nmap scripts directory exists
    if [ ! -d "/usr/share/nmap/scripts" ]; then
        print_warning "Nmap scripts directory not found. Some features may not work."
        return 0
    fi

    print_verbose "Nmap requirements validation passed"
    return 0
}

# Function to clean up Nmap output files
cleanup_nmap_outputs() {
    local target_ip="$1"
    
    local output_patterns=(
        "${target_ip}_*_scan_output.txt"
        "${target_ip}_*_IPv4_scan_output.txt"
        "${target_ip}_*_IPv6_scan_output.txt"
    )

    for pattern in "${output_patterns[@]}"; do
        rm -f $pattern 2>/dev/null
    done

    print_verbose "Cleaned up Nmap output files for $target_ip"
}

# Initialize Nmap module
init_nmap() {
    check_nmap_requirements || return 1
    print_verbose "Nmap module initialized"
    return 0
}