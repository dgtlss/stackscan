#!/bin/bash

# Third-Party Scanners Module for StackScan
# Handles Wapiti, Nikto, WPScan, and SQLMap operations

# Global scanner statistics
STATS_WAPITI_SCANS=0
STATS_NIKTO_SCANS=0
STATS_WPSCAN_SCANS=0
STATS_SQLMAP_SCANS=0

# Function to check if external scanner tool is available
check_scanner_available() {
    local scanner="$1"
    if ! command -v "$scanner" &> /dev/null; then
        print_warning "$(date '+[%Y-%m-%d %H:%M:%S]') ${scanner} not found - skipping ${scanner} scans"
        log_message "WARNING" "${scanner} not available in PATH"
        return 1
    fi
    return 0
}

# Function to handle scanner errors gracefully
handle_scanner_error() {
    local scanner_name="$1"
    local exit_code="$2"
    local target="$3"

    if [ $exit_code -ne 0 ]; then
        ((STATS_FAILED_SCANS++))
        if [ $exit_code -eq 124 ]; then
            log_message "WARNING" "${scanner_name} scan timed out on ${target}"
            print_warning "$(date '+[%Y-%m-%d %H:%M:%S]') ${scanner_name} scan timed out on ${target} (continuing...)"
        elif [ $exit_code -eq 127 ]; then
            log_message "WARNING" "${scanner_name} command not found - skipping"
            print_warning "$(date '+[%Y-%m-%d %H:%M:%S]') ${scanner_name} not installed - skipping scan"
        else
            log_message "WARNING" "${scanner_name} scan failed with exit code ${exit_code} on ${target}"
            print_warning "$(date '+[%Y-%m-%d %H:%M:%S]') ${scanner_name} scan failed on ${target} (continuing...)"
        fi
        return 1
    fi
    return 0
}

# Wapiti web vulnerability scanner
run_wapiti_scan() {
    local target_ip="$1"
    shift  # Shift to get ports array
    local ports=("$@")
    
    if ! check_scanner_available "wapiti"; then
        return 1
    fi

    local wapiti_pids=()
    declare -A wapiti_scanned_ports
    local wapiti_scan_count=0

    trap '' PIPE  # Ignore SIGPIPE to prevent script termination

    for port in "${ports[@]}"; do
        if [ "${wapiti_scanned_ports[$port]}" ]; then
            continue
        fi

        local url="http://$target_ip:$port"
        if [[ "$port" == "443" || "$port" == "8443" ]]; then
            url="https://$target_ip:$port"
        fi

        print_status "$(date '+[%Y-%m-%d %H:%M:%S]') Starting Wapiti scan on $target_ip:$port..."
        local output_file="${SCAN_DIR:-.}/${target_ip}_${port}_wapiti_output.txt"
        
        # Log exact Wapiti command being executed
        print_verbose "Executing Wapiti command: wapiti -u \"$url\" $WAPITI_OPTIONS -f txt -o \"$output_file\""

        (run_with_timeout 3600 wapiti -u "$url" $WAPITI_OPTIONS -f txt -o "$output_file" > "${output_file}_log.txt" 2>&1) &
        local wapiti_pid=$!
        wapiti_pids+=("$wapiti_pid")

        wapiti_scanned_ports[$port]=1
        ((wapiti_scan_count++))

        # Start spinner for this Wapiti process
        (spinner "Wapiti on Port $port") &
        local spinner_pid=$!

        # Wait for Wapiti to complete and kill spinner
        wait "$wapiti_pid" || true
        kill $spinner_pid 2>/dev/null

        # Add dividing line after each scan's output
        echo " " >> "$output_file"
        echo "------------------------------------------------------------------" >> "$output_file"
        echo " " >> "$output_file"
    done

    # Wait for all Wapiti processes to complete
    for pid in "${wapiti_pids[@]}"; do
        wait $pid || true
    done

    STATS_WAPITI_SCANS=$wapiti_scan_count

    print_status "$(date '+[%Y-%m-%d %H:%M:%S]') Wapiti scan on $target_ip:$port completed."
    print_verbose "$(date '+[%Y-%m-%d %H:%M:%S]') Wapiti scan on $target_ip:$port completed."
}

# Nikto web server scanner
run_nikto_scan() {
    local target_ip="$1"
    shift  # Shift to get ports array
    local ports=("$@")
    
    if ! check_scanner_available "nikto"; then
        return 1
    fi

    local nikto_pids=()
    declare -A nikto_scanned_ports
    local nikto_scan_count=0

    trap '' PIPE  # Ignore SIGPIPE to prevent script termination

    for port in "${ports[@]}"; do
        if [ "${nikto_scanned_ports[$port]}" ]; then
            continue
        fi

        print_status "$(date '+[%Y-%m-%d %H:%M:%S]') Starting Nikto scan on $target_ip:$port..."

        local output_file="${target_ip}_${port}_nikto_output.txt"

        # Log exact Nikto command being executed
        print_verbose "Nikto command executed for $target_ip:$port: nikto -h $target_ip -p $port $NIKTO_OPTIONS -output ${output_file}"

        # Run Nikto in background and immediately capture PID
        (run_with_timeout 3600 nikto -h "$target_ip" -p "$port" $NIKTO_OPTIONS -output "$output_file" > "${output_file}_log.txt" 2>&1) &
        local nikto_pid=$!
        nikto_pids+=("$nikto_pid")

        # Add dividing line after each scan's output
        {
            echo " "
            echo "------------------------------------------------------------------"
            echo " "
        } >> "$output_file"

        nikto_scanned_ports[$port]=1
        ((nikto_scan_count++))

        # Start spinner for this Nikto process
        (spinner "Nikto on Port $port") &
        local spinner_pid=$!

        # Wait for Nikto to complete and kill spinner
        wait "$nikto_pid" || true
        kill $spinner_pid 2>/dev/null

        print_verbose "Nikto command executed for $target_ip:$port: nikto -h $target_ip -p $port $NIKTO_OPTIONS -output ${target_ip}_${port}_nikto_output.txt"
    done

    # Wait for all Nikto processes to complete
    for pid in "${nikto_pids[@]}"; do
        wait $pid
    done

    STATS_NIKTO_SCANS=$nikto_scan_count

    print_status "$(date '+[%Y-%m-%d %H:%M:%S]') Nikto scan on $target_ip:$port completed."
    print_verbose "$(date '+[%Y-%m-%d %H:%M:%S]') Nikto scan on $target_ip:$port completed."
}

# WPScan WordPress vulnerability scanner
run_wpscan_scan() {
    local target_ip="$1"
    shift  # Shift to get ports array
    local ports=("$@")
    
    if ! check_scanner_available "wpscan"; then
        return 1
    fi

    local wpscan_pids=()
    declare -A wpscan_scanned_ports
    local wpscan_scan_count=0

    for port in "${ports[@]}"; do
        if [ "${wpscan_scanned_ports[$port]}" ]; then
            continue  # Skip if already scanned
        fi

        local url="http://$target_ip:$port"
        if [[ "$port" == "443" || "$port" == "8443" ]]; then
            url="https://$target_ip:$port"
        fi

        print_status "$(date '+[%Y-%m-%d %H:%M:%S]') Starting WPScan on $url..."
        local output_file="${target_ip}_${port}_wpscan_output.txt"

        # Log exact WPScan command being executed
        print_verbose "WPScan command executed for $url: wpscan $WPSCAN_OPTIONS --url $url > $output_file"

        (run_with_timeout 3600 sudo -u "$SUDO_USER" wpscan $WPSCAN_OPTIONS --url "$url" > "$output_file" 2>&1) &
        local wpscan_pid=$!
        wpscan_pids+=("$wpscan_pid")

        wpscan_scanned_ports[$port]=1
        ((wpscan_scan_count++))

        # Start spinner for this WPScan process
        (spinner "WPScan on Port $port") &
        local spinner_pid=$!

        # Wait for WPScan to complete and kill spinner
        wait "$wpscan_pid" || true
        kill $spinner_pid 2>/dev/null

        # Add dividing line after each scan's output
        echo " " >> "$output_file"
        echo "------------------------------------------------------------------" >> "$output_file"
        echo " " >> "$output_file"
    done

    # Wait for all WPScan processes to complete
    for pid in "${wpscan_pids[@]}"; do
        wait $pid || true
    done

    STATS_WPSCAN_SCANS=$wpscan_scan_count

    print_status "$(date '+[%Y-%m-%d %H:%M:%S]') WPScan scan on $target_ip:$port completed."
    print_verbose "$(date '+[%Y-%m-%d %H:%M:%S]') WPScan scan on $target_ip:$port completed."
}

# SQLMap SQL injection scanner
run_sqlmap_scan() {
    local target_ip="$1"
    shift  # Shift to get ports array
    local ports=("$@")
    
    if ! check_scanner_available "sqlmap"; then
        return 1
    fi

    local sqlmap_pids=()
    declare -A sqlmap_scanned_ports
    local sqlmap_scan_count=0

    for port in "${ports[@]}"; do
        if [ "${sqlmap_scanned_ports[$port]}" ]; then
            continue  # Skip if already scanned
        fi

        local url="http://$target_ip:$port"
        if [[ "$port" == "443" || "$port" == "8443" ]]; then
            url="https://$target_ip:$port"
        fi

        print_status "$(date '+[%Y-%m-%d %H:%M:%S]') Starting SQLMap on $url..."
        local output_file="${target_ip}_${port}_sqlmap_output.txt"

        # Log exact SQLmap command being executed
        print_verbose "SQLMap command executed for $url: sqlmap $SQLMAP_OPTIONS -u \"$url\" > $output_file"

        (run_with_timeout 3600 sudo -u "$SUDO_USER" sqlmap $SQLMAP_OPTIONS -u "$url" > "$output_file" 2>&1) &
        local sqlmap_pid=$!
        sqlmap_pids+=("$sqlmap_pid")

        sqlmap_scanned_ports[$port]=1
        ((sqlmap_scan_count++))

        # Start spinner for this SQLMap process
        (spinner "SQLMap on Port $port") &
        local spinner_pid=$!

        # Wait for SQLMap to complete and kill spinner
        wait "$sqlmap_pid" || true
        kill $spinner_pid 2>/dev/null

        # Add dividing line after each scan's output
        echo " " >> "$output_file"
        echo "------------------------------------------------------------------" >> "$output_file"
        echo " " >> "$output_file"
    done

    # Wait for all SQLMap processes to complete
    for pid in "${sqlmap_pids[@]}"; do
        wait $pid || true
    done

    STATS_SQLMAP_SCANS=$sqlmap_scan_count

    print_status "$(date '+[%Y-%m-%d %H:%M:%S]') SQLMap scan on $target_ip:$port completed."
    print_verbose "$(date '+[%Y-%m-%d %H:%M:%S]') SQLMap scan on $target_ip:$port completed."
}

# Function to run all applicable third-party scans with optimized parallelism
run_third_party_scans() {
    local target_ip="$1"
    local open_ports="$2"
    local wp_detected="$3"
    local sql_detected="$4"

    # Initialize arrays to hold PIDs
    local wapiti_pids=()
    local nikto_pids=()
    local wpscan_pids=()
    local sqlmap_pids=()

    # If no open ports found, skip all scans
    if [ -z "$open_ports" ]; then
        print_warning "No open web ports found. Skipping third-party scans."
        return 0
    fi

    # Calculate optimal parallel jobs based on CPU cores and available memory
    local cpu_cores=$(nproc 2>/dev/null || echo "4")
    local available_memory=$(free -m | awk 'NR==2{print $4}' 2>/dev/null || echo "1024")
    local max_parallel_jobs=$((cpu_cores > 8 ? 8 : cpu_cores))
    
    # Adjust for memory constraints (need ~200MB per scanner)
    local memory_limited_jobs=$((available_memory / 200))
    if [ $memory_limited_jobs -lt $max_parallel_jobs ]; then
        max_parallel_jobs=$memory_limited_jobs
    fi
    
    print_verbose "Running third-party scans with up to $max_parallel_jobs parallel jobs"

    # Convert ports string to array and optimize port distribution
    local ports_array=($open_ports)
    local port_count=${#ports_array[@]}
    local ports_per_scanner=$((port_count / 4 + 1))  # Distribute among 4 scanners

    # Optimized parallel scanner execution
    local scanner_count=0
    
    # Run Wapiti with subset of ports
    if check_scanner_available "wapiti"; then
        local wapiti_ports=("${ports_array[@]:0:$ports_per_scanner}")
        run_wapiti_scan "$target_ip" "${wapiti_ports[@]}" &
        local wapiti_pid=$!
        wapiti_pids+=($wapiti_pid)
        ((scanner_count++))
        print_verbose "Started Wapiti scan (PID: $wapiti_pid) with ${#wapiti_ports[@]} ports"
    fi

    # Run Nikto with subset of ports (staggered start)
    sleep 1  # Stagger to reduce immediate load
    if check_scanner_available "nikto"; then
        local nikto_start=$ports_per_scanner
        local nikto_end=$((nikto_start + ports_per_scanner))
        local nikto_ports=("${ports_array[@]:$nikto_start:$ports_per_scanner}")
        run_nikto_scan "$target_ip" "${nikto_ports[@]}" &
        local nikto_pid=$!
        nikto_pids+=($nikto_pid)
        ((scanner_count++))
        print_verbose "Started Nikto scan (PID: $nikto_pid) with ${#nikto_ports[@]} ports"
    fi

    # Wait for initial scans to start before resource-intensive ones
    sleep 2

    # Run WPScan only if WordPress was detected
    if [ "$wp_detected" = "true" ] && check_scanner_available "wpscan"; then
        local wpscan_start=$((ports_per_scanner * 2))
        local wpscan_end=$((wpscan_start + ports_per_scanner))
        local wpscan_ports=("${ports_array[@]:$wpscan_start:$ports_per_scanner}")
        run_wpscan_scan "$target_ip" "${wpscan_ports[@]}" &
        local wpscan_pid=$!
        wpscan_pids+=($wpscan_pid)
        ((scanner_count++))
        print_verbose "Started WPScan scan (PID: $wpscan_pid) with ${#wpscan_ports[@]} ports"
    fi

    # Run SQLMap only if an SQL database was detected
    if [ "$sql_detected" = "true" ] && check_scanner_available "sqlmap"; then
        local sqlmap_start=$((ports_per_scanner * 3))
        local sqlmap_end=$((sqlmap_start + ports_per_scanner))
        if [ $sqlmap_start -lt $port_count ]; then
            local sqlmap_ports=("${ports_array[@]:$sqlmap_start:$ports_per_scanner}")
            run_sqlmap_scan "$target_ip" "${sqlmap_ports[@]}" &
            local sqlmap_pid=$!
            sqlmap_pids+=($sqlmap_pid)
            ((scanner_count++))
            print_verbose "Started SQLMap scan (PID: $sqlmap_pid) with ${#sqlmap_ports[@]} ports"
        fi
    fi

    # Function to monitor and wait for scanner completion with load balancing
    wait_for_scanners() {
        local pids_array_name="$1"
        local scanner_name="$2"
        local -n pids_array
        eval "pids_array=(\"\${${pids_array_name}[@]}\")"
        
        if [ ${#pids_array[@]} -eq 0 ]; then
            print_verbose "No $scanner_name scans to wait for"
            return 0
        fi

        print_verbose "Waiting for ${#pids_array[@]} $scanner_name scan(s) to complete..."
        
        # Wait with timeout and progress monitoring
        local timeout=7200  # 2 hours max for all scanners
        local elapsed=0
        
        while [ $elapsed -lt $timeout ]; do
            local running_pids=()
            for pid in "${pids_array[@]}"; do
                if kill -0 "$pid" 2>/dev/null; then
                    running_pids+=("$pid")
                fi
            done
            
            if [ ${#running_pids[@]} -eq 0 ]; then
                break
            fi
            
            # Check for dead processes and handle errors
            for pid in "${pids_array[@]}"; do
                if ! kill -0 "$pid" 2>/dev/null; then
                    wait $pid
                    handle_scanner_error "$scanner_name" $? "$target_ip" || true
                fi
            done
            
            sleep 5
            elapsed=$((elapsed + 5))
        done
        
        # Force kill any remaining processes after timeout
        for pid in "${pids_array[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                print_warning "Terminating $scanner_name scan (PID: $pid) due to timeout"
                kill -TERM "$pid" 2>/dev/null || true
                sleep 2
                kill -KILL "$pid" 2>/dev/null || true
            fi
        done
        
        print_verbose "All $scanner_name scans completed or terminated"
    }

    # Wait for all scanner groups to complete
    wait_for_scanners "wapiti_pids" "Wapiti"
    wait_for_scanners "nikto_pids" "Nikto"
    wait_for_scanners "wpscan_pids" "WPScan"
    wait_for_scanners "sqlmap_pids" "SQLMap"

    print_status "Third-party scans completed for $target_ip ($scanner_count scanner groups executed)"
}

# Function to validate all scanner requirements
check_scanner_requirements() {
    local missing_scanners=()

    # Check each scanner
    for scanner in wapiti nikto wpscan sqlmap; do
        if ! command -v "$scanner" &> /dev/null; then
            missing_scanners+=("$scanner")
        fi
    done

    if [ ${#missing_scanners[@]} -gt 0 ]; then
        print_warning "Some scanners are not available: ${missing_scanners[*]}"
        print_warning "Install missing scanners for full functionality."
        return 1
    fi

    print_verbose "All scanner requirements validated"
    return 0
}

# Function to clean up scanner output files
cleanup_scanner_outputs() {
    local target_ip="$1"
    
    local output_patterns=(
        "${target_ip}_*_wapiti_output.txt"
        "${target_ip}_*_nikto_output.txt"
        "${target_ip}_*_wpscan_output.txt"
        "${target_ip}_*_sqlmap_output.txt"
        "${target_ip}_*_output.txt_log.txt"
    )

    for pattern in "${output_patterns[@]}"; do
        rm -f $pattern 2>/dev/null
    done

    print_verbose "Cleaned up scanner output files for $target_ip"
}

# Initialize scanners module
init_scanners() {
    check_scanner_requirements || return 0  # Don't fail, just warn
    print_verbose "Third-party scanners module initialized"
    return 0
}