#!/bin/bash
# benchmark_20.sh
# Comprehensive benchmark comparing arp-scan, go-arpscan (standard), and go-arpscan (fast)
# across 20 distinct test scenarios.

set -euo pipefail

# Ensure running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root (e.g., using sudo)." >&2
    exit 1
fi

echo "Using pre-built bin/go-arpscan..."

# Ensure bin/go-arpscan and arp-scan are available
if [ ! -x bin/go-arpscan ]; then
    echo "ERROR: bin/go-arpscan not found or not executable." >&2
    exit 1
fi
if ! command -v arp-scan >/dev/null 2>&1; then
    echo "ERROR: arp-scan is not installed or not in PATH." >&2
    exit 1
fi

# Auto-detect default interface and subnet prefix
INTERFACE=$(ip route show default | awk '/default/ {print $5}' | head -n1)
if [ -z "$INTERFACE" ]; then
    # Fallback to first non-loopback interface
    INTERFACE=$(ip link show | awk -F': ' '/state UP/ {print $2}' | grep -v "lo" | head -n1)
fi
if [ -z "$INTERFACE" ]; then
    echo "ERROR: Could not detect active network interface." >&2
    exit 1
fi

SUBNET=$(ip addr show "$INTERFACE" | awk '/inet / {print $2}' | head -n1)
if [ -z "$SUBNET" ]; then
    echo "ERROR: Could not detect IP subnet on interface $INTERFACE." >&2
    exit 1
fi

IP_PREFIX=$(echo "$SUBNET" | cut -d/ -f1 | cut -d. -f1-3)
OWN_IP=$(echo "$SUBNET" | cut -d/ -f1)

# Parse octets for building custom ranges
A=$(echo "$IP_PREFIX" | cut -d. -f1)
B=$(echo "$IP_PREFIX" | cut -d. -f2)
C=$(echo "$IP_PREFIX" | cut -d. -f3)

# Define target ranges based on prefix
RANGE_24="${IP_PREFIX}.1-${IP_PREFIX}.254"
RANGE_16="${IP_PREFIX}.100-${IP_PREFIX}.115"
RANGE_64="${IP_PREFIX}.100-${IP_PREFIX}.163"
# 1000 hosts spanned across 4 C-class blocks (e.g. C to C+3)
C_END=$((C + 3))
RANGE_1000="${A}.${B}.${C}.1-${A}.${B}.${C_END}.254"

# Safe non-existent IP in the local prefix
UNUSED_IP="${IP_PREFIX}.250"
# Safe spoof source IP
SPOOF_IP="${IP_PREFIX}.222"

echo "========================================================="
echo "BENCHMARK ENVIRONMENT CONFIGURATION"
echo "========================================================="
echo "Interface:       $INTERFACE"
echo "Subnet:          $SUBNET"
echo "IP Prefix:       $IP_PREFIX"
echo "Own IP:          $OWN_IP"
echo "Range /24:       $RANGE_24"
echo "Range /16 (16):  $RANGE_16"
echo "Range /64 (64):  $RANGE_64"
echo "Range /22 (1000):$RANGE_1000"
echo "Unused IP:       $UNUSED_IP"
echo "Spoof IP:        $SPOOF_IP"
echo "========================================================="

# Results CSV file
CSV_OUT="benchmark_results.csv"
echo "TestID,TestName,Tool,Round,ElapsedMs,HostsFound,Status" > "$CSV_OUT"

# Temp files for capturing stdout/stderr
STDOUT_TEMP=$(mktemp)
STDERR_TEMP=$(mktemp)
trap 'rm -f "$STDOUT_TEMP" "$STDERR_TEMP"' EXIT

# Helper function to run a command and measure its performance
# Args: test_id, test_name, tool_name (arp-scan|go-std|go-fast), round, command...
run_cmd_measured() {
    local tid="$1"
    local tname="$2"
    local tool="$3"
    local round="$4"
    shift 4
    local cmd=("$@")

    # Clear temp files
    > "$STDOUT_TEMP"
    > "$STDERR_TEMP"

    # Measure time using bash epoch milliseconds
    local start_time
    local end_time
    start_time=$(date +%s.%N)

    local exit_code=0
    # Run the command
    "${cmd[@]}" > "$STDOUT_TEMP" 2> "$STDERR_TEMP" || exit_code=$?

    end_time=$(date +%s.%N)

    if [ $exit_code -ne 0 ]; then
        echo "ERROR: Test $tid ($tname) failed for $tool on round $round with exit code $exit_code." >&2
        echo "--- STDERR ---" >&2
        cat "$STDERR_TEMP" >&2
        echo "--- STDOUT ---" >&2
        cat "$STDOUT_TEMP" >&2
        exit 1
    fi

    # Calculate elapsed milliseconds
    local elapsed_ms
    elapsed_ms=$(awk -v start="$start_time" -v end="$end_time" 'BEGIN {print int((end - start) * 1000)}')

    # Count hosts found (lines of output)
    local hosts_found
    hosts_found=$(grep -c '^' "$STDOUT_TEMP" || true)

    # Log to CSV
    echo "$tid,\"$tname\",$tool,$round,$elapsed_ms,$hosts_found,OK" >> "$CSV_OUT"
    echo "  [$tool] Round $round: ${elapsed_ms}ms, found $hosts_found hosts"
}

# Run 3 rounds of a test case for all three configurations: arp-scan, go-std, go-fast
# Args: test_id, test_name, targets, timeout_ms, interval_arp, interval_go, retries, extra_args_arp, extra_args_go
run_test_case() {
    local tid="$1"
    local tname="$2"
    local targets="$3"
    local timeout_ms="$4"
    local interval_arp="$5"
    local interval_go="$6"
    local retries="$7"
    local extra_arp="$8"
    local extra_go="$9"

    echo "Running Test $tid: $tname..."

    # We will alternate the order of tools across rounds to avoid network state bias
    # Round 1: arp-scan, go-std, go-fast
    # Round 2: go-fast, arp-scan, go-std
    # Round 3: go-std, go-fast, arp-scan

    for round in 1 2 3; do
        # Build commands
        # Note: --plain (-x) and --quiet (-q) are used to only print responding hosts (one per line)
        local arp_args=("-I" "$INTERFACE" "-q" "-x" "-g" "--retry=$retries" "--timeout=$timeout_ms")
        if [ "$interval_arp" != "NONE" ]; then
            arp_args+=("--interval=$interval_arp")
        fi
        if [ -n "$extra_arp" ]; then
            # Parse arguments correctly by word splitting
            read -r -a extra_arp_arr <<< "$extra_arp"
            arp_args+=("${extra_arp_arr[@]}")
        fi
        arp_args+=("$targets")

        local go_args=("-I" "$INTERFACE" "-q" "-g" "--retry=$retries" "--host-timeout=${timeout_ms}ms")

        if [ "$interval_go" != "NONE" ]; then
            go_args+=("--interval=$interval_go")
        fi
        if [ -n "$extra_go" ]; then
            read -r -a extra_go_arr <<< "$extra_go"
            go_args+=("${extra_go_arr[@]}")
        fi
        local go_std_args=("bin/go-arpscan" "${go_args[@]}" "$targets")
        local go_fast_args=("bin/go-arpscan" "${go_args[@]}" "--fast" "$targets")
        local arp_cmd=("arp-scan" "${arp_args[@]}")

        case $round in
            1)
                run_cmd_measured "$tid" "$tname" "arp-scan" "$round" "${arp_cmd[@]}"
                run_cmd_measured "$tid" "$tname" "go-std" "$round" "${go_std_args[@]}"
                run_cmd_measured "$tid" "$tname" "go-fast" "$round" "${go_fast_args[@]}"
                ;;
            2)
                run_cmd_measured "$tid" "$tname" "go-fast" "$round" "${go_fast_args[@]}"
                run_cmd_measured "$tid" "$tname" "arp-scan" "$round" "${arp_cmd[@]}"
                run_cmd_measured "$tid" "$tname" "go-std" "$round" "${go_std_args[@]}"
                ;;
            3)
                run_cmd_measured "$tid" "$tname" "go-std" "$round" "${go_std_args[@]}"
                run_cmd_measured "$tid" "$tname" "go-fast" "$round" "${go_fast_args[@]}"
                run_cmd_measured "$tid" "$tname" "arp-scan" "$round" "${arp_cmd[@]}"
                ;;
        esac
        # Small settling sleep to let the interface cool down
        sleep 0.1
    done
    echo ""
}

# ==============================================================================
# DEFINE THE 20 TEST SCENARIOS
# ==============================================================================

# 1. Standard scan /24
run_test_case "1" "Standard /24" "$RANGE_24" "500" "1" "1ms" "2" "" ""

# 2. Standard /24, Retry=1
run_test_case "2" "Standard /24, Retry 1" "$RANGE_24" "500" "1" "1ms" "1" "" ""

# 3. Standard /24, Retry=5
run_test_case "3" "Standard /24, Retry 5" "$RANGE_24" "300" "1" "1ms" "5" "" ""

# 4. Short Timeout (100ms)
run_test_case "4" "Short Timeout 100ms" "$RANGE_24" "100" "1" "1ms" "2" "" ""

# 5. Very Short Timeout (50ms)
run_test_case "5" "Very Short Timeout 50ms" "$RANGE_24" "50" "1" "1ms" "2" "" ""

# 6. Long Timeout (1000ms)
run_test_case "6" "Long Timeout 1000ms" "$RANGE_24" "1000" "1" "1ms" "2" "" ""

# 7. Fast Interval (200us)
run_test_case "7" "Fast Interval 200us" "$RANGE_24" "500" "200u" "200us" "2" "" ""

# 8. Very Fast Interval (50us)
run_test_case "8" "Very Fast Interval 50us" "$RANGE_24" "300" "50u" "50us" "2" "" ""

# 9. Slow Interval (10ms)
run_test_case "9" "Slow Interval 10ms" "$RANGE_24" "500" "10" "10ms" "2" "" ""

# 10. Very Slow Interval (50ms)
run_test_case "10" "Very Slow Interval 50ms" "$RANGE_24" "500" "50" "50ms" "2" "" ""

# 11. Small Range (16 hosts)
run_test_case "11" "Small Range 16 hosts" "$RANGE_16" "500" "1" "1ms" "2" "" ""

# 12. Medium Range (64 hosts)
run_test_case "12" "Medium Range 64 hosts" "$RANGE_64" "500" "1" "1ms" "2" "" ""

# 13. Large Range (1000 hosts)
run_test_case "13" "Large Range 1000 hosts" "$RANGE_1000" "300" "1" "1ms" "1" "" ""

# 14. Single Host (Own IP)
run_test_case "14" "Single Host (Own IP)" "$OWN_IP" "100" "1" "1ms" "1" "" ""

# 15. Single Host (Non-existent)
run_test_case "15" "Single Host (Non-existent)" "$UNUSED_IP" "200" "1" "1ms" "1" "" ""

# 16. Random Target Order
run_test_case "16" "Random Order" "$RANGE_24" "500" "1" "1ms" "2" "-R" "-R"

# 17. Numeric Only (No DNS)
# Note: arp-scan doesn't have a -N but it doesn't resolve DNS by default anyway unless configured.
# go-arpscan does DNS unless --numeric / -N is used.
run_test_case "17" "Numeric Only (No DNS)" "$RANGE_24" "500" "1" "1ms" "2" "" "-N"

# 18. Custom Source IP
run_test_case "18" "Custom Source IP" "$RANGE_24" "500" "1" "1ms" "2" "-s $SPOOF_IP" "-s $SPOOF_IP"

# 19. Custom Source MAC
run_test_case "19" "Custom Source MAC" "$RANGE_24" "500" "1" "1ms" "2" "-u 00:11:22:33:44:55" "-u 00:11:22:33:44:55"

# 20. Bandwidth Limit 1M
run_test_case "20" "Bandwidth Limit 1M" "$RANGE_24" "500" "NONE" "NONE" "2" "-B 1M" "-B 1M"

# ==============================================================================
# COMPUTE STATISTICS AND GENERATE REPORT
# ==============================================================================

echo "========================================================="
echo "BENCHMARK SUMMARY GENERATION"
echo "========================================================="

# We will generate a nice report using awk.
REPORT_FILE="benchmark_summary.md"
cat << 'EOF' > "$REPORT_FILE"
# Benchmark Results Summary

This file summarizes the benchmark comparing `arp-scan`, `go-arpscan` (Standard engine), and `go-arpscan` (Fast engine) across 20 distinct test cases.

## System Info
EOF

echo "- **Interface:** $INTERFACE" >> "$REPORT_FILE"
echo "- **Subnet:** $SUBNET" >> "$REPORT_FILE"
echo "- **Date:** $(date)" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

cat << 'EOF' >> "$REPORT_FILE"
## Summary Table

| ID | Test Scenario | arp-scan (Avg ms) | go-std (Avg ms) | go-fast (Avg ms) | Hosts (arp/std/fast) | Fastest Tool |
|---|---|---|---|---|---|---|
EOF

awk -F, '
NR > 1 {
    # CSV fields: TestID, TestName, Tool, Round, ElapsedMs, HostsFound, Status
    tid = $1
    tname = $2
    # strip quotes
    gsub(/"/, "", tname)
    tool = $3
    ms = $5
    hosts = $6

    key = tid "|" tname
    test_ids[tid] = key
    
    sum_ms[key, tool] += ms
    sum_hosts[key, tool] += hosts
    count[key, tool]++
}
END {
    # Print table rows sorted by TestID
    for (i = 1; i <= 20; i++) {
        # Find the key for this ID
        key = ""
        for (k in test_ids) {
            split(k, parts, " ")
            if (k == i) {
                key = test_ids[k]
                break
            }
        }
        if (key == "") continue

        split(key, parts, "|")
        name = parts[2]

        avg_arp = count[key, "arp-scan"] > 0 ? sprintf("%.1f", sum_ms[key, "arp-scan"] / count[key, "arp-scan"]) : "N/A"
        avg_std = count[key, "go-std"] > 0 ? sprintf("%.1f", sum_ms[key, "go-std"] / count[key, "go-std"]) : "N/A"
        avg_fast = count[key, "go-fast"] > 0 ? sprintf("%.1f", sum_ms[key, "go-fast"] / count[key, "go-fast"]) : "N/A"

        h_arp = count[key, "arp-scan"] > 0 ? sprintf("%.1f", sum_hosts[key, "arp-scan"] / count[key, "arp-scan"]) : "N/A"
        h_std = count[key, "go-std"] > 0 ? sprintf("%.1f", sum_hosts[key, "go-std"] / count[key, "go-std"]) : "N/A"
        h_fast = count[key, "go-fast"] > 0 ? sprintf("%.1f", sum_hosts[key, "go-fast"] / count[key, "go-fast"]) : "N/A"

        # Determine fastest
        val_arp = avg_arp != "N/A" ? avg_arp + 0.0 : 999999.0
        val_std = avg_std != "N/A" ? avg_std + 0.0 : 999999.0
        val_fast = avg_fast != "N/A" ? avg_fast + 0.0 : 999999.0

        fastest = ""
        min_val = val_arp
        if (val_std < min_val) min_val = val_std
        if (val_fast < min_val) min_val = val_fast

        if (min_val == val_arp && min_val == val_std && min_val == val_fast) {
            fastest = "Tie"
        } else if (min_val == val_arp) {
            fastest = "**arp-scan**"
        } else if (min_val == val_fast) {
            fastest = "**go-fast**"
        } else {
            fastest = "**go-std**"
        }

        printf "| %d | %s | %s | %s | %s | %s/%s/%s | %s |\n", i, name, avg_arp, avg_std, avg_fast, h_arp, h_std, h_fast, fastest
    }
}
' "$CSV_OUT" >> "$REPORT_FILE"

echo "Benchmark completed! Results saved to $CSV_OUT and summary report generated at $REPORT_FILE."
