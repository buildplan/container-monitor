#!/bin/bash

# Description:
# This script monitors Docker containers on the system.
# It checks container status, resource usage (CPU, Memory, Disk, Network),
# checks for image updates, checks container logs for errors/warnings,
# and monitors container restarts.
# Output is printed to the standard output with improved formatting and colors and logged to a file.
#
# Configuration:
#   Configuration is primarily done via config.sh and environment variables.
#   Environment variables override settings in config.sh.
#   Script defaults are used if no other configuration is found.
#
# Environment Variables (can be set to customize script behavior):
#   - LOG_LINES_TO_CHECK: Number of log lines to check.
#   - CHECK_FREQUENCY_MINUTES: Frequency of checks in minutes (Note: Script is run by external scheduler).
#   - LOG_FILE: Path to the log file.
#   - CONTAINER_NAMES: Comma-separated list of container names to monitor. Overrides config.sh.
#   - CPU_WARNING_THRESHOLD: CPU usage percentage threshold for warnings.
#   - MEMORY_WARNING_THRESHOLD: Memory usage percentage threshold for warnings.
#   - DISK_SPACE_THRESHOLD: Disk space usage percentage threshold for warnings (for container mounts).
#   - NETWORK_ERROR_THRESHOLD: Network error/drop count threshold for warnings.
#   - HOST_DISK_CHECK_FILESYSTEM: Filesystem path on host to check for disk usage (e.g., "/", "/var/lib/docker"). Default: "/".
#
# Usage:
#   ./docker-container-monitor.sh                           	- Monitor based on config (or all running)
#   ./docker-container-monitor.sh summary                   	- Run all checks silently and show only the final summary.
#   ./docker-container-monitor.sh summary <c1> <c2> ...     	- Summary mode for specific containers.
#   ./docker-container-monitor.sh <container1> <container2> ... - Monitor specific containers (full output)
#   ./docker-container-monitor.sh logs                      	- Show logs for all running containers
#   ./docker-container-monitor.sh logs <container_name>     	- Show logs for a specific container
#   ./docker-container-monitor.sh logs errors <container_name> 	- Show errors in logs for a specific container
#   ./docker-container-monitor.sh save logs <container_name> 	- Save logs for a specific container to a file
#   ./container-monitor.sh --no-update        			- Run without checking for a script update.
#
# Prerequisites:
#   - Docker
#   - jq (for processing JSON output from docker inspect and docker stats)
#   - skopeo (for checking for container image updates)
#   - bc or awk (awk is used in this script for float comparisons to reduce dependencies)
#   - timeout (from coreutils, for docker exec commands)

# --- Script & Update Configuration ---
VERSION="v0.4"
# !!! IMPORTANT !!!
SCRIPT_URL="https://github.com/buildplan/container-monitor/raw/refs/heads/main/container-monitor.sh"

# --- ANSI Color Codes ---
COLOR_RESET="\033[0m"
COLOR_RED="\033[0;31m"
COLOR_GREEN="\033[0;32m"
COLOR_YELLOW="\033[0;33m"
COLOR_CYAN="\033[0;36m"
COLOR_MAGENTA="\033[0;35m"
COLOR_BLUE="\033[0;34m"

# --- Global Flags ---
SUMMARY_ONLY_MODE=false
PRINT_MESSAGE_FORCE_STDOUT=false

# --- Script Default Configuration Values ---
_SCRIPT_DEFAULT_LOG_LINES_TO_CHECK=20
_SCRIPT_DEFAULT_CHECK_FREQUENCY_MINUTES=360
_SCRIPT_DEFAULT_LOG_FILE="$(cd "$(dirname "$0")" && pwd)/docker-monitor.log"
_SCRIPT_DEFAULT_CPU_WARNING_THRESHOLD=80
_SCRIPT_DEFAULT_MEMORY_WARNING_THRESHOLD=80
_SCRIPT_DEFAULT_DISK_SPACE_THRESHOLD=80
_SCRIPT_DEFAULT_NETWORK_ERROR_THRESHOLD=10
_SCRIPT_DEFAULT_HOST_DISK_CHECK_FILESYSTEM="/"
_SCRIPT_DEFAULT_NOTIFICATION_CHANNEL="none"
_SCRIPT_DEFAULT_DISCORD_WEBHOOK_URL="your_discord_webhook_url_here"
_SCRIPT_DEFAULT_NTFY_SERVER_URL="https://ntfy.sh"
_SCRIPT_DEFAULT_NTFY_TOPIC="your_ntfy_topic_here"
_SCRIPT_DEFAULT_NTFY_ACCESS_TOKEN=""
declare -a _SCRIPT_DEFAULT_CONTAINER_NAMES_ARRAY=()

# --- Initialize Working Configuration ---
LOG_LINES_TO_CHECK="$_SCRIPT_DEFAULT_LOG_LINES_TO_CHECK"
CHECK_FREQUENCY_MINUTES="$_SCRIPT_DEFAULT_CHECK_FREQUENCY_MINUTES"
LOG_FILE="$_SCRIPT_DEFAULT_LOG_FILE"
CPU_WARNING_THRESHOLD="$_SCRIPT_DEFAULT_CPU_WARNING_THRESHOLD"
MEMORY_WARNING_THRESHOLD="$_SCRIPT_DEFAULT_MEMORY_WARNING_THRESHOLD"
DISK_SPACE_THRESHOLD="$_SCRIPT_DEFAULT_DISK_SPACE_THRESHOLD"
NETWORK_ERROR_THRESHOLD="$_SCRIPT_DEFAULT_NETWORK_ERROR_THRESHOLD"
HOST_DISK_CHECK_FILESYSTEM="$_SCRIPT_DEFAULT_HOST_DISK_CHECK_FILESYSTEM"
NOTIFICATION_CHANNEL="$_SCRIPT_DEFAULT_NOTIFICATION_CHANNEL"
DISCORD_WEBHOOK_URL="$_SCRIPT_DEFAULT_DISCORD_WEBHOOK_URL"
NTFY_SERVER_URL="$_SCRIPT_DEFAULT_NTFY_SERVER_URL"
NTFY_TOPIC="$_SCRIPT_DEFAULT_NTFY_TOPIC"
NTFY_ACCESS_TOKEN="$_SCRIPT_DEFAULT_NTFY_ACCESS_TOKEN"
declare -a CONTAINER_NAMES_FROM_CONFIG_FILE=()

# --- Source Configuration File (config.sh) ---
_CONFIG_FILE_PATH="$(cd "$(dirname "$0")" && pwd)/config.sh"
if [ -f "$_CONFIG_FILE_PATH" ]; then
    source "$_CONFIG_FILE_PATH"
    LOG_LINES_TO_CHECK="${LOG_LINES_TO_CHECK_DEFAULT:-$LOG_LINES_TO_CHECK}"
    CHECK_FREQUENCY_MINUTES="${CHECK_FREQUENCY_MINUTES_DEFAULT:-$CHECK_FREQUENCY_MINUTES}"
    LOG_FILE="${LOG_FILE_DEFAULT:-$LOG_FILE}"
    CPU_WARNING_THRESHOLD="${CPU_WARNING_THRESHOLD_DEFAULT:-$CPU_WARNING_THRESHOLD}"
    MEMORY_WARNING_THRESHOLD="${MEMORY_WARNING_THRESHOLD_DEFAULT:-$MEMORY_WARNING_THRESHOLD}"
    DISK_SPACE_THRESHOLD="${DISK_SPACE_THRESHOLD_DEFAULT:-$DISK_SPACE_THRESHOLD}"
    NETWORK_ERROR_THRESHOLD="${NETWORK_ERROR_THRESHOLD_DEFAULT:-$NETWORK_ERROR_THRESHOLD}"
    HOST_DISK_CHECK_FILESYSTEM="${HOST_DISK_CHECK_FILESYSTEM_DEFAULT:-$HOST_DISK_CHECK_FILESYSTEM}"
    NOTIFICATION_CHANNEL="${NOTIFICATION_CHANNEL_DEFAULT:-$NOTIFICATION_CHANNEL}"
    DISCORD_WEBHOOK_URL="${DISCORD_WEBHOOK_URL_DEFAULT:-$DISCORD_WEBHOOK_URL}"
    NTFY_SERVER_URL="${NTFY_SERVER_URL_DEFAULT:-$NTFY_SERVER_URL}"
    NTFY_TOPIC="${NTFY_TOPIC_DEFAULT:-$NTFY_TOPIC}"
    NTFY_ACCESS_TOKEN="${NTFY_ACCESS_TOKEN_DEFAULT:-$NTFY_ACCESS_TOKEN}"
    if declare -p CONTAINER_NAMES_DEFAULT &>/dev/null && [[ "$(declare -p CONTAINER_NAMES_DEFAULT)" == "declare -a"* ]]; then
        if [ ${#CONTAINER_NAMES_DEFAULT[@]} -gt 0 ]; then
            CONTAINER_NAMES_FROM_CONFIG_FILE=("${CONTAINER_NAMES_DEFAULT[@]}")
        fi
    fi
else
    echo -e "${COLOR_YELLOW}[WARNING]${COLOR_RESET} Configuration file '$_CONFIG_FILE_PATH' not found. Using script defaults or environment variables."
fi

# --- Override with Environment Variables ---
LOG_LINES_TO_CHECK="${LOG_LINES_TO_CHECK:-$LOG_LINES_TO_CHECK}"
CHECK_FREQUENCY_MINUTES="${CHECK_FREQUENCY_MINUTES:-$CHECK_FREQUENCY_MINUTES}"
LOG_FILE="${LOG_FILE:-$LOG_FILE}"
CPU_WARNING_THRESHOLD="${CPU_WARNING_THRESHOLD:-$CPU_WARNING_THRESHOLD}"
MEMORY_WARNING_THRESHOLD="${MEMORY_WARNING_THRESHOLD:-$MEMORY_WARNING_THRESHOLD}"
DISK_SPACE_THRESHOLD="${DISK_SPACE_THRESHOLD:-$DISK_SPACE_THRESHOLD}"
NETWORK_ERROR_THRESHOLD="${NETWORK_ERROR_THRESHOLD:-$NETWORK_ERROR_THRESHOLD}"
HOST_DISK_CHECK_FILESYSTEM="${HOST_DISK_CHECK_FILESYSTEM:-$HOST_DISK_CHECK_FILESYSTEM}"
NOTIFICATION_CHANNEL="${NOTIFICATION_CHANNEL:-$NOTIFICATION_CHANNEL}"
DISCORD_WEBHOOK_URL="${DISCORD_WEBHOOK_URL:-$DISCORD_WEBHOOK_URL}"
NTFY_SERVER_URL="${NTFY_SERVER_URL:-$NTFY_SERVER_URL}"
NTFY_TOPIC="${NTFY_TOPIC:-$NTFY_TOPIC}"
NTFY_ACCESS_TOKEN="${NTFY_ACCESS_TOKEN:-$NTFY_ACCESS_TOKEN}"

# --- Prerequisite Checks ---
if ! command -v docker &>/dev/null; then echo -e "${COLOR_RED}[FATAL]${COLOR_RESET} Docker command not found." >&2; exit 1; fi
if ! command -v jq &>/dev/null; then echo -e "${COLOR_RED}[FATAL]${COLOR_RESET} jq command not found." >&2; exit 1; fi
if ! command -v skopeo &>/dev/null; then echo -e "${COLOR_RED}[FATAL]${COLOR_RESET} skopeo not found. Update checks will be skipped." >&2; fi
if ! command -v awk &>/dev/null; then echo -e "${COLOR_RED}[FATAL]${COLOR_RESET} awk command not found." >&2; exit 1; fi
if ! command -v timeout &>/dev/null; then echo -e "${COLOR_RED}[FATAL]${COLOR_RESET} timeout command not found." >&2; exit 1; fi

# --- Functions ---

print_message() {
    local message="$1"
    local color_type="$2"
    local color_code=""
    local log_output_no_color=""

    case "$color_type" in
        "INFO") color_code="$COLOR_CYAN" ;;
        "GOOD") color_code="$COLOR_GREEN" ;;
        "WARNING") color_code="$COLOR_YELLOW" ;;
        "DANGER") color_code="$COLOR_RED" ;;
        "SUMMARY") color_code="$COLOR_MAGENTA" ;;
        *) color_code="$COLOR_RESET"; color_type="NONE" ;;
    esac

    log_output_no_color=$(echo "$message" | sed -r "s/\x1B\[[0-9;]*[mK]//g")

    local do_stdout_print=true
    if [ "$SUMMARY_ONLY_MODE" = "true" ]; then
        if [ "$PRINT_MESSAGE_FORCE_STDOUT" = "false" ]; then
            do_stdout_print=false
        fi
    fi

    if [ "$do_stdout_print" = "true" ]; then
        if [[ "$color_type" == "NONE" ]]; then
            echo -e "${message}"
        else
            local colored_message_for_echo="${color_code}[${color_type}]${COLOR_RESET} ${message}"
            echo -e "${colored_message_for_echo}"
        fi
    fi

    if [ -n "$LOG_FILE" ]; then
        local log_prefix_for_file="[${color_type}]"
        if [[ "$color_type" == "NONE" ]]; then log_prefix_for_file=""; fi
        local log_dir; log_dir=$(dirname "$LOG_FILE")
        if [ ! -d "$log_dir" ]; then
            if ! mkdir -p "$log_dir" &>/dev/null; then
                echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} Cannot create log directory '$log_dir'. Logging disabled." >&2
                LOG_FILE="" # Disable logging for the rest of the script
            fi
        fi
        if [ -n "$LOG_FILE" ] && touch "$LOG_FILE" &>/dev/null; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') ${log_prefix_for_file} ${log_output_no_color}" >> "$LOG_FILE"
        elif [ -n "$LOG_FILE" ]; then
            echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} Cannot write to LOG_FILE ('$LOG_FILE'). Logging disabled." >&2
            LOG_FILE="" # Disable logging
        fi
    fi
}

send_discord_notification() {
    local message="$1"
    local title="$2"
    if [[ "$DISCORD_WEBHOOK_URL" != *"your_discord_webhook_url_here"* && -n "$DISCORD_WEBHOOK_URL" ]]; then
        # Create a JSON-safe version of the message by replacing newlines with \n
        json_message=$(echo "$message" | sed 's/$/\\n/' | tr -d '\n')

        # Construct the JSON payload
        json_payload=$(cat <<EOF
{
  "username": "Docker Monitor",
  "embeds": [{
    "title": "$title",
    "description": "$json_message",
    "color": 15158332,
    "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")"
  }]
}
EOF
)
        # Send the payload
        curl -s -H "Content-Type: application/json" -X POST -d "$json_payload" "$DISCORD_WEBHOOK_URL" > /dev/null
    else
        print_message "Discord webhook URL is not configured." "DANGER"
    fi
}

send_ntfy_notification() {
    local message="$1"
    local title="$2"
    local auth_header=""

    if [[ -n "$NTFY_ACCESS_TOKEN" ]]; then
        auth_header="Authorization: Bearer $NTFY_ACCESS_TOKEN"
    fi

    if [[ "$NTFY_SERVER_URL" == "https://ntfy.sh" && "$NTFY_TOPIC" == "your_ntfy_topic_here" ]]; then
         print_message "Ntfy topic is not configured." "DANGER"
         return
    fi

    # Send the notification using the configured server URL and topic
    curl -s -H "Title: $title" -H "Tags: warning" -H "$auth_header" -d "$message" "$NTFY_SERVER_URL/$NTFY_TOPIC" > /dev/null
}

send_notification() {
    local message="$1"
    local title="$2"
    case "$NOTIFICATION_CHANNEL" in
        "discord") send_discord_notification "$message" "$title" ;;
        "ntfy") send_ntfy_notification "$message" "$title" ;;
    esac
}

self_update() {
    echo "A new version of this script is available. Would you like to update now? (y/n)"
    read -r response
    if [[ "$response" =~ ^[yY]$ ]]; then
        local temp_file
        temp_file=$(mktemp)
        if curl -sL "$SCRIPT_URL" -o "$temp_file"; then
            if bash -n "$temp_file"; then
                mv "$temp_file" "$0"
                chmod +x "$0"
                echo "Update successful. Please run the script again."
                exit 0
            else
                echo "Downloaded file is not a valid script. Update aborted."
                rm -f "$temp_file"
                exit 1
            fi
        else
            echo "Failed to download the update."
            rm -f "$temp_file"
            exit 1
        fi
    fi
}

check_container_status() {
    local container_name="$1"; local inspect_data="$2"; local cpu_for_status_msg="$3"; local mem_for_status_msg="$4"
    local status health_status detailed_health
    status=$(jq -r '.[0].State.Status' <<< "$inspect_data"); health_status="not configured"
    if jq -e '.[0].State.Health != null and .[0].State.Health.Status != null' <<< "$inspect_data" >/dev/null 2>&1; then
        health_status=$(jq -r '.[0].State.Health.Status' <<< "$inspect_data")
    fi
    if [ "$status" != "running" ]; then
        print_message "  ${COLOR_BLUE}Status:${COLOR_RESET} Not running (Status: $status, Health: $health_status, CPU: $cpu_for_status_msg, Mem: $mem_for_status_msg)" "DANGER"; return 1
    else
        if [ "$health_status" = "healthy" ]; then
            print_message "  ${COLOR_BLUE}Status:${COLOR_RESET} Running and healthy (Status: $status, Health: $health_status, CPU: $cpu_for_status_msg, Mem: $mem_for_status_msg)" "GOOD"; return 0
        elif [ "$health_status" = "unhealthy" ]; then
            print_message "  ${COLOR_BLUE}Status:${COLOR_RESET} Running but UNHEALTHY (Status: $status, Health: $health_status, CPU: $cpu_for_status_msg, Mem: $mem_for_status_msg)" "DANGER"
            detailed_health=$(jq -r '.[0].State.Health | tojson' <<< "$inspect_data")
            if [ -n "$detailed_health" ] && [ "$detailed_health" != "null" ]; then print_message "    ${COLOR_BLUE}Detailed Health Info:${COLOR_RESET} $detailed_health" "WARNING"; fi; return 1
        elif [ "$health_status" = "not configured" ]; then
            print_message "  ${COLOR_BLUE}Status:${COLOR_RESET} Running (Status: $status, Health: $health_status, CPU: $cpu_for_status_msg, Mem: $mem_for_status_msg)" "GOOD"; return 0
        else
            print_message "  ${COLOR_BLUE}Status:${COLOR_RESET} Running (Status: $status, Health: $health_status, CPU: $cpu_for_status_msg, Mem: $mem_for_status_msg)" "WARNING"; return 1
        fi
    fi
}

check_container_restarts() {
    local container_name="$1"; local inspect_data="$2"; local restart_count is_restarting
    restart_count=$(jq -r '.[0].RestartCount' <<< "$inspect_data"); is_restarting=$(jq -r '.[0].State.Restarting' <<< "$inspect_data")
    if [ "$is_restarting" = "true" ]; then print_message "  ${COLOR_BLUE}Restart Status:${COLOR_RESET} Container '$container_name' is currently restarting." "WARNING"; return 1; fi
    if [ "$restart_count" -gt 0 ]; then print_message "  ${COLOR_BLUE}Restart Status:${COLOR_RESET} Container '$container_name' has restarted $restart_count times." "WARNING"; return 1; fi
    print_message "  ${COLOR_BLUE}Restart Status:${COLOR_RESET} No unexpected restarts detected for '$container_name'." "GOOD"; return 0
}

check_resource_usage() {
    local container_name="$1"; local cpu_percent="$2"; local mem_percent="$3"; local issues_found=0
    if [[ "$cpu_percent" =~ ^[0-9.]+$ ]]; then
        if awk -v cpu="$cpu_percent" -v threshold="$CPU_WARNING_THRESHOLD" 'BEGIN {exit !(cpu > threshold)}'; then
            print_message "  ${COLOR_BLUE}CPU Usage:${COLOR_RESET} High CPU usage detected (${cpu_percent}% > ${CPU_WARNING_THRESHOLD}% threshold)" "WARNING"; issues_found=1
        else
            print_message "  ${COLOR_BLUE}CPU Usage:${COLOR_RESET} Normal (${cpu_percent}%)" "INFO"
        fi
    else
        print_message "  ${COLOR_BLUE}CPU Usage:${COLOR_RESET} Could not determine CPU usage (value: ${cpu_percent})" "WARNING"; issues_found=1
    fi
    if [[ "$mem_percent" =~ ^[0-9.]+$ ]]; then
        if awk -v mem="$mem_percent" -v threshold="$MEMORY_WARNING_THRESHOLD" 'BEGIN {exit !(mem > threshold)}'; then
            print_message "  ${COLOR_BLUE}Memory Usage:${COLOR_RESET} High memory usage detected (${mem_percent}% > ${MEMORY_WARNING_THRESHOLD}% threshold)" "WARNING"; issues_found=1
        else
            print_message "  ${COLOR_BLUE}Memory Usage:${COLOR_RESET} Normal (${mem_percent}%)" "INFO"
        fi
    else
        print_message "  ${COLOR_BLUE}Memory Usage:${COLOR_RESET} Could not determine memory usage (value: ${mem_percent})" "WARNING"; issues_found=1
    fi
    return $issues_found
}

check_disk_space() {
    local container_name="$1"; local inspect_data="$2"; local issues_found=0
    local num_mounts; num_mounts=$(jq -r '.[0].Mounts | length // 0' <<< "$inspect_data" 2>/dev/null)
    if ! [[ "$num_mounts" =~ ^[0-9]+$ ]] || [ "$num_mounts" -eq 0 ]; then
        # This container has no mounts, which is fine. Exit silently.
        return 0
    fi

    for ((i=0; i<num_mounts; i++)); do
        local mp_destination
        mp_destination=$(jq -r ".[0].Mounts[$i].Destination // empty" <<< "$inspect_data" 2>/dev/null)
        if [ -z "$mp_destination" ]; then continue; fi

        # Gracefully skip special virtual filesystems
        if [[ "$mp_destination" == *".sock" || "$mp_destination" == "/proc"* || "$mp_destination" == "/sys"* || "$mp_destination" == "/dev"* || "$mp_destination" == "/host/"* ]]; then
            continue
        fi

        # Try to get disk usage, but don't warn if it fails.
        local disk_usage_output
        disk_usage_output=$(timeout 5 docker exec "$container_name" df -P "$mp_destination" 2>/dev/null)
        if [ $? -ne 0 ]; then
            # The command failed, likely due to permissions or it's not a real filesystem. Skip it quietly.
            continue
        fi

        local disk_usage
        disk_usage=$(echo "$disk_usage_output" | awk 'NR==2 {val=$(NF-1); sub(/%$/,"",val); print val}')

        # Only report if usage is high. This prevents repetitive "Normal usage" messages.
        if [[ "$disk_usage" =~ ^[0-9]+$ ]] && [ "$disk_usage" -ge "$DISK_SPACE_THRESHOLD" ]; then
            print_message "  ${COLOR_BLUE}Disk Space:${COLOR_RESET} High usage ($disk_usage%) at '$mp_destination' in '$container_name'." "WARNING"; issues_found=1
        fi
    done
    return $issues_found
}

check_network() {
    local container_name="$1"; local issues_found=0
    local network_stats; network_stats=$(timeout 5 docker exec "$container_name" cat /proc/net/dev 2>/dev/null)
    if [ -z "$network_stats" ]; then print_message "  ${COLOR_BLUE}Network:${COLOR_RESET} Could not get network stats for '$container_name'." "WARNING"; return 1; fi
    local network_issue_reported_for_container=false
    while IFS= read -r line; do
        if [[ "$line" == *:* ]]; then
            local interface data_part errors packets
            interface=$(echo "$line" | awk -F ':' '{print $1}' | sed 's/^[ \t]*//;s/[ \t]*$//')
            data_part=$(echo "$line" | cut -d':' -f2-)
            read -r _r_bytes _r_packets _r_errs _r_drop _ _ _ _ _ _t_bytes _t_packets _t_errs _t_drop <<< "$data_part"
            if ! [[ "$_r_errs" =~ ^[0-9]+$ && "$_t_drop" =~ ^[0-9]+$ ]]; then continue; fi
            errors=$((_r_errs + _t_drop))
            if [ "$errors" -gt "$NETWORK_ERROR_THRESHOLD" ]; then
                print_message "  ${COLOR_BLUE}Network:${COLOR_RESET} Interface '$interface' has $errors errors/drops in '$container_name'." "WARNING"; issues_found=1; network_issue_reported_for_container=true
            fi
        fi
    done <<< "$(tail -n +3 <<< "$network_stats")"
    if [ $issues_found -eq 0 ]; then print_message "  ${COLOR_BLUE}Network:${COLOR_RESET} No significant network issues detected for '$container_name'." "INFO"; fi
    return $issues_found
}

check_for_updates() {
    local container_name="$1"; local current_image_ref="$2"

    # 1. Prerequisite and Initial Checks
    if ! command -v skopeo &>/dev/null; then print_message "  ${COLOR_BLUE}Update Check:${COLOR_RESET} skopeo not installed. Skipping." "INFO"; return 0; fi
    if [[ "$current_image_ref" == *@sha256:* || "$current_image_ref" =~ ^sha256: ]]; then
        print_message "  ${COLOR_BLUE}Update Check:${COLOR_RESET} Image for '$container_name' is pinned by digest. Skipping." "INFO"; return 0
    fi

    # 2. Extract Image Name and Tag
    local current_tag="latest"
    local image_name_no_tag="$current_image_ref"
    if [[ "$current_image_ref" == *":"* ]]; then
        current_tag="${current_image_ref##*:}"
        image_name_no_tag="${current_image_ref%:$current_tag}"
    fi

    # 3. Construct the base repository path for skopeo
    local registry_host="registry-1.docker.io"
    local image_path_for_skopeo="$image_name_no_tag"
    if [[ "$image_name_no_tag" == *"/"* ]]; then
        local first_part; first_part=$(echo "$image_name_no_tag" | cut -d'/' -f1)
        if [[ "$first_part" == *"."* || "$first_part" == "localhost" || "$first_part" == *":"* ]]; then
            registry_host="$first_part"
            image_path_for_skopeo=$(echo "$image_name_no_tag" | cut -d'/' -f2-)
        fi
    else
        # Handle official images on Docker Hub which need a 'library/' prefix
        image_path_for_skopeo="library/$image_name_no_tag"
    fi
    local skopeo_repo_ref="docker://$registry_host/$image_path_for_skopeo"

    # 4. Handle 'latest' tag by comparing digests
    if [ "$current_tag" == "latest" ]; then
        local local_digest; local_digest=$(docker inspect -f '{{index .RepoDigests 0}}' "$current_image_ref" 2>/dev/null | cut -d'@' -f2)
        if [ -z "$local_digest" ]; then print_message "  ${COLOR_BLUE}Update Check:${COLOR_RESET} Could not get local digest for '$current_image_ref'. Cannot check 'latest' tag." "WARNING"; return 1; fi

        local skopeo_output; skopeo_output=$(skopeo inspect "${skopeo_repo_ref}:latest" 2>&1)
        if [ $? -ne 0 ]; then
            print_message "  ${COLOR_BLUE}Update Check:${COLOR_RESET} Error inspecting remote image '${skopeo_repo_ref}:latest'." "DANGER"; return 1
        fi

        local remote_digest; remote_digest=$(jq -r '.Digest' <<< "$skopeo_output")
        if [ "$remote_digest" != "$local_digest" ]; then
            print_message "  ${COLOR_BLUE}Update Check:${COLOR_RESET} New 'latest' image available for '$current_image_ref'." "WARNING"; return 1
        else
            print_message "  ${COLOR_BLUE}Update Check:${COLOR_RESET} Image '$current_image_ref' is up-to-date." "GOOD"; return 0
        fi
    fi

    # 5. Handle versioned tags by finding the latest stable tag
    # Get all tags, filter for stable semantic versions, sort them, and get the latest.
    local latest_stable_version
    latest_stable_version=$(skopeo list-tags "$skopeo_repo_ref" 2>/dev/null | \
                              jq -r '.Tags[]' | \
                              grep -E '^[v]?[0-9\.]+$' | \
                              grep -v -E 'alpha|beta|rc|dev|test' | \
                              sort -V | \
                              tail -n 1)

    if [ -z "$latest_stable_version" ]; then
        print_message "  ${COLOR_BLUE}Update Check:${COLOR_RESET} Could not determine latest stable version for '$image_name_no_tag'. Skipping." "INFO"
        return 0
    fi

    # Compare the current tag with the latest discovered stable version
    # 'v' prefix is handled to allow comparing 'v2.10' with '2.10'
    if [[ "v$current_tag" != "v$latest_stable_version" && "$current_tag" != "$latest_stable_version" ]]; then
        # Use sort -V to determine if the latest version is actually newer
        if [[ "$(printf '%s\n' "$latest_stable_version" "$current_tag" | sort -V | tail -n 1)" == "$latest_stable_version" ]]; then
            print_message "  ${COLOR_BLUE}Update Check:${COLOR_RESET} Update available for '$image_name_no_tag'. Latest stable is ${latest_stable_version} (you have ${current_tag})." "WARNING"; return 1
        else
            # This case handles running a newer (e.g., pre-release) version than the latest stable
            print_message "  ${COLOR_BLUE}Update Check:${COLOR_RESET} Image '$current_image_ref' is newer than latest stable. No action needed." "GOOD"; return 0
        fi
    else
        print_message "  ${COLOR_BLUE}Update Check:${COLOR_RESET} Image '$current_image_ref' is the latest stable version." "GOOD"; return 0
    fi
}

check_logs() {
    local container_name="$1"; local print_to_stdout="${2:-false}"; local filter_errors="${3:-false}"; local raw_logs
    raw_logs=$(docker logs --tail "$LOG_LINES_TO_CHECK" "$container_name" 2>&1)
    if [ $? -ne 0 ]; then print_message "  ${COLOR_BLUE}Log Check:${COLOR_RESET} Error retrieving logs for '$container_name'." "DANGER"; return 1; fi
    if [ -n "$raw_logs" ]; then
        if echo "$raw_logs" | grep -q -i -E 'error|panic|fail|fatal'; then
            print_message "  ${COLOR_BLUE}Log Check:${COLOR_RESET} Potential errors/warnings found in recent logs." "WARNING"; return 1
        else
            print_message "  ${COLOR_BLUE}Log Check:${COLOR_RESET} Logs checked, no obvious widespread errors found." "GOOD"; return 0
        fi
    else
        print_message "  ${COLOR_BLUE}Log Check:${COLOR_RESET} No log output in last $LOG_LINES_TO_CHECK lines." "INFO"; return 0
    fi
}

save_logs() {
    local container_name="$1"; local log_file_name="${container_name}_logs_$(date '+%Y-%m-%d_%H-%M-%S').log"
    if docker logs "$container_name" > "$log_file_name" 2>"${log_file_name}.err"; then
        print_message "Logs for '$container_name' saved to '$log_file_name'." "GOOD"
    else
        print_message "Error saving logs for '$container_name'. See '${log_file_name}.err'." "DANGER"
    fi
}

check_host_disk_usage() { # Echos output, does not call print_message directly
    local target_filesystem="${HOST_DISK_CHECK_FILESYSTEM:-/}" 
    local usage_line size_hr used_hr avail_hr capacity
    local output_string 

    usage_line=$(df -Ph "$target_filesystem" 2>/dev/null | awk 'NR==2')
    if [ -n "$usage_line" ]; then
        size_hr=$(echo "$usage_line" | awk '{print $2}')
        used_hr=$(echo "$usage_line" | awk '{print $3}')
        avail_hr=$(echo "$usage_line" | awk '{print $4}')
        capacity=$(echo "$usage_line" | awk '{print $5}' | tr -d '%')
        if [[ "$capacity" =~ ^[0-9]+$ ]]; then
             output_string="  ${COLOR_BLUE}Host Disk Usage ($target_filesystem):${COLOR_RESET} $capacity% used (${COLOR_BLUE}Size:${COLOR_RESET} $size_hr, ${COLOR_BLUE}Used:${COLOR_RESET} $used_hr, ${COLOR_BLUE}Available:${COLOR_RESET} $avail_hr)"
        else
            output_string="  ${COLOR_BLUE}Host Disk Usage ($target_filesystem):${COLOR_RESET} Could not parse percentage (Raw: '$usage_line')"
        fi
    else
        output_string="  ${COLOR_BLUE}Host Disk Usage ($target_filesystem):${COLOR_RESET} Could not determine usage."
    fi
    echo "$output_string"
}

check_host_memory_usage() { # Echos output, does not call print_message directly
    local mem_line total_mem used_mem free_mem perc_used output_string
    if command -v free >/dev/null 2>&1; then
        read -r _ total_mem used_mem free_mem _ < <(free -m | awk 'NR==2')
        if [[ "$total_mem" =~ ^[0-9]+$ && "$used_mem" =~ ^[0-9]+$ && "$total_mem" -gt 0 ]]; then
            perc_used=$(awk -v used="$used_mem" -v total="$total_mem" 'BEGIN {printf "%.0f", (used * 100 / total)}')
            output_string="  ${COLOR_BLUE}Host Memory Usage:${COLOR_RESET} ${COLOR_BLUE}Total:${COLOR_RESET} ${total_mem}MB, ${COLOR_BLUE}Used:${COLOR_RESET} ${used_mem}MB (${perc_used}%), ${COLOR_BLUE}Free:${COLOR_RESET} ${free_mem}MB"
        else
            output_string="  ${COLOR_BLUE}Host Memory Usage:${COLOR_RESET} Could not parse values from 'free -m'."
        fi
    else
        output_string="  ${COLOR_BLUE}Host Memory Usage:${COLOR_RESET} 'free' command not found."
    fi
    echo "$output_string"
}

print_summary() { # Uses print_message with FORCE_STDOUT
  local container_name_summary issues issue_emoji
  local printed_containers=()
  local host_disk_summary_output host_memory_summary_output

  PRINT_MESSAGE_FORCE_STDOUT=true # Enable stdout for all messages within this function

  print_message "-------------------------- Host System Stats ---------------------------" "SUMMARY"
  host_disk_summary_output=$(check_host_disk_usage)
  host_memory_summary_output=$(check_host_memory_usage)

  print_message "$host_disk_summary_output" "SUMMARY"
  print_message "$host_memory_summary_output" "SUMMARY"

  if [ ${#WARNING_OR_ERROR_CONTAINERS[@]} -gt 0 ]; then
    print_message "------------------- Summary of Container Issues Found --------------------" "SUMMARY"
    print_message "The following containers have warnings or errors:" "SUMMARY"

    for container_name_summary in "${WARNING_OR_ERROR_CONTAINERS[@]}"; do
      local already_printed=0
      for pc in "${printed_containers[@]}"; do if [[ "$pc" == "$container_name_summary" ]]; then already_printed=1; break; fi; done
      if [[ "$already_printed" -eq 1 ]]; then continue; fi
      printed_containers+=("$container_name_summary")
      issues="${CONTAINER_ISSUES_MAP["$container_name_summary"]:-Unknown Issue}"
      issue_emoji="❌" 
      if [[ "$issues" == *"Status"* ]]; then issue_emoji="🛑";
      elif [[ "$issues" == *"Restarts"* ]]; then issue_emoji="🔥";
      elif [[ "$issues" == *"Logs"* ]]; then issue_emoji="📜";
      elif [[ "$issues" == *"Update"* ]]; then issue_emoji="🔄";
      elif [[ "$issues" == *"Resources"* ]]; then issue_emoji="📈";
      elif [[ "$issues" == *"Disk"* ]]; then issue_emoji="💾";
      elif [[ "$issues" == *"Network"* ]]; then issue_emoji="🌐"; fi
      print_message "- ${container_name_summary} ${issue_emoji} (${COLOR_BLUE}Issues:${COLOR_RESET} ${issues})" "WARNING"
    done
  else
    print_message "------------------- Summary of Container Issues Found --------------------" "SUMMARY"
    print_message "No issues found in monitored containers. All container checks passed. ✅" "GOOD"
  fi
  print_message "------------------------------------------------------------------------" "SUMMARY"

  PRINT_MESSAGE_FORCE_STDOUT=false # Reset the flag
}

perform_checks_for_container() {
    local container_name_or_id="$1"
    local results_dir="$2"
    exec &> "$results_dir/$container_name_or_id.log"
    print_message "${COLOR_BLUE}Container:${COLOR_RESET} ${container_name_or_id}" "INFO"
    local inspect_json; inspect_json=$(docker inspect "$container_name_or_id" 2>/dev/null)
    if [ -z "$inspect_json" ]; then
        print_message "  ${COLOR_BLUE}Status:${COLOR_RESET} Container not found or inspect failed." "DANGER"
        echo "Not Found" > "$results_dir/$container_name_or_id.issues"
        return
    fi
    local container_actual_name stats_json cpu_percent mem_percent
    container_actual_name=$(jq -r '.[0].Name' <<< "$inspect_json" | sed 's|^/||')
    stats_json=$(docker stats --no-stream --format '{{json .}}' "$container_name_or_id" 2>/dev/null)
    cpu_percent="N/A"; mem_percent="N/A"
    if [ -n "$stats_json" ]; then
        cpu_percent=$(jq -r '.CPUPerc // "N/A"' <<< "$stats_json" | tr -d '%')
        mem_percent=$(jq -r '.MemPerc // "N/A"' <<< "$stats_json" | tr -d '%')
    else
        print_message "  ${COLOR_BLUE}Stats:${COLOR_RESET} Could not retrieve stats for '$container_actual_name'." "WARNING"
    fi
    local issue_tags=()
    check_container_status "$container_actual_name" "$inspect_json" "$cpu_percent" "$mem_percent"; if [ $? -ne 0 ]; then issue_tags+=("Status"); fi
    check_container_restarts "$container_actual_name" "$inspect_json"; if [ $? -ne 0 ]; then issue_tags+=("Restarts"); fi
    check_resource_usage "$container_actual_name" "$cpu_percent" "$mem_percent"; if [ $? -ne 0 ]; then issue_tags+=("Resources"); fi
    check_disk_space "$container_actual_name" "$inspect_json"; if [ $? -ne 0 ]; then issue_tags+=("Disk"); fi
    check_network "$container_actual_name"; if [ $? -ne 0 ]; then issue_tags+=("Network"); fi
    local current_image_ref_for_update; current_image_ref_for_update=$(jq -r '.[0].Config.Image' <<< "$inspect_json")
    check_for_updates "$container_actual_name" "$current_image_ref_for_update"; if [ $? -ne 0 ]; then issue_tags+=("Update"); fi
    check_logs "$container_actual_name" "false" "false"; if [ $? -ne 0 ]; then issue_tags+=("Logs"); fi
    if [ ${#issue_tags[@]} -gt 0 ]; then
        (IFS=,; echo "${issue_tags[*]}") > "$results_dir/$container_actual_name.issues"
    fi
}

# --- Main Execution ---
declare -a CONTAINERS_TO_CHECK=()
declare -a WARNING_OR_ERROR_CONTAINERS=()
declare -A CONTAINER_ISSUES_MAP

# --- Argument & Mode Parsing ---
run_update_check=true
if [ "$1" == "--no-update" ]; then run_update_check=false; shift; fi

if [[ "$run_update_check" == true && "$SCRIPT_URL" != *"your-username/your-repo"* ]]; then
    latest_version=$(curl -sL "$SCRIPT_URL" | grep -m 1 "VERSION=" | cut -d'"' -f2)
    if [[ -n "$latest_version" && "$VERSION" != "$latest_version" ]]; then self_update; fi
fi

if [ "$#" -gt 0 ] && [ "$1" = "summary" ]; then SUMMARY_ONLY_MODE=true; shift; fi

if [ "$SUMMARY_ONLY_MODE" = "false" ]; then
    if [ "$#" -gt 0 ]; then
      case "$1" in
        logs)
          # Logic for logs and save commands
          exit 0 ;;
        save)
          # Logic for logs and save commands
          exit 0 ;;
        *) CONTAINERS_TO_CHECK=("$@") ;;
      esac
    fi
elif [ "$#" -gt 0 ]; then
    CONTAINERS_TO_CHECK=("$@")
fi

# --- Determine Containers to Monitor ---
if [ ${#CONTAINERS_TO_CHECK[@]} -eq 0 ]; then
    if [ -n "$CONTAINER_NAMES" ]; then
        IFS=',' read -r -a temp_env_names <<< "$CONTAINER_NAMES"
        for name_from_env in "${temp_env_names[@]}"; do
            name_trimmed="${name_from_env#"${name_from_env%%[![:space:]]*}"}"; name_trimmed="${name_trimmed%"${name_trimmed##*[![:space:]]}"}"
            if [ -n "$name_trimmed" ]; then CONTAINERS_TO_CHECK+=("$name_trimmed"); fi
        done
    elif [ ${#CONTAINER_NAMES_FROM_CONFIG_FILE[@]} -gt 0 ]; then
        CONTAINERS_TO_CHECK=("${CONTAINER_NAMES_FROM_CONFIG_FILE[@]}")
    else
        mapfile -t all_running_names < <(docker container ls --format '{{.Names}}' 2>/dev/null)
        if [ ${#all_running_names[@]} -gt 0 ]; then CONTAINERS_TO_CHECK=("${all_running_names[@]}"); fi
    fi
fi

# --- Run Monitoring ---
if [ ${#CONTAINERS_TO_CHECK[@]} -gt 0 ]; then
    results_dir=$(mktemp -d)
    export -f perform_checks_for_container print_message check_container_status check_container_restarts \
               check_resource_usage check_disk_space check_network check_for_updates check_logs
    export COLOR_RESET COLOR_RED COLOR_GREEN COLOR_YELLOW COLOR_CYAN COLOR_BLUE COLOR_MAGENTA \
           LOG_LINES_TO_CHECK CPU_WARNING_THRESHOLD MEMORY_WARNING_THRESHOLD DISK_SPACE_THRESHOLD NETWORK_ERROR_THRESHOLD

    if [ "$SUMMARY_ONLY_MODE" = "false" ]; then
        echo "Starting asynchronous checks for ${#CONTAINERS_TO_CHECK[@]} containers..."
        start_time=$(date +%s)
        mkfifo progress_pipe
        (
            # Define spinner characters
	    spinner_chars=("|" "/" "-" '\')
            spinner_idx=0
            processed=0
            total=${#CONTAINERS_TO_CHECK[@]}

            # Read from the pipe to update the progress
            while read -r; do
                processed=$((processed + 1))

                # --- Calculations for display ---
                percent=$((processed * 100 / total))
                bar_len=40
                bar_filled_len=$((processed * bar_len / total))

                # --- Elapsed time calculation ---
                current_time=$(date +%s)
                elapsed=$((current_time - start_time))
                elapsed_str=$(printf "%02d:%02d" $((elapsed/60)) $((elapsed%60)))

                # --- Spinner character ---
                spinner_char=${spinner_chars[spinner_idx]}
                spinner_idx=$(((spinner_idx + 1) % 4))

                # --- Build the bar strings ---
		bar_filled=""
		for ((j=0; j<bar_filled_len; j++)); do bar_filled+="█"; done
		bar_empty=""
		for ((j=0; j< (bar_len - bar_filled_len) ; j++)); do bar_empty+="░"; done

                # --- Print the full progress line ---
                printf "\r${COLOR_GREEN}Progress: [%s%s] %3d%% (%d/%d) | Elapsed: %s [${spinner_char}]${COLOR_RESET}" \
                       "$bar_filled" "$bar_empty" "$percent" "$processed" "$total" "$elapsed_str"

             done < progress_pipe

            # Print a final newline to clean up
            echo
        ) &
        progress_pid=$!
        exec 3> progress_pipe
    fi

    printf "%s\n" "${CONTAINERS_TO_CHECK[@]}" | xargs -P 8 -I {} bash -c "perform_checks_for_container '{}' '$results_dir' && echo >&3"

    if [ "$SUMMARY_ONLY_MODE" = "false" ]; then
        exec 3>&-
        wait "$progress_pid"
        rm progress_pipe
        echo
        print_message "${COLOR_BLUE}---------------------- Docker Container Monitoring Results ----------------------${COLOR_RESET}" "INFO"
        for container in "${CONTAINERS_TO_CHECK[@]}"; do
            if [ -f "$results_dir/$container.log" ]; then
                cat "$results_dir/$container.log"; echo "-------------------------------------------------------------------------"
            fi
        done
    fi

    for issue_file in "$results_dir"/*.issues; do
        if [ -f "$issue_file" ]; then
            container_name=$(basename "$issue_file" .issues)
            issues=$(cat "$issue_file")
            WARNING_OR_ERROR_CONTAINERS+=("$container_name")
            CONTAINER_ISSUES_MAP["$container_name"]="$issues"
        fi
    done

    # This will show the summary of issues found asynchronously
    print_summary

    if [ ${#WARNING_OR_ERROR_CONTAINERS[@]} -gt 0 ]; then
        summary_message=""
        for container in "${WARNING_OR_ERROR_CONTAINERS[@]}"; do
            issues=${CONTAINER_ISSUES_MAP["$container"]}
            summary_message+="\n- **$container**: $issues"
        done
        summary_message=$(echo -e "$summary_message" | sed 's/^[[:space:]]*//')
        send_notification "$summary_message" "🚨 Docker Monitoring Alert"
    fi

    rm -rf "$results_dir"
fi

# --- Final Message ---
PRINT_MESSAGE_FORCE_STDOUT=true
if [ "$SUMMARY_ONLY_MODE" = "true" ]; then
    # The summary is already printed, just confirm completion
    print_message "Summary generation completed." "SUMMARY"
elif [ ${#CONTAINERS_TO_CHECK[@]} -eq 0 ]; then
    print_message "No containers specified or found running to monitor." "INFO"
    print_summary # Show host stats even if no containers monitored
else
    print_message "${COLOR_GREEN}Docker monitoring script completed successfully.${COLOR_RESET}" "INFO"
fi

exit 0
