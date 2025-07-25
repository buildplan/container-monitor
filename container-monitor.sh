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
#   ./docker-container-monitor.sh <container1> <container2> ... - Monitor specific containers (full output)
#   ./container-monitor.sh --pull      				- Choose which containers to update (only pull new image, manually recreate)
#   ./container-monitor.sh --update                             - Choose which containers to update and recreate (pull and recreate container)
#   ./container-monitor.sh --exclude=c1,c2           		- Run on all containers, excluding specific ones.
#   ./docker-container-monitor.sh summary                   	- Run all checks silently and show only the final summary.
#   ./docker-container-monitor.sh summary <c1> <c2> ...     	- Summary mode for specific containers.
#   ./docker-container-monitor.sh logs                      	- Show logs for all running containers
#   ./container-monitor.sh logs <container> [pattern...] 	- Show logs for a container, with optional filtering (e.g., logs my-app error warn).
#   ./docker-container-monitor.sh save logs <container_name> 	- Save logs for a specific container to a file
#   ./container-monitor.sh --prune                              - Run Docker's system prune to clean up unused resources.
#   ./container-monitor.sh --no-update        			- Run without checking for a script update.
#   ./container-monitor.sh --help [or -h]                 	- Shows script usage commands.
#
# Prerequisites:
#   - Docker
#   - jq (for processing JSON output from docker inspect and docker stats)
#   - yq (for yaml config file)
#   - skopeo (for checking for container image updates)
#   - bc or awk (awk is used in this script for float comparisons to reduce dependencies)
#   - timeout (from coreutils, for docker exec commands)

# --- Script & Update Configuration ---
VERSION="v0.40"
VERSION_DATE="2025-07-23"
SCRIPT_URL="https://github.com/buildplan/container-monitor/raw/refs/heads/main/container-monitor.sh"
CHECKSUM_URL="${SCRIPT_URL}.sha256" # hash check

# --- ANSI Color Codes ---
COLOR_RESET=$'\033[0m'
COLOR_RED=$'\033[0;31m'
COLOR_GREEN=$'\033[0;32m'
COLOR_YELLOW=$'\033[0;33m'
COLOR_CYAN=$'\033[0;36m'
COLOR_MAGENTA=$'\033[0;35m'
COLOR_BLUE=$'\033[0;34m'

# --- Global Flags ---
SUMMARY_ONLY_MODE=false
PRINT_MESSAGE_FORCE_STDOUT=false
INTERACTIVE_UPDATE_MODE=false
RECREATE_MODE=false
UPDATE_SKIPPED=false

# --- Get path to script directory ---
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export SCRIPT_DIR

STATE_FILE="$SCRIPT_DIR/.monitor_state.json"
LOCK_FILE="$SCRIPT_DIR/.monitor_state.lock"

# --- Script Default Configuration Values ---
_SCRIPT_DEFAULT_LOG_LINES_TO_CHECK=20
_SCRIPT_DEFAULT_CHECK_FREQUENCY_MINUTES=360
_SCRIPT_DEFAULT_LOG_FILE="$SCRIPT_DIR/docker-monitor.log"
_SCRIPT_DEFAULT_CPU_WARNING_THRESHOLD=80
_SCRIPT_DEFAULT_MEMORY_WARNING_THRESHOLD=80
_SCRIPT_DEFAULT_DISK_SPACE_THRESHOLD=80
_SCRIPT_DEFAULT_NETWORK_ERROR_THRESHOLD=10
_SCRIPT_DEFAULT_HOST_DISK_CHECK_FILESYSTEM="/"
_SCRIPT_DEFAULT_NOTIFICATION_CHANNEL="none"
_SCRIPT_DEFAULT_DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/xxxxxxxx"
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

# --- Functions ---

load_configuration() {
    _CONFIG_FILE_PATH="$SCRIPT_DIR/config.yml"

    if [ -f "$_CONFIG_FILE_PATH" ] && ! yq e '.' "$_CONFIG_FILE_PATH" >/dev/null 2>&1; then
        print_message "Invalid syntax in config.yml. Please check the file for errors." "DANGER"
        exit 1
    fi

    get_config_val() {
        if [ -f "$_CONFIG_FILE_PATH" ]; then
            yq e "$1 // \"\"" "$_CONFIG_FILE_PATH"
        else
            echo ""
        fi
    }

    # Helper function to set a final variable value based on priority
    set_final_config() {
        local var_name="$1"; local yaml_path="$2"; local default_value="$3"
        local env_value; env_value=$(printenv "$var_name")
        local yaml_value; yaml_value=$(get_config_val "$yaml_path")

        if [ -n "$env_value" ]; then
            printf -v "$var_name" '%s' "$env_value"
        elif [ -n "$yaml_value" ]; then
            printf -v "$var_name" '%s' "$yaml_value"
        else
            printf -v "$var_name" '%s' "$default_value"
        fi
    }

    # Set all configuration variables
    set_final_config "LOG_LINES_TO_CHECK"            ".general.log_lines_to_check"           "$_SCRIPT_DEFAULT_LOG_LINES_TO_CHECK"
    set_final_config "LOG_FILE"                      ".general.log_file"                     "$_SCRIPT_DEFAULT_LOG_FILE"
    set_final_config "CPU_WARNING_THRESHOLD"         ".thresholds.cpu_warning"               "$_SCRIPT_DEFAULT_CPU_WARNING_THRESHOLD"
    set_final_config "MEMORY_WARNING_THRESHOLD"      ".thresholds.memory_warning"            "$_SCRIPT_DEFAULT_MEMORY_WARNING_THRESHOLD"
    set_final_config "DISK_SPACE_THRESHOLD"          ".thresholds.disk_space"                "$_SCRIPT_DEFAULT_DISK_SPACE_THRESHOLD"
    set_final_config "NETWORK_ERROR_THRESHOLD"       ".thresholds.network_error"             "$_SCRIPT_DEFAULT_NETWORK_ERROR_THRESHOLD"
    set_final_config "HOST_DISK_CHECK_FILESYSTEM"    ".host_system.disk_check_filesystem"    "$_SCRIPT_DEFAULT_HOST_DISK_CHECK_FILESYSTEM"
    set_final_config "NOTIFICATION_CHANNEL"          ".notifications.channel"                "$_SCRIPT_DEFAULT_NOTIFICATION_CHANNEL"
    set_final_config "DISCORD_WEBHOOK_URL"           ".notifications.discord.webhook_url"    "$_SCRIPT_DEFAULT_DISCORD_WEBHOOK_URL"
    set_final_config "NTFY_SERVER_URL"               ".notifications.ntfy.server_url"        "$_SCRIPT_DEFAULT_NTFY_SERVER_URL"
    set_final_config "NTFY_TOPIC"                    ".notifications.ntfy.topic"             "$_SCRIPT_DEFAULT_NTFY_TOPIC"
    set_final_config "NTFY_ACCESS_TOKEN"             ".notifications.ntfy.access_token"      "$_SCRIPT_DEFAULT_NTFY_ACCESS_TOKEN"
    set_final_config "NOTIFY_ON"                     ".notifications.notify_on"              "Updates,Logs,Status,Restarts,Resources,Disk,Network"
    set_final_config "UPDATE_CHECK_CACHE_HOURS"      ".general.update_check_cache_hours"     "6"
    set_final_config "DOCKER_USERNAME"               ".auth.docker_username"                 ""
    set_final_config "DOCKER_PASSWORD"               ".auth.docker_password"                 ""
    set_final_config "LOCK_TIMEOUT_SECONDS"          ".general.lock_timeout_seconds"         "10"

    if ! mapfile -t LOG_ERROR_PATTERNS < <(yq e '.logs.error_patterns[]' "$_CONFIG_FILE_PATH" 2>&1); then
        print_message "Failed to parse log error patterns. Using defaults." "WARNING"
        LOG_ERROR_PATTERNS=()
    fi

    # Validate NOTIFICATION_CHANNEL
    if [[ "$NOTIFICATION_CHANNEL" != "discord" && "$NOTIFICATION_CHANNEL" != "ntfy" && "$NOTIFICATION_CHANNEL" != "none" ]]; then
        print_message "Invalid notification_channel '$NOTIFICATION_CHANNEL' in config.yml. Valid values are: discord, ntfy, none. Disabling notifications." "WARNING"
        NOTIFICATION_CHANNEL="none"
    fi

    # Validate NOTIFY_ON values
    if [ -n "$NOTIFY_ON" ]; then
        valid_issues=("Updates" "Logs" "Status" "Restarts" "Resources" "Disk" "Network")
        IFS=',' read -r -a notify_on_array <<< "$NOTIFY_ON"
        for issue in "${notify_on_array[@]}"; do
            local is_valid=false
            for valid_issue in "${valid_issues[@]}"; do
                if [[ "${issue,,}" == "${valid_issue,,}" ]]; then
                    is_valid=true
                    break
                fi
            done
            if [ "$is_valid" = false ]; then
                print_message "Invalid notify_on value '$issue' in config.yml. Valid values are: ${valid_issues[*]}" "WARNING"
            fi
        done
    elif [ "$NOTIFICATION_CHANNEL" != "none" ]; then
        print_message "notify_on is empty in config.yml. No notifications will be sent." "WARNING"
    fi

    # Normalize NOTIFY_ON to use standard case (optional, ensures consistency)
    if [ -n "$NOTIFY_ON" ]; then
        local normalized_notify_on=""
        IFS=',' read -r -a notify_on_array <<< "$NOTIFY_ON"
        for issue in "${notify_on_array[@]}"; do
            case "${issue,,}" in
                updates) normalized_notify_on+="Updates," ;;
                logs) normalized_notify_on+="Logs," ;;
                status) normalized_notify_on+="Status," ;;
                restarts) normalized_notify_on+="Restarts," ;;
                resources) normalized_notify_on+="Resources," ;;
                disk) normalized_notify_on+="Disk," ;;
                network) normalized_notify_on+="Network," ;;
                *) normalized_notify_on+="$issue," ;; # Preserve invalid values for warning
            esac
        done
        NOTIFY_ON="${normalized_notify_on%,}" # Remove trailing comma
    fi

    # Load the list of default containers from the config file if no ENV var is set for it
    if [ -z "$CONTAINER_NAMES" ] && [ -f "$_CONFIG_FILE_PATH" ]; then
        mapfile -t CONTAINER_NAMES_FROM_CONFIG_FILE < <(yq e '.containers.monitor_defaults[]' "$_CONFIG_FILE_PATH" 2>/dev/null)
    fi

}

print_help() {
    local format="  %-64s %s\n"

    printf "${COLOR_GREEN}Usage:${COLOR_RESET}\n"
    printf "$format" "${COLOR_YELLOW}./container-monitor.sh${COLOR_RESET}" "${COLOR_CYAN}- Monitor based on config (or all running)${COLOR_RESET}"
    printf "$format" "${COLOR_YELLOW}./container-monitor.sh <container1> <container2> ...${COLOR_RESET}" "${COLOR_CYAN}- Monitor specific containers${COLOR_RESET}"
    printf "$format" "${COLOR_YELLOW}./container-monitor.sh --pull${COLOR_RESET}" "${COLOR_CYAN}- Interactively pull new images for containers${COLOR_RESET}"
    printf "$format" "${COLOR_YELLOW}./container-monitor.sh --update${COLOR_RESET}" "${COLOR_CYAN}- Interactively pull and recreate containers${COLOR_RESET}"
    printf "$format" "${COLOR_YELLOW}./container-monitor.sh --exclude=c1,c2${COLOR_RESET}" "${COLOR_CYAN}- Run on all containers, excluding specific ones${COLOR_RESET}"
    printf "$format" "${COLOR_YELLOW}./container-monitor.sh summary${COLOR_RESET}" "${COLOR_CYAN}- Run checks silently and show only summary${COLOR_RESET}"
    printf "$format" "${COLOR_YELLOW}./container-monitor.sh logs <container> [pattern...]${COLOR_RESET}" "${COLOR_CYAN}- Show logs for a container, with optional filters${COLOR_RESET}"
    printf "$format" "${COLOR_YELLOW}./container-monitor.sh save logs <container>${COLOR_RESET}" "${COLOR_CYAN}- Save logs for a specific container to a file${COLOR_RESET}"
    printf "$format" "${COLOR_YELLOW}./container-monitor.sh --prune${COLOR_RESET}" "${COLOR_CYAN}- Run Docker's system prune to clean up resources${COLOR_RESET}"
    printf "$format" "${COLOR_YELLOW}./container-monitor.sh --no-update${COLOR_RESET}" "${COLOR_CYAN}- Run without checking for a script update${COLOR_RESET}"
    printf "$format" "${COLOR_YELLOW}./container-monitor.sh --help [or -h]${COLOR_RESET}" "${COLOR_CYAN}- Show this help message${COLOR_RESET}"

    printf "\n${COLOR_GREEN}Notes:${COLOR_RESET}\n"
    printf "  ${COLOR_CYAN}- Environment variables (e.g., NOTIFICATION_CHANNEL) override config.yml${COLOR_RESET}\n"
    printf "  ${COLOR_CYAN}- Dependencies: docker, jq, yq, skopeo, gawk, coreutils, wget${COLOR_RESET}\n"
}

print_header_box() {
    # --- Configuration for the box ---
    local box_width=55
    local border_color="$COLOR_CYAN"
    local version_color="$COLOR_GREEN"
    local date_color="$COLOR_RESET"
    local update_color="$COLOR_YELLOW"

    # --- Prepare content lines ---
    local line1="Container Monitor ${VERSION}"
    local line2="Updated: ${VERSION_DATE}"
    local line3=""
    if [ "$UPDATE_SKIPPED" = true ]; then
        line3="A new version is available to update"
    fi

    # --- Helper function to print a centered line within the box ---
    print_centered_line() {
        local text="$1"
        local text_color="$2"
        local text_len=${#text}

        # Calculate padding needed on each side to center the text
        local padding_total=$((box_width - text_len))
        local padding_left=$((padding_total / 2))
        local padding_right=$((padding_total - padding_left))

        # Print the fully constructed line
        printf "${border_color}║%*s%s%s%*s${border_color}║${COLOR_RESET}\n" \
            "$padding_left" "" \
            "${text_color}" "${text}" \
            "$padding_right" ""
    }

    # --- Draw the box ---
    local border_char="═"
    local top_border=""
    for ((i=0; i<box_width; i++)); do top_border+="$border_char"; done

    echo -e "${border_color}╔${top_border}╗${COLOR_RESET}"
    print_centered_line "$line1" "$version_color"
    print_centered_line "$line2" "$date_color"

    # If the optional update line exists, print it
    if [ -n "$line3" ]; then
        local separator_char="─"
        local separator=""
        for ((i=0; i<box_width; i++)); do separator+="$separator_char"; done
        echo -e "${border_color}╠${separator}╣${COLOR_RESET}"
        print_centered_line "$line3" "$update_color"
    fi

    echo -e "${border_color}╚${top_border}╝${COLOR_RESET}"
    echo
}

check_and_install_dependencies() {
    local missing_pkgs=()
    local manual_install_needed=false
    local yq_missing=false
    local pkg_manager=""
    local arch=""

    # 1. Determine OS Package Manager
    if command -v apt-get &>/dev/null; then
        pkg_manager="apt"
    elif command -v dnf &>/dev/null; then
        pkg_manager="dnf"
    elif command -v yum &>/dev/null; then
        pkg_manager="yum"
    fi

    # 2. Determine Architecture for yq
    case "$(uname -m)" in
        x86_64) arch="amd64" ;;
        aarch64) arch="arm64" ;;
        *) arch="unsupported" ;;
    esac

    # 3. Define dependencies
    declare -A deps=(
        [jq]=jq
        [skopeo]=skopeo
        [awk]=gawk
        [timeout]=coreutils
        [wget]=wget
    )

    print_message "Checking for required command-line tools..." "INFO"

    # Check for ALL dependencies

    if ! command -v docker &>/dev/null; then
        print_message "Docker is not installed. This is a critical dependency. Please follow the official instructions at https://docs.docker.com/engine/install/" "DANGER"
        manual_install_needed=true
    fi

    if ! command -v yq &>/dev/null; then
        yq_missing=true
    fi

    for cmd in "${!deps[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing_pkgs+=("${deps[$cmd]}")
        fi
    done

    # Offer to install packages via the system's package manager
    if [ ${#missing_pkgs[@]} -gt 0 ]; then
        print_message "The following required packages can be installed via your package manager: ${missing_pkgs[*]}" "WARNING"
        if [ -n "$pkg_manager" ]; then
            read -rp "Would you like to attempt to install them now? (y/n): " response
            if [[ "$response" =~ ^[yY]$ ]]; then
                print_message "Attempting to install with 'sudo $pkg_manager'... You may be prompted for your password." "INFO"
                local install_cmd
                if [ "$pkg_manager" == "apt" ]; then
                    install_cmd="sudo apt-get update && sudo apt-get install -y"
                else
                    install_cmd="sudo $pkg_manager install -y"
                fi

                if eval "$install_cmd ${missing_pkgs[*]}"; then
                    print_message "Package manager dependencies installed successfully." "GOOD"
                else
                    print_message "Failed to install dependencies. Please install them manually." "DANGER"
                    exit 1
                fi
            else
                print_message "Installation cancelled. Please install all dependencies manually." "DANGER"
                exit 1
            fi
        else
            print_message "No supported package manager (apt/dnf/yum) found. Please install packages manually." "DANGER"
            exit 1
        fi
    fi

    # Offer to download and install yq if it was missing
    if [ "$yq_missing" = true ]; then
        print_message "yq is not installed. It is required for parsing config.yml." "WARNING"
        if [ "$arch" == "unsupported" ]; then
            print_message "Your system architecture ($(uname -m)) is not supported for automatic yq installation. Please install it manually from https://github.com/mikefarah/yq/" "DANGER"
            manual_install_needed=true
        else
            read -rp "Would you like to download the latest version for your architecture ($arch) now? (y/n): " response
            if [[ "$response" =~ ^[yY]$ ]]; then
                print_message "Attempting to download yq with 'sudo wget'... You may be prompted for your password." "INFO"
                local yq_url="https://github.com/mikefarah/yq/releases/latest/download/yq_linux_${arch}"
                if sudo wget "$yq_url" -O /usr/bin/yq && sudo chmod +x /usr/bin/yq; then
                    print_message "yq installed successfully to /usr/bin/yq." "GOOD"
                else
                    print_message "Failed to download or install yq. Please install it manually." "DANGER"
                    manual_install_needed=true
                fi
            else
                print_message "Installation cancelled. Please install yq manually." "DANGER"
                manual_install_needed=true
            fi
        fi
    fi

    # Exit if manual installations are still required
    if [ "$manual_install_needed" = true ]; then
        print_message "Please address the manually installed dependencies listed above before running the script again." "DANGER"
        exit 1
    fi

    # If we get here, all dependencies are met
    if [ "$yq_missing" = false ] && [ ${#missing_pkgs[@]} -eq 0 ]; then
         print_message "All required dependencies are installed." "GOOD"
    fi
}

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

    if [[ "$DISCORD_WEBHOOK_URL" == *"your_discord_webhook_url_here"* || -z "$DISCORD_WEBHOOK_URL" ]]; then
        print_message "Discord webhook URL is not configured." "DANGER"
        return
    fi

    local json_payload
    json_payload=$(jq -n \
                  --arg title "$title" \
                  --arg description "$message" \
                  '{
                    "username": "Docker Monitor",
                    "embeds": [{
                      "title": $title,
                      "description": $description,
                      "color": 15158332,
                      "timestamp": "'$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")'"
                    }]
                  }')

    run_with_retry curl -s -H "Content-Type: application/json" -X POST -d "$json_payload" "$DISCORD_WEBHOOK_URL" > /dev/null
}

send_ntfy_notification() {
    local message="$1"
    local title="$2"

    if [[ "$NTFY_TOPIC" == "your_ntfy_topic_here" || -z "$NTFY_TOPIC" ]]; then
         print_message "Ntfy topic is not configured in config.yml." "DANGER"
         return
    fi

    local priority; priority=$(get_config_val ".notifications.ntfy.priority")
    local icon_url; icon_url=$(get_config_val ".notifications.ntfy.icon_url")
    local click_url; click_url=$(get_config_val ".notifications.ntfy.click_url")


    if [[ -n "$priority" && ! "$priority" =~ ^[1-5]$ ]]; then
        print_message "Invalid ntfy priority '$priority' in config.yml. Must be 1-5. Using default." "WARNING"
        priority="" # Clear the invalid value
    fi
    priority=${priority:-3}
    if [[ -n "$icon_url" && ! "$icon_url" =~ ^https?:// ]]; then
        print_message "Invalid ntfy icon_url '$icon_url' in config.yml. Must be a valid URL." "WARNING"
        icon_url=""
    fi
    if [[ -n "$click_url" && ! "$click_url" =~ ^https?:// ]]; then
        print_message "Invalid ntfy click_url '$click_url' in config.yml. Must be a valid URL." "WARNING"
        click_url=""
    fi

    local curl_opts=()
    curl_opts+=("-s")
    curl_opts+=("-H" "Title: $title")
    curl_opts+=("-H" "Tags: warning")

    if [[ -n "$priority" ]]; then
        curl_opts+=("-H" "Priority: $priority")
    fi
    if [[ -n "$icon_url" ]]; then
        curl_opts+=("-H" "Icon: $icon_url")
    fi
    if [[ -n "$click_url" ]]; then
        curl_opts+=("-H" "Click: $click_url")
    fi
    if [[ -n "$NTFY_ACCESS_TOKEN" ]]; then
        curl_opts+=("-H" "Authorization: Bearer $NTFY_ACCESS_TOKEN")
    fi

    curl_opts+=("-d" "$message")
    run_with_retry curl "${curl_opts[@]}" "$NTFY_SERVER_URL/$NTFY_TOPIC" > /dev/null
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
    if [[ ! "$response" =~ ^[yY]$ ]]; then
        UPDATE_SKIPPED=true
        return
    fi

    # Create a temporary directory
    local temp_dir
    temp_dir=$(mktemp -d)
    if [ ! -d "$temp_dir" ]; then
        print_message "Failed to create temporary directory. Update aborted." "DANGER"
        exit 1
    fi

    # Set a trap to automatically clean up the temporary directory on script exit
    trap 'rm -rf -- "$temp_dir"' EXIT

    local temp_script="$temp_dir/$(basename "$SCRIPT_URL")"
    local temp_checksum="$temp_dir/$(basename "$CHECKSUM_URL")"

    print_message "Downloading new script version..." "INFO"
    if ! curl -sL "$SCRIPT_URL" -o "$temp_script"; then
        print_message "Failed to download the new script. Update aborted." "DANGER"
        exit 1
    fi

    print_message "Downloading checksum..." "INFO"
    if ! curl -sL "$CHECKSUM_URL" -o "$temp_checksum"; then
        print_message "Failed to download the checksum file. Update aborted." "DANGER"
        exit 1
    fi

    print_message "Verifying checksum..." "INFO"
    # The sha256sum command must be run from the directory containing the files
    (cd "$temp_dir" && sha256sum -c "$(basename "$CHECKSUM_URL")" --quiet)
    if [ $? -ne 0 ]; then
        print_message "Checksum verification failed! The downloaded file may be corrupt. Update aborted." "DANGER"
        exit 1
    fi
    print_message "Checksum verified successfully." "GOOD"

    print_message "Checking script syntax..." "INFO"
    if ! bash -n "$temp_script"; then
        print_message "Downloaded file is not a valid script. Update aborted." "DANGER"
        exit 1
    fi
    print_message "Syntax check passed." "GOOD"

    # If all checks pass, move the new script into place
    if ! mv "$temp_script" "$0"; then
        print_message "Failed to replace the old script file. Update aborted." "DANGER"
        exit 1
    fi
    chmod +x "$0"

    # Clean up the trap and temporary files before exiting
    trap - EXIT
    rm -rf -- "$temp_dir"

    print_message "Update successful. Please run the script again." "GOOD"
    exit 0
}

run_with_retry() {
    local max_attempts=3
    local attempt=0
    local exit_code=0

    # Hide stdout of the command, but show stderr on failure
    # Pass stdout through on success
    local output
    output=$("$@" 2> >(tee /dev/stderr))
    exit_code=$?

    while [ $exit_code -ne 0 ] && [ $attempt -lt $max_attempts ]; do
        attempt=$((attempt + 1))
        local sleep_time=$((2**attempt))
        print_message "Command failed. Retrying in ${sleep_time}s... (Attempt ${attempt}/${max_attempts})" "WARNING"
        sleep "$sleep_time"
        output=$("$@" 2> >(tee /dev/stderr))
        exit_code=$?
    done

    if [ $exit_code -ne 0 ]; then
        print_message "Command failed after $max_attempts attempts." "DANGER"
    fi

    # Print the final output from the command
    echo "$output"
    return $exit_code
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
    local container_name="$1"; local inspect_data="$2"
    local saved_restart_counts_json="$3" # accept saved state as an argument

    local current_restart_count is_restarting
    current_restart_count=$(jq -r '.[0].RestartCount' <<< "$inspect_data")
    is_restarting=$(jq -r '.[0].State.Restarting' <<< "$inspect_data")

    # Get the previously saved restart count from the JSON state
    local saved_restart_count
    saved_restart_count=$(jq -r --arg name "$container_name" '.restarts[$name] // 0' <<< "$saved_restart_counts_json")

    # Check for restart loops
    if [ "$is_restarting" = "true" ]; then
        print_message "  ${COLOR_BLUE}Restart Status:${COLOR_RESET} Container is currently restarting." "WARNING"; return 1
    fi
    # Check if the restart count has increased
    if [ "$current_restart_count" -gt "$saved_restart_count" ]; then
        print_message "  ${COLOR_BLUE}Restart Status:${COLOR_RESET} Container has restarted (total: $current_restart_count)." "WARNING"; return 1
    fi

    print_message "  ${COLOR_BLUE}Restart Status:${COLOR_RESET} No new restarts detected (total: $current_restart_count)." "GOOD"; return 0
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
    local state_json="$3" # Accept full state JSON

    # 1. Prerequisite and Initial Checks
    if ! command -v skopeo &>/dev/null; then print_message "  ${COLOR_BLUE}Update Check:${COLOR_RESET} skopeo not installed. Skipping." "INFO" >&2; return 0; fi
    if [[ "$current_image_ref" == *@sha256:* || "$current_image_ref" =~ ^sha256: ]]; then
        print_message "  ${COLOR_BLUE}Update Check:${COLOR_RESET} Image for '$container_name' is pinned by digest. Skipping." "INFO" >&2; return 0
    fi

    # 2. Check for a valid cache entry first
    local cache_key; cache_key=$(echo "$current_image_ref" | sed 's/[/:]/_/g') # Create a valid JSON key
    local cached_entry; cached_entry=$(jq -r --arg key "$cache_key" '.updates[$key] // ""' <<< "$state_json")
    if [ -n "$cached_entry" ]; then
        local cached_ts; cached_ts=$(jq -r '.timestamp' <<< "$cached_entry")
        local current_ts; current_ts=$(date +%s)
        local cache_age_sec=$((current_ts - cached_ts))
        local cache_max_age_sec=$((UPDATE_CHECK_CACHE_HOURS * 3600))
        if [ "$cache_age_sec" -lt "$cache_max_age_sec" ]; then
            local cached_msg; cached_msg=$(jq -r '.message' <<< "$cached_entry")
            local cached_code; cached_code=$(jq -r '.exit_code' <<< "$cached_entry")
            if [ "$cached_code" -ne 0 ]; then
                print_message "  ${COLOR_BLUE}Update Check:${COLOR_RESET} ${cached_msg} (cached)" "WARNING" >&2; echo "$cached_msg"; return "$cached_code"
            else
                print_message "  ${COLOR_BLUE}Update Check:${COLOR_RESET} Image '$current_image_ref' is up-to-date (cached)." "GOOD" >&2; return 0
            fi
        fi
    fi

    # 3. Prepare for Live Check
    local current_tag="latest"
    local image_name_no_tag="$current_image_ref"
    if [[ "$current_image_ref" == *":"* ]]; then
        current_tag="${current_image_ref##*:}"
        image_name_no_tag="${current_image_ref%:$current_tag}"
    fi
    local registry_host="registry-1.docker.io"; local image_path_for_skopeo="$image_name_no_tag"
    if [[ "$image_name_no_tag" == *"/"* ]]; then
        local first_part; first_part=$(echo "$image_name_no_tag" | cut -d'/' -f1)
        if [[ "$first_part" == *"."* || "$first_part" == "localhost" || "$first_part" == *":"* ]]; then
            registry_host="$first_part"; image_path_for_skopeo=$(echo "$image_name_no_tag" | cut -d'/' -f2-)
        fi
    else
        image_path_for_skopeo="library/$image_name_no_tag"
    fi
    local skopeo_repo_ref="docker://$registry_host/$image_path_for_skopeo"
    local skopeo_opts=()
    if [ -n "$DOCKER_USERNAME" ] && [ -n "$DOCKER_PASSWORD" ]; then
        skopeo_opts+=("--creds" "$DOCKER_USERNAME:$DOCKER_PASSWORD")
    fi
    get_release_url() { yq e ".containers.release_urls.\"${1}\" // \"\"" "$SCRIPT_DIR/config.yml"; }

    # Helper to read the strategy from config.yml, falling back to "default"
    get_update_strategy() {
        yq e ".containers.update_strategies.\"${1}\" // .containers.update_strategies.\"${1%%:*}\" // \"default\"" "$SCRIPT_DIR/config.yml" 2>/dev/null
    }
    local strategy; strategy=$(get_update_strategy "$image_name_no_tag")

    # Always treat 'latest' tag as a digest check, regardless of strategy
    if [ "$current_tag" == "latest" ]; then
        strategy="digest"
    fi

    local latest_stable_version=""
    local update_check_failed=false

    case "$strategy" in
        "digest")
            local local_digest; local_digest=$(docker inspect -f '{{index .RepoDigests 0}}' "$current_image_ref" 2>/dev/null | cut -d'@' -f2)
            if [ -z "$local_digest" ]; then
                print_message "  ${COLOR_BLUE}Update Check:${COLOR_RESET} Could not get local digest for '$current_image_ref'. Cannot check tag '$current_tag'." "WARNING" >&2; update_check_failed=true
            else
                local skopeo_output; skopeo_output=$(skopeo "${skopeo_opts[@]}" inspect "${skopeo_repo_ref}:${current_tag}" 2>&1)
                if [ $? -ne 0 ]; then
                    print_message "  ${COLOR_BLUE}Update Check:${COLOR_RESET} Error inspecting remote image '${skopeo_repo_ref}:${current_tag}'." "DANGER" >&2; update_check_failed=true
                else
                    local remote_digest; remote_digest=$(jq -r '.Digest' <<< "$skopeo_output")
                    if [ "$remote_digest" != "$local_digest" ]; then
                        latest_stable_version="New image available for tag '${current_tag}'"
                    fi
                fi
            fi
            ;;

        "semver")
            # Strict X.Y.Z filter.
            latest_stable_version=$(skopeo "${skopeo_opts[@]}" list-tags "$skopeo_repo_ref" 2>/dev/null | jq -r '.Tags[]' | grep -E '^[v]?[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -n 1)
            ;;

        "major-lock")
            # Dynamic filter based on current tag.
            local major_version="${current_tag%%.*}"
            local variant=""
            if [[ "$current_tag" == *"-"* ]]; then
                variant="-${current_tag#*-}"
            fi
            latest_stable_version=$(skopeo "${skopeo_opts[@]}" list-tags "$skopeo_repo_ref" 2>/dev/null | jq -r '.Tags[]' | grep -E "^${major_version}(\.[0-9]+)*${variant}$" | sort -V | tail -n 1)
            ;;

        *) # "default" logicg
            latest_stable_version=$(skopeo "${skopeo_opts[@]}" list-tags "$skopeo_repo_ref" 2>/dev/null | jq -r '.Tags[]' | grep -E '^[v]?[0-9\.]+$' | grep -v -E 'alpha|beta|rc|dev|test' | sort -V | tail -n 1)
            ;;
    esac

    # Final check and reporting
    if [ "$update_check_failed" = true ]; then
        return 1
    elif [ -z "$latest_stable_version" ]; then
        # This can happen if no tags match the filter, which is not an error.
        print_message "  ${COLOR_BLUE}Update Check:${COLOR_RESET} No newer version found for '$image_name_no_tag' with strategy '$strategy'." "GOOD" >&2; return 0
    fi

    # Compare versions
    if [[ "$strategy" == "digest" ]]; then
        # For digest, latest_stable_version is a message, not a version number
        local summary_message="$latest_stable_version"
        local release_url; release_url=$(get_release_url "$image_name_no_tag")
        if [ -n "$release_url" ]; then summary_message+=", Notes: $release_url"; fi
        print_message "  ${COLOR_BLUE}Update Check:${COLOR_RESET} $summary_message" "WARNING" >&2
        echo "$summary_message"
        return 1
    elif [[ "v$current_tag" != "v$latest_stable_version" && "$current_tag" != "$latest_stable_version" ]] && [[ "$(printf '%s\n' "$latest_stable_version" "$current_tag" | sort -V | tail -n 1)" == "$latest_stable_version" ]]; then
        local summary_message="Update available: ${latest_stable_version}"
        local release_url; release_url=$(get_release_url "$image_name_no_tag")
        if [ -n "$release_url" ]; then summary_message+=", Notes: $release_url"; fi
        print_message "  ${COLOR_BLUE}Update Check:${COLOR_RESET} Update available for '$image_name_no_tag'. Latest stable is ${latest_stable_version} (you have ${current_tag})." "WARNING" >&2
        echo "$summary_message"
        return 1
    else
        print_message "  ${COLOR_BLUE}Update Check:${COLOR_RESET} Image '$current_image_ref' is up-to-date." "GOOD" >&2; return 0
    fi
}

check_logs() {
    local container_name="$1"
    local state_json="$2"

    # First, get the logs and immediately check if the command was successful
    local raw_logs
    raw_logs=$(docker logs --tail "$LOG_LINES_TO_CHECK" "$container_name" 2>&1)
    if [ $? -ne 0 ]; then
        print_message "  ${COLOR_BLUE}Log Check:${COLOR_RESET} Error retrieving logs for '$container_name'." "DANGER" >&2
        echo "" # Return an empty hash
        return 1 # Return an error code to trigger a "Logs" issue
    fi

    local error_regex
    if [ ${#LOG_ERROR_PATTERNS[@]} -gt 0 ]; then
        error_regex=$(printf "%s|" "${LOG_ERROR_PATTERNS[@]}")
        error_regex="${error_regex%|}"
    else
        error_regex='error|panic|fail|fatal'
    fi

    # Now, grep for errors within the logs we successfully retrieved
    local current_errors
    current_errors=$(echo "$raw_logs" | grep -i -E "$error_regex")

    local new_hash=""
    if [ -n "$current_errors" ]; then
        # If errors are found, generate a hash of them
        new_hash=$(echo "$current_errors" | sort | sha256sum | awk '{print $1}')
    fi

    # Get the previously saved error hash from the state file
    local saved_hash
    saved_hash=$(jq -r --arg name "$container_name" '.logs[$name] // ""' <<< "$state_json")

    # Echo the new hash so the calling function can save it to the state
    echo "$new_hash"

    # Determine the exit code based on a change in the error state
    if [[ -n "$new_hash" && "$new_hash" != "$saved_hash" ]]; then
        print_message "  ${COLOR_BLUE}Log Check:${COLOR_RESET} New errors/warnings found in logs." "WARNING" >&2
        return 1
    elif [[ -z "$new_hash" && -n "$saved_hash" ]]; then
        print_message "  ${COLOR_BLUE}Log Check:${COLOR_RESET} Previously logged errors have been resolved." "GOOD" >&2
        return 0
    elif [ -n "$new_hash" ]; then
        print_message "  ${COLOR_BLUE}Log Check:${COLOR_RESET} No *new* errors found (persistent errors may exist)." "GOOD" >&2
        return 0
    else
        print_message "  ${COLOR_BLUE}Log Check:${COLOR_RESET} Logs checked, no obvious widespread errors found." "GOOD" >&2
        return 0
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

run_prune() {
    echo
    print_message "The prune command will run 'docker system prune -a'." "WARNING"
    print_message "This will remove ALL unused containers, networks, images, and the build cache." "WARNING"
    print_message "${COLOR_RED}This action is irreversible.${COLOR_RESET}" "NONE"
    echo

    local response
    read -rp "Are you absolutely sure you want to continue? (y/n): " response
    if [[ "$response" =~ ^[yY]$ ]]; then
        print_message "Running 'docker system prune -a'..." "INFO"
        docker system prune -a
        print_message "Prune command completed." "GOOD"
    else
        print_message "Prune operation cancelled." "INFO"
    fi
}

pull_new_image() {
    local container_name_to_update="$1"
    print_message "Getting image details for '$container_name_to_update'..." "INFO"

    if [ -n "$DOCKER_USERNAME" ] && [ -n "$DOCKER_PASSWORD" ]; then
        if ! echo "$DOCKER_PASSWORD" | docker login -u "$DOCKER_USERNAME" --password-stdin >/dev/null 2>&1; then
            print_message "Failed to login to Docker registry. Please check credentials." "DANGER"
        fi
    fi

    local current_image_ref
    current_image_ref=$(docker inspect -f '{{.Config.Image}}' "$container_name_to_update" 2>/dev/null)
    if [ -z "$current_image_ref" ]; then
        print_message "Could not find image for '$container_name_to_update'. Aborting update." "DANGER"
        return 1
    fi

    print_message "Pulling new image for: $current_image_ref" "INFO"
    if docker pull "$current_image_ref"; then
        print_message "Successfully pulled new image for '$container_name_to_update'." "GOOD"
        print_message "  ${COLOR_YELLOW}ACTION REQUIRED:${COLOR_RESET} You now need to manually recreate the container (e.g., using 'docker compose up -d --force-recreate' or your management tool) to apply the update." "WARNING"
    else
        print_message "Failed to pull new image for '$container_name_to_update'." "DANGER"
    fi
}

recreate_container() {
    local container_name="$1"
    print_message "Starting full update for '$container_name'..." "INFO"

    # 1. Get compose project details from the container's labels
    local working_dir; working_dir=$(docker inspect --format '{{ index .Config.Labels "com.docker.compose.project.working_dir" }}' "$container_name" 2>/dev/null)
    local service_name; service_name=$(docker inspect --format '{{ index .Config.Labels "com.docker.compose.service" }}' "$container_name" 2>/dev/null)
    local config_files; config_files=$(docker inspect --format '{{ index .Config.Labels "com.docker.compose.project.config_files" }}' "$container_name" 2>/dev/null)

    if [ -z "$working_dir" ] || [ -z "$service_name" ]; then
        print_message "Cannot auto-recreate '$container_name'. Not managed by a known docker-compose version." "DANGER"
        return 1
    fi

    # 2. Build the base docker-compose command, including the -f flags for the specific files
    local compose_cmd_base=("docker" "compose")
    if [ -n "$config_files" ]; then
        IFS=',' read -r -a files_array <<< "$config_files"
        for file in "${files_array[@]}"; do
            compose_cmd_base+=("-f" "$file")
        done
    fi

    # 3. Run the update commands inside a subshell for safety
    (
        cd "$working_dir" || { print_message "Failed to navigate to compose directory: '$working_dir'" "DANGER"; exit 1; }

        print_message "Running 'docker compose pull $service_name'..." "INFO"
        if ! "${compose_cmd_base[@]}" pull "$service_name" < /dev/null; then
            print_message "Failed to pull new image for service '$service_name'." "DANGER"
            exit 1
        fi

        print_message "Running 'docker compose up -d --force-recreate $service_name'..." "INFO"
        if ! "${compose_cmd_base[@]}" up -d --force-recreate "$service_name" < /dev/null; then
            print_message "Failed to recreate service '$service_name'." "DANGER"
            exit 1
        fi

        print_message "Container '$container_name' (service '$service_name') successfully updated. ✅" "GOOD"
        print_message " ⚠ ${COLOR_YELLOW}ACTION REQUIRED:${COLOR_RESET} To make this update permanent, update the image tag in your compose file for the '${service_name}' service." "WARNING"
    )
}

run_interactive_update_mode() {
    print_message "Starting interactive update check..." "INFO"

    local containers_with_updates=()
    local container_update_details=() # Array to store the detailed message

    # 1. Find all running containers
    mapfile -t all_containers < <(docker container ls --format '{{.Names}}' 2>/dev/null)
    if [ ${#all_containers[@]} -eq 0 ]; then
        print_message "No running containers found to check." "INFO"
        return
    fi
    print_message "Checking ${#all_containers[@]} containers for available updates..." "NONE"

    # 2. Check each container for updates
    for container in "${all_containers[@]}"; do
        local current_image; current_image=$(docker inspect -f '{{.Config.Image}}' "$container" 2>/dev/null)
        local update_details; update_details=$(check_for_updates "$container" "$current_image")
        if [ $? -ne 0 ]; then
            containers_with_updates+=("$container")
            container_update_details+=("$update_details")
        fi
    done

    # 3. If no updates, exit
    if [ ${#containers_with_updates[@]} -eq 0 ]; then
        print_message "All containers are up-to-date. Nothing to do. ✅" "GOOD"
        return
    fi

    # 4. If updates are found, present the menu
    print_message "The following containers have updates available:" "INFO"
    for i in "${!containers_with_updates[@]}"; do
        echo -e "  ${COLOR_CYAN}[$((i + 1))]${COLOR_RESET} ${containers_with_updates[i]} (${COLOR_YELLOW}${container_update_details[i]}${COLOR_RESET})"
    done
    echo ""

    # 5. Get user input
    read -rp "Enter the number(s) of the containers to update (e.g., '1' or '1,3'), or 'all', or press Enter to cancel: " choice
    if [ -z "$choice" ]; then
        print_message "Update cancelled by user." "INFO"
        return
    fi

    # 6. Process the choice and pull images
        local containers_to_process=()
        if [ "$choice" == "all" ]; then
            containers_to_process=("${containers_with_updates[@]}")
        else
            IFS=',' read -r -a selections <<< "$choice"
            for sel in "${selections[@]}"; do
                if [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 1 ] && [ "$sel" -le "${#containers_with_updates[@]}" ]; then
                    containers_to_process+=("${containers_with_updates[$((sel - 1))]}")
                else
                    print_message "Invalid selection: '$sel'. Skipping." "DANGER"
                fi
            done
        fi

        for container_to_update in "${containers_to_process[@]}"; do
            if [ "$RECREATE_MODE" = true ]; then
                # If --update was used, call the new function
                recreate_container "$container_to_update"
            else
                # Otherwise, call the original pull function
                pull_new_image "$container_to_update"
            fi
        done

    # prune choice
    echo
    local prune_choice
    read -rp "${COLOR_YELLOW}Update process finished. Would you like to clean up the system now? (y/n): ${COLOR_RESET}" prune_choice
    if [[ "$prune_choice" =~ ^[yY]$ ]]; then
        run_prune
    fi

    print_message "Interactive update process finished." "INFO"
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
      local display_issues="${issues//|/, }"
      issue_emoji="❌" 
      if [[ "$issues" == *"Status"* ]]; then issue_emoji="🛑";
      elif [[ "$issues" == *"Restarts"* ]]; then issue_emoji="🔥";
      elif [[ "$issues" == *"Logs"* ]]; then issue_emoji="📜";
      elif [[ "$issues" == *"Update"* ]]; then issue_emoji="🔄";
      elif [[ "$issues" == *"Resources"* ]]; then issue_emoji="📈";
      elif [[ "$issues" == *"Disk"* ]]; then issue_emoji="💾";
      elif [[ "$issues" == *"Network"* ]]; then issue_emoji="🌐"; fi
      print_message "- ${container_name_summary} ${issue_emoji} (${COLOR_BLUE}Issues:${COLOR_RESET} ${display_issues})" "WARNING"
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
    local state_json_string="$CURRENT_STATE_JSON_STRING" # Read state from environment

    # Redirect stdout to a log file for this container's check
    exec &> "$results_dir/$container_name_or_id.log"

    print_message "${COLOR_BLUE}Container:${COLOR_RESET} ${container_name_or_id}" "INFO"
    local inspect_json; inspect_json=$(docker inspect "$container_name_or_id" 2>/dev/null)
    if [ -z "$inspect_json" ]; then
        print_message "  ${COLOR_BLUE}Status:${COLOR_RESET} Container not found or inspect failed." "DANGER"
        echo "Not Found" > "$results_dir/$container_name_or_id.issues"
        return
    fi

    local container_actual_name; container_actual_name=$(jq -r '.[0].Name' <<< "$inspect_json" | sed 's|^/||')
    local current_restart_count; current_restart_count=$(jq -r '.[0].RestartCount' <<< "$inspect_json")
    echo "$current_restart_count" > "$results_dir/$container_actual_name.restarts" # Save current restart count

    local stats_json; stats_json=$(docker stats --no-stream --format '{{json .}}' "$container_name_or_id" 2>/dev/null)
    local cpu_percent="N/A"; local mem_percent="N/A"
    if [ -n "$stats_json" ]; then
        cpu_percent=$(jq -r '.CPUPerc // "N/A"' <<< "$stats_json" | tr -d '%')
        mem_percent=$(jq -r '.MemPerc // "N/A"' <<< "$stats_json" | tr -d '%')
    else
        print_message "  ${COLOR_BLUE}Stats:${COLOR_RESET} Could not retrieve stats for '$container_actual_name'." "WARNING"
    fi

    local issue_tags=()
    check_container_status "$container_actual_name" "$inspect_json" "$cpu_percent" "$mem_percent"; if [ $? -ne 0 ]; then issue_tags+=("Status"); fi
    # Pass the state JSON string as the third argument
    check_container_restarts "$container_actual_name" "$inspect_json" "$state_json_string"; if [ $? -ne 0 ]; then issue_tags+=("Restarts"); fi
    check_resource_usage "$container_actual_name" "$cpu_percent" "$mem_percent"; if [ $? -ne 0 ]; then issue_tags+=("Resources"); fi
    check_disk_space "$container_actual_name" "$inspect_json"; if [ $? -ne 0 ]; then issue_tags+=("Disk"); fi
    check_network "$container_actual_name"; if [ $? -ne 0 ]; then issue_tags+=("Network"); fi

    local current_image_ref_for_update; current_image_ref_for_update=$(jq -r '.[0].Config.Image' <<< "$inspect_json")

    # Capture all output to determine if the check was cached, and pass the state string
    local update_output; update_output=$(check_for_updates "$container_actual_name" "$current_image_ref_for_update" "$state_json_string" 2>&1)
    local update_exit_code=$?
    local update_details; update_details=$(echo "$update_output" | tail -n 1) # Message is always last line

    if [ "$update_exit_code" -ne 0 ]; then
        issue_tags+=("$update_details")
    fi

    # If not, it was a live check and the result should be cached for next time.
    if ! echo "$update_output" | grep -q "(cached)"; then
        local cache_key; cache_key=$(echo "$current_image_ref_for_update" | sed 's/[/:]/_/g')
	jq -n --arg key "$cache_key" --arg msg "$update_details" --argjson code "$update_exit_code" \
	  '{key: $key, data: {message: $msg, exit_code: $code, timestamp: (now | floor)}}' > "$results_dir/$container_actual_name.update_cache"
    fi

    local new_log_hash
    new_log_hash=$(check_logs "$container_actual_name" "$state_json_string")
    if [ $? -ne 0 ]; then
        issue_tags+=("Logs")
    fi
    echo "$new_log_hash" > "$results_dir/$container_actual_name.log_hash"

    if [ ${#issue_tags[@]} -gt 0 ]; then
        (IFS='|'; echo "${issue_tags[*]}") > "$results_dir/$container_actual_name.issues"
    fi
}

# --- Main Execution ---
main() {
    # Help, show script commands
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        print_help
        return 0
    fi

    # 1. Check for and offer to install any missing dependencies
    check_and_install_dependencies

    # 2. Load all configuration from files and environment variables
    load_configuration

    # 3. Handle the --no-update flag before doing anything else
    local run_update_check=true
    declare -a initial_args=("$@")
    for arg in "$@"; do
        if [[ "$arg" == "--no-update" ]]; then
            run_update_check=false
            break
        fi
    done
    # 3a. --prune flag
    for arg in "$@"; do
        if [[ "$arg" == "--prune" ]]; then
            run_prune
            exit 0
        fi
    done

    # 4. Check for script updates if not skipped
    if [[ "$run_update_check" == true && "$SCRIPT_URL" != *"your-username/your-repo"* ]]; then
        local latest_version
        latest_version=$(curl -sL "$SCRIPT_URL" | grep -m 1 "VERSION=" | cut -d'"' -f2)
        if [[ -n "$latest_version" && "$VERSION" != "$latest_version" ]]; then
            self_update
        fi
    fi

    # 5. Determine script mode before printing header
    if [[ " ${initial_args[*]} " =~ " --pull " ]]; then
        INTERACTIVE_UPDATE_MODE=true
    fi
    if [[ " ${initial_args[*]} " =~ " summary " ]]; then
        SUMMARY_ONLY_MODE=true
    fi

    # 6. Print the header box for manual runs, checking for terminal compatibility
    if [ "$SUMMARY_ONLY_MODE" = false ] && [ "$INTERACTIVE_UPDATE_MODE" = false ]; then
        if [ -t 1 ] && tput colors &>/dev/null && [ "$(tput colors)" -ge 8 ]; then
            print_header_box
        else
            # Simple fallback for incompatible terminals
            echo "--- Container Monitor ${VERSION} ---"
        fi
    fi

    # --- Initialize arrays for this run ---
    declare -a CONTAINERS_TO_CHECK=()
    declare -a WARNING_OR_ERROR_CONTAINERS=()
    declare -A CONTAINER_ISSUES_MAP
    declare -a CONTAINERS_TO_EXCLUDE=()

    declare -a remaining_args=()
    for arg in "$@"; do
        case "$arg" in
            --exclude=*)
                local EXCLUDE_STR="${arg#*=}"
                IFS=',' read -r -a CONTAINERS_TO_EXCLUDE <<< "$EXCLUDE_STR"
                ;;
            --update)
                RECREATE_MODE=true
                INTERACTIVE_UPDATE_MODE=true
                ;;
            # Ignore flags already processed
            --no-update|--pull|summary)
                ;;
            *)
                remaining_args+=("$arg")
                ;;
        esac
    done
    set -- "${remaining_args[@]}"

    # --- Handle Different Execution Modes ---
    if [ "$INTERACTIVE_UPDATE_MODE" = true ]; then
        run_interactive_update_mode
        return 0
    fi

    if [ "$#" -gt 0 ]; then
        if [ "$SUMMARY_ONLY_MODE" = "false" ]; then
            case "$1" in
                logs)
                    shift # Move past "logs"
                    if [ -z "$1" ]; then
                        print_message "Usage: $0 logs <container_name> [filter1] [filter2] ..." "DANGER"
                        return 1
                    fi
                    local container_to_log="$1"
                    shift

                    if [ $# -eq 0 ]; then
                        print_message "--- Showing all recent logs for '$container_to_log' ---" "INFO"
                        docker logs --tail "$LOG_LINES_TO_CHECK" "$container_to_log"
                    else
                        local all_args_string="$*"
                        local processed_args_string="${all_args_string//,/' '}"

                        local final_patterns=()
                        read -r -a final_patterns <<< "$processed_args_string"

                        local egrep_pattern
                        egrep_pattern=$(IFS='|'; echo "${final_patterns[*]}")

                        local filter_list
                        filter_list=$(printf "'%s' " "${final_patterns[@]}")

                        print_message "--- Filtering logs for '$container_to_log' with patterns: ${filter_list}---" "INFO"

                        docker logs --tail "$LOG_LINES_TO_CHECK" "$container_to_log" 2>&1 | grep -E -i --color=auto "$egrep_pattern"
                    fi
                    return 0
                    ;;
                save)
                    shift
                    if [[ "$1" == "logs" && -n "$2" ]]; then
                        local container_to_save="$2"
                        save_logs "$container_to_save"
                    else
                        echo "Usage: $0 save logs <container_name>"
                    fi
                    return 0
                    ;;
                *)
                    CONTAINERS_TO_CHECK=("$@")
                    ;;
            esac

        else
            # If in summary mode, all remaining args are container names
            CONTAINERS_TO_CHECK=("$@")
        fi
    fi

    # --- Determine Containers to Monitor ---
    if [ ${#CONTAINERS_TO_CHECK[@]} -eq 0 ]; then
        if [ -n "$CONTAINER_NAMES" ]; then
            IFS=',' read -r -a temp_env_names <<< "$CONTAINER_NAMES"
            for name_from_env in "${temp_env_names[@]}"; do
                local name_trimmed="${name_from_env#"${name_from_env%%[![:space:]]*}"}"; name_trimmed="${name_trimmed%"${name_trimmed##*[![:space:]]}"}"
                if [ -n "$name_trimmed" ]; then CONTAINERS_TO_CHECK+=("$name_trimmed"); fi
            done
        elif [ ${#CONTAINER_NAMES_FROM_CONFIG_FILE[@]} -gt 0 ]; then
            CONTAINERS_TO_CHECK=("${CONTAINER_NAMES_FROM_CONFIG_FILE[@]}")
        else
            mapfile -t all_running_names < <(docker container ls --format '{{.Names}}' 2>/dev/null)
            if [ ${#all_running_names[@]} -gt 0 ]; then CONTAINERS_TO_CHECK=("${all_running_names[@]}"); fi
        fi
    fi

    # Filter out excluded containers
    if [ ${#CONTAINERS_TO_EXCLUDE[@]} -gt 0 ]; then
        local temp_containers_to_check=()
        for container in "${CONTAINERS_TO_CHECK[@]}"; do
            local is_excluded=false
            for excluded in "${CONTAINERS_TO_EXCLUDE[@]}"; do
                if [[ "$container" == "$excluded" ]]; then
                    is_excluded=true
                    break
                fi
            done
            if [ "$is_excluded" = false ]; then
                temp_containers_to_check+=("$container")
            fi
        done
        CONTAINERS_TO_CHECK=("${temp_containers_to_check[@]}")
    fi

    # --- Run Monitoring ---
    if [ ${#CONTAINERS_TO_CHECK[@]} -gt 0 ]; then
        local results_dir; results_dir=$(mktemp -d)

        # Stale lock file cleanup: If lock file is older than 60 minutes, remove it.
        if [ -f "$LOCK_FILE" ] && [[ $(find "$LOCK_FILE" -mmin +60) ]]; then
            print_message "Removing stale lock file older than 60 minutes." "WARNING"
            rm -f "$LOCK_FILE"
        fi

        # Acquire lock, waiting up to LOCK_TIMEOUT_SECONDS
        local lock_start_time; lock_start_time=$(date +%s)
        while ! ( set -C; echo "$$" > "$LOCK_FILE" ) 2>/dev/null; do
            local current_time; current_time=$(date +%s)
            if (( (current_time - lock_start_time) >= LOCK_TIMEOUT_SECONDS )); then
                print_message "Could not acquire lock '$LOCK_FILE' for state update after $LOCK_TIMEOUT_SECONDS seconds. Another instance may be running." "DANGER"
                exit 1
            fi
            sleep 1
        done
        trap 'rm -f "$LOCK_FILE"' EXIT

        # Ensure state file exists and has basic structure
        if [ ! -f "$STATE_FILE" ] || ! jq -e . "$STATE_FILE" >/dev/null 2>&1; then
            print_message "State file is missing or invalid. Creating a new one." "INFO"
            echo '{"updates": {}, "restarts": {}, "logs": {}}' > "$STATE_FILE"
        fi
        local current_state_json; current_state_json=$(cat "$STATE_FILE")

        # Release lock before starting parallel jobs
        rm -f "$LOCK_FILE"
        trap - EXIT

        export -f perform_checks_for_container print_message check_container_status check_container_restarts \
                   check_resource_usage check_disk_space check_network check_for_updates check_logs
        export COLOR_RESET COLOR_RED COLOR_GREEN COLOR_YELLOW COLOR_CYAN COLOR_BLUE COLOR_MAGENTA \
               LOG_LINES_TO_CHECK CPU_WARNING_THRESHOLD MEMORY_WARNING_THRESHOLD DISK_SPACE_THRESHOLD \
               NETWORK_ERROR_THRESHOLD UPDATE_CHECK_CACHE_HOURS

        if [ "$SUMMARY_ONLY_MODE" = "false" ]; then
            echo "Starting asynchronous checks for ${#CONTAINERS_TO_CHECK[@]} containers..."
            local start_time; start_time=$(date +%s)
            mkfifo progress_pipe
            (
                local spinner_chars=("|" "/" "-" '\')
                local spinner_idx=0
                local processed=0
                local total=${#CONTAINERS_TO_CHECK[@]}
                while read -r; do
                    processed=$((processed + 1))
                    local percent=$((processed * 100 / total))
                    local bar_len=40
                    local bar_filled_len=$((processed * bar_len / total))    
                    local current_time; current_time=$(date +%s)
                    local elapsed=$((current_time - start_time))
                    local elapsed_str; elapsed_str=$(printf "%02d:%02d" $((elapsed/60)) $((elapsed%60)))
                    local spinner_char=${spinner_chars[spinner_idx]}
                    spinner_idx=$(((spinner_idx + 1) % 4))
                    local bar_filled=""
                    for ((j=0; j<bar_filled_len; j++)); do bar_filled+="█"; done
                    local bar_empty=""
                    for ((j=0; j< (bar_len - bar_filled_len) ; j++)); do bar_empty+="░"; done
                    printf "\r${COLOR_GREEN}Progress: [%s%s] %3d%% (%d/%d) | Elapsed: %s [${spinner_char}]${COLOR_RESET}" \
                            "$bar_filled" "$bar_empty" "$percent" "$processed" "$total" "$elapsed_str"
                done < progress_pipe
                    echo
            ) &
            local progress_pid=$!
            exec 3> progress_pipe
        fi

        # Export the state as an environment variable so it's available to sub-shells
        export CURRENT_STATE_JSON_STRING="$current_state_json"
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
                local container_name; container_name=$(basename "$issue_file" .issues)
                local issues; issues=$(cat "$issue_file")
                WARNING_OR_ERROR_CONTAINERS+=("$container_name")
                CONTAINER_ISSUES_MAP["$container_name"]="$issues"
            fi
        done

        print_summary

        # --- Notification Logic ---
        if [ ${#WARNING_OR_ERROR_CONTAINERS[@]} -gt 0 ]; then
            local summary_message=""
            local notify_issues=false
            IFS=',' read -r -a notify_on_array <<< "$NOTIFY_ON"
            for container in "${WARNING_OR_ERROR_CONTAINERS[@]}"; do
                local issues=${CONTAINER_ISSUES_MAP["$container"]}
                local filtered_issues_array=() # Use an array to store filtered issues

                # Use the pipe delimiter to correctly split the issues
                IFS='|' read -r -a issue_array <<< "$issues"

                for issue in "${issue_array[@]}"; do
                    for notify_issue in "${notify_on_array[@]}"; do
                        # Handle Updates specially since it contains additional details
                        if [[ "${notify_issue,,}" == "updates" && "$issue" == Update* ]] || [[ "${issue,,}" == "${notify_issue,,}" ]]; then
                            filtered_issues_array+=("$issue") # Add the full issue to the array
                            notify_issues=true
                            break # Found a match, move to the next issue
                        fi
                    done
                done

                if [ ${#filtered_issues_array[@]} -gt 0 ]; then
                    # Join the array elements with a comma for the final message
                    local filtered_issues_str
                    filtered_issues_str=$(IFS=, ; echo "${filtered_issues_array[*]}")
                    summary_message+="\n[$container]\n- $filtered_issues_str\n"
                fi
            done

            if [ "$notify_issues" = true ]; then
                summary_message=$(echo -e "$summary_message" | sed 's/^[[:space:]]*//')
                if [ -n "$summary_message" ]; then
                    local notification_title="🚨 Container Monitor on $(hostname)"
                    send_notification "$summary_message" "$notification_title"
                fi
            fi
	fi

        # --- UPDATE AND SAVE STATE ---
        # Re-acquire lock to safely write the new state
        local lock_acquired=false
        for ((i=0; i<LOCK_TIMEOUT_SECONDS*10; i++)); do
            if ( set -C; echo "$$" > "$LOCK_FILE" ) 2>/dev/null; then
                trap 'rm -f "$LOCK_FILE"' EXIT
                lock_acquired=true
                break
            fi
            sleep 0.1
        done
        if [ "$lock_acquired" = false ]; then
            print_message "Could not acquire lock for state update after $LOCK_TIMEOUT_SECONDS seconds." "DANGER"
            rm -rf "$results_dir"
            return 1
        fi

        local new_state_json="$current_state_json"
        # Update restart counts
        for restart_file in "$results_dir"/*.restarts; do
            if [ -f "$restart_file" ]; then
                local container_name; container_name=$(basename "$restart_file" .restarts)
                local count; count=$(cat "$restart_file")
                new_state_json=$(jq --arg name "$container_name" --argjson val "$count" '.restarts[$name] = $val' <<< "$new_state_json")
            fi
        done
        # Update caches from live checks
        for cache_update_file in "$results_dir"/*.update_cache; do
            if [ -f "$cache_update_file" ]; then
                local cache_data; cache_data=$(cat "$cache_update_file")
                local key; key=$(jq -r '.key' <<< "$cache_data")
                local data; data=$(jq -r '.data' <<< "$cache_data")
                new_state_json=$(jq --arg key "$key" --argjson data "$data" '.updates[$key] = $data' <<< "$new_state_json")
            fi
        done

        # Update log error hashes
        for log_hash_file in "$results_dir"/*.log_hash; do
            if [ -f "$log_hash_file" ]; then
                local container_name; container_name=$(basename "$log_hash_file" .log_hash)
                local hash; hash=$(cat "$log_hash_file")
                if [ -n "$hash" ]; then
                    # If a new hash exists, add/update it in the state file
                    new_state_json=$(jq --arg name "$container_name" --arg val "$hash" '.logs[$name] = $val' <<< "$new_state_json")
                else
                    # If the hash is empty, the error was resolved, so remove the key
                    new_state_json=$(jq --arg name "$container_name" 'del(.logs[$name])' <<< "$new_state_json")
                fi
            fi
        done

        # Write the new state and release the lock
        echo "$new_state_json" > "$STATE_FILE"
        rm -f "$LOCK_FILE"
        trap - EXIT

        rm -rf "$results_dir"
    fi

    PRINT_MESSAGE_FORCE_STDOUT=true
    if [ "$SUMMARY_ONLY_MODE" = "true" ]; then
        print_message "Summary generation completed." "SUMMARY"
    elif [ ${#CONTAINERS_TO_CHECK[@]} -eq 0 ]; then
        print_message "No containers specified or found running to monitor." "INFO"
        print_summary
    else
        print_message "${COLOR_GREEN}Docker monitoring script completed successfully.${COLOR_RESET}" "INFO"
    fi
}

main "$@"
