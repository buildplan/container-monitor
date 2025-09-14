#!/usr/bin/env bash
set -uo pipefail

# --- v0.48 ---
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
#   ./container-monitor.sh                               - Monitor based on config (or all running)
#   ./container-monitor.sh <container1> <container2> ... - Monitor specific containers (full output)
#   ./container-monitor.sh --pull                        - Choose which containers to update (only pull new image, manually recreate)
#   ./container-monitor.sh --update                      - Choose which containers to update and recreate (pull and recreate container)
#   ./container-monitor.sh --force-update                - Force update check in non-interactive mode (e.g., cron)
#   ./container-monitor.sh --exclude=c1,c2               - Run on all containers, excluding specific ones.
#   ./container-monitor.sh summary                       - Run all checks silently and show only the final summary.
#   ./container-monitor.sh summary <c1> <c2> ...         - Summary mode for specific containers.
#   ./container-monitor.sh logs                          - Show logs for all running containers
#   ./container-monitor.sh logs <container> [pattern...] - Show logs for a container, with optional filtering (e.g., logs my-app error warn).
#   ./container-monitor.sh save logs <container>         - Save logs for a specific container to a file
#   ./container-monitor.sh --prune                       - Run Docker's system prune to clean up unused resources.
#   ./container-monitor.sh --no-update                   - Run without checking for a script update.
#   ./container-monitor.sh --help [or -h]                - Shows script usage commands.
#
# Prerequisites:
#   - Docker
#   - jq (for processing JSON output from docker inspect and docker stats)
#   - yq (for yaml config file)
#   - skopeo (for checking for container image updates)
#   - bc or awk (awk is used in this script for float comparisons to reduce dependencies)
#   - timeout (from coreutils, for docker exec commands)

# --- Script & Update Configuration ---
VERSION="v0.48"
VERSION_DATE="2025-09-14"
SCRIPT_URL="https://github.com/buildplan/container-monitor/raw/refs/heads/main/container-monitor.sh"
CHECKSUM_URL="${SCRIPT_URL}.sha256" # sha256 hash check

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
_SCRIPT_DEFAULT_LOG_FILE="$SCRIPT_DIR/container-monitor.log"
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
CONTAINER_NAMES=""
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
        if [[ ! "$LOG_FILE" = /* ]]; then
            LOG_FILE="$SCRIPT_DIR/$LOG_FILE"
        fi
    }

    _SCRIPT_DEFAULT_LOG_CLEAN_PATTERN='^[^ ]+[[:space:]]+'
    set_final_config "LOG_LINES_TO_CHECK"            ".general.log_lines_to_check"           "$_SCRIPT_DEFAULT_LOG_LINES_TO_CHECK"
    set_final_config "LOG_FILE"                      ".general.log_file"                     "$_SCRIPT_DEFAULT_LOG_FILE"
    set_final_config "LOG_CLEAN_PATTERN"             ".logs.log_clean_pattern"               "$_SCRIPT_DEFAULT_LOG_CLEAN_PATTERN"
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
    set_final_config "DOCKER_CONFIG_PATH"            ".auth.docker_config_path"              "~/.docker/config.json"
    set_final_config "LOCK_TIMEOUT_SECONDS"          ".general.lock_timeout_seconds"         "10"

    if ! mapfile -t LOG_ERROR_PATTERNS < <(yq e '.logs.error_patterns[]' "$_CONFIG_FILE_PATH" 2>&1); then
        print_message "Failed to parse log error patterns. Using defaults." "WARNING"
        LOG_ERROR_PATTERNS=()
    fi
    if [[ "$NOTIFICATION_CHANNEL" != "discord" && "$NOTIFICATION_CHANNEL" != "ntfy" && "$NOTIFICATION_CHANNEL" != "none" ]]; then
        print_message "Invalid notification_channel '$NOTIFICATION_CHANNEL' in config.yml. Valid values are: discord, ntfy, none. Disabling notifications." "WARNING"
        NOTIFICATION_CHANNEL="none"
    fi
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
                *) normalized_notify_on+="$issue," ;;
            esac
        done
        NOTIFY_ON="${normalized_notify_on%,}"
    fi
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
    local box_width=55
    local border_color="$COLOR_CYAN"
    local version_color="$COLOR_GREEN"
    local date_color="$COLOR_RESET"
    local update_color="$COLOR_YELLOW"
    local line1="Container Monitor ${VERSION}"
    local line2="Updated: ${VERSION_DATE}"
    local line3=""
    if [ "$UPDATE_SKIPPED" = true ]; then
        line3="A new version is available to update"
    fi
    print_centered_line() {
        local text="$1"
        local text_color="$2"
        local text_len=${#text}
        local padding_total=$((box_width - text_len))
        local padding_left=$((padding_total / 2))
        local padding_right=$((padding_total - padding_left))
        printf "${border_color}║%*s%s%s%*s${border_color}║${COLOR_RESET}\n" \
            "$padding_left" "" \
            "${text_color}" "${text}" \
            "$padding_right" ""
    }
    local border_char="═"
    local top_border=""
    for ((i=0; i<box_width; i++)); do top_border+="$border_char"; done
    echo -e "${border_color}╔${top_border}╗${COLOR_RESET}"
    print_centered_line "$line1" "$version_color"
    print_centered_line "$line2" "$date_color"
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
    if command -v apt-get &>/dev/null; then
        pkg_manager="apt"
    elif command -v dnf &>/dev/null; then
        pkg_manager="dnf"
    elif command -v yum &>/dev/null; then
        pkg_manager="yum"
    fi
    case "$(uname -m)" in
        x86_64) arch="amd64" ;;
        aarch64) arch="arm64" ;;
        *) arch="unsupported" ;;
    esac
    declare -A deps=(
        [jq]=jq
        [skopeo]=skopeo
        [awk]=gawk
        [timeout]=coreutils
        [wget]=wget
    )
    print_message "Checking for required command-line tools..." "INFO"
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
    if [ ${#missing_pkgs[@]} -gt 0 ]; then
        print_message "The following required packages are missing: ${missing_pkgs[*]}" "DANGER"
        if [ -t 0 ]; then
            if [ -n "$pkg_manager" ]; then
                read -rp "Would you like to attempt to install them now? (y/n): " response
                if [[ "$response" =~ ^[yY]$ ]]; then
                    print_message "Attempting to install with 'sudo $pkg_manager'... You may be prompted for your password." "INFO"
                    if [ "$pkg_manager" == "apt" ]; then
                        if sudo apt-get update && sudo apt-get install -y "${missing_pkgs[@]}"; then
                            print_message "Package manager dependencies installed successfully." "GOOD"
                        else
                            print_message "Failed to install dependencies. Please install them manually." "DANGER"
                            manual_install_needed=true
                        fi
                    else
                        if sudo "$pkg_manager" install -y "${missing_pkgs[@]}"; then
                            print_message "Package manager dependencies installed successfully." "GOOD"
                        else
                            print_message "Failed to install dependencies. Please install them manually." "DANGER"
                            manual_install_needed=true
                        fi
                    fi
                else
                    print_message "Installation cancelled. Please install dependencies manually." "DANGER"
                    manual_install_needed=true
                fi
            else
                print_message "No supported package manager (apt/dnf/yum) found. Please install packages manually." "DANGER"
                manual_install_needed=true
            fi
        else
            print_message "Cannot install interactively. Please install the packages manually." "DANGER"
            manual_install_needed=true
        fi
    fi
    if [ "$yq_missing" = true ]; then
        print_message "yq is not installed. It is required for parsing config.yml." "DANGER"
        if [ "$arch" == "unsupported" ]; then
             print_message "Your system architecture ($(uname -m)) is not supported for automatic yq installation. Please install it manually from https://github.com/mikefarah/yq/" "DANGER"
             manual_install_needed=true
        elif [ -t 0 ]; then
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
        else
            print_message "Cannot install interactively. Please install yq manually." "DANGER"
            manual_install_needed=true
        fi
    fi
    if [ "$manual_install_needed" = true ]; then
        print_message "Please address the missing dependencies listed above before running the script again." "DANGER"
        exit 1
    fi
    if ! $yq_missing && [ ${#missing_pkgs[@]} -eq 0 ]; then
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
                LOG_FILE=""
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
        priority=""
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
    local temp_dir
    temp_dir=$(mktemp -d)
    if [ ! -d "$temp_dir" ]; then
        print_message "Failed to create temporary directory. Update aborted." "DANGER"
        exit 1
    fi
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
    if ! mv "$temp_script" "$0"; then
        print_message "Failed to replace the old script file. Update aborted." "DANGER"
        exit 1
    fi
    chmod +x "$0"
    trap - EXIT
    rm -rf -- "$temp_dir"
    print_message "Update successful. Please run the script again." "GOOD"
    exit 0
}
run_with_retry() {
    local max_attempts=3
    local attempt=0
    local exit_code=0
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
    local saved_restart_counts_json="$3"
    local current_restart_count is_restarting
    current_restart_count=$(jq -r '.[0].RestartCount' <<< "$inspect_data")
    is_restarting=$(jq -r '.[0].State.Restarting' <<< "$inspect_data")
    local saved_restart_count
    saved_restart_count=$(jq -r --arg name "$container_name" '.restarts[$name] // 0' <<< "$saved_restart_counts_json")
    if [ "$is_restarting" = "true" ]; then
        print_message "  ${COLOR_BLUE}Restart Status:${COLOR_RESET} Container is currently restarting." "WARNING"; return 1
    fi
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
        return 0
    fi
    for ((i=0; i<num_mounts; i++)); do
        local mp_destination
        mp_destination=$(jq -r ".[0].Mounts[$i].Destination // empty" <<< "$inspect_data" 2>/dev/null)
        if [ -z "$mp_destination" ]; then continue; fi
        if [[ "$mp_destination" == *".sock" || "$mp_destination" == "/proc"* || "$mp_destination" == "/sys"* || "$mp_destination" == "/dev"* || "$mp_destination" == "/host/"* ]]; then
            continue
        fi
        local disk_usage_output
        disk_usage_output=$(timeout 5 docker exec "$container_name" df -P "$mp_destination" 2>/dev/null)
        if [ $? -ne 0 ]; then
            continue
        fi
        local disk_usage
        disk_usage=$(echo "$disk_usage_output" | awk 'NR==2 {val=$(NF-1); sub(/%$/,"",val); print val}')
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
get_update_strategy() {
    local image_name="$1"
    local service_name="${image_name##*/}" 
    local strategy=""
    strategy=$(yq e ".containers.update_strategies.\"$image_name\" // \"\"" "$SCRIPT_DIR/config.yml" 2>/dev/null)
    if [ -z "$strategy" ] && [ "$image_name" != "$service_name" ]; then
        strategy=$(yq e ".containers.update_strategies.\"$service_name\" // \"\"" "$SCRIPT_DIR/config.yml" 2>/dev/null)
    fi
    if [ -n "$strategy" ]; then
        echo "$strategy"
    else
        echo "default"
    fi
}
check_for_updates() {
    local container_name="$1"; local current_image_ref="$2"
    local state_json="$3"
    if ! command -v skopeo &>/dev/null; then print_message "  ${COLOR_BLUE}Update Check:${COLOR_RESET} skopeo not installed. Skipping." "INFO" >&2; return 0; fi
    if [[ "$current_image_ref" == *@sha256:* || "$current_image_ref" =~ ^sha256: ]]; then
        print_message "  ${COLOR_BLUE}Update Check:${COLOR_RESET} Image for '$container_name' is pinned by digest. Skipping." "INFO" >&2; return 0
    fi
    local cache_key; cache_key=$(echo "$current_image_ref" | sed 's/[/:]/_/g')
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
    local current_tag="latest"
    local image_name_no_tag="$current_image_ref"
    if [[ "$current_image_ref" == *":"* ]]; then
        current_tag="${current_image_ref##*:}"
        image_name_no_tag="${current_image_ref%:$current_tag}"
    fi
    local lookup_name; lookup_name=$(echo "$image_name_no_tag" | sed -e 's#^docker.io/##' -e 's#^library/##')
    local strategy; strategy=$(get_update_strategy "$lookup_name")
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
    if [ -n "$DOCKER_CONFIG_PATH" ]; then
        local expanded_path; expanded_path="${DOCKER_CONFIG_PATH/#\~/$HOME}"
        export DOCKER_CONFIG="${expanded_path%/*}"
    fi
    local skopeo_opts=()
    if [ -n "$DOCKER_USERNAME" ] && [ -n "$DOCKER_PASSWORD" ]; then
        skopeo_opts+=("--creds" "$DOCKER_USERNAME:$DOCKER_PASSWORD")
    fi
    get_release_url() { yq e ".containers.release_urls.\"${1}\" // \"\"" "$SCRIPT_DIR/config.yml"; }
    if [[ "$current_tag" =~ ^(latest|stable|rolling)$ ]]; then
        strategy="digest"
    fi
    local latest_stable_version=""
    local update_check_failed=false
    local error_message=""
    case "$strategy" in
        "digest")
            local local_inspect; local_inspect=$(docker inspect "$current_image_ref" 2>/dev/null)
            local local_digest; local_digest=$(jq -r '(.[0].RepoDigests[]? | select(startswith("'"$registry_host/$image_path_for_skopeo"'@")) | split("@")[1]) // (.[0].RepoDigests[0]? | split("@")[1])' <<< "$local_inspect")
            if [ -z "$local_digest" ]; then
                error_message="Could not get local digest for '$current_image_ref'. Cannot check tag '$current_tag'."
                update_check_failed=true
            else
                local remote_inspect_output; remote_inspect_output=$(skopeo "${skopeo_opts[@]}" inspect "${skopeo_repo_ref}:${current_tag}" 2>&1)
                if [ $? -ne 0 ]; then
                    error_message="Error inspecting remote image '${skopeo_repo_ref}:${current_tag}'. Details: $remote_inspect_output"
                    update_check_failed=true
                else
                    local remote_digest; remote_digest=$(jq -r '.Digest' <<< "$remote_inspect_output")
                    if [ "$remote_digest" != "$local_digest" ]; then
                        local local_size; local_size=$(jq -r '.[0].Size' <<< "$local_inspect")
                        local remote_created; remote_created=$(jq -r '.Created' <<< "$remote_inspect_output")
                        local remote_size; remote_size=$(jq -r '.Size' <<< "$remote_inspect_output")
                        local size_delta=$((remote_size - local_size))
                        local human_readable_delta; human_readable_delta=$(awk -v delta="$size_delta" 'BEGIN { s="B K M G T P E Z Y"; split(s, a); sig=delta<0?"-":"+"; delta=delta<0?-delta:delta; while(delta >= 1024 && length(s) > 1) { delta /= 1024; s=substr(s, 3) } printf "%s%.1f%s", sig, delta, substr(s, 1, 1) }')
                        local remote_date; remote_date=$(date -d "$remote_created" +"%Y-%m-%d %H:%M")
                        latest_stable_version="New build found (Created: $remote_date, Size Δ: ${human_readable_delta}B)"
                    fi
                fi
            fi
            ;;
        *)
            local skopeo_output; skopeo_output=$(skopeo "${skopeo_opts[@]}" list-tags "$skopeo_repo_ref" 2>&1)
            if [ $? -ne 0 ]; then
                error_message="Error listing tags for '${skopeo_repo_ref}'. Details: $skopeo_output"
                update_check_failed=true
            else
                local tag_filter; local sort_cmd
                sort_cmd=("sort" "-V")
                case "$strategy" in
                    "semver") tag_filter='^[v]?[0-9]+\.[0-9]+\.[0-9]+$';;
                    "major-lock")
                        local major_version="${current_tag%%.*}"; local variant=""
                        if [[ "$current_tag" == *"-"* ]]; then variant="-${current_tag#*-}"; fi
                        tag_filter="^${major_version}(\.[0-9]+)*${variant}$"
                        ;;
                    *) tag_filter='^[v]?[0-9\.]+$';;
                esac
                latest_stable_version=$(echo "$skopeo_output" | jq -r '.Tags[]' | grep -E "$tag_filter" | grep -v -- '-.*' | "${sort_cmd[@]}" | tail -n 1)
            fi
            ;;
    esac
    if [ "$update_check_failed" = true ]; then
        print_message "  ${COLOR_BLUE}Update Check:${COLOR_RESET} $error_message" "DANGER" >&2
        echo "$error_message"
        return 1
    elif [ -z "$latest_stable_version" ]; then
        print_message "  ${COLOR_BLUE}Update Check:${COLOR_RESET} No newer version found for '$image_name_no_tag' with strategy '$strategy'." "GOOD" >&2; return 0
    fi
    if [[ "$strategy" == "digest" ]]; then
        local summary_message="$latest_stable_version"
        local release_url; release_url=$(get_release_url "$lookup_name")
        if [ -n "$release_url" ]; then summary_message+=", Notes: $release_url"; fi
        print_message "  ${COLOR_BLUE}Update Check:${COLOR_RESET} $summary_message" "WARNING" >&2
        echo "$summary_message"
        return 1
    elif [[ "v$current_tag" != "v$latest_stable_version" && "$current_tag" != "$latest_stable_version" ]] && [[ "$(printf '%s\n' "$latest_stable_version" "$current_tag" | sort -V | tail -n 1)" == "$latest_stable_version" ]]; then
        local summary_message="Update available: ${latest_stable_version}"
        local release_url; release_url=$(get_release_url "$lookup_name")
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
    local saved_state_obj; saved_state_obj=$(jq -r --arg name "$container_name" '.logs[$name] // "{}"' <<< "$state_json")
    local last_timestamp; last_timestamp=$(jq -r '.last_timestamp // ""' <<< "$saved_state_obj")
    local saved_hash; saved_hash=$(jq -r '.last_hash // ""' <<< "$saved_state_obj")
    local docker_logs_cmd=("docker" "logs" "--timestamps")
    if [ -n "$last_timestamp" ]; then
        docker_logs_cmd+=("--since" "$last_timestamp")
    else
        docker_logs_cmd+=("--tail" "$LOG_LINES_TO_CHECK")
    fi
    docker_logs_cmd+=("$container_name")
    local raw_logs cli_stderr
    local tmp_err; tmp_err=$(mktemp)
    raw_logs=$("${docker_logs_cmd[@]}" 2> "$tmp_err"); local docker_exit_code=$?
    cli_stderr=$(<"$tmp_err")
    rm -f "$tmp_err"
    if [ -n "$cli_stderr" ]; then
        if [ $docker_exit_code -ne 0 ]; then
            print_message "  ${COLOR_BLUE}Log Check:${COLOR_RESET} Docker command failed for '$container_name' with exit code ${docker_exit_code}. See logs for details." "DANGER" >&2
        else
        :
        fi
    fi
    if [ -z "$raw_logs" ]; then
        print_message "  ${COLOR_BLUE}Log Check:${COLOR_RESET} No new log entries." "GOOD" >&2
        echo "$saved_state_obj" && return 0
    fi
    local logs_to_process="$raw_logs"
    local first_line_ts; first_line_ts=$(echo "$raw_logs" | head -n 1 | awk '{print $1}')
    if [[ -n "$last_timestamp" && "$first_line_ts" == "$last_timestamp" ]]; then
        logs_to_process=$(echo "$raw_logs" | tail -n +2)
    fi
    if [ -z "$logs_to_process" ]; then
        print_message "  ${COLOR_BLUE}Log Check:${COLOR_RESET} No new unique log entries since last check." "GOOD" >&2
        echo "$saved_state_obj" && return 0
    fi
    local error_regex; error_regex=$(printf "%s|" "${LOG_ERROR_PATTERNS[@]:-error|panic|fail|fatal}")
    error_regex="${error_regex%|}"
    local current_errors; current_errors=$(echo "$logs_to_process" | grep -i -E "$error_regex")
    local new_hash=""
    if [ -n "$current_errors" ]; then
        local cleaned_errors; cleaned_errors=$(echo "$current_errors" | sed -E "s/$LOG_CLEAN_PATTERN//")
        new_hash=$(echo "$cleaned_errors" | sort | sha256sum | awk '{print $1}')
    fi
    local new_last_timestamp; new_last_timestamp=$(echo "$raw_logs" | tail -n 1 | awk '{print $1}')
    if [ -z "$new_last_timestamp" ]; then
        new_last_timestamp="$last_timestamp"
    elif ! [[ "$new_last_timestamp" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T ]]; then
        new_last_timestamp="$last_timestamp"
    fi
    jq -n --arg hash "$new_hash" --arg ts "$new_last_timestamp" \
      '{last_hash: $hash, last_timestamp: $ts}'
    if [[ -n "$new_hash" && "$new_hash" != "$saved_hash" ]]; then
        print_message "  ${COLOR_BLUE}Log Check:${COLOR_RESET} New error patterns found." "WARNING" >&2
        return 1
    else
        print_message "  ${COLOR_BLUE}Log Check:${COLOR_RESET} Processed new logs, no new error patterns." "GOOD" >&2
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
check_host_disk_usage() {
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
check_host_memory_usage() {
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
    local update_details="$2"
    print_message "Getting image details for '$container_name_to_update'..." "INFO"
    local current_image_ref; current_image_ref=$(docker inspect -f '{{.Config.Image}}' "$container_name_to_update" 2>/dev/null)
    local image_to_pull="$current_image_ref"
    if [[ ! "$update_details" == *"New build found"* ]]; then
        local image_name_no_tag="${current_image_ref%:*}"
        local new_version; new_version=$(echo "$update_details" | grep -oE '[v]?[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n 1)
        if [ -n "$new_version" ]; then
            image_to_pull="${image_name_no_tag}:${new_version}"
        fi
    fi
    print_message "Pulling new image: $image_to_pull" "INFO"
    if docker pull "$image_to_pull"; then
        print_message "Successfully pulled new image for '$container_name_to_update'." "GOOD"
        print_message "  ${COLOR_YELLOW}ACTION REQUIRED:${COLOR_RESET} You now need to manually recreate the container to apply the update." "WARNING"
    else
        print_message "Failed to pull new image for '$container_name_to_update'." "DANGER"
    fi
}
process_container_update() {
    local container_name="$1"
    local update_details="$2"
    print_message "Starting guided update for '$container_name'..." "INFO"
    local inspect_json; inspect_json=$(docker inspect "$container_name" 2>/dev/null)
    if [ -z "$inspect_json" ]; then print_message "Failed to inspect container '$container_name'." "DANGER"; return 1; fi
    local working_dir; working_dir=$(jq -r '.[0].Config.Labels["com.docker.compose.project.working_dir"] // ""' <<< "$inspect_json")
    local service_name; service_name=$(jq -r '.[0].Config.Labels["com.docker.compose.service"] // ""' <<< "$inspect_json")
    local config_files; config_files=$(jq -r '.[0].Config.Labels["com.docker.compose.project.config_files"] // ""' <<< "$inspect_json")
    local current_image_ref; current_image_ref=$(jq -r '.[0].Config.Image' <<< "$inspect_json")
    if [ -z "$working_dir" ] || [ -z "$service_name" ]; then
        print_message "Cannot auto-recreate '$container_name'. Not managed by a known docker-compose version." "DANGER"
        pull_new_image "$container_name" "$update_details"
        return
    fi
    local compose_cmd_base=("docker" "compose")
    if [ -n "$config_files" ]; then
        IFS=',' read -r -a files_array <<< "$config_files"
        for file in "${files_array[@]}"; do compose_cmd_base+=("-f" "$file"); done
    fi
    if [[ "$update_details" == *"New build found"* ]]; then
        print_message "Image uses a rolling tag. Proceeding with standard pull and recreate." "INFO"
        (
            cd "$working_dir" || exit 1
            if "${compose_cmd_base[@]}" pull "$service_name" < /dev/null && \
               "${compose_cmd_base[@]}" up -d --force-recreate "$service_name" < /dev/null; then
                print_message "Container '$container_name' successfully updated. ✅" "GOOD"
            else
                print_message "An error occurred during the update of '$container_name'." "DANGER"
            fi
        )
        return
    fi
    local image_name_no_tag="${current_image_ref%:*}"
    local new_version; new_version=$(echo "$update_details" | grep -oE '[v]?[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n 1)
    if [ -z "$new_version" ]; then
        print_message "Could not determine the new version for '$container_name'. Cannot proceed." "DANGER"
        return 1
    fi
    local new_image_ref="${image_name_no_tag}:${new_version}"
    print_message "Pulling new image '${new_image_ref}'..." "INFO"
    if ! docker pull "$new_image_ref"; then
        print_message "Failed to pull new image '${new_image_ref}'. Aborting update." "DANGER"
        return 1
    fi
    print_message "Successfully pulled new image." "GOOD"
    print_message " ⚠ ${COLOR_YELLOW}The new image has been pulled. Now, the compose file must be updated to use it.${COLOR_RESET}" "WARNING"
    echo
    local main_compose_file="${config_files%%,*}"
    local full_compose_path
    if [[ "$main_compose_file" == /* ]]; then
        full_compose_path="$main_compose_file"
    else
        full_compose_path="$working_dir/$main_compose_file"
    fi
    print_message "GUIDE: In the file, change the image tag to version: ${COLOR_GREEN}${new_version}${COLOR_RESET}" "INFO"
    echo
    local edit_response
    read -rp "Would you like to open '${full_compose_path}' now to edit the tag? (y/n): " edit_response < /dev/tty
    if [[ "$edit_response" =~ ^[yY]$ ]]; then
        local editor_cmd
        if [ -n "${VISUAL:-}" ]; then
            editor_cmd="$VISUAL"
        elif [ -n "${EDITOR:-}" ]; then
            editor_cmd="$EDITOR"
        elif command -v nano &>/dev/null; then
            editor_cmd="nano"
        else
            editor_cmd="/usr/bin/vi"
        fi
        "$editor_cmd" "$full_compose_path" < /dev/tty
        print_message "Verifying changes in compose file..." "INFO"
        if ! grep -q -E "image:.*:${new_version}" "$full_compose_path"; then
            print_message "Verification failed. The new image tag '${new_version}' was not found in the file." "DANGER"
            print_message "Please apply the changes manually and run 'docker compose up -d'." "WARNING"
            return
        fi
        print_message "Verification successful!" "GOOD"
        local apply_response
        echo
        read -rp "${COLOR_YELLOW}File closed. Recreate '${container_name}' now to apply the changes? (y/n): ${COLOR_RESET}" apply_response < /dev/tty
        echo
        if [[ "$apply_response" =~ ^[yY]$ ]]; then
            print_message "Applying changes by recreating the container..." "INFO"
            (
                cd "$working_dir" || exit 1
                if "${compose_cmd_base[@]}" up -d --force-recreate "$service_name" < /dev/null; then
                     print_message "Container '$container_name' successfully updated with new version. ✅" "GOOD"
                else
                     print_message "An error occurred while recreating '$container_name'." "DANGER"
                fi
            )
        else
            print_message "Changes not applied. Please run 'docker compose up -d' in '${working_dir}' manually." "WARNING"
        fi
    else
        print_message "Manual edit skipped. Please edit '${full_compose_path}' and run 'docker compose up -d' manually." "WARNING"
    fi
}
run_interactive_update_mode() {
    print_message "Starting interactive update check..." "INFO"
    local containers_with_updates=()
    local container_update_details=()
    if [ ! -f "$STATE_FILE" ] || ! jq -e . "$STATE_FILE" >/dev/null 2>&1; then
        print_message "State file is missing or invalid. Creating a new one." "INFO"
        echo '{"updates": {}, "restarts": {}, "logs": {}}' > "$STATE_FILE"
    fi
    local state_json; state_json=$(cat "$STATE_FILE")
    mapfile -t all_containers < <(docker container ls --format '{{.Names}}' 2>/dev/null)
    if [ ${#all_containers[@]} -eq 0 ]; then
        print_message "No running containers found to check." "INFO"
        return
    fi
    print_message "Checking ${#all_containers[@]} containers for available updates..." "NONE"
    for container in "${all_containers[@]}"; do
        local current_image; current_image=$(docker inspect -f '{{.Config.Image}}' "$container" 2>/dev/null)
        local update_details; update_details=$(check_for_updates "$container" "$current_image" "$state_json")
        if [ $? -ne 0 ]; then
            containers_with_updates+=("$container")
            container_update_details+=("$update_details")
        fi
    done
    if [ ${#containers_with_updates[@]} -eq 0 ]; then
        print_message "All containers are up-to-date. Nothing to do. ✅" "GOOD"
        return
    fi
    print_message "The following containers have updates available:" "INFO"
    for i in "${!containers_with_updates[@]}"; do
        echo -e "  ${COLOR_CYAN}[$((i + 1))]${COLOR_RESET} ${containers_with_updates[i]} (${COLOR_YELLOW}${container_update_details[i]}${COLOR_RESET})"
    done
    echo ""
    read -rp "Enter the number(s) of the containers to update (e.g., '1' or '1,3'), or 'all', or press Enter to cancel: " choice
    if [ -z "$choice" ]; then
        print_message "Update cancelled by user." "INFO"
        return
    fi
    local selections_to_process=()
    local details_to_process=()
    if [ "$choice" == "all" ]; then
            selections_to_process=("${containers_with_updates[@]}")
            details_to_process=("${container_update_details[@]}")
    else
        IFS=',' read -r -a selections <<< "$choice"
        for sel in "${selections[@]}"; do
            if [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 1 ] && [ "$sel" -le "${#containers_with_updates[@]}" ]; then
            local index=$((sel - 1))
            selections_to_process+=("${containers_with_updates[$index]}")
            details_to_process+=("${container_update_details[$index]}")
            else
                print_message "Invalid selection: '$sel'. Skipping." "DANGER"
            fi
        done
    fi
        for i in "${!selections_to_process[@]}"; do
            local container_to_update="${selections_to_process[$i]}"
            local details_for_this_container="${details_to_process[$i]}"
            if [ "$RECREATE_MODE" = true ]; then
                process_container_update "$container_to_update" "$details_for_this_container"
            else
                pull_new_image "$container_to_update" "$details_for_this_container"
            fi
        done
    echo
    local prune_choice
    read -rp "${COLOR_YELLOW}Update process finished. Would you like to clean up the system now? (y/n): ${COLOR_RESET}" prune_choice
    if [[ "$prune_choice" =~ ^[yY]$ ]]; then
        print_message "Waiting 5 seconds for Docker daemon to settle before pruning..." "INFO"
        sleep 5
        run_prune
    fi
    print_message "Interactive update process finished." "INFO"
}
print_summary() {
  local container_name_summary issues issue_emoji
  local printed_containers=()
  local host_disk_summary_output host_memory_summary_output
  PRINT_MESSAGE_FORCE_STDOUT=true
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
    	local issues="${CONTAINER_ISSUES_MAP["$container_name_summary"]:-Unknown Issue}"
    	local emoji_string=""
    	if [[ "$issues" == *"Status"* ]]; then emoji_string+="🛑"; fi
    	if [[ "$issues" == *"Restarts"* ]]; then emoji_string+="🔥"; fi
    	if [[ "$issues" == *"Logs"* ]]; then emoji_string+="📜"; fi
    	if [[ "$issues" == *"Update"* ]]; then emoji_string+="🔄"; fi
    	if [[ "$issues" == *"Resources"* ]]; then emoji_string+="📈"; fi
    	if [[ "$issues" == *"Disk"* ]]; then emoji_string+="💾"; fi
	if [[ "$issues" == *"Network"* ]]; then emoji_string+="📶"; fi
    	if [ -z "$emoji_string" ]; then emoji_string="❌"; fi
    	print_message "- ${container_name_summary} ${emoji_string}" "WARNING"
    	IFS='|' read -r -a issue_array <<< "$issues"
    	for issue_detail in "${issue_array[@]}"; do
            print_message "  - ${issue_detail}" "WARNING"
    	done
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
    local state_json_string="$CURRENT_STATE_JSON_STRING"
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
    check_container_restarts "$container_actual_name" "$inspect_json" "$state_json_string"; if [ $? -ne 0 ]; then issue_tags+=("Restarts"); fi
    check_resource_usage "$container_actual_name" "$cpu_percent" "$mem_percent"; if [ $? -ne 0 ]; then issue_tags+=("Resources"); fi
    check_disk_space "$container_actual_name" "$inspect_json"; if [ $? -ne 0 ]; then issue_tags+=("Disk"); fi
    check_network "$container_actual_name"; if [ $? -ne 0 ]; then issue_tags+=("Network"); fi
    local current_image_ref_for_update; current_image_ref_for_update=$(jq -r '.[0].Config.Image' <<< "$inspect_json")
    local update_output; update_output=$(check_for_updates "$container_actual_name" "$current_image_ref_for_update" "$state_json_string" 2>&1)
    local update_exit_code=$?
    local update_details; update_details=$(echo "$update_output" | tail -n 1)

    if [ "$update_exit_code" -ne 0 ]; then
	issue_tags+=("Updates: $update_details")
    fi
    if ! echo "$update_output" | grep -q "(cached)"; then
        local cache_key; cache_key=$(echo "$current_image_ref_for_update" | sed 's/[/:]/_/g')
        jq -n --arg key "$cache_key" --arg img_ref "$current_image_ref_for_update" --arg msg "$update_details" --argjson code "$update_exit_code" \
          '{key: $key, image_ref: $img_ref, data: {message: $msg, exit_code: $code, timestamp: (now | floor)}}' > "$results_dir/$container_actual_name.update_cache"
    fi
    local new_log_state_json
    new_log_state_json=$(check_logs "$container_actual_name" "$state_json_string")
    if [ $? -ne 0 ]; then
        issue_tags+=("Logs")
    fi
    echo "$new_log_state_json" > "$results_dir/$container_actual_name.log_state"

    if [ ${#issue_tags[@]} -gt 0 ]; then
        (IFS='|'; echo "${issue_tags[*]}") > "$results_dir/$container_actual_name.issues"
    fi
}

# --- Main Execution ---
main() {
    declare -a WARNING_OR_ERROR_CONTAINERS=()
    declare -A CONTAINER_ISSUES_MAP
    declare -a CONTAINER_ARGS=()
    declare -a CONTAINERS_TO_EXCLUDE=()
    local run_update_check=true
    local force_update_check=false
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --exclude=*)
                local EXCLUDE_STR="${1#*=}"
                IFS=',' read -r -a CONTAINERS_TO_EXCLUDE <<< "$EXCLUDE_STR"
                shift
                ;;
            --update)
                RECREATE_MODE=true
                INTERACTIVE_UPDATE_MODE=true
                shift
                ;;
            --pull)
                INTERACTIVE_UPDATE_MODE=true
                shift
                ;;
            --prune)
                run_prune
                exit 0
                ;;
            --force-update)
                force_update_check=true
                shift
                ;;
            --no-update)
                run_update_check=false
                shift
                ;;
            summary)
                SUMMARY_ONLY_MODE=true
                shift
                ;;
            -h|--help)
                print_help
                return 0
                ;;
            -*)
                print_message "Unknown option: $1" "DANGER"
                print_help
                return 1
                ;;
            *)
                CONTAINER_ARGS+=("$1")
                shift
                ;;
        esac
    done

    # --- Initial Setup ---
    check_and_install_dependencies
    load_configuration

    # --- Self-Update Check ---
    if [[ "$force_update_check" == true || ("$run_update_check" == true && -t 1) ]]; then
        if [[ "$SCRIPT_URL" != *"your-username/your-repo"* ]]; then
            local latest_version
            latest_version=$(curl -sL "$SCRIPT_URL" | grep -m 1 "VERSION=" | cut -d'"' -f2)
            if [[ -n "$latest_version" && "$VERSION" != "$latest_version" ]]; then
                self_update
            fi
        fi
    fi
    # --- Mode Execution ---
    if [ "$INTERACTIVE_UPDATE_MODE" = true ]; then
        run_interactive_update_mode
        return 0
    fi
    if [ "$SUMMARY_ONLY_MODE" = false ]; then
        if [ -t 1 ] && tput colors &>/dev/null && [ "$(tput colors)" -ge 8 ]; then
            print_header_box
        else
            echo "--- Container Monitor ${VERSION} ---"
        fi
    fi
    declare -a CONTAINERS_TO_CHECK=()
    if [ "${#CONTAINER_ARGS[@]}" -gt 0 ]; then
        if [[ "${CONTAINER_ARGS[0]}" == "logs" && "$SUMMARY_ONLY_MODE" == false ]]; then
            local container_to_log="${CONTAINER_ARGS[1]:-}"
            if [ -z "$container_to_log" ]; then
                print_message "Usage: $0 logs <container_name> [filter...]" "DANGER"; return 1;
            fi
            local filter_patterns=("${CONTAINER_ARGS[@]:2}")
            if [ ${#filter_patterns[@]} -eq 0 ]; then
                print_message "--- Showing all recent logs for '$container_to_log' ---" "INFO"
                docker logs --tail "$LOG_LINES_TO_CHECK" "$container_to_log"
            else
                local all_args_string="${filter_patterns[*]}"
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
        elif [[ "${CONTAINER_ARGS[0]}" == "save" && "${CONTAINER_ARGS[1]}" == "logs" && -n "${CONTAINER_ARGS[2]}" && "$SUMMARY_ONLY_MODE" == false ]]; then
            save_logs "${CONTAINER_ARGS[2]}"; return 0;
        fi
        CONTAINERS_TO_CHECK=("${CONTAINER_ARGS[@]}")
    else
        local CONTAINER_NAMES_FROM_ENV; CONTAINER_NAMES_FROM_ENV=$(printenv CONTAINER_NAMES || true)
        if [ -n "$CONTAINER_NAMES_FROM_ENV" ]; then
            IFS=',' read -r -a CONTAINERS_TO_CHECK <<< "$CONTAINER_NAMES_FROM_ENV"
        elif [ ${#CONTAINER_NAMES_FROM_CONFIG_FILE[@]} -gt 0 ]; then
            CONTAINERS_TO_CHECK=("${CONTAINER_NAMES_FROM_CONFIG_FILE[@]}")
        else
            mapfile -t all_running_names < <(docker container ls --format '{{.Names}}' 2>/dev/null)
            if [ ${#all_running_names[@]} -gt 0 ]; then CONTAINERS_TO_CHECK=("${all_running_names[@]}"); fi
        fi
    fi
    if [ ${#CONTAINERS_TO_EXCLUDE[@]} -gt 0 ]; then
        local temp_containers_to_check=()
        for container in "${CONTAINERS_TO_CHECK[@]}"; do
            local is_excluded=false
            for excluded in "${CONTAINERS_TO_EXCLUDE[@]}"; do
                if [[ "$container" == "$excluded" ]]; then is_excluded=true; break; fi
            done
            if [ "$is_excluded" = false ]; then temp_containers_to_check+=("$container"); fi
        done
        CONTAINERS_TO_CHECK=("${temp_containers_to_check[@]}")
    fi

    # --- Main Monitoring Logic ---
    if [ ${#CONTAINERS_TO_CHECK[@]} -gt 0 ]; then
        local results_dir; results_dir=$(mktemp -d)
        if [ -f "$LOCK_FILE" ]; then
            local locked_pid; locked_pid=$(cat "$LOCK_FILE")
            if ! ps -p "$locked_pid" > /dev/null; then
                print_message "Removing stale lock file for non-existent PID $locked_pid." "WARNING"
                rm -f "$LOCK_FILE"
            fi
        fi
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
        if [ ! -f "$STATE_FILE" ] || ! jq -e . "$STATE_FILE" >/dev/null 2>&1; then
            print_message "State file is missing or invalid. Creating a new one." "INFO"
            echo '{"updates": {}, "restarts": {}, "logs": {}}' > "$STATE_FILE"
        fi
        local current_state_json; current_state_json=$(cat "$STATE_FILE")
        rm -f "$LOCK_FILE"
        trap - EXIT
        export -f perform_checks_for_container print_message check_container_status check_container_restarts \
                   check_resource_usage check_disk_space check_network check_for_updates check_logs get_update_strategy
        export COLOR_RESET COLOR_RED COLOR_GREEN COLOR_YELLOW COLOR_CYAN COLOR_BLUE COLOR_MAGENTA \
               LOG_LINES_TO_CHECK CPU_WARNING_THRESHOLD MEMORY_WARNING_THRESHOLD DISK_SPACE_THRESHOLD \
               NETWORK_ERROR_THRESHOLD UPDATE_CHECK_CACHE_HOURS
        if [ "$SUMMARY_ONLY_MODE" = false ]; then
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
        if [ ${#WARNING_OR_ERROR_CONTAINERS[@]} -gt 0 ]; then
            local summary_message=""
            local notify_issues=false
            IFS=',' read -r -a notify_on_array <<< "$NOTIFY_ON"
            for container in "${WARNING_OR_ERROR_CONTAINERS[@]}"; do
                local issues=${CONTAINER_ISSUES_MAP["$container"]}
                local filtered_issues_array=()
                IFS='|' read -r -a issue_array <<< "$issues"
                for issue in "${issue_array[@]}"; do
                    for notify_issue in "${notify_on_array[@]}"; do
                        if [[ "${notify_issue,,}" == "updates" && "$issue" == Update* ]] || [[ "${issue,,}" == "${notify_issue,,}" ]]; then
                            filtered_issues_array+=("$issue")
                            notify_issues=true
                            break
                        fi
                    done
                done

                if [ ${#filtered_issues_array[@]} -gt 0 ]; then
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
        local new_state_json; new_state_json=$(cat "$STATE_FILE")
        new_state_json=$(jq '.restarts = (.restarts // {}) | .logs = (.logs // {}) | .updates = (.updates // {})' <<< "$new_state_json")
        for restart_file in "$results_dir"/*.restarts; do
            if [ -f "$restart_file" ]; then
                local container_name; container_name=$(basename "$restart_file" .restarts)
                local count; count=$(cat "$restart_file")
                new_state_json=$(jq --arg name "$container_name" --argjson val "$count" '.restarts[$name] = $val' <<< "$new_state_json")
            fi
        done
        for log_state_file in "$results_dir"/*.log_state; do
            if [ -f "$log_state_file" ]; then
                local container_name; container_name=$(basename "$log_state_file" .log_state)
                local log_state_obj; log_state_obj=$(cat "$log_state_file")
                if jq -e '.last_timestamp' <<< "$log_state_obj" >/dev/null; then
                    new_state_json=$(jq --arg name "$container_name" --argjson val "$log_state_obj" '.logs[$name] = $val' <<< "$new_state_json")
                fi
            fi
        done
        for cache_update_file in "$results_dir"/*.update_cache; do
            if [ -f "$cache_update_file" ]; then
                local cache_data; cache_data=$(cat "$cache_update_file")
                local key; key=$(jq -r '.key' <<< "$cache_data")
                local data; data=$(jq -r '.data' <<< "$cache_data")
                new_state_json=$(jq --arg key "$key" --argjson data "$data" '.updates[$key] = $data' <<< "$new_state_json")
            fi
        done
        mapfile -t all_system_containers < <(docker ps -a --format '{{.Names}}')
        local all_system_containers_json; all_system_containers_json=$(printf '%s\n' "${all_system_containers[@]}" | jq -R . | jq -s .)
        new_state_json=$(jq --argjson valid_names "$all_system_containers_json" '
            .restarts = (.restarts | with_entries(select(.key as $k | $valid_names | index($k)))) |
            .logs = (.logs | with_entries(select(.key as $k | $valid_names | index($k))))
        ' <<< "$new_state_json")
        echo "$new_state_json" > "$STATE_FILE"
        rm -f "$LOCK_FILE"
        trap - EXIT
        rm -rf "$results_dir"
    else
        PRINT_MESSAGE_FORCE_STDOUT=true
        if [ "$SUMMARY_ONLY_MODE" = "true" ]; then
            print_message "Summary generation completed." "SUMMARY"
        elif [ ${#CONTAINERS_TO_CHECK[@]} -eq 0 ]; then
            print_message "No containers specified or found running to monitor." "INFO"
            print_summary
        else
            print_message "${COLOR_GREEN}Docker monitoring script completed successfully.${COLOR_RESET}" "INFO"
        fi
    fi
}
main "$@"
