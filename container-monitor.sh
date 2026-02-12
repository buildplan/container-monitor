#!/usr/bin/env bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
set -uo pipefail

# --- v0.81.5 ---
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
#   ./container-monitor.sh --check-setup                 - Check the script setup and dependencies.
#   ./container-monitor.sh --setup-timer                 - Setup cronjob or systemd timer.
#   ./container-monitor.sh <container1> <container2> ... - Monitor specific containers (full output)
#   ./container-monitor.sh --pull                        - Choose which containers to update (only pull new image, manually recreate)
#   ./container-monitor.sh --update                      - Choose which containers to update and recreate (pull and recreate container)
#   ./container-monitor.sh --force-update                - Force update check in non-interactive mode (e.g., cron)
#   ./container-monitor.sh --exclude=c1,c2               - Run on all containers, excluding specific ones.
#   ./container-monitor.sh --summary                       - Run all checks silently and show only the final summary.
#   ./container-monitor.sh --summary <c1> <c2> ...         - Summary mode for specific containers.
#   ./container-monitor.sh --logs                          - Show logs for all running containers
#   ./container-monitor.sh --logs <container> [pattern...] - Show logs for a container, with optional filtering (e.g., logs my-app error warn).
#   ./container-monitor.sh --save-logs <container>         - Save logs for a specific container to a file
#   ./container-monitor.sh --prune                       - Run Docker's system prune to clean up unused resources.
#   ./container-monitor.sh --force                       - Bypass cache and force a new check for image updates
#   ./container-monitor.sh --no-update                   - Run without checking for a script update.
#   ./container-monitor.sh --auto-update                 - Automatically update containers with floating tags (e.g. latest).
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
VERSION="v0.81.5"
VERSION_DATE="2026-02-12"
SCRIPT_URL="https://github.com/buildplan/container-monitor/raw/refs/heads/main/container-monitor.sh"
CHECKSUM_URL="${SCRIPT_URL}.sha256" # sha256 hash check

# --- ANSI Color Codes ---
if [ -t 1 ]; then
    COLOR_RESET=$'\033[0m'
    COLOR_RED=$'\033[0;31m'
    COLOR_GREEN=$'\033[0;32m'
    COLOR_YELLOW=$'\033[0;33m'
    COLOR_CYAN=$'\033[0;36m'
    COLOR_MAGENTA=$'\033[0;35m'
    COLOR_BLUE=$'\033[0;34m'
else
    COLOR_RESET=''
    COLOR_RED=''
    COLOR_GREEN=''
    COLOR_YELLOW=''
    COLOR_CYAN=''
    COLOR_MAGENTA=''
    COLOR_BLUE=''
fi

# --- Global Flags ---
SUMMARY_ONLY_MODE=false
PRINT_MESSAGE_FORCE_STDOUT=false
INTERACTIVE_UPDATE_MODE=false
RECREATE_MODE=false
UPDATE_SKIPPED=false
FORCE_UPDATE_CHECK=false

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
# Initialize variables
LOG_LINES_TO_CHECK="${LOG_LINES_TO_CHECK:-$_SCRIPT_DEFAULT_LOG_LINES_TO_CHECK}"
CHECK_FREQUENCY_MINUTES="${CHECK_FREQUENCY_MINUTES:-$_SCRIPT_DEFAULT_CHECK_FREQUENCY_MINUTES}"
# Pre-load of Log File
if [ -z "${LOG_FILE:-}" ] && [ -f "$SCRIPT_DIR/config.yml" ]; then
    PRELOAD_LOG=$(grep -E "^[[:space:]]*log_file:" "$SCRIPT_DIR/config.yml" | head -n 1 | sed -E 's/.*log_file:[[:space:]]*["'\'']?([^"'\'']+)["'\'']?.*/\1/')
    if [ -n "$PRELOAD_LOG" ]; then
        if [[ "$PRELOAD_LOG" != /* ]]; then LOG_FILE="$SCRIPT_DIR/$PRELOAD_LOG"; else LOG_FILE="$PRELOAD_LOG"; fi
    fi
fi
LOG_FILE="${LOG_FILE:-$_SCRIPT_DEFAULT_LOG_FILE}"
# Initialize remaining variables
CPU_WARNING_THRESHOLD="${CPU_WARNING_THRESHOLD:-$_SCRIPT_DEFAULT_CPU_WARNING_THRESHOLD}"
MEMORY_WARNING_THRESHOLD="${MEMORY_WARNING_THRESHOLD:-$_SCRIPT_DEFAULT_MEMORY_WARNING_THRESHOLD}"
DISK_SPACE_THRESHOLD="${DISK_SPACE_THRESHOLD:-$_SCRIPT_DEFAULT_DISK_SPACE_THRESHOLD}"
NETWORK_ERROR_THRESHOLD="${NETWORK_ERROR_THRESHOLD:-$_SCRIPT_DEFAULT_NETWORK_ERROR_THRESHOLD}"
HOST_DISK_CHECK_FILESYSTEM="${HOST_DISK_CHECK_FILESYSTEM:-$_SCRIPT_DEFAULT_HOST_DISK_CHECK_FILESYSTEM}"
NOTIFICATION_CHANNEL="${NOTIFICATION_CHANNEL:-$_SCRIPT_DEFAULT_NOTIFICATION_CHANNEL}"
DISCORD_WEBHOOK_URL="${DISCORD_WEBHOOK_URL:-$_SCRIPT_DEFAULT_DISCORD_WEBHOOK_URL}"
GENERIC_WEBHOOK_URL="${GENERIC_WEBHOOK_URL:-}"
NTFY_SERVER_URL="${NTFY_SERVER_URL:-$_SCRIPT_DEFAULT_NTFY_SERVER_URL}"
NTFY_TOPIC="${NTFY_TOPIC:-$_SCRIPT_DEFAULT_NTFY_TOPIC}"
NTFY_ACCESS_TOKEN="${NTFY_ACCESS_TOKEN:-$_SCRIPT_DEFAULT_NTFY_ACCESS_TOKEN}"
CONTAINER_NAMES="${CONTAINER_NAMES:-}"
declare -a CONTAINER_NAMES_FROM_CONFIG_FILE=()

# --- Functions ---
secure_config_file() {
    local config_file="${1:-${SCRIPT_DIR}/config.yml}"
    local required_perms="600"
    local current_perms
    if [[ ! -f "$config_file" ]]; then
        return 0
    fi
    if current_perms=$(stat -c '%a' "$config_file" 2>/dev/null); then
        :
    elif current_perms=$(stat -f '%OLp' "$config_file" 2>/dev/null); then
        current_perms=$(echo "$current_perms" | grep -o '[0-7]\{3\}$')
    else
        current_perms=""
    fi
    if [[ -z "$current_perms" ]]; then
        return 0
    fi
    if [[ "$current_perms" != "$required_perms" ]]; then
        if [[ -n "$(declare -f print_message)" ]]; then
            print_message "WARNING: Config file permissions are $current_perms (should be $required_perms). Attempting to fix..." WARNING
        fi
        if chmod 600 "$config_file" 2>/dev/null; then
            if [[ -n "$(declare -f print_message)" ]]; then
                print_message "Config file permissions fixed to 600." GOOD
            fi
        else
            if [[ -n "$(declare -f print_message)" ]]; then
                print_message "WARNING: Could not change config file permissions. Insufficient privileges or ownership issue. Continuing anyway..." WARNING
            fi
        fi
    else
        if [[ -n "$(declare -f print_message)" ]]; then
            print_message "Config file permissions are secure ($required_perms)." GOOD
        fi
    fi
    return 0
}
load_configuration() {
    _CONFIG_FILE_PATH="$SCRIPT_DIR/config.yml"
    secure_config_file "$_CONFIG_FILE_PATH"

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
    set_final_config "GENERIC_WEBHOOK_URL"           ".notifications.generic.webhook_url"    ""
    set_final_config "NTFY_SERVER_URL"               ".notifications.ntfy.server_url"        "$_SCRIPT_DEFAULT_NTFY_SERVER_URL"
    set_final_config "NTFY_TOPIC"                    ".notifications.ntfy.topic"             "$_SCRIPT_DEFAULT_NTFY_TOPIC"
    set_final_config "NTFY_ACCESS_TOKEN"             ".notifications.ntfy.access_token"      "$_SCRIPT_DEFAULT_NTFY_ACCESS_TOKEN"
    set_final_config "NOTIFY_ON"                     ".notifications.notify_on"              "Updates,Logs,Status,Restarts,Resources,Disk,Network"
    set_final_config "UPDATE_CHECK_CACHE_HOURS"      ".general.update_check_cache_hours"     "6"
    set_final_config "DOCKER_USERNAME"               ".auth.docker_username"                 ""
    set_final_config "DOCKER_PASSWORD"               ".auth.docker_password"                 ""
    set_final_config "DOCKER_CONFIG_PATH"            ".auth.docker_config_path"              "$HOME/.docker/config.json"
    set_final_config "LOCK_TIMEOUT_SECONDS"          ".general.lock_timeout_seconds"         "10"
    set_final_config "HEALTHCHECKS_JOB_URL"          ".general.healthchecks_job_url"         ""
    set_final_config "HEALTHCHECKS_FAIL_ON"          ".general.healthchecks_fail_on"         ""
    set_final_config "AUTO_UPDATE_ENABLED"           ".auto_update.enabled"                  "false"

    mapfile -t AUTO_UPDATE_TAGS < <(yq e '.auto_update.tags[]' "$_CONFIG_FILE_PATH" 2>/dev/null)
    if [ ${#AUTO_UPDATE_TAGS[@]} -eq 0 ]; then AUTO_UPDATE_TAGS=("latest" "stable" "main" "master" "nightly"); fi

    mapfile -t AUTO_UPDATE_INCLUDE < <(yq e '.auto_update.include[]' "$_CONFIG_FILE_PATH" 2>/dev/null)
    mapfile -t AUTO_UPDATE_EXCLUDE < <(yq e '.auto_update.exclude[]' "$_CONFIG_FILE_PATH" 2>/dev/null)

    if ! mapfile -t LOG_ERROR_PATTERNS < <(yq e '.logs.error_patterns[]' "$_CONFIG_FILE_PATH" 2>/dev/null); then
        print_message "Failed to parse log error patterns. Using defaults." "WARNING"
        LOG_ERROR_PATTERNS=()
    fi
    if [[ "$NOTIFICATION_CHANNEL" != "discord" && "$NOTIFICATION_CHANNEL" != "ntfy" && "$NOTIFICATION_CHANNEL" != "generic" && "$NOTIFICATION_CHANNEL" != "none" ]]; then
        print_message "Invalid notification_channel '$NOTIFICATION_CHANNEL'..." "WARNING"
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
    if [ -f "$_CONFIG_FILE_PATH" ]; then
        local temp_exclude_array=()
        mapfile -t temp_exclude_array < <(yq e '.containers.exclude.updates[]' "$_CONFIG_FILE_PATH" 2>/dev/null)
        EXCLUDE_UPDATES_LIST_STR=$(IFS=,; echo "${temp_exclude_array[*]}")
        export EXCLUDE_UPDATES_LIST_STR
    fi
}
print_help() {
    printf '%bUsage:%b\n' "$COLOR_GREEN" "$COLOR_RESET"
    printf '  %-64s %s\n' "${COLOR_YELLOW}./container-monitor.sh [options] [container...]" "${COLOR_CYAN}- Run monitoring on named or configured containers.${COLOR_RESET}"

    printf '\n%bActions:%b\n' "$COLOR_GREEN" "$COLOR_RESET"
    printf '  %-64s %s\n' "${COLOR_YELLOW}--update${COLOR_RESET}" "${COLOR_CYAN}- Interactively pull and recreate containers with updates.${COLOR_RESET}"
    printf '  %-64s %s\n' "${COLOR_YELLOW}--auto-update${COLOR_RESET}" "${COLOR_CYAN}- Automatically update containers with floating tags (e.g. latest).${COLOR_RESET}"
    printf '  %-64s %s\n' "${COLOR_YELLOW}--pull${COLOR_RESET}" "${COLOR_CYAN}- Interactively pull new images only (no recreation).${COLOR_RESET}"
    printf '  %-64s %s\n' "${COLOR_YELLOW}--summary [container...]${COLOR_RESET}" "${COLOR_CYAN}- Show only the final summary report, hiding individual checks.${COLOR_RESET}"
    printf '  %-64s %s\n' "${COLOR_YELLOW}--logs <container> [pattern...]${COLOR_RESET}" "${COLOR_CYAN}- Show recent logs for a container, with optional text filters.${COLOR_RESET}"
    printf '  %-64s %s\n' "${COLOR_YELLOW}--save-logs <container>${COLOR_RESET}" "${COLOR_CYAN}- Save a container's full logs to a timestamped file.${COLOR_RESET}"
    printf '  %-64s %s\n' "${COLOR_YELLOW}--prune${COLOR_RESET}" "${COLOR_CYAN}- Run Docker's system prune command interactively.${COLOR_RESET}"
    printf '  %-64s %s\n' "${COLOR_YELLOW}--check-setup${COLOR_RESET}" "${COLOR_CYAN}- Verify dependencies and script configuration.${COLOR_RESET}"
    printf '  %-64s %s\n' "${COLOR_YELLOW}--setup-timer${COLOR_RESET}" "${COLOR_CYAN}- Install cron job or systemd timer for automated monitoring.${COLOR_RESET}"
    printf '  %-64s %s\n' "${COLOR_YELLOW}-h, --help${COLOR_RESET}" "${COLOR_CYAN}- Show this help message.${COLOR_RESET}"

    printf '\n%bModifiers:%b\n' "$COLOR_GREEN" "$COLOR_RESET"
    printf '  %-64s %s\n' "${COLOR_YELLOW}--exclude=<c1,c2,...>${COLOR_RESET}" "${COLOR_CYAN}- Exclude specified containers from all checks.${COLOR_RESET}"
    printf '  %-64s %s\n' "${COLOR_YELLOW}--force${COLOR_RESET}" "${COLOR_CYAN}- Bypass cache for image update checks (force live check).${COLOR_RESET}"
    printf '  %-64s %s\n' "${COLOR_YELLOW}--force-update${COLOR_RESET}" "${COLOR_CYAN}- Force prompt for script self-update even if unattended.${COLOR_RESET}"
    printf '  %-64s %s\n' "${COLOR_YELLOW}--no-update${COLOR_RESET}" "${COLOR_CYAN}- Skip script self-update check this run.${COLOR_RESET}"

    printf '\n%bConfiguration & Notes:%b\n' "$COLOR_GREEN" "$COLOR_RESET"
    printf '  %b- Config loaded as: defaults -> %bconfig.yml%b -> environment variables.%b\n' "$COLOR_CYAN" "$COLOR_YELLOW" "$COLOR_CYAN" "$COLOR_RESET"
    printf '  %b- To skip only image update checks, use the %bexclude%b section in %bconfig.yml%b.%b\n' "$COLOR_CYAN" "$COLOR_YELLOW" "$COLOR_CYAN" "$COLOR_YELLOW" "$COLOR_CYAN" "$COLOR_RESET"
    printf '  %b- Dependencies: %bdocker, jq, yq, skopeo, gawk, coreutils (timeout), wget%b.%b\n' "$COLOR_CYAN" "$COLOR_YELLOW" "$COLOR_CYAN" "$COLOR_RESET"
    printf '  %b- For automation (cron), avoid interactive flags: --pull, --update, --prune.%b\n' "$COLOR_CYAN" "$COLOR_RESET"

    printf '\n%bExamples:%b\n' "$COLOR_GREEN" "$COLOR_RESET"
    printf '  %bMonitor specific containers with summary:%b\n' "$COLOR_YELLOW" "$COLOR_RESET"
    printf '    ./container-monitor.sh --summary nginx myapp\n\n'
    printf '  %bShow logs with filter patterns:%b\n' "$COLOR_YELLOW" "$COLOR_RESET"
    printf '    ./container-monitor.sh --logs myapp error warn\n\n'
    printf '  %bSkip update checks for local containers via config.yml:%b\n' "$COLOR_YELLOW" "$COLOR_RESET"
    printf '    containers:\n      exclude:\n        updates:\n          - mylocalapp\n          - another-build\n'
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
    else
        if ! docker info >/dev/null 2>&1; then
            if [ "${CONTAINER_MONITOR_RELOADED:-false}" = "true" ]; then
                print_message "Critical: Script reloaded but permissions are still denied." "DANGER"
                print_message "Automatic fix failed. Please log out and log back in manually." "DANGER"
                manual_install_needed=true
            elif id -nG "$USER" | grep -qw "docker"; then
                print_message "User '$USER' is already in the 'docker' group, but the current shell session is stale." "INFO"
                if command -v sg &>/dev/null; then
                    print_message "Auto-reloading script to activate permissions..." "GOOD"
                    local args_str=""
                    printf -v args_str "%q " "$@"
                    export CONTAINER_MONITOR_RELOADED=true
                    exec sg docker -c "$0 $args_str"
                else
                    print_message "Cannot auto-reload. Please run 'newgrp docker' or log out/in." "WARNING"
                    manual_install_needed=true
                fi
            else
                print_message "Docker is installed, but the current user ('$USER') cannot access the Docker daemon." "WARNING"
                print_message "This usually means the user is not in the 'docker' group." "INFO"
                if [ -t 0 ]; then
                    read -rp "Would you like to add '$USER' to the 'docker' group to fix this? (y/n): " response
                    if [[ "$response" =~ ^[yY]$ ]]; then
                        print_message "Attempting to fix permissions..." "INFO"
                        sudo groupadd docker 2>/dev/null || true
                        if sudo usermod -aG docker "$USER"; then
                            print_message "User '$USER' added to 'docker' group successfully." "GOOD"
                            if [ -d "$HOME/.docker" ]; then
                                print_message "Fixing ownership of ~/.docker directory..." "INFO"
                                sudo chown -R "$USER":"$USER" "$HOME/.docker"
                                sudo chmod -R g+rwx "$HOME/.docker"
                            fi
                            if command -v sg &>/dev/null; then
                                print_message "Reloading script with new permissions..." "GOOD"
                                local args_str=""
                                printf -v args_str "%q " "$@"
                                export CONTAINER_MONITOR_RELOADED=true
                                exec sg docker -c "$0 $args_str"
                            else
                                print_message "Could not auto-reload. Please run 'newgrp docker' or log out and back in." "WARNING"
                                exit 0
                            fi
                        else
                            print_message "Failed to add user to group. Please run: sudo usermod -aG docker $USER" "DANGER"
                            manual_install_needed=true
                        fi
                    else
                        print_message "Skipping permission fix." "WARNING"
                        print_message "To fix manually, run: sudo usermod -aG docker \$USER" "INFO"
                        print_message "Then log out and back in." "INFO"
                        manual_install_needed=true
                    fi
                else
                    print_message "Cannot fix permissions interactively. To fix, run: sudo usermod -aG docker $USER" "DANGER"
                    manual_install_needed=true
                fi
            fi
        fi
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
                    local install_success=false
                    if [ "$pkg_manager" == "apt" ]; then
                       sudo apt-get update && sudo apt-get install -y "${missing_pkgs[@]}" && install_success=true
                    else
                       sudo "$pkg_manager" install -y "${missing_pkgs[@]}" && install_success=true
                    fi
                    if [ "$install_success" = true ]; then
                        print_message "Package manager dependencies installed successfully." "GOOD"
                    else
                        print_message "Failed to install dependencies. Please install them manually." "DANGER"
                        manual_install_needed=true
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
    _install_yq() {
        local arch_to_install="$1"
        local tag_to_install="$2"
        print_message "Attempting to download yq... You may be prompted for your password." "INFO"
        if [ -z "$tag_to_install" ]; then
             tag_to_install=$(curl -sL -o /dev/null -w "%{url_effective}" "https://github.com/mikefarah/yq/releases/latest" | xargs basename 2>/dev/null)
        fi
        if [ -z "$tag_to_install" ]; then
            print_message "Failed to get the latest yq version tag from GitHub." "DANGER"
            return 1
        fi
        local yq_url="https://github.com/mikefarah/yq/releases/download/${tag_to_install}/yq_linux_${arch_to_install}"
		if sudo wget --timeout=15 "$yq_url" -O /usr/local/bin/yq && sudo chmod +x /usr/local/bin/yq; then
            print_message "yq installed/updated successfully to ${tag_to_install}." "GOOD"
            return 0
        else
            print_message "Failed to download or install yq. Please do so manually." "DANGER"
            return 1
        fi
    }
    if ! command -v yq &>/dev/null; then
        print_message "yq is not installed. It is required for parsing config.yml." "DANGER"
        if [ "$arch" == "unsupported" ]; then
            print_message "Your system architecture ($(uname -m)) is not supported for automatic yq installation. Please install it manually." "DANGER"
            manual_install_needed=true
        elif [ -t 0 ]; then
            read -rp "Would you like to download the latest version for your architecture ($arch) now? (y/n): " response
            if [[ "$response" =~ ^[yY]$ ]]; then
                if ! _install_yq "$arch" ""; then
                    manual_install_needed=true
                fi
            else
                print_message "Installation cancelled. The script requires yq to function." "DANGER"
                manual_install_needed=true
            fi
        else
            print_message "yq is missing. Cannot install interactively. Please install it manually." "DANGER"
            manual_install_needed=true
        fi
    else
        print_message "Checking for yq updates..." "INFO"
        local local_yq_version; local_yq_version=$(yq --version | awk '{print $NF}')
        local latest_yq_tag; latest_yq_tag=$(curl -sL -o /dev/null -w "%{url_effective}" "https://github.com/mikefarah/yq/releases/latest" | xargs basename 2>/dev/null)
        if [[ -n "$latest_yq_tag" && "$local_yq_version" != "$latest_yq_tag" ]]; then
            if [ -t 0 ]; then
                local api_url="https://api.github.com/repos/mikefarah/yq/releases/tags/${latest_yq_tag}"
                local release_notes
                release_notes=$(curl -sL "$api_url" | jq -r '.body // "Could not retrieve release notes."')
                echo
                print_message "A new version of yq is available!" "WARNING"
                echo -e "  ${COLOR_CYAN}Current Version:${COLOR_RESET} $local_yq_version"
                echo -e "  ${COLOR_GREEN}New Version:    ${COLOR_RESET} $latest_yq_tag"
                echo
                echo -e "  ${COLOR_YELLOW}Release Notes for ${latest_yq_tag}:${COLOR_RESET}"
                echo -e "    ${release_notes//$'\n'/$'\n'    }"
                echo
                read -rp "Would you like to update yq now? (y/n): " response
                if [[ "$response" =~ ^[yY]$ ]]; then
                    _install_yq "$arch" "$latest_yq_tag"
                else
                    print_message "yq update skipped. Continuing with old version." "INFO"
                fi
            else
                local update_msg="A new version of yq is available: ${latest_yq_tag} (you have ${local_yq_version})."
                print_message "$update_msg" "WARNING"
                print_message "To update, run the script manually from your terminal." "INFO"
                local notif_title; notif_title="⚠️ Dependency Update Recommended on $(hostname)"
                send_notification "$update_msg" "$notif_title"
            fi
        elif [ -n "$local_yq_version" ]; then
            print_message "yq is up-to-date (version ${local_yq_version})." "GOOD"
        else
            print_message "Could not determine local yq version. Skipping update check." "WARNING"
        fi
    fi
    if [ "$manual_install_needed" = true ]; then
        print_message "Please address the missing dependencies listed above before running the script again." "DANGER"
        exit 1
    fi
    if [ ${#missing_pkgs[@]} -eq 0 ] && command -v yq &>/dev/null; then
        print_message "All required dependencies are installed." "GOOD"
    fi
}
run_setup_check() {
    print_message "--- Running Setup & Dependency Check ---" "INFO"
    local all_ok=true

    # 1. Check for system packages (docker, jq, etc.)
    local missing_pkgs=()
    declare -A deps=( [docker]=docker [jq]=jq [skopeo]=skopeo [awk]=gawk [timeout]=coreutils [wget]=wget )
    for cmd in "${!deps[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing_pkgs+=("${deps[$cmd]}")
        fi
    done

    if [ ${#missing_pkgs[@]} -gt 0 ]; then
        print_message "✖ System dependencies missing: ${missing_pkgs[*]}" "DANGER"
        all_ok=false
    else
        print_message "✔ System dependencies are installed." "GOOD"
    fi

    # 2. Check yq status (installed and up-to-date)
    if ! command -v yq &>/dev/null; then
        print_message "✖ yq is not installed. It's a required dependency." "DANGER"
        all_ok=false
    else
        local local_yq_version; local_yq_version=$(yq --version | awk '{print $NF}')
        local latest_yq_tag; latest_yq_tag=$(curl -sL -o /dev/null -w "%{url_effective}" "https://github.com/mikefarah/yq/releases/latest" | xargs basename 2>/dev/null)
        if [[ -n "$latest_yq_tag" && "$local_yq_version" != "$latest_yq_tag" ]]; then
            print_message "❕ yq has an update available: ${latest_yq_tag} (you have ${local_yq_version})." "WARNING"
            print_message "  Run the script manually to get an update prompt." "INFO"
        else
            print_message "✔ yq is up-to-date (version ${local_yq_version})." "GOOD"
        fi
    fi

    # 3. Check for script update
    local latest_version; latest_version=$(curl -sL "$SCRIPT_URL" | grep -m 1 "VERSION=" | cut -d'"' -f2)
    if [[ -n "$latest_version" && "$VERSION" != "$latest_version" ]]; then
        print_message "❕ This script has an update available: ${latest_version} (you have ${VERSION})." "WARNING"
        print_message "  Run the script manually to get an update prompt." "INFO"
    else
        print_message "✔ Script is up-to-date (version ${VERSION})." "GOOD"
    fi

    # 4. Check config.yml
    _CONFIG_FILE_PATH="$SCRIPT_DIR/config.yml"
    if [ ! -f "$_CONFIG_FILE_PATH" ]; then
        print_message "❕ config.yml not found. The script will use default values." "WARNING"
    elif ! yq e '.' "$_CONFIG_FILE_PATH" >/dev/null 2>&1; then
        print_message "✖ config.yml has invalid syntax." "DANGER"
        all_ok=false
    else
        print_message "✔ config.yml found and has valid syntax." "GOOD"
    fi
    echo
    if [ "$all_ok" = true ]; then
        print_message "Setup check passed. The script is ready to run." "GOOD"
    else
        print_message "Setup check failed. Please address the errors (✖) above." "DANGER"
        return 1
    fi
}
setup_automated_schedule() {
    print_message "--- Container Monitor Automation Setup ---" "INFO"
    echo
    local SCRIPT_PATH
    SCRIPT_PATH="$SCRIPT_DIR/$(basename "$0")"
    if [ ! -f "$SCRIPT_PATH" ]; then
        print_message "Error: Cannot determine script path." "DANGER"
        return 1
    fi
    print_message "Script location: $SCRIPT_PATH" "INFO"
    echo
    echo -e "${COLOR_CYAN}What task do you want to schedule?${COLOR_RESET}"
    echo "  1) Standard Monitoring (Checks health, resources, and sends alerts)"
    echo "  2) Auto-Updater (Automatically updates and recreates containers)"
    echo
    local task_type="monitor"
    local task_choice
    read -rp "Enter your choice (1 or 2): " task_choice
    case "$task_choice" in
        1) task_type="monitor" ;;
        2) task_type="update" ;;
        *) print_message "Invalid choice." "DANGER"; return 1 ;;
    esac
    echo
    echo -e "${COLOR_CYAN}Select scheduler type:${COLOR_RESET}"
    echo "  1) cron (traditional, simple)"
    echo "  2) systemd timer (modern, recommended for systemd-based systems)"
    echo
    read -rp "Enter your choice (1 or 2): " scheduler_choice
    case "$scheduler_choice" in
        1)
            setup_cron_schedule "$SCRIPT_PATH" "$task_type"
            ;;
        2)
            setup_systemd_timer "$SCRIPT_PATH" "$task_type"
            ;;
        *)
            print_message "Invalid choice. Exiting." "DANGER"
            return 1
            ;;
    esac
}
setup_cron_schedule() {
    local script_path="$1"
    local task_type="$2"
    local job_name=""
    if [ "$task_type" == "update" ]; then job_name="Auto-Update"; else job_name="Monitor"; fi
    print_message "Setting up cron job for: $job_name" "INFO"
    echo
    if ! command -v crontab &>/dev/null; then
        print_message "Error: crontab command not found. Please install cron first." "DANGER"
        return 1
    fi
    echo -e "${COLOR_CYAN}Select frequency for $job_name:${COLOR_RESET}"
    if [ "$task_type" == "update" ]; then
        echo "  1) Once a day (at 04:00 AM) [Recommended]"
        echo "  2) Once a week (Sunday at 04:00 AM)"
        echo "  3) Custom"
    else
        echo "  1) Every 6 hours"
        echo "  2) Every 12 hours"
        echo "  3) Once a day (at midnight)"
        echo "  4) Twice a day (at 6 AM and 6 PM)"
        echo "  5) Custom"
    fi
    echo
    read -rp "Enter your choice: " freq_choice
    local cron_expression=""
    local description=""
    show_cron_guide() {
        echo
        echo -e "${COLOR_YELLOW}Cron expression format:${COLOR_RESET}"
        echo "  ┌───────────── minute (0 - 59)"
        echo "  │ ┌───────────── hour (0 - 23)"
        echo "  │ │ ┌───────────── day of the month (1 - 31)"
        echo "  │ │ │ ┌───────────── month (1 - 12)"
        echo "  │ │ │ │ ┌───────────── day of the week (0 - 6) (Sunday to Saturday)"
        echo "  │ │ │ │ │"
        echo "  * * * * *"
        echo
        echo "Examples:"
        echo "  0 */4 * * * - Every 4 hours"
        echo "  30 2 * * * - At 2:30 AM every day"
        echo "  0 9,17 * * 1-5  - At 9 AM and 5 PM on weekdays"
        echo
    }
    if [ "$task_type" == "update" ]; then
        case "$freq_choice" in
            1) cron_expression="0 4 * * *"; description="daily at 04:00 AM" ;;
            2) cron_expression="0 4 * * 0"; description="every Sunday at 04:00 AM" ;;
            3)
                show_cron_guide
                read -rp "Enter your custom cron expression: " cron_expression
                description="custom schedule ($cron_expression)"
                ;;
            *) print_message "Invalid choice." "DANGER"; return 1 ;;
        esac
    else
        case "$freq_choice" in
            1) cron_expression="0 */6 * * *"; description="every 6 hours" ;;
            2) cron_expression="0 */12 * * *"; description="every 12 hours" ;;
            3) cron_expression="0 0 * * *"; description="daily at midnight" ;;
            4) cron_expression="0 6,18 * * *"; description="twice a day (6 AM/PM)" ;;
            5)
                show_cron_guide
                read -rp "Enter your custom cron expression: " cron_expression
                description="custom schedule ($cron_expression)"
                ;;
            *) print_message "Invalid choice." "DANGER"; return 1 ;;
        esac
    fi
    local cron_command=""
    if [ "$task_type" == "update" ]; then
        cron_command="$cron_expression $script_path --auto-update > /dev/null 2>&1"
    else
        cron_command="$cron_expression $script_path --summary >> $LOG_FILE 2>&1"
    fi
    echo
    print_message "The following cron job will be added:" "INFO"
    echo -e "  ${COLOR_YELLOW}$cron_command${COLOR_RESET}"
    echo -e "  ${COLOR_CYAN}(Runs $description)${COLOR_RESET}"
    echo
    read -rp "Do you want to proceed? (y/n): " confirm
    if [[ ! "$confirm" =~ ^[yY]$ ]]; then
        print_message "Installation cancelled." "WARNING"
        return 0
    fi
    local search_term="$script_path"
    if [ "$task_type" == "update" ]; then search_term="--auto-update"; else search_term="--summary"; fi
    local existing_cron
    existing_cron=$(crontab -l 2>/dev/null | grep -F "$script_path" | grep -F -- "$search_term" || true)
    if [ -n "$existing_cron" ]; then
        print_message "Found existing $job_name job:" "WARNING"
        echo -e "  ${COLOR_YELLOW}$existing_cron${COLOR_RESET}"
        echo
        read -rp "Replace it? (y/n): " replace
        if [[ "$replace" =~ ^[yY]$ ]]; then
            (crontab -l 2>/dev/null | grep -vF -- "$search_term") | crontab - 2>/dev/null
            print_message "Old job removed." "GOOD"
        else
            print_message "Keeping existing cron job. No changes made." "INFO"
            return 0
        fi
    fi
    (crontab -l 2>/dev/null; echo "$cron_command") | crontab -
    if [ $? -eq 0 ]; then
        print_message "$job_name cron job installed successfully!" "GOOD"
        echo
        print_message "Your container monitor will now run $description" "INFO"
        print_message "Logs will be written to: $LOG_FILE" "INFO"
        echo
        print_message "To view or edit your cron jobs, run: crontab -e" "INFO"
        print_message "To remove this cron job, run: crontab -e and delete the line containing '$script_path'" "INFO"
    else
        print_message "Failed to install cron job." "DANGER"
        return 1
    fi
}
setup_systemd_timer() {
    local script_path="$1"
    local task_type="$2"
    local job_name=""
    local service_suffix=""
    local cmd_flag=""
    if [ "$task_type" == "update" ]; then
        job_name="Auto-Updater"
        service_suffix="-update"
        cmd_flag="--auto-update"
    else
        job_name="Monitor"
        service_suffix=""
        cmd_flag="--summary"
    fi
    print_message "Setting up systemd timer for: $job_name" "INFO"
    echo
    if ! command -v systemctl &>/dev/null; then
        print_message "Error: systemctl command not found. This system may not use systemd." "DANGER"
        print_message "Please use the cron option instead." "INFO"
        return 1
    fi
    local use_user_service=false
    local systemd_dir=""
    local systemctl_cmd="systemctl"

    echo -e "${COLOR_CYAN}Install as:${COLOR_RESET}"
    echo "  1) System service (requires root/sudo, runs for all users)"
    echo "  2) User service (runs only for current user, no sudo required)"
    echo
    read -rp "Enter your choice (1 or 2): " service_type

    case "$service_type" in
        1)
            systemd_dir="/etc/systemd/system"
            systemctl_cmd="sudo systemctl"
            ;;
        2)
            use_user_service=true
            systemd_dir="${HOME}/.config/systemd/user"
            systemctl_cmd="systemctl --user"
            mkdir -p "$systemd_dir"
            ;;
        *)
            print_message "Invalid choice. Exiting." "DANGER"
            return 1
            ;;
    esac

    # Helper for the OnCalendar guide
    show_timer_guide() {
        echo
        echo -e "${COLOR_YELLOW}Systemd timer OnCalendar format examples:${COLOR_RESET}"
        echo "  hourly              - Every hour"
        echo "  daily               - Every day at midnight"
        echo "  weekly              - Every week on Monday at midnight"
        echo "  *-*-* 00/2:00:00    - Every 2 hours"
        echo "  *-*-* 08:00:00      - Every day at 8 AM"
        echo "  Mon,Fri 09:00:00    - Mondays and Fridays at 9 AM"
        echo
        echo "For more info: https://www.freedesktop.org/software/systemd/man/systemd.time.html"
        echo
    }
    echo
    echo -e "${COLOR_CYAN}Select frequency for $job_name:${COLOR_RESET}"
    local freq_choice
    local timer_oncalendar=""
    local description=""
    if [ "$task_type" == "update" ]; then
        echo "  1) Once a day (at 04:00 AM) [Recommended]"
        echo "  2) Custom"
        echo
        read -rp "Enter your choice (1 or 2): " freq_choice
        case "$freq_choice" in
            1) timer_oncalendar="*-*-* 04:00:00"; description="daily at 04:00 AM" ;;
            2)
                show_timer_guide
                read -rp "Enter your custom OnCalendar value: " timer_oncalendar
                description="custom schedule ($timer_oncalendar)"
                ;;
            *) print_message "Invalid choice." "DANGER"; return 1 ;;
        esac
    else
        echo "  1) Every 6 hours"
        echo "  2) Every 12 hours"
        echo "  3) Once a day (at midnight)"
        echo "  4) Twice a day (at 6 AM and 6 PM)"
        echo "  5) Every 4 hours"
        echo "  6) Custom interval"
        echo
        read -rp "Enter your choice (1-6): " freq_choice
        case "$freq_choice" in
            1) timer_oncalendar="*-*-* 00/6:00:00"; description="every 6 hours" ;;
            2) timer_oncalendar="*-*-* 00/12:00:00"; description="every 12 hours" ;;
            3) timer_oncalendar="daily"; description="once a day at midnight" ;;
            4) timer_oncalendar="*-*-* 06,18:00:00"; description="twice a day at 6 AM and 6 PM" ;;
            5) timer_oncalendar="*-*-* 00/4:00:00"; description="every 4 hours" ;;
            6)
                show_timer_guide
                read -rp "Enter your custom OnCalendar value: " timer_oncalendar
                description="custom schedule ($timer_oncalendar)"
                ;;
            *) print_message "Invalid choice." "DANGER"; return 1 ;;
        esac
    fi
    local service_name="container-monitor${service_suffix}"
    local service_file="${systemd_dir}/${service_name}.service"
    local timer_file="${systemd_dir}/${service_name}.timer"
    local service_content="[Unit]
Description=Docker Container ${job_name}
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=$script_path $cmd_flag
StandardOutput=append:$LOG_FILE
StandardError=append:$LOG_FILE"

    if [ "$use_user_service" = true ]; then
        service_content="[Unit]
Description=Docker Container ${job_name}
After=docker.service

[Service]
Type=oneshot
ExecStart=$script_path $cmd_flag
StandardOutput=append:$LOG_FILE
StandardError=append:$LOG_FILE

[Install]
WantedBy=default.target"
    else
        service_content+="\n\n[Install]\nWantedBy=multi-user.target"
    fi

    local timer_content="[Unit]
Description=Timer for Docker Container ${job_name}
Requires=${service_name}.service

[Timer]
OnCalendar=$timer_oncalendar
Persistent=true

[Install]
WantedBy=timers.target"

    echo
    print_message "The following systemd units will be created:" "INFO"
    echo
    echo -e "${COLOR_YELLOW}Service file: $service_file${COLOR_RESET}"
    echo "$service_content"
    echo
    echo -e "${COLOR_YELLOW}Timer file: $timer_file${COLOR_RESET}"
    echo "$timer_content"
    echo
    echo -e "  ${COLOR_CYAN}(Runs $description)${COLOR_RESET}"
    echo
    read -rp "Do you want to proceed? (y/n): " confirm
    if [[ ! "$confirm" =~ ^[yY]$ ]]; then
        print_message "Installation cancelled." "WARNING"
        return 0
    fi
    if [ -f "$service_file" ] || [ -f "$timer_file" ]; then
        print_message "Systemd units already exist for this service." "WARNING"
        read -rp "Do you want to replace them? (y/n): " replace
        if [[ ! "$replace" =~ ^[yY]$ ]]; then
            print_message "Installation cancelled." "WARNING"
            return 0
        fi
        $systemctl_cmd stop ${service_name}.timer 2>/dev/null || true
        $systemctl_cmd disable ${service_name}.timer 2>/dev/null || true
    fi
    if [ "$use_user_service" = true ]; then
        echo -e "$service_content" > "$service_file"
        echo -e "$timer_content" > "$timer_file"
    else
        echo -e "$service_content" | sudo tee "$service_file" > /dev/null
        echo -e "$timer_content" | sudo tee "$timer_file" > /dev/null
    fi

    if [ $? -ne 0 ]; then
        print_message "Failed to create systemd unit files." "DANGER"
        return 1
    fi
    print_message "Systemd unit files created successfully." "GOOD"
    print_message "Reloading systemd daemon..." "INFO"
    $systemctl_cmd daemon-reload

    if [ $? -ne 0 ]; then
        print_message "Failed to reload systemd daemon." "DANGER"
        return 1
    fi
    print_message "Enabling and starting the timer..." "INFO"
    $systemctl_cmd enable ${service_name}.timer
    $systemctl_cmd start ${service_name}.timer
    if [ $? -eq 0 ]; then
        print_message "Systemd timer installed and started successfully!" "GOOD"
        echo
        print_message "Your container monitor will now run $description" "INFO"
        print_message "Logs will be written to: $LOG_FILE" "INFO"
        echo
        echo -e "${COLOR_CYAN}Useful commands:${COLOR_RESET}"
        echo "  View timer status:  $systemctl_cmd status ${service_name}.timer"
        echo "  View service logs:  $systemctl_cmd status ${service_name}.service"
        if [ "$use_user_service" = false ]; then
            echo "  View journal logs:  sudo journalctl -u ${service_name}.service"
        else
            echo "  View journal logs:  journalctl --user -u ${service_name}.service"
        fi
        echo "  Stop timer:         $systemctl_cmd stop ${service_name}.timer"
        echo "  Disable timer:      $systemctl_cmd disable ${service_name}.timer"
        echo "  Test service now:   $systemctl_cmd start ${service_name}.service"
        echo
        print_message "Next scheduled run:" "INFO"
        $systemctl_cmd list-timers ${service_name}.timer
    else
        print_message "Failed to enable/start systemd timer." "DANGER"
        return 1
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
    local current_date
    current_date=$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")
    local json_payload
    json_payload=$(jq -n \
                  --arg title "$title" \
                  --arg description "$message" \
                  --arg timestamp "$current_date" \
                  '{
                    "username": "Docker Monitor",
                    "embeds": [{
                      "title": $title,
                      "description": $description,
                      "color": 15158332,
                      "timestamp": $timestamp
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
send_generic_notification() {
    local message="$1"
    local title="$2"
    local json_payload
    json_payload=$(jq -n --arg text "$title: $message" '{text: $text}')
    if [ -n "${GENERIC_WEBHOOK_URL:-}" ]; then
        run_with_retry curl -s -H "Content-Type: application/json" -X POST -d "$json_payload" "$GENERIC_WEBHOOK_URL" > /dev/null
    else
        print_message "Generic Webhook URL is missing." "WARNING"
    fi
}
send_notification() {
    local message="$1"
    local title="$2"
    case "$NOTIFICATION_CHANNEL" in
        "discord") send_discord_notification "$message" "$title" ;;
        "ntfy")    send_ntfy_notification "$message" "$title" ;;
        "generic") send_generic_notification "$message" "$title" ;;
        "none"|"") ;;
        *)         print_message "Unknown notification channel: '$NOTIFICATION_CHANNEL'." "DANGER" ;;
    esac
}
send_healthchecks_job_ping() {
  local base_url="$1"
  local status="$2"
  local body="${3:-}"
  base_url="${base_url%/}"
  if [[ -z "$base_url" || ! "$base_url" =~ ^https?:// ]]; then
    print_message "Healthchecks: job URL not set or invalid: '$base_url'." "WARNING"
    return 0
  fi
  local endpoint="$base_url"
  case "$status" in
    start) endpoint+="/start" ;;
    fail)  endpoint+="/fail" ;;
    up)    : ;;
    *)     : ;;
  esac
  if [[ -n "$body" ]]; then
    (curl -fsS --connect-timeout 3 -m 8 --retry 1 \
      --data-raw "$body" "$endpoint" >/dev/null 2>&1 || \
      print_message "Healthchecks: job ping '$status' failed (curl)." "WARNING") &
  else
    (curl -fsS --connect-timeout 3 -m 8 --retry 1 \
      "$endpoint" >/dev/null 2>&1 || \
      print_message "Healthchecks: job ping '$status' failed (curl)." "WARNING") &
  fi
}
self_update() {
    local latest_version="$1"
    local repo_owner="buildplan"
    local repo_name="container-monitor"
    local api_url="https://api.github.com/repos/${repo_owner}/${repo_name}/releases/tags/${latest_version}"
    local release_notes
    if command -v jq &>/dev/null; then
        release_notes=$(curl -sL "$api_url" | jq -r '.body // "Could not retrieve release notes."')
    else
        release_notes="jq is not installed, cannot fetch release notes."
    fi
    echo
    print_message "A new version of the script is available!" "INFO"
    echo -e "  ${COLOR_CYAN}Current Version:${COLOR_RESET} $VERSION"
    echo -e "  ${COLOR_GREEN}New Version:    ${COLOR_RESET} $latest_version"
    echo
    echo -e "  ${COLOR_YELLOW}Release Notes for ${latest_version}:${COLOR_RESET}"
    echo -e "    ${release_notes//$'\n'/$'\n'    }"
    echo
    read -rp "Would you like to update now? (y/n): " response
    if [[ ! "$response" =~ ^[yY]$ ]]; then
        UPDATE_SKIPPED=true
        print_message "Update skipped by user." "INFO"
        return
    fi
    local temp_dir
    temp_dir=$(mktemp -d)
    if [ ! -d "$temp_dir" ]; then
        print_message "Failed to create temporary directory. Update aborted." "DANGER"
        exit 1
    fi
    trap 'rm -rf -- "$temp_dir"' EXIT
    local temp_script; temp_script="$temp_dir/$(basename "$SCRIPT_URL")"
    local temp_checksum; temp_checksum="$temp_dir/$(basename "$CHECKSUM_URL")"
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
    local container_name="$1"
    local inspect_data="$2"
    local cpu_for_status_msg="$3"
    local mem_for_status_msg="$4"
    local status health_status
    status=$(jq -r '.[0].State.Status' <<< "$inspect_data")
    health_status="not configured"
    if jq -e '.[0].State.Health != null and .[0].State.Health.Status != null' <<< "$inspect_data" >/dev/null 2>&1; then
        health_status=$(jq -r '.[0].State.Health.Status' <<< "$inspect_data")
    fi
    if [ "$status" != "running" ]; then
        print_message "  ${COLOR_BLUE}Status:${COLOR_RESET} Not running (Status: $status, Health: $health_status, CPU: $cpu_for_status_msg, Mem: $mem_for_status_msg)" "DANGER"
        return 1
    fi
    if [ "$health_status" = "healthy" ]; then
        print_message "  ${COLOR_BLUE}Status:${COLOR_RESET} Running and healthy (Status: $status, Health: $health_status, CPU: $cpu_for_status_msg, Mem: $mem_for_status_msg)" "GOOD"
        return 0
    elif [ "$health_status" = "unhealthy" ]; then
        print_message "  ${COLOR_BLUE}Status:${COLOR_RESET} Running but UNHEALTHY (Status: $status, Health: $health_status, CPU: $cpu_for_status_msg, Mem: $mem_for_status_msg)" "DANGER"
        local failing_streak last_output last_exit_code
        failing_streak=$(jq -r '.[0].State.Health.FailingStreak // 0' <<< "$inspect_data")
        last_exit_code=$(jq -r '.[0].State.Health.Log[-1].ExitCode // "unknown"' <<< "$inspect_data")
        last_output=$(jq -r '.[0].State.Health.Log[-1].Output // "No output"' <<< "$inspect_data" | grep -v "^[[:space:]]*%" | grep -Ei "curl:|error|failed|refused|timeout" | head -n 3 | sed 's/^[[:space:]]*//')
        if [ -z "$last_output" ]; then
            last_output=$(jq -r '.[0].State.Health.Log[-1].Output // "No output"' <<< "$inspect_data" | tail -n 1 | sed 's/^[[:space:]]*//')
        fi
        print_message "    ${COLOR_BLUE}Health Check Details:${COLOR_RESET} Failed $failing_streak consecutive time(s), Exit Code: $last_exit_code" "WARNING"
        print_message "    ${COLOR_BLUE}Last Error:${COLOR_RESET} $last_output" "WARNING"
        return 1
    elif [ "$health_status" = "not configured" ]; then
        print_message "  ${COLOR_BLUE}Status:${COLOR_RESET} Running (Status: $status, Health: $health_status, CPU: $cpu_for_status_msg, Mem: $mem_for_status_msg)" "GOOD"
        return 0
    else
        print_message "  ${COLOR_BLUE}Status:${COLOR_RESET} Running (Status: $status, Health: $health_status, CPU: $cpu_for_status_msg, Mem: $mem_for_status_msg)" "WARNING"
        return 1
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
        local mp_destination mp_type mp_source
        mp_destination=$(jq -r ".[0].Mounts[$i].Destination // empty" <<< "$inspect_data" 2>/dev/null)
        mp_type=$(jq -r ".[0].Mounts[$i].Type // empty" <<< "$inspect_data" 2>/dev/null)
        mp_source=$(jq -r ".[0].Mounts[$i].Source // empty" <<< "$inspect_data" 2>/dev/null)
        if [ -z "$mp_destination" ]; then continue; fi
        if [[ "$mp_destination" == *".sock" || "$mp_destination" == "/proc"* || "$mp_destination" == "/sys"* || "$mp_destination" == "/dev"* || "$mp_destination" == "/host/"* ]]; then
            continue
        fi
        local disk_usage_output
        if ! disk_usage_output=$(timeout 5 docker exec "$container_name" df -P "$mp_destination" 2>/dev/null); then
            if [[ "$mp_type" == "bind" ]] && [ -n "$mp_source" ] && [ -d "$mp_source" ]; then
                disk_usage_output=$(df -P "$mp_source" 2>/dev/null) || continue
            else
                continue
            fi
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
    local network_stats
    network_stats=$(timeout 5 docker exec "$container_name" cat /proc/net/dev 2>/dev/null)
    if [ -n "$network_stats" ]; then
        local network_issue_reported_for_container=false
        while IFS= read -r line; do
            if [[ "$line" == *:* ]]; then
                local interface data_part errors
                interface=$(echo "$line" | awk -F ':' '{print $1}' | sed 's/^[ \t]*//;s/[ \t]*$//')
                data_part=$(echo "$line" | cut -d':' -f2-)
                read -r _r_bytes _r_packets _r_errs _r_drop _ _ _ _ _t_bytes _t_packets _t_errs _t_drop <<< "$data_part"
                if ! [[ "$_r_errs" =~ ^[0-9]+$ && "$_t_drop" =~ ^[0-9]+$ ]]; then continue; fi
                errors=$((_r_errs + _t_drop))
                if [ "$errors" -gt "$NETWORK_ERROR_THRESHOLD" ]; then
                    print_message "  ${COLOR_BLUE}Network:${COLOR_RESET} Interface '$interface' has $errors errors/drops in '$container_name'." "WARNING"
                    issues_found=1
                fi
            fi
        done <<< "$(tail -n +3 <<< "$network_stats")"
        if [ $issues_found -eq 0 ]; then
            print_message "  ${COLOR_BLUE}Network:${COLOR_RESET} No significant network issues detected for '$container_name'." "INFO"
        fi
    else
        local container_pid
        container_pid=$(docker inspect -f '{{.State.Pid}}' "$container_name" 2>/dev/null)
        if [ -n "$container_pid" ] && [ "$container_pid" -gt 0 ]; then
            network_stats=$(timeout 5 cat "/proc/$container_pid/net/dev" 2>/dev/null)
            if [ -n "$network_stats" ]; then
                while IFS= read -r line; do
                    if [[ "$line" == *:* ]]; then
                        local interface data_part errors
                        interface=$(echo "$line" | awk -F ':' '{print $1}' | sed 's/^[ \t]*//;s/[ \t]*$//')
                        data_part=$(echo "$line" | cut -d':' -f2-)
                        read -r _r_bytes _r_packets _r_errs _r_drop _ _ _ _ _t_bytes _t_packets _t_errs _t_drop <<< "$data_part"
                        if ! [[ "$_r_errs" =~ ^[0-9]+$ && "$_t_drop" =~ ^[0-9]+$ ]]; then continue; fi
                        errors=$((_r_errs + _t_drop))
                        if [ "$errors" -gt "$NETWORK_ERROR_THRESHOLD" ]; then
                            print_message "  ${COLOR_BLUE}Network:${COLOR_RESET} Interface '$interface' has $errors errors/drops in '$container_name' (via host namespace)." "WARNING"
                            issues_found=1
                        fi
                    fi
                done <<< "$(tail -n +3 <<< "$network_stats")"
                if [ $issues_found -eq 0 ]; then
                    print_message "  ${COLOR_BLUE}Network:${COLOR_RESET} No significant network issues detected for '$container_name' (via host namespace)." "INFO"
                fi
            else
                print_message "  ${COLOR_BLUE}Network:${COLOR_RESET} Could not access network stats for '$container_name' (minimal container, host access failed)." "WARNING"
                issues_found=1
            fi
        else
            print_message "  ${COLOR_BLUE}Network:${COLOR_RESET} Could not get PID for '$container_name'." "WARNING"
            issues_found=1
        fi
    fi
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

    local excluded_from_updates=()
    if [ -n "${EXCLUDE_UPDATES_LIST_STR:-}" ]; then
        IFS=',' read -r -a excluded_from_updates <<< "$EXCLUDE_UPDATES_LIST_STR"
    fi

    for excluded_container in "${excluded_from_updates[@]}"; do
        if [[ "$container_name" == "$excluded_container" ]]; then
            print_message "  ${COLOR_BLUE}Update Check:${COLOR_RESET} Skipping for '$container_name' (on exclude list)." "INFO" >&2
            return 0
        fi
    done
    if ! command -v skopeo &>/dev/null; then print_message "  ${COLOR_BLUE}Update Check:${COLOR_RESET} skopeo not installed. Skipping." "INFO" >&2; return 0; fi
    if [[ "$current_image_ref" == *@sha256:* || "$current_image_ref" =~ ^sha256: ]]; then
        print_message "  ${COLOR_BLUE}Update Check:${COLOR_RESET} Image for '$container_name' is pinned by digest. Skipping." "INFO" >&2; return 0
    fi
    local local_inspect; local_inspect=$(docker inspect "$current_image_ref" 2>/dev/null)
    if ! jq -e '.[0].RepoDigests and (.[0].RepoDigests | length) > 0' <<< "$local_inspect" >/dev/null 2>&1; then
        print_message "  ${COLOR_BLUE}Update Check:${COLOR_RESET} Skipping '$container_name' (local or non-registry image)." "INFO" >&2
        return 0
    fi
    local cache_key; cache_key=$(echo "$current_image_ref" | sed 's/[/:]/_/g')
    if [ "$FORCE_UPDATE_CHECK" = false ]; then
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
    if [[ "$current_tag" =~ ^(latest|stable|release|rolling|main|master|nightly|edge|lts)$ ]]; then
        strategy="digest"
    fi
    local latest_stable_version=""
    local update_check_failed=false
    local error_message=""
    case "$strategy" in
        "digest")
            local local_digest; local_digest=$(jq -r '(.[0].RepoDigests[]? | select(startswith("'"$registry_host/$image_path_for_skopeo"'@")) | split("@")[1]) // (.[0].RepoDigests[0]? | split("@")[1])' <<< "$local_inspect")
            if [ -z "$local_digest" ]; then
                error_message="Could not get local digest for '$current_image_ref'. Cannot check tag '$current_tag'."
                update_check_failed=true
            else
                local remote_inspect_output; remote_inspect_output=$(skopeo "${skopeo_opts[@]}" inspect --no-tags "${skopeo_repo_ref}:${current_tag}" 2>&1)
                if [ $? -ne 0 ]; then
                    error_message="Error inspecting remote image '${skopeo_repo_ref}:${current_tag}'. Details: $remote_inspect_output"
                    update_check_failed=true
                else
                    local remote_digest; remote_digest=$(jq -r '.Digest' <<< "$remote_inspect_output")
                    if [ "$remote_digest" != "$local_digest" ]; then
                        local local_size; local_size=$(jq -r '.[0].Size // 0' <<< "$local_inspect")
                        local remote_created; remote_created=$(jq -r '.Created' <<< "$remote_inspect_output")
                        local remote_size; remote_size=$(jq -r '.Size // 0' <<< "$remote_inspect_output")
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
                local tag_filter
                local sort_cmd=("sort" "-V")
                local suffix_part=""
                if [[ "$current_tag" =~ ^(v?[0-9]+(\.[0-9]+)*)(.*)$ ]]; then
                    suffix_part="${BASH_REMATCH[3]}"
                fi
                if [ -n "$suffix_part" ]; then
                    local escaped_suffix; escaped_suffix="${suffix_part//./\\.}"
                    tag_filter="^[v]?[0-9\.]+$escaped_suffix$"
                    latest_stable_version=$(echo "$skopeo_output" | jq -r '.Tags[]' | grep -E "$tag_filter" | "${sort_cmd[@]}" | tail -n 1)
                else
                    if [[ "$strategy" == "major-lock" ]]; then
                        local major_version=""
                        if [[ "$current_tag" =~ ^v?([0-9]+) ]]; then
                            major_version="${BASH_REMATCH[1]}"
                        fi
                        if [ -n "$major_version" ]; then
                            tag_filter="^[v]?${major_version}\.[0-9\.]+$"
                        else
                            tag_filter='^[v]?[0-9\.]+$'
                        fi
                    elif [[ "$strategy" == "semver" ]]; then
                        tag_filter='^[v]?[0-9]+\.[0-9]+(\.[0-9]+)*$'
                    else
                        tag_filter='^[v]?[0-9\.]+$'
                    fi
                    latest_stable_version=$(echo "$skopeo_output" | jq -r '.Tags[]' | grep -E "$tag_filter" | "${sort_cmd[@]}" | tail -n 1)
                fi
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
        return 100
    elif [[ "v$current_tag" != "v$latest_stable_version" && "$current_tag" != "$latest_stable_version" ]] && [[ "$(printf '%s\n' "$latest_stable_version" "$current_tag" | sort -V | tail -n 1)" == "$latest_stable_version" ]]; then
        local summary_message="Update available: ${latest_stable_version}"
        local release_url; release_url=$(get_release_url "$lookup_name")
        if [ -n "$release_url" ]; then summary_message+=", Notes: $release_url"; fi
        print_message "  ${COLOR_BLUE}Update Check:${COLOR_RESET} Update available for '$image_name_no_tag'. Latest stable is ${latest_stable_version} (you have ${current_tag})." "WARNING" >&2
        echo "$summary_message"
        return 100
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
        local cleaned_errors
        if [ -n "$LOG_CLEAN_PATTERN" ]; then
            cleaned_errors=$(echo "$current_errors" | sed -E "s/$LOG_CLEAN_PATTERN//")
        else
            cleaned_errors="$current_errors"
        fi
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
    local container_name="$1"; local log_file_name; log_file_name="${container_name}_logs_$(date '+%Y-%m-%d_%H-%M-%S').log"
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
        local new_full_tag
        new_full_tag=$(echo "$update_details" | sed -n 's/^Update available: \([^,]*\).*/\1/p')
        if [ -n "$new_full_tag" ]; then
             image_to_pull="${image_name_no_tag}:${new_full_tag}"
        else
            local new_version; new_version=$(echo "$update_details" | grep -oE '[v]?[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n 1)
            if [ -n "$new_version" ]; then
                image_to_pull="${image_name_no_tag}:${new_version}"
            fi
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
is_rolling_tag() {
    local image_ref="$1"
    if [[ "$image_ref" != *":"* ]]; then
        return 0
    fi
    if [[ "$image_ref" =~ :(latest|stable|rolling|dev|edge|nightly|main|master)(-.+)?$ ]]; then
        return 0
    else
        return 1
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
    if is_rolling_tag "$current_image_ref" || [[ "$update_details" == *"New build found"* ]]; then
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
    local new_version
    new_version=$(echo "$update_details" | sed -n 's/^Update available: \([^,]*\).*/\1/p')
    if [ -z "$new_version" ]; then
        new_version=$(echo "$update_details" | grep -oE '[v]?[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n 1)
    fi
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
        if [ $? -eq 100 ]; then
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
    if [[ "${RECREATE_MODE}" == "true" ]]; then
        local prune_choice
        read -rp "${COLOR_YELLOW}Update process finished. Would you like to clean up the system now? (y/n) ${COLOR_RESET}" prune_choice
        if [[ "${prune_choice}" =~ ^[yY]$ ]]; then
            print_message "Waiting 5 seconds for Docker daemon to settle before pruning..." "INFO"
            sleep 5
            run_prune
        fi
    fi
    print_message "Interactive update process finished." "INFO"
}
print_summary() {
    local total_containers_checked="$1"
    local container_name_summary issues
    local host_disk_summary_output host_memory_summary_output
    local -A seen_containers
    local unique_containers=()
    for container in "${WARNING_OR_ERROR_CONTAINERS[@]}"; do
        if ! [[ -v seen_containers[$container] ]]; then
            unique_containers+=("$container")
            seen_containers["$container"]=1
        fi
    done
    local issue_container_count=${#unique_containers[@]}
    local healthy_container_count=$((total_containers_checked - issue_container_count))
    PRINT_MESSAGE_FORCE_STDOUT=true
    print_message "-------------------------- Host System Stats ---------------------------" "SUMMARY"
    host_disk_summary_output=$(check_host_disk_usage)
    host_memory_summary_output=$(check_host_memory_usage)
    print_message "$host_disk_summary_output" "SUMMARY"
    print_message "$host_memory_summary_output" "SUMMARY"
    print_message "------------------- Container Health Overview --------------------" "SUMMARY"
    if [ "$total_containers_checked" -gt 0 ]; then
        local health_message="  Checked $total_containers_checked containers: ${COLOR_GREEN}${healthy_container_count} healthy ✅${COLOR_RESET}"
        if [ "$issue_container_count" -gt 0 ]; then
            health_message+=", ${COLOR_YELLOW}${issue_container_count} with issues ⚠️${COLOR_RESET}"
        fi
        print_message "$health_message" "SUMMARY"
    fi
    if [ ${#unique_containers[@]} -gt 0 ]; then
        print_message "------------------- Summary of Container Issues Found --------------------" "SUMMARY"
        print_message "The following containers have warnings or errors:" "SUMMARY"
        for container_name_summary in "${unique_containers[@]}"; do
            local issues="${CONTAINER_ISSUES_MAP["$container_name_summary"]:-Unknown Issue}"
            print_message "- ${container_name_summary} ⚠️" "WARNING"
            IFS='|' read -r -a issue_array <<< "$issues"
            for issue_detail in "${issue_array[@]}"; do
                local issue_prefix="❌"
                local needs_default_print=true
                case "$issue_detail" in
                    Status*)
                        issue_prefix="🛑" ;;
                    Restarts*)
                        issue_prefix="🔥" ;;
                    Logs*)
                        issue_prefix="📜" ;;
                    Update*)
                        issue_prefix="🔄"
                        local main_msg notes_url
                        if [[ "$issue_detail" == *", Notes: "* ]]; then
                            main_msg="${issue_detail%%, Notes: *}"
                            notes_url="${issue_detail#*, Notes: }"
                        else
                            main_msg="$issue_detail"
                            notes_url=""
                        fi
                        print_message "  - ${issue_prefix} ${main_msg}" "WARNING"
                        if [[ -n "$notes_url" ]]; then
                            print_message "    - Notes: ${notes_url}" "WARNING"; fi
                        needs_default_print=false ;;
                    Resources*)
                        issue_prefix="📈" ;;
                    Disk*)
                        issue_prefix="💾" ;;
                    Network*)
                        issue_prefix="📶" ;;
                    *) ;;
                esac
                if [ "$needs_default_print" = true ]; then
                    print_message "  - ${issue_prefix} ${issue_detail}" "WARNING"
                fi
            done
        done
    else
        print_message "------------------- Summary of Container Issues Found --------------------" "SUMMARY"
        if [ "$total_containers_checked" -gt 0 ]; then
            print_message "All $total_containers_checked monitored containers are healthy. No issues found. ✅" "GOOD"
        else
            print_message "No containers were monitored. No issues to report." "GOOD"
        fi
    fi
    if [ -n "$HEALTHCHECKS_JOB_URL" ]; then
        print_message "  Healthcheck Ping: A job status ping was sent." "SUMMARY"
    fi
    print_message "------------------------------------------------------------------------" "SUMMARY"
    PRINT_MESSAGE_FORCE_STDOUT=false
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
run_auto_update_mode() {
    if [ "$AUTO_UPDATE_ENABLED" != "true" ]; then
        print_message "Auto-update is disabled in config.yml." "WARNING"
        return
    fi
    print_message "--- Starting Auto-Update Process ---" "INFO"
    if [ ! -f "$STATE_FILE" ] || ! jq -e . "$STATE_FILE" >/dev/null 2>&1; then
        echo '{"updates": {}, "restarts": {}, "logs": {}}' > "$STATE_FILE"
    fi
    local state_json; state_json=$(cat "$STATE_FILE")
    mapfile -t all_containers < <(docker container ls --format '{{.Names}}' 2>/dev/null)
    local successful_updates=()
    local failed_updates=()
    local updates_performed=0
    for container in "${all_containers[@]}"; do
        local skipped=false
        for pattern in "${AUTO_UPDATE_EXCLUDE[@]}"; do
            if [[ "$container" =~ $pattern ]]; then skipped=true; break; fi
        done
        if [ "$skipped" = true ]; then continue; fi
        if [ ${#AUTO_UPDATE_INCLUDE[@]} -gt 0 ]; then
            local included=false
            for pattern in "${AUTO_UPDATE_INCLUDE[@]}"; do
                if [[ "$container" =~ $pattern ]]; then included=true; break; fi
            done
            if [ "$included" = false ]; then continue; fi
        fi
        local compose_project
        compose_project=$(docker inspect "$container" 2>/dev/null | jq -r '.[0].Config.Labels["com.docker.compose.project"] // empty')
        if [ -z "$compose_project" ]; then
            continue
        fi
        local current_image; current_image=$(docker inspect -f '{{.Config.Image}}' "$container" 2>/dev/null)
        local tag_eligible=false
        if [[ "$current_image" != *":"* ]]; then
             for tag in "${AUTO_UPDATE_TAGS[@]}"; do
                if [[ "$tag" == "latest" ]]; then
                    tag_eligible=true; break
                fi
             done
        else
            for tag in "${AUTO_UPDATE_TAGS[@]}"; do
                if [[ "$current_image" == *":$tag" ]] || [[ "$current_image" == *"$tag"* ]]; then
                    tag_eligible=true; break
                fi
            done
        fi
        if [ "$tag_eligible" = false ]; then continue; fi
        local old_force_flag="$FORCE_UPDATE_CHECK"
        FORCE_UPDATE_CHECK=true
        local update_details
        update_details=$(check_for_updates "$container" "$current_image" "$state_json" 2>&1 | tail -n 1)
        local update_status=$?
        FORCE_UPDATE_CHECK="$old_force_flag"
        if [ $update_status -eq 100 ]; then
            print_message "Auto-updating '$container'..." "INFO"
            process_container_update "$container" "$update_details"
            if [ "$(docker inspect -f '{{.State.Status}}' "$container" 2>/dev/null)" == "running" ]; then
                updates_performed=$((updates_performed + 1))
                successful_updates+=("$container")
                print_message "Update verified: '$container' is running." "GOOD"
            else
                failed_updates+=("$container")
                print_message "Update check failed: '$container' is NOT running." "DANGER"
            fi
        fi
    done
    if [ ${#successful_updates[@]} -gt 0 ] || [ ${#failed_updates[@]} -gt 0 ]; then
        local host_name; host_name=$(hostname)
        local notif_title="🚀 Auto-Update Summary: ${host_name}"
        local notif_msg=""
        if [ ${#successful_updates[@]} -gt 0 ]; then
            notif_msg+="✅ Updated (${#successful_updates[@]}):"
            for c in "${successful_updates[@]}"; do
                notif_msg+=$'\n  - '"$c"
            done
        fi
        if [ ${#failed_updates[@]} -gt 0 ]; then
            if [ -n "$notif_msg" ]; then notif_msg+=$'\n\n'; fi
            notif_msg+="❌ Failed (${#failed_updates[@]}):"
            for c in "${failed_updates[@]}"; do
                notif_msg+=$'\n  - '"$c"
            done
        fi
        send_notification "$notif_msg" "$notif_title"
    fi
    if [ "$updates_performed" -gt 0 ]; then
        print_message "Cleaning up unused images..." "INFO"
        docker image prune -f > /dev/null 2>&1
        print_message "Auto-update complete. $updates_performed containers updated." "GOOD"
    else
        print_message "No auto-updates required." "INFO"
    fi
}

# --- Main Execution ---
main() {
    # --- Argument Parsing ---
    local ORIGINAL_ARGS=("$@")
    declare -a CONTAINER_ARGS=()
    declare -a CONTAINERS_TO_EXCLUDE=()
    local ACTION="monitor" # Default action
    local LOG_TARGET=""
    declare -a LOG_PATTERNS=()
    local run_update_check=true
    local force_update_check=false

    while [ "$#" -gt 0 ]; do
        case "$1" in
            # --- Behavior-modifying flags ---
            --exclude=*)
                local EXCLUDE_STR="${1#*=}"
                IFS=',' read -r -a CONTAINERS_TO_EXCLUDE <<< "$EXCLUDE_STR"
                shift
                ;;
            --force)
                FORCE_UPDATE_CHECK=true
                shift
                ;;
            --force-update)
                force_update_check=true
                shift
                ;;
            --no-update)
                run_update_check=false
                shift
                ;;
            --summary)
                SUMMARY_ONLY_MODE=true
                shift
                ;;
            --auto-update)
                if [[ "$ACTION" != "monitor" ]]; then print_message "Error: Cannot combine actions." "DANGER"; return 1; fi
                ACTION="auto-update"
                shift
                ;;

            # --- Action flags (only one can be used) ---
            --check-setup)
                if [[ "$ACTION" != "monitor" ]]; then print_message "Error: Cannot combine actions." "DANGER"; return 1; fi
                ACTION="check-setup"
                shift
                ;;
            --setup-timer)
                if [[ "$ACTION" != "monitor" ]]; then print_message "Error: Cannot combine actions." "DANGER"; return 1; fi
                ACTION="setup-timer"
                shift
                ;;
            --update|--pull)
                if [[ "$ACTION" != "monitor" ]]; then print_message "Error: Cannot combine actions like --update and --logs." "DANGER"; return 1; fi
                ACTION="interactive-update"
                if [[ "$1" == "--update" ]]; then RECREATE_MODE=true; fi
                INTERACTIVE_UPDATE_MODE=true
                shift
                ;;
            --prune)
                if [[ "$ACTION" != "monitor" ]]; then print_message "Error: Cannot combine actions like --prune and --logs." "DANGER"; return 1; fi
                ACTION="prune"
                shift
                ;;
            --logs)
                if [[ "$ACTION" != "monitor" ]]; then print_message "Error: Cannot combine actions like --logs and --update." "DANGER"; return 1; fi
                ACTION="logs"
                shift
                if [ "$#" -eq 0 ] || [[ "$1" == --* ]]; then
                    print_message "Error: The --logs flag requires a container name." "DANGER"
                    print_message "Example Usage: $0 --logs my-container error" "INFO"
                    return 1
                fi
                LOG_TARGET="$1"
                shift
                while [[ "$#" -gt 0 && ! "$1" =~ ^-- ]]; do
                    LOG_PATTERNS+=("$1")
                    shift
                done
                ;;
            --save-logs)
                 if [[ "$ACTION" != "monitor" ]]; then print_message "Error: Cannot combine actions like --save-logs and --update." "DANGER"; return 1; fi
                 ACTION="save-logs"
                 shift
                 if [[ -z "$1" || "$1" == --* ]]; then print_message "Error: --save-logs requires a container name." "DANGER"; return 1; fi
                 LOG_TARGET="$1"
                 shift
                ;;

            # --- Help and Error Handling ---
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
                # Collect container names for the default 'monitor' action
                CONTAINER_ARGS+=("$1")
                shift
                ;;
        esac
    done

    # --- Initial Setup ---
    # Log Separation
    if [ -f "$LOG_FILE" ] && [ -s "$LOG_FILE" ]; then
        {
            echo ""
            echo "========================================================================"
            echo ""
        } >> "$LOG_FILE" 2>/dev/null || true
    fi

    check_and_install_dependencies "${ORIGINAL_ARGS[@]}"
    load_configuration

    # --- Self-Update Check ---
    if [[ "$force_update_check" == true || ("$run_update_check" == true && -t 1) ]]; then
        if [[ "$SCRIPT_URL" != *"your-username/your-repo"* ]]; then
            local latest_version
            latest_version=$(curl -sL "$SCRIPT_URL" | grep -m 1 "VERSION=" | cut -d'"' -f2)
            if [[ -n "$latest_version" && "$VERSION" != "$latest_version" ]]; then
                self_update "$latest_version"
            fi
        fi
    fi

    # --- Action Execution ---
    case "$ACTION" in
        "check-setup")
            run_setup_check
            ;;
        setup-timer)
            setup_automated_schedule
            return $?
            ;;
        "prune")
            run_prune
            ;;
        "interactive-update")
            run_interactive_update_mode
            ;;
        "logs")
            if [ ${#LOG_PATTERNS[@]} -eq 0 ]; then
                print_message "--- Showing all recent logs for '$LOG_TARGET' ---" "INFO"
                docker logs --tail "$LOG_LINES_TO_CHECK" "$LOG_TARGET"
            else
                local egrep_pattern; egrep_pattern=$(IFS='|'; echo "${LOG_PATTERNS[*]}")
                local filter_list; filter_list=$(printf "'%s' " "${LOG_PATTERNS[@]}")
                print_message "--- Filtering logs for '$LOG_TARGET' with patterns: ${filter_list}---" "INFO"
                docker logs --tail "$LOG_LINES_TO_CHECK" "$LOG_TARGET" 2>&1 | grep -E -i --color=auto "$egrep_pattern"
            fi
            ;;
        "save-logs")
            save_logs "$LOG_TARGET"
            ;;
        "monitor")
            perform_monitoring "${CONTAINER_ARGS[@]}"
            ;;
        "auto-update")
            run_auto_update_mode
            ;;
    esac
}

perform_monitoring() {
    declare -a WARNING_OR_ERROR_CONTAINERS=()
    declare -A CONTAINER_ISSUES_MAP
    declare -a initial_containers=("$@")

    if [ "$SUMMARY_ONLY_MODE" = false ]; then
        if [ -t 1 ] && tput colors &>/dev/null && [ "$(tput colors)" -ge 8 ]; then
            print_header_box
        else
            echo "--- Container Monitor ${VERSION} ---"
        fi
    fi

    declare -a CONTAINERS_TO_CHECK=()
    if [ "${#initial_containers[@]}" -gt 0 ]; then
        CONTAINERS_TO_CHECK=("${initial_containers[@]}")
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

    if [ ${#CONTAINERS_TO_CHECK[@]} -gt 0 ]; then
        local results_dir; results_dir=$(mktemp -d)
        trap 'rm -rf "$results_dir"' EXIT INT TERM
        local progress_pipe="${results_dir}/progress_pipe"
        if [ -f "$LOCK_FILE" ]; then
            local locked_pid; locked_pid=$(cat "$LOCK_FILE")
            if ! ps -p "$locked_pid" > /dev/null; then
                print_message "Removing stale lock file for non-existent PID $locked_pid." "WARNING"
                rm -f "$LOCK_FILE"
            fi
        fi
        local lock_dir; lock_dir="${SCRIPT_DIR}/.monitor.lock"
        local lock_attempts=0
        local max_lock_attempts=10
        while ! mkdir "$lock_dir" 2>/dev/null; do
            if [ "$(find "$lock_dir" -mmin +10 2>/dev/null)" ]; then
                echo "Removing stale lock directory..."
                rmdir "$lock_dir"
            fi
            if [ $lock_attempts -ge $max_lock_attempts ]; then
                print_message "Could not acquire lock after ${max_lock_attempts}s. Check '$lock_dir'." "DANGER"
                rm -rf "$results_dir"
                exit 1
            fi
            sleep 1
            lock_attempts=$((lock_attempts + 1))
        done
        # shellcheck disable=SC2064
        trap "rmdir '$lock_dir'; rm -rf '$results_dir'" EXIT
        if [[ -n "$HEALTHCHECKS_JOB_URL" ]]; then
          send_healthchecks_job_ping "$HEALTHCHECKS_JOB_URL" "start"
        fi
        if [ ! -f "$STATE_FILE" ] || ! jq -e . "$STATE_FILE" >/dev/null 2>&1; then
            print_message "State file is missing or invalid. Creating a new one." "INFO"
            echo '{"updates": {}, "restarts": {}, "logs": {}}' > "$STATE_FILE"
        fi
        local current_state_json; current_state_json=$(cat "$STATE_FILE")
        export -f perform_checks_for_container print_message check_container_status check_container_restarts \
                   check_resource_usage check_disk_space check_network check_for_updates check_logs get_update_strategy
        export COLOR_RESET COLOR_RED COLOR_GREEN COLOR_YELLOW COLOR_CYAN COLOR_BLUE COLOR_MAGENTA \
               LOG_LINES_TO_CHECK CPU_WARNING_THRESHOLD MEMORY_WARNING_THRESHOLD DISK_SPACE_THRESHOLD \
               NETWORK_ERROR_THRESHOLD UPDATE_CHECK_CACHE_HOURS FORCE_UPDATE_CHECK EXCLUDE_UPDATES_LIST_STR SUMMARY_ONLY_MODE
        if [ "$SUMMARY_ONLY_MODE" = false ]; then
            echo "Starting asynchronous checks for ${#CONTAINERS_TO_CHECK[@]} containers..."
            local start_time; start_time=$(date +%s)
            mkfifo "$progress_pipe"
            (
			    local spinner_chars=("|" "/" "-" "\\")
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
                done < "$progress_pipe"
                    echo
            ) &
            local progress_pid=$!
            exec 3> "$progress_pipe"
        else
            exec 3> /dev/null
        fi
        export CURRENT_STATE_JSON_STRING="$current_state_json"
        printf "%s\n" "${CONTAINERS_TO_CHECK[@]}" | xargs -P 8 -I {} bash -c "perform_checks_for_container '{}' '$results_dir'; echo >&3"
        exec 3>&-
        if [ "$SUMMARY_ONLY_MODE" = "false" ]; then
            wait "$progress_pid" 2>/dev/null || true
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

        # Ping Healthchecks.io (if configured)
        if [ -n "$HEALTHCHECKS_JOB_URL" ]; then
            _get_canonical_issue_tag() {
                local tag_string="$1"
                case "${tag_string,,}" in
                    updates*)   echo "Updates" ;;
                    logs*)      echo "Logs" ;;
                    status*)    echo "Status" ;;
                    restarts*)  echo "Restarts" ;;
                    resources*) echo "Resources" ;;
                    disk*)      echo "Disk" ;;
                    network*)   echo "Network" ;;
                    *)          echo "" ;;
                esac
            }
            local job_failed=false
            local body=""
            local job_fail_details=()
            declare -A fail_on=()
            if [[ -n "$HEALTHCHECKS_FAIL_ON" ]]; then
                IFS=',' read -r -a fail_list <<< "$HEALTHCHECKS_FAIL_ON"
                for f in "${fail_list[@]}"; do
                    local canonical_tag
                    canonical_tag=$(_get_canonical_issue_tag "$f")
                    if [[ -n "$canonical_tag" ]]; then
                        fail_on["$canonical_tag"]=1
                    fi
                done
            fi
            if [[ ${#fail_on[@]} -gt 0 && ${#WARNING_OR_ERROR_CONTAINERS[@]} -gt 0 ]]; then
                for container in "${!CONTAINER_ISSUES_MAP[@]}"; do
                    local container_fail_tags=()
                    IFS='|' read -r -a issue_array <<< "${CONTAINER_ISSUES_MAP[$container]}"
                    for it in "${issue_array[@]}"; do
                        local canonical_tag
                        canonical_tag=$(_get_canonical_issue_tag "$it")
                        if [[ -n "$canonical_tag" && -n "${fail_on[$canonical_tag]:-}" ]]; then
                            container_fail_tags+=("$canonical_tag")
                        fi
                    done
                    if [[ ${#container_fail_tags[@]} -gt 0 ]]; then
                        local tags_csv
                        tags_csv=$(IFS=,; echo "${container_fail_tags[*]}")
                        job_fail_details+=("${container}: ${tags_csv}")
                        job_failed=true
                    fi
                done
            fi
            if [ "$job_failed" = true ]; then
                local fail_details
                printf -v fail_details '%s\n' "${job_fail_details[@]}"
                body="Host: $(hostname)
---
${fail_details}"
                print_message "Healthcheck: Attempting job fail ping..." "INFO"
                send_healthchecks_job_ping "$HEALTHCHECKS_JOB_URL" "fail" "$body"
            else
                body="OK (Host: $(hostname))"
                print_message "Healthcheck: Attempting job up ping..." "INFO"
                send_healthchecks_job_ping "$HEALTHCHECKS_JOB_URL" "up" "$body"
            fi
        fi

        print_summary "${#CONTAINERS_TO_CHECK[@]}"
        if [ ${#WARNING_OR_ERROR_CONTAINERS[@]} -gt 0 ]; then
            local summary_message=""
            local notify_issues=false
            IFS=',' read -r -a notify_on_array <<< "$NOTIFY_ON"
            local -A seen_containers_notif
            local unique_containers_notif=()
            for container in "${WARNING_OR_ERROR_CONTAINERS[@]}"; do
                if ! [[ -v seen_containers_notif[$container] ]]; then
                    unique_containers_notif+=("$container")
                    seen_containers_notif["$container"]=1
                fi
            done
            for container in "${unique_containers_notif[@]}"; do
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
                    local formatted_issues_str=""
                    for issue_detail in "${filtered_issues_array[@]}"; do
                        local issue_prefix="❌"
                        case "$issue_detail" in
                            Status*) issue_prefix="🛑" ;;
                            Restarts*) issue_prefix="🔥" ;;
                            Logs*) issue_prefix="📜" ;;
                            Update*) issue_prefix="🔄"
                                local main_msg notes_url
                                if [[ "$issue_detail" == *", Notes: "* ]]; then
                                    main_msg="${issue_detail%%, Notes: *}"
                                    notes_url="${issue_detail#*, Notes: }"
                                else
                                    main_msg="$issue_detail"
                                    notes_url=""
                                fi
                                formatted_issues_str+="\n- ${issue_prefix} ${main_msg}"
                                if [[ -n "$notes_url" ]]; then
                                    formatted_issues_str+="\n  - Notes: ${notes_url}"
                                fi
                                continue ;;
                            Resources*) issue_prefix="📈" ;;
                            Disk*) issue_prefix="💾" ;;
                            Network*) issue_prefix="📶" ;;
                            *) ;;
                        esac
                        formatted_issues_str+="\n- ${issue_prefix} ${issue_detail}"
                    done
                    summary_message+="\n[${container}]${formatted_issues_str}\n"
                fi
            done
            if [ "$notify_issues" = true ]; then
                summary_message=$(echo -e "$summary_message" | sed 's/^[[:space:]]*//')
                if [ -n "$summary_message" ]; then
                    local notification_title; notification_title="🚨 Container Monitor on $(hostname)"
                    send_notification "$summary_message" "$notification_title"
                fi
            fi
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
        if [ -d "$lock_dir" ]; then
            rmdir "$lock_dir"
        fi
        rm -rf "$results_dir"
        trap - EXIT INT TERM
    else
        PRINT_MESSAGE_FORCE_STDOUT=true
        if [ "$SUMMARY_ONLY_MODE" = "true" ]; then
            print_message "Summary generation completed." "SUMMARY"
        elif [ ${#CONTAINERS_TO_CHECK[@]} -eq 0 ]; then
            print_message "No containers specified or found running to monitor." "INFO"
            print_summary "${#CONTAINERS_TO_CHECK[@]}"
        else
            print_message "${COLOR_GREEN}Docker monitoring script completed successfully.${COLOR_RESET}" "INFO"
        fi
    fi
}
main "$@"
