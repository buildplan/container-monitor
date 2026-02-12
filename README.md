# Docker Container Monitor

[![Shell Script Linting](https://github.com/buildplan/container-monitor/actions/workflows/lint.yml/badge.svg)](https://github.com/buildplan/container-monitor/actions/workflows/lint.yml)
[![Test Script Execution](https://github.com/buildplan/container-monitor/actions/workflows/test-execution.yml/badge.svg)](https://github.com/buildplan/container-monitor/actions/workflows/test-execution.yml)

A Bash script to monitor Docker containers. It checks container health, resource usage, and image updates, sending notifications about any issues it finds. The script is designed to be fast, efficient, and easily automated.

-----

## Features

- **Intelligent Dependency Checking**: Automatically detects missing dependencies and offers to install them on supported systems (Debian, Ubuntu, Fedora, etc.).
- **Asynchronous Checks**: Uses `xargs` to run checks on multiple containers in parallel for faster execution.
- **Advanced Update Detection**: Uses `skopeo` to check for new image versions for both `:latest` and version-pinned tags.
- **Release Note Integration**: Displays a direct link to release notes when an update is available.
- **Interactive Updates**: A special mode (`--pull` or `--update`) to scan for all available updates and let you choose which new images to pull & recreate.
- **Auto-Updates**: Optionally automate updates for containers using floating tags (like `:latest`). It strictly targets **Docker Compose** containers to ensure configuration is preserved, includes configurable include/exclude lists, and automatically cleans up old images after a successful update.
- **Comprehensive Health Monitoring**: Checks container status, health checks (`healthy`/`unhealthy`), and restart counts.
- **Resource & Log Scanning**: Monitors CPU, memory, disk usage, and network errors against configurable thresholds, and scans logs for error keywords.
- **Self-Updating**: The script can check its source repository and prompt you to update to the latest version.
- **Flexible Notifications**: Sends alerts to **Discord** or a self-hosted **ntfy** server with the hostname included.
- **Selective Notifications**: Configure which types of issues (e.g., `Updates`, `Logs`) should trigger a notification.
- **Stateful Monitoring**: Remembers previous runs to provide intelligent alerts.
  - **Update Caching**: Avoids excessive registry checks by caching update results.
  - **Restart Tracking**: Only alerts on *new* container restarts, not old ones.
- **Summary Report**: Provides a final summary with host-level stats and a list of containers with issues.
- **Automated Scheduling**: Built-in setup wizard to install monitoring as a **systemd timer** or **cron job** with configurable frequency.
- **Job Monitoring (Healthchecks.io):** Pings a monitoring URL at the start and end of each run (`/start`, `/fail`). It can be configured to only send a failure ping for *serious* issues (e.g., `Status`, `Restarts`) while ignoring minor ones (e.g., `Updates`).

-----

## Prerequisites

The script requires a few common command-line tools.

- `docker`
- `jq`
- `yq`
- `skopeo`
- `gawk`
- `coreutils` (provides `timeout`)
- `curl`

When you first run the script, it will check for these dependencies. If any are missing, it will offer to automatically install them for you. For complex dependencies like `docker`, it will guide you with instructions.

-----

## Installation

### 1. Get the Project Files

Download the main script and the YAML configuration file.

```bash
# Download the main script
curl -LO https://raw.githubusercontent.com/buildplan/container-monitor/refs/heads/main/container-monitor.sh

# Download the template configuration file
curl -LO https://raw.githubusercontent.com/buildplan/container-monitor/refs/heads/main/config.yml
```

### 2. Verify Script Integrity (Recommended)

To ensure the script is authentic, verify its SHA256 checksum.

```bash
# Download the official checksum file
curl -LO https://raw.githubusercontent.com/buildplan/container-monitor/refs/heads/main/container-monitor.sh.sha256

# Run the check (it should output: container-monitor.sh: OK)
sha256sum -c container-monitor.sh.sha256
```

### 3. Make it Executable

```bash
chmod +x container-monitor.sh
```

### 4. Configure the Script

Open `config.yml` with a text editor to set your monitoring defaults, notification channels, and release note URLs.

-----

## Configuration

The script is configured through the `config.yml` file or by setting environment variables. Environment variables will always override settings from the YAML file.

### The `config.yml` File

This is the central place for all settings. It is structured into sections for clarity.

**Example `config.yml`:**

```yaml
# General script settings
general:
  log_lines_to_check: 40
  log_file: "container-monitor.log"
  update_check_cache_hours: 6
  lock_timeout_seconds: 30
  healthchecks_job_url: "" # e.g., "https://hc.mydomain.com/ping/YOUR-KEY-HERE"
  healthchecks_fail_on: "" # Comma-separated list of issues to fail on:

# Custom patterns for the log checker
logs:
  error_patterns:
    - "Exception"
    - "SEVERE"
    - "Traceback"

# Credentials for private registries (safer as ENV vars)
auth:
  docker_username: ""
  docker_password: ""

# Thresholds for resource warnings
thresholds:
  cpu_warning: 80
  memory_warning: 80
  disk_space: 80
  network_error: 10

# Notifications settings
notifications:
  channel: "none" # Set to "discord", "ntfy", "generic", or "none"
  notify_on: "Updates,Logs,Restarts,Status" # Comma-separated list of issues to alert on
  discord:
    webhook_url: ""
  generic:
    webhook_url: ""
  ntfy:
    server_url: "https://ntfy.sh"
    topic: "your_topic"
    access_token: ""
    priority: 3

# Container-specific settings
containers:
  # Add the names of containers to monitor by default
  monitor_defaults:
    - "dozzle-agent"
    - "beszel-agent"
    - "postgres"

  # URLs for release notes, used for update checks
  release_urls:
    amir20/dozzle: "https://github.com/amir20/dozzle/releases"
    henrygd/beszel: "https://github.com/henrygd/beszel/releases"
    postgres: "https://www.postgresql.org/docs/release/"

  # (Optional)
  # If a container isn't listed here, it uses the 'default' strategy.
  update_strategies:
    postgres: "digest"
    grafana/grafana: "semver"
    # some-specific-app: "major-lock"

  # Exclude specific containers from the update check
  exclude:
    updates:
      - my-local-app-1
      - my-backend-api

auto_update:
  # set this to true and add a separate cronjob for auto-updates
  enabled: false
  tags: ["latest", "stable", "main"]
  include: ["beszel-agent", "dozzle-agent"]
  exclude: ["postgres"]
```

### Environment Variables

You can override any setting from the YAML file by exporting an environment variable. The variable name is the uppercase version of the YAML path.

### General & Logging

| YAML Path | ENV Variable | Default | Description |
| :--- | :---: | :---: | :--- |
| `general.log_lines_to_check` | `LOG_LINES_TO_CHECK` | `20` | Number of recent log lines to scan for errors. |
| `general.log_file` | `LOG_FILE` | `container-monitor.log` | Path to the script's output log file. |
| `general.update_check_cache_hours` | `UPDATE_CHECK_CACHE_HOURS` | `6` | How long to cache image update results. |
| `general.lock_timeout_seconds` | `LOCK_TIMEOUT_SECONDS` | `10` | Seconds to wait for a lock file before exiting. |
| `logs.log_clean_pattern` | `LOG_CLEAN_PATTERN` | `^[^ ]+[[:space:]]+` | Regex to strip variable data from logs before hashing. |
| `general.healthchecks_job_url` | `HEALTHCHECKS_JOB_URL` | `(empty)` | The full URL for a Healthchecks.io job (e.g., `https://hc-ping.com/UUID-HERE`). |
| `general.healthchecks_fail_on` | `HEALTHCHECKS_FAIL_ON` | `(empty)` | Comma-separated list of issues to trigger a `/fail` ping (e.g., `Status,Restarts`). If empty, pings success even if issues are found. |

### Thresholds & Monitoring

| YAML Path | ENV Variable | Default | Description |
| :--- | :---: | :---: | :--- |
| `thresholds.cpu_warning` | `CPU_WARNING_THRESHOLD` | `80` | CPU usage % that triggers a warning. |
| `thresholds.memory_warning` | `MEMORY_WARNING_THRESHOLD` | `80` | Memory usage % that triggers a warning. |
| `thresholds.disk_space` | `DISK_SPACE_THRESHOLD` | `80` | Disk usage % for a container mount that triggers a warning. |
| `thresholds.network_error` | `NETWORK_ERROR_THRESHOLD` | `10` | Network error/drop count that triggers a warning. |
| `host_system.disk_check_filesystem` | `HOST_DISK_CHECK_FILESYSTEM` | `/` | The host filesystem to monitor for disk space. |
| N/A | `CONTAINER_NAMES` | `(empty)` | Comma-separated list of containers to monitor. |

### Notifications

| YAML Path | ENV Variable | Default | Description |
| :--- | :---: | :---: | :--- |
| `notifications.channel` | `NOTIFICATION_CHANNEL` | `none` | Notification channel: `discord`, `ntfy`, or `none`. |
| `notifications.notify_on` | `NOTIFY_ON` | All issues | Comma-separated list of issue types to send alerts for. |
| `notifications.discord.webhook_url` | `DISCORD_WEBHOOK_URL` | `(empty)` | The webhook URL for Discord notifications. |
| `notifications.ntfy.server_url` | `NTFY_SERVER_URL` | `https://ntfy.sh` | The server URL for ntfy notifications. |
| `notifications.ntfy.topic` | `NTFY_TOPIC` | `(empty)` | The topic to publish ntfy notifications to. |

### Authentication

| YAML Path | ENV Variable | Default | Description |
| :--- | :---: | :---: | :--- |
| `auth.docker_username` | `DOCKER_USERNAME` | `(empty)` | Username for a private Docker registry. |
| `auth.docker_password` | `DOCKER_PASSWORD` | `(empty)` | Password for a private Docker registry. |
| `auth.docker_config_path` | `DOCKER_CONFIG_PATH` | `~/.docker/config.json` | Path to Docker's `config.json` file for authentication. |

**Tip**: To find the names of your running containers, use `docker ps --format '{{.Names}}'`. You can add these names to the `monitor_defaults` list in `config.yml`.

-----

## Usage

The script offers several modes of operation via command-line flags.

### Running Checks

- **Run a standard check**: `./container-monitor.sh`
- **Check specific containers**: `./container-monitor.sh portainer traefik`
- **Exclude containers**: `./container-monitor.sh --exclude=watchtower,pihole`
- **Run in Summary-Only Mode**: `./container-monitor.sh --summary`

### Managing Updates

- **Interactive Pull Mode**: Scans for updates and lets you choose which new images to **pull**. You must recreate the containers manually.
  `./container-monitor.sh --pull`
- **Interactive Update Mode**: Scans for updates and lets you choose which containers to **pull and recreate** using Docker Compose.
  `./container-monitor.sh --update`
- **Auto-Update Mode**: Automatically pulls and recreates containers that match your auto-update configuration (floating tags only).
  `./container-monitor.sh --auto-update`
- **Skip Self-Update**: Runs the script without checking for a new version of itself.
  `./container-monitor.sh --no-update`

### Other Utilities

- **System Cleanup**: Interactively run `docker system prune -a` to remove all unused Docker resources.
  `./container-monitor.sh --prune`
- **View Logs**: View recent logs for a container, with optional keyword filtering.
  `./container-monitor.sh --logs portainer error critical`

-----

## Auto-Update Setup

The auto-update feature is designed to run independently from the monitoring checks. You can schedule it to run at off-peak hours (e.g., 3 AM).

### 1. Configure `config.yml`

Enable the feature and define your safety rules:

```yaml
auto_update:
  enabled: true
  # Only update containers with these tags
  tags: ["latest", "stable", "main"]
  # Exclude critical services
  exclude:
    - "postgres"
    - "mongo"
```

### 2. Schedule the Job

Add a separate cron job or timer to run the update command.

**Example Cron (Daily at 3 AM):**

```bash
0 3 * * * /path/to/container-monitor.sh --auto-update >> /var/log/container-monitor-updates.log 2>&1
```

-----

## Automation (Running as a Service)

### Automatic Setup with `--setup-timer`

The easiest way to automate container monitoring is using the built-in setup wizard:

```bash
./container-monitor.sh --setup-timer
```

This interactive command will guide you through:

1. **Choose your scheduler:**
   - **systemd timer** (modern, recommended for systemd-based systems)
   - **cron** (traditional, works everywhere)

2. **Select monitoring frequency:**
   - Every 6 or 12 hours
   - Once a day (at midnight)
   - Twice a day (6 AM & 6 PM)
   - Every 4 hours (systemd only)
   - Custom schedule (define the timing)

3. **For systemd timers:**
   - Choose between **system-wide** (runs for all users with sudo) or **user** (runs only for your user, no sudo needed)
   - The wizard automatically creates and enables the timer

4. **For cron jobs:**
   - The wizard adds the job to your crontab
   - Detects and offers to replace existing jobs

**Example:**

```bash
\$ ./container-monitor.sh --setup-timer
--- Container Monitor Automation Setup ---
Script location: /home/user/container-monitor.sh

Select scheduler type:

1) cron (traditional, simple)
2) systemd timer (modern, recommended for systemd-based systems)

Enter your choice (1 or 2): 2

Install as:

1) System service (requires root/sudo, runs for all users)
2) User service (runs only for current user, no sudo required)

Enter your choice (1 or 2): 2

Select monitoring frequency:

1) Every 6 hours
2) Every 12 hours
3) Once a day (at midnight)
4) Twice a day (at 6 AM and 6 PM)
5) Every 4 hours
6) Custom interval

Enter your choice (1-6): 1
...
Systemd timer installed and started successfully!
```

### Manual Setup Option A: systemd Timer

To set up manually, create `/etc/systemd/system/container-monitor.service` and `container-monitor.timer`.

- **`container-monitor.service`**:
  
  ```ini
  [Unit]
  Description=Run Docker Container Monitor Script

  [Service]
  Type=oneshot
  ExecStart=/path/to/your/container-monitor.sh --no-update --summary
  ```

- **`container-monitor.timer`**:

  ```ini
  [Unit]
  Description=Run Docker Container Monitor every 6 hours

  [Timer]
  OnCalendar=*-*-* 0/6:00:00
  Persistent=true

  [Install]
  WantedBy=timers.target
  ```

Then enable the timer: `sudo systemctl enable --now container-monitor.timer`

### Manual Setup Option B: Cron Job

1. Open your crontab: `crontab -e`
2. Add the following line to run the script every 6 hours:

  ```bash
  0 */6 * * * /path/to/your/container-monitor.sh --no-update --summary > /dev/null 2>&1
  ```

-----

## Example Summary Output

```bash
$ ./container-monitor.sh
[INFO] Checking for required command-line tools...
[GOOD] All required dependencies are installed.
╔═══════════════════════════════════════════════════════╗
║                Container Monitor v0.XX                ║
║                  Updated: 2025-XX-XX                  ║
╚═══════════════════════════════════════════════════════╝

Starting asynchronous checks for 5 containers...
Progress: [████████████████████████████████████████] 100% (5/5) | Elapsed: 00:15 [/]

...

[SUMMARY] -------------------------- Host System Stats ---------------------------
[SUMMARY]   Host Disk Usage (/): 9% used (Size: 120G, Used: 10G, Available: 110G)
[SUMMARY]   Host Memory Usage: Total: 7906MB, Used: 1749MB (22%), Free: 5023MB
[SUMMARY] ------------------- Summary of Container Issues Found --------------------
[SUMMARY] The following containers have warnings or errors:
[WARNING] - beszel-agent 📜 (Issues: Logs)
[WARNING] - dozzle-agent 🔄 (Issues: Update available for 'latest' tag, Notes: https://github.com/amir20/dozzle/releases)
[SUMMARY] ------------------------------------------------------------------------
```

### Example Update Output

```bash
[INFO] Starting interactive update check...
Checking 5 containers for available updates...
[GOOD]   Update Check: Image 'traefik:v3.4.4' is up-to-date.
[WARNING]   Update Check: New 'latest' image available for 'amir20/dozzle:latest'.
[GOOD]   Update Check: Image 'crowdsecurity/crowdsec:latest' is up-to-date.
[GOOD]   Update Check: Image 'ghcr.io/moghtech/komodo-periphery:latest' is up-to-date.
[GOOD]   Update Check: Image 'henrygd/beszel-agent' is up-to-date.
[INFO] The following containers have updates available:
  [1] dozzle-agent (Update available for 'latest' tag, Notes: https://github.com/amir20/dozzle/releases)

Enter the number(s) of the containers to update (e.g., '1' or '1,3'), or 'all', or press Enter to cancel: 1
[INFO] Starting full update for 'dozzle-agent'...
[INFO] Running 'docker compose pull' in '/home/alis/appdata/dozzle-agent'...
[+] Pulling 5/5
 ✔ dozzle-agent Pulled                                                                                                      3.1s 
   ✔ d1031bc74aea Already exists                                                                                            0.0s 
   ✔ b1453502e061 Already exists                                                                                            0.0s 
   ✔ 4be4f422404f Pull complete                                                                                             0.7s 
   ✔ b1ae23dd5d38 Pull complete                                                                                             1.3s 
[INFO] Running 'docker compose up -d --force-recreate'...
[+] Running 1/1
 ✔ Container dozzle-agent  Started                                                                                          1.4s 
[GOOD] Container 'dozzle-agent' successfully updated and recreated. ✅
```

### Example Auto-Update Output

```bash
$ ./container-monitor.sh --auto-update
[INFO] --- Starting Auto-Update Process ---
[INFO] Auto-updating 'dozzle-agent'...
[INFO] Starting guided update for 'dozzle-agent'...
[INFO] Image uses a rolling tag. Proceeding with standard pull and recreate.
[+] Pulling 5/5
 ✔ dozzle-agent Pulled                               4.2s 
[+] Running 1/1
 ✔ Container dozzle-agent  Started                   1.1s 
[GOOD] Update verified: 'dozzle-agent' is running.
[INFO] Cleaning up unused images...
[GOOD] Auto-update complete. 1 containers updated.
```

## Logging

All script output, including detailed checks from non-summary runs, is logged to the file specified in `config.yml` (default: `container-monitor.log`). For long-term use, consider using `logrotate` to manage the log file size.

## State and Caching

To support stateful restart alerts and update caching, the script creates a file named `.monitor_state.json` in the same directory.

- **Purpose**: This file stores the last known restart count for each container and the cached results of image update checks.
- **Management**: You should not need to edit this file. If you want to reset the script's memory of all restarts and clear the update cache, you can safely delete this file; it will be recreated on the next run.

## Troubleshooting

- **Permissions:** If you get "Permission denied," ensure the user running the script can access the Docker socket (e.g., is in the `docker` group).
- **Logs:** If the script doesn't behave as expected, check the log file for detailed error messages.
- **Dependencies:** Run the script manually. Its built-in dependency checker will tell you if any required tools like `jq` or `yq` are missing and offer to install them.
