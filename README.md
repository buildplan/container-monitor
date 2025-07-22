# Docker Container Monitor

[![Shell Script Linting](https://github.com/buildplan/container-monitor/actions/workflows/lint.yml/badge.svg)](https://github.com/buildplan/container-monitor/actions/workflows/lint.yml)
[![Test Script Execution](https://github.com/buildplan/container-monitor/actions/workflows/test-execution.yml/badge.svg)](https://github.com/buildplan/container-monitor/actions/workflows/test-execution.yml)

A  Bash script to monitor Docker containers. It checks container health, resource usage, and image updates, sending notifications about any issues it finds. The script is designed to be fast, efficient, and easily automated.

-----

### Features

  - **Intelligent Dependency Checking**: Automatically detects missing dependencies and offers to install them on supported systems (Debian, Ubuntu, Fedora, etc.).
  - **Asynchronous Checks**: Uses `xargs` to run checks on multiple containers in parallel for faster execution.
  - **Advanced Update Detection**: Uses `skopeo` to check for new image versions for both `:latest` and version-pinned tags.
  - **Release Note Integration**: Displays a direct link to release notes when an update is available.
  - **Interactive Updates**: A special mode (`--pull` or `--update`) to scan for all available updates and let you choose which new images to pull & recreate.
  - **Comprehensive Health Monitoring**: Checks container status, health checks (`healthy`/`unhealthy`), and restart counts.
  - **Resource & Log Scanning**: Monitors CPU, memory, disk usage, and network errors against configurable thresholds, and scans logs for error keywords.
  - **Self-Updating**: The script can check its source repository and prompt you to update to the latest version.
  - **Flexible Notifications**: Sends alerts to **Discord** or a self-hosted **ntfy** server with the hostname included.
  - **Selective Notifications**: Configure which types of issues (e.g., `Updates`, `Logs`) should trigger a notification.
  - **Stateful Monitoring**: Remembers previous runs to provide intelligent alerts.
       - **Update Caching**: Avoids excessive registry checks by caching update results.
       - **Restart Tracking**: Only alerts on *new* container restarts, not old ones.
  - **Summary Report**: Provides a final summary with host-level stats and a list of containers with issues.

-----

### Prerequisites

The script requires a few common command-line tools.

  - `docker`
  - `jq`
  - `yq`
  - `skopeo`
  - `gawk`
  - `coreutils` (provides `timeout`)
  - `wget`

When you first run the script, it will check for these dependencies. If any are missing, it will offer to automatically install them for you. For complex dependencies like `docker`, it will guide you with instructions.

-----

### Installation

#### 1\. Get the Project Files

Download the main script and the YAML configuration file.

```bash
# Download the main script
wget https://github.com/buildplan/container-monitor/raw/main/container-monitor.sh

# Download the template configuration file
wget https://github.com/buildplan/container-monitor/raw/main/config.yml
```

#### 2\. Verify Script Integrity (Recommended)

To ensure the script is authentic, verify its SHA256 checksum.

```bash
# Download the official checksum file
wget https://github.com/buildplan/container-monitor/raw/main/container-monitor.sh.sha256

# Run the check (it should output: container-monitor.sh: OK)
sha256sum -c container-monitor.sh.sha256
```

#### 3\. Make it Executable

```bash
chmod +x container-monitor.sh
```

#### 4\. Configure the Script

Open `config.yml` with a text editor to set your monitoring defaults, notification channels, and release note URLs.

-----

### Configuration

The script is configured through the `config.yml` file or by setting environment variables. Environment variables will always override settings from the YAML file.

#### The `config.yml` File

This is the central place for all settings. It is structured into sections for clarity.

**Example `config.yml`:**

```yaml
general:
  log_file: "docker-monitor.log"

notifications:
  channel: "discord"
  notify_on: "Updates,Logs,Status"
  discord:
    webhook_url: "https://discord.com/api/webhooks/your_hook_here"
  ntfy:
    server_url: "https://ntfy.sh"
    topic: "your_topic"
    priority: 4
    icon_url: "https://cdn.jsdelivr.net/gh/selfhst/icons/png/docker.png"

containers:
  monitor_defaults:
    - "portainer"
    - "traefik"
  release_urls:
    portainer/portainer-ce: "https://github.com/portainer/portainer/releases"
```

#### Environment Variables

You can override any setting from the YAML file by exporting an environment variable. The variable name is the uppercase version of the YAML path.

| YAML Path | ENV Variable | Default | Description |
|---|---|---|---|
| `.general.log_lines_to_check`|`LOG_LINES_TO_CHECK`| `20` | Number of log lines to scan for errors. |
| `.general.update_check_cache_hours`|`UPDATE_CHECK_CACHE_HOURS`| `6` | How long to cache image update results. |
| `.thresholds.cpu_warning` |`CPU_WARNING_THRESHOLD`| `80` | CPU usage % to trigger a warning. |
| `.thresholds.memory_warning`|`MEMORY_WARNING_THRESHOLD`| `80` | Memory usage % to trigger a warning. |
| `.notifications.channel` |`NOTIFICATION_CHANNEL`| `"none"` | Notification channel: `"discord"`, `"ntfy"`, or `"none"`. |
| `.notifications.notify_on` |`NOTIFY_ON`| All issues | Comma-separated list of issue types to send alerts for. |
| `.auth.docker_username` |`DOCKER_USERNAME`| (empty) | Username for private registries. |
| `.auth.docker_password` |`DOCKER_PASSWORD`| (empty) | Password for private registries. |

**Tip**: To find the names of your running containers, use `docker ps --format '{{.Names}}'`. You can add these names to the `monitor_defaults` list in `config.yml`.

-----

### Usage

The script offers several modes of operation via command-line flags.

#### Running Checks

  - **Run a standard check**: `./container-monitor.sh`
  - **Check specific containers**: `./container-monitor.sh portainer traefik`
  - **Exclude containers**: `./container-monitor.sh --exclude=watchtower,pihole`
  - **Run in Summary-Only Mode**: `./container-monitor.sh summary`

#### Managing Updates

  - **Interactive Pull Mode**: Scans for updates and lets you choose which new images to **pull**. You must recreate the containers manually.
    `./container-monitor.sh --pull`
  - **Interactive Update Mode**: Scans for updates and lets you choose which containers to **pull and recreate** using Docker Compose.
    `./container-monitor.sh --update`
  - **Skip Self-Update**: Runs the script without checking for a new version of itself.
    `./container-monitor.sh --no-update`

#### Other Utilities

  - **System Cleanup**: Interactively run `docker system prune -a` to remove all unused Docker resources.
    `./container-monitor.sh --prune`
  - **View Logs**: View recent logs for a container, with optional keyword filtering.
    `./container-monitor.sh logs portainer error critical`

-----

### Automation (Running as a Service)

For automated execution, using `summary` and `--no-update` is recommended.

#### Option A: systemd Timer Setup (Recommended)

Create `/etc/systemd/system/docker-monitor.service` and `docker-monitor.timer`.

  - **`docker-monitor.service`**:
    ```ini
    [Unit]
    Description=Run Docker Container Monitor Script

    [Service]
    Type=oneshot
    ExecStart=/path/to/your/container-monitor.sh --no-update summary
    ```
  - **`docker-monitor.timer`**:
    ```ini
    [Unit]
    Description=Run Docker Container Monitor every 6 hours

    [Timer]
    OnCalendar=*-*-* 0/6:00:00
    Persistent=true

    [Install]
    WantedBy=timers.target
    ```

Then enable the timer: `sudo systemctl enable --now docker-monitor.timer`

#### Option B: Cron Job Setup

1.  Open your crontab: `crontab -e`
2.  Add the following line to run the script every 6 hours:
    ```crontab
    0 */6 * * * /path/to/your/container-monitor.sh --no-update summary >/dev/null 2>&1
    ```

-----

### Example Summary Output

```
$ ./container-monitor.sh
[INFO] Checking for required command-line tools...
[GOOD] All required dependencies are installed.
╔═══════════════════════════════════════════════════════╗
║                Container Monitor v0.30                ║
║                  Updated: 2025-07-19                  ║
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

### Example update output

```
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

### Logging

All script output, including detailed checks from non-summary runs, is logged to the file specified in `config.yml` (default: `docker-monitor.log`). For long-term use, consider using `logrotate` to manage the log file size.

### State and Caching

To support stateful restart alerts and update caching, the script creates a file named `.monitor_state.json` in the same directory.

  - **Purpose**: This file stores the last known restart count for each container and the cached results of image update checks.
  - **Management**: You should not need to edit this file. If you want to reset the script's memory of all restarts and clear the update cache, you can safely delete this file; it will be recreated on the next run.

### Troubleshooting

  - **Permissions:** If you get "Permission denied," ensure the user running the script can access the Docker socket (e.g., is in the `docker` group).
  - **Logs:** If the script doesn't behave as expected, check the log file for detailed error messages.
  - **Dependencies:** Run the script manually. Its built-in dependency checker will tell you if any required tools like `jq` or `yq` are missing and offer to install them.
