# Docker Container Monitor

[![Shell Script Linting](https://github.com/buildplan/container-monitor/actions/workflows/lint.yml/badge.svg)](https://github.com/buildplan/container-monitor/actions/workflows/lint.yml)
[![Test Script Execution](https://github.com/buildplan/container-monitor/actions/workflows/test-execution.yml/badge.svg)](https://github.com/buildplan/container-monitor/actions/workflows/test-execution.yml)

A comprehensive Bash script to monitor Docker containers. It checks container health, resource usage, and image updates, sending notifications about any issues it finds. The script is designed to be fast, efficient, and easily automated.

### Features

  - **Intelligent Dependency Checking**: Automatically detects missing dependencies and offers to install them on supported systems (Debian, Ubuntu, Fedora, etc.).
  - **Asynchronous Checks**: Uses `xargs` to run checks on multiple containers in parallel for faster execution.
  - **Advanced Update Detection**: Uses `skopeo` to check for new image versions for both `:latest` and version-pinned tags.
  - **Release Note Integration**: Displays a direct link to release notes when an update is available.
  - **Interactive Updates**: A special mode (`--interactive-update`) to scan for all available updates and let you choose which new images to pull.
  - **Comprehensive Health Monitoring**: Checks container status, health checks (`healthy`/`unhealthy`), and restart counts.
  - **Resource & Log Scanning**: Monitors CPU, memory, disk usage, and network errors against configurable thresholds, and scans logs for error keywords.
  - **Self-Updating**: The script can check its source repository and prompt you to update to the latest version.
  - **Flexible Notifications**: Sends alerts to **Discord** or a self-hosted **ntfy** server with the hostname included.
  - **Polished Interface**: Displays an informative header box and a progress bar during manual runs.
  - **Summary Report**: Provides a final summary with host-level stats and a list of containers with issues.

-----

### Prerequisites

The script requires a few common command-line tools. However, it includes a smart setup process to help you install them.

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

Download the main script and the new, simplified YAML configuration file.

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
  discord:
    webhook_url: "https://discord.com/api/webhooks/your_hook_here"

containers:
  monitor_defaults:
    - "portainer"
    - "traefik"
  release_urls:
    portainer/portainer-ce: "https://github.com/portainer/portainer/releases"
```

#### Environment Variables

You can override any setting from the YAML file by exporting an environment variable. The variable name is the uppercase version of the YAML path.

| Environment Variable | YAML Path | Default |
|---|---|---|
| `LOG_LINES_TO_CHECK` | `.general.log_lines_to_check` | `40` |
| `CPU_WARNING_THRESHOLD` | `.thresholds.cpu_warning` | `80` |
| `NOTIFICATION_CHANNEL` | `.notifications.channel` | `none`|
| `DISCORD_WEBHOOK_URL`| `.notifications.discord.webhook_url`| `...` |
| `CONTAINER_NAMES` | n/a | (empty) | Comma-separated string of containers to monitor (overrides `monitor_defaults`). |

> **Note**: You can list Docker container names with `docker ps -a --format '{{.Names}}'`. Then, edit `config.yml` to add the names of the containers you want to monitor by default to 'monitor_defaults:`.

-----

### Usage

#### Running Checks

  - **Run a standard check:**
    `./container-monitor.sh`
  - **Run a check on specific containers:**
    `./container-monitor.sh portainer traefik`
  - **Run a check excluding containers:**
    `./container-monitor.sh --exclude=watchtower`
  - **Run in Summary-Only Mode (for automation):**
    `./container-monitor.sh summary`

#### Managing Updates

  - **Interactively update containers:**
    `./container-monitor.sh --interactive-update`
  - **Skip the self-update check:**
    `./container-monitor.sh --no-update`

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
[SUMMARY] -------------------------- Host System Stats ---------------------------
[SUMMARY]   Host Disk Usage (/): 34% used (Size: 25G, Used: 7.9G, Available: 16G)
[SUMMARY]   Host Memory Usage: Total: 1967MB, Used: 848MB (43%), Free: 132MB
[SUMMARY] ------------------- Summary of Container Issues Found --------------------
[SUMMARY] The following containers have warnings or errors:
[WARNING] - portainer 🔄 (Issues: Update available: 2.20.1, Notes: https://github.com/portainer/portainer/releases)
[WARNING] - dozzle 📈 (Issues: Resources)
[WARNING] - beszel-agent 📜 (Issues: Logs)
[SUMMARY] ------------------------------------------------------------------------
```

### Logging

All script output, including detailed checks from non-summary runs, is logged to the file specified in `config.yml` (default: `docker-monitor.log`). For long-term use, consider using `logrotate` to manage the log file size.

### Troubleshooting

  - **Permissions:** If you get "Permission denied," ensure the user running the script can access the Docker socket (e.g., is in the `docker` group).
  - **Logs:** If the script doesn't behave as expected, check the log file for detailed error messages.
  - **Dependencies:** Run the script manually. Its built-in dependency checker will tell you if any required tools like `jq` or `yq` are missing and offer to install them.
