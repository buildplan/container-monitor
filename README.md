# Docker Container Monitor

A comprehensive Bash script to monitor Docker containers. It checks container health, resource usage, and image updates, sending notifications about any issues it finds. The script is designed to be fast, efficient, and easily automated.

### ✨ Features

  - **Asynchronous Checks**: Uses `xargs` to run checks on multiple containers in parallel, making it significantly faster for hosts with many containers.
  - **Interactive Updates**: A special mode to scan for updates and let you choose which new images to pull.
  - **Image Update Checks**: Uses `skopeo` to see if newer versions of your container images are available.
  - **Release Note Integration**: Displays a direct link to release notes when an update is available, making it easy to see what's new.
  - **Container Health**: Checks running status, health checks (`healthy`/`unhealthy`), and restart counts.
  - **Resource Monitoring**: Monitors CPU and Memory usage against configurable thresholds.
  - **Log Scanning**: Scans recent container logs for keywords like `error`, `panic`, and `fatal`.
  - **Self-Updating**: The script can check its source repository and prompt you to update to the latest version.
  - **Flexible Notifications**: Sends alerts for any detected issues to **Discord** or a self-hosted **ntfy** server.
  - **Informative Progress Bar**: Displays a fancy, color-coded progress bar showing the percentage complete, elapsed time, and a spinner during interactive runs.

-----

### ✅ Prerequisites

The script relies on a few common command-line tools:

  - `docker`
  - `jq`
  - `skopeo`
  - `coreutils` (provides `timeout`)
  - `gawk` (provides `awk`)

For **Debian-based systems (e.g., Ubuntu)**, you can install them using:

```bash
sudo apt-get update
sudo apt-get install -y skopeo jq coreutils gawk
```

-----

### 🚀 Installation

#### 1\. Get the Script and Config File

```bash
# Download the main script
wget https://github.com/buildplan/container-monitor/raw/main/container-monitor.sh

# Download the template config file
wget https://github.com/buildplan/container-monitor/raw/main/config.sh
```

#### 2\. Verify Script Integrity (Recommended)

To ensure the script has not been altered, you can verify its SHA256 checksum.

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

#### 4\. Customize `config.sh`

Open `config.sh` with a text editor (`nano config.sh`) to set your monitoring defaults.

#### 5\. (Optional) Add Release Note URLs

To see links to release notes when updates are available, create a file named `release_urls.conf` in the same directory as the script.

**Example `release_urls.conf` content:**

```
# Format: <docker_image_name_without_tag>=<url_to_release_notes>
portainer/portainer-ce=https://github.com/portainer/portainer/releases
linuxserver/heimdall=https://github.com/linuxserver/Heimdall/releases
```

-----

### ⚙️ Configuration

The script is configured by editing `config.sh` or by setting environment variables. Environment variables will always override settings from the config file.

| Environment Variable | `config.sh` Variable | Default | Description |
|---|---|---|---|
| `CONTAINER_NAMES` | `CONTAINER_NAMES_DEFAULT` (array) | (empty) | Comma-separated string of container names to monitor. |
| `LOG_LINES_TO_CHECK` | `LOG_LINES_TO_CHECK_DEFAULT` | `20` | Number of log lines to scan for errors. |
| `CPU_WARNING_THRESHOLD` | `CPU_WARNING_THRESHOLD_DEFAULT` | `80` | CPU usage % to trigger a warning. |
| `MEMORY_WARNING_THRESHOLD`| `MEMORY_WARNING_THRESHOLD_DEFAULT`| `80` | Memory usage % to trigger a warning. |
| `DISK_SPACE_THRESHOLD` | `DISK_SPACE_THRESHOLD_DEFAULT` | `80` | Disk usage % on a container mount to trigger a warning. |
| `NETWORK_ERROR_THRESHOLD`| `NETWORK_ERROR_THRESHOLD_DEFAULT`| `10` | Number of network errors/drops on an interface. |
| `HOST_DISK_CHECK_FILESYSTEM`| `HOST_DISK_CHECK_FILESYSTEM_DEFAULT` | `/` | Host filesystem path to check for the summary. |
| `LOG_FILE` | `LOG_FILE_DEFAULT` | (script dir) | Path to the output log file. |
| `NOTIFICATION_CHANNEL`| `NOTIFICATION_CHANNEL_DEFAULT`| `none` | Notification channel: `"discord"`, `"ntfy"`, or `"none"`. |
| `DISCORD_WEBHOOK_URL`| `DISCORD_WEBHOOK_URL_DEFAULT`| `...` | Your Discord webhook URL. |
| `NTFY_SERVER_URL` | `NTFY_SERVER_URL_DEFAULT` | `https://ntfy.sh`| URL of your ntfy server. |
| `NTFY_TOPIC` | `NTFY_TOPIC_DEFAULT` | `...` | Your ntfy topic. |
| `NTFY_ACCESS_TOKEN` | `NTFY_ACCESS_TOKEN_DEFAULT` | (empty) | Access token for private ntfy topics. |

  - **Note**: You can list Docker container names with `docker ps -a --format '{{.Names}}'`. Then, edit `config.sh` to add the names of the containers you want to monitor by default to the `CONTAINER_NAMES_DEFAULT` array.

-----

### 🏃‍♀️ Usage

#### Running Checks

  - **Run a full check with detailed output:**
    `./container-monitor.sh`

  - **Run a check on specific containers:**
    `./container-monitor.sh traefik crowdsec`

  - **Run a check excluding specific containers:**
    `./container-monitor.sh --exclude=portainer,unifi-controller`

  - **Run in Summary-Only Mode (for automation):**
    `./container-monitor.sh summary`

#### Managing Updates

  - **Interactively update containers:**
    `./container-monitor.sh --interactive-update`

  - **Skip the self-update check:**
    `./container-monitor.sh --no-update`

#### Viewing Logs

  - **Show recent logs for a specific container:**
    `./container-monitor.sh logs traefik`

  - **Show only error-related lines from logs:**
    `./container-monitor.sh logs errors traefik`

  - **Save full logs to a file:**
    `./container-monitor.sh save logs traefik`

-----

### 🤖 Automation (Running as a Service)

The script is designed to be run periodically by a scheduler.

#### Option A: systemd Timer Setup (Recommended)

Create two files in `/etc/systemd/system/`: `docker-monitor.service` and `docker-monitor.timer`.

  - `docker-monitor.service`:

    ```ini
    [Unit]
    Description=Run Docker Container Monitor Script

    [Service]
    Type=oneshot
    ExecStart=/path/to/your/container-monitor.sh --no-update summary
    ```

  - `docker-monitor.timer`:

    ```ini
    [Unit]
    Description=Run Docker Container Monitor every 6 hours

    [Timer]
    OnCalendar=*-*-* 0/6:00:00
    Persistent=true

    [Install]
    WantedBy=timers.target
    ```

Then enable and start the timer:

```bash
sudo systemctl enable --now docker-monitor.timer
```

#### Option B: Cron Job Setup

1.  Open your crontab: `crontab -e`
2.  Add the following line to run the script every 6 hours:
    ```crontab
    0 */6 * * * /path/to/your/container-monitor.sh --no-update summary >/dev/null 2>&1
    ```

-----

### 📊 Example Summary Output

```
[SUMMARY] -------------------------- Host System Stats ---------------------------
[SUMMARY]   Host Disk Usage (/): 34% used (Size: 25G, Used: 7.9G, Available: 16G)
[SUMMARY]   Host Memory Usage: Total: 1967MB, Used: 848MB (43%), Free: 132MB
[SUMMARY] ------------------- Summary of Container Issues Found --------------------
[SUMMARY] The following containers have warnings or errors:
[WARNING] - portainer 🔄 (Issues: Update available: 2.20.1 | Notes: https://github.com/portainer/portainer/releases)
[WARNING] - dozzle 📈 (Issues: Resources)
[WARNING] - beszel-agent 📜 (Issues: Logs)
[SUMMARY] ------------------------------------------------------------------------
```

### 🔧 Troubleshooting

  - **Permissions:** If you get "Permission denied" for Docker commands, ensure the user running the script can access the Docker socket (e.g., is in the `docker` group).
  - **Logs:** If the script doesn't behave as expected, check the `docker-monitor.log` file for detailed error messages.
  - **Dependencies:** Verify that `docker` is running and that `jq`, `skopeo`, `awk`, and `timeout` are installed and in the system's `PATH`.
  - **Container Names:** Double-check that container names in your configuration exactly match the output of `docker ps`.
