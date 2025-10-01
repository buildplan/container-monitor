## Key Features

The script performs several distinct checks for each container:

* **📝 Status & Health:** Verifies if a container is running and checks its built-in Docker health status (e.g., `healthy`, `unhealthy`).
* **📈 Resource Usage:** Checks CPU and Memory usage against configurable warning thresholds.
* **💾 Disk Space:** Checks the disk usage of the container's mounts against a threshold.
* **🌐 Network Health:** Checks for network errors and dropped packets inside the container.
* **🔄 Image Updates:** A sophisticated check using **skopeo** to see if a newer version of the container's image is available in its registry. It supports several strategies (`digest`, `semver`, `major-lock`) for different kinds of image tags.
* **📜 Log Analysis:** Scans recent container logs for specific error patterns (configurable in `config.yml`). It's smart enough to only report *new* errors since the last check.
* **🔥 Restart Monitoring:** Detects if a container has restarted since the last script run.

***

## Configuration Hierarchy

The script uses a clear configuration priority system, which makes it very flexible:

1.  **Environment Variables:** Any configuration parameter set as an environment variable (e.g., `export CPU_WARNING_THRESHOLD=90`) will **always take the highest priority**.
2.  **`config.yml` File:** If an environment variable isn't set, the script reads the value from the `config.yml` file. This is the primary way to configure the script.
3.  **Script Defaults:** If a setting is absent from both environment variables and the config file, a hard-coded default value within the script is used.

***

## Usage & Command-Line Flags

The script has several modes of operation controlled by command-line flags:

* **Default Monitor (`./container-monitor.sh`)**: Runs checks on containers defined in `config.yml` or all running containers if none are defined.
* **Targeted Monitor (`./container-monitor.sh <name>`)**: Runs checks only on the specified container(s).
* **Summary Mode (`--summary`)**: Runs all checks silently and prints only a final summary of issues found.
* **Interactive Update (`--pull` or `--update`)**: This is a major feature. It checks all containers for updates and presents an interactive menu to the user to select which ones to update.
    * `--pull`: Just pulls the new image.
    * `--update`: A guided process that attempts to pull the image and then recreate the container, detecting `docker-compose` setups to do so automatically.
* **Utility Flags**: Includes options for checking dependencies (`--check-setup`), viewing logs (`--logs`), pruning the Docker system (`--prune`), and more.

***

## Architecture and Internal Logic

* **Parallel Processing**: The script runs checks for multiple containers **in parallel** (using `xargs -P 8`) for significant speed improvements. It collects the results from temporary files for the final report.
* **State Management**: It uses `.monitor_state.json` to store the last known state (restart counts, log timestamps/hashes, cached update check results). This makes the monitoring "stateful" and intelligent.
* **Locking**: It uses a `.monitor_state.lock` file to prevent race conditions, ensuring that if two instances of the script are started simultaneously, only one can write to the state file at a time.
* **Self-Contained Dependency Management**: The script can prompt the user to automatically install missing dependencies like `jq`, `skopeo`, and even `yq`, making setup much easier.
* **Self-Updating**: It can check its own source code on GitHub for new versions and perform a secure, checksum-verified self-update.
