To deploy your `container-monitor.sh` and `config.yml`, across multiple server Ansible playbook can be used if config and containers are same.

### Preparation

Before running the playbook, an `inventory.ini` file is required. This is a simple list of servers.

```ini
[docker_servers]
server1.yourdomain.com
server2.yourdomain.com
192.168.1.50
```

Download the `container-monitor.sh` and `config.yml` files. Update `config.yml`.

---

### The Playbook

This playbook performs the following steps:

1. **Installs System Dependencies**: Ensures `jq`, `wget`, and `curl` are present.
2. **Secures the Directory**: Creates a dedicated folder for the monitor.
3. **Deploys Files**: Copies your script and configuration file.
4. **Sets Permissions**: Ensures the script is executable and the config is private (600).
5. **Automates**: Runs the script's own `--setup-timer` logic to handle the systemd/cron scheduling.

Create a file named `deploy-monitor.yml`:

```yaml
---
- name: Deploy Container Monitor with Advanced Dependency Management
  hosts: docker_servers
  become: yes
  vars:
    monitor_dest: "/usr/local/bin/container-monitor"
    script_src: "./container-monitor.sh"
    config_src: "./config.yml"
    yq_version: "v4.44.1" # Standardizing version across fleet

  tasks:
    - name: Install base system dependencies
      package:
        name: [jq, skopeo, gawk, coreutils, curl, wget]
        state: present
      # This handles both apt (Debian/Ubuntu) and dnf/yum (Fedora/RHEL)

    - name: Check if yq is installed
      command: which yq
      register: yq_check
      ignore_errors: yes
      changed_when: false

    - name: Install yq binary if missing
      block:
        - name: Determine System Architecture
          set_fact:
            yq_arch: "{{ 'amd64' if ansible_architecture == 'x86_64' else 'arm64' }}"

        - name: Download yq binary
          get_url:
            url: "https://github.com/mikefarah/yq/releases/download/{{ yq_version }}/yq_linux_{{ yq_arch }}"
            dest: "/usr/local/bin/yq"
            mode: '0755'
      when: yq_check.rc != 0

    - name: Create monitor directory
      file:
        path: "{{ monitor_dest }}"
        state: directory
        mode: '0755'

    - name: Deploy script and config
      copy:
        src: "{{ item.src }}"
        dest: "{{ monitor_dest }}/{{ item.dest }}"
        mode: "{{ item.mode }}"
      loop:
        - { src: "{{ script_src }}", dest: "container-monitor.sh", mode: "0755" }
        - { src: "{{ config_src }}", dest: "config.yml", mode: "0600" }

    - name: Initialize Monitor Stateful File
      copy:
        content: '{"updates": {}, "restarts": {}, "logs": {}}'
        dest: "{{ monitor_dest }}/.monitor_state.json"
        force: no # Don't overwrite if it already exists
        mode: '0644'
      # Pre-creating this ensures the script has its state file ready

    - name: Schedule Monitoring (Systemd Timer)
      command: "{{ monitor_dest }}/container-monitor.sh --setup-timer"
      args:
        creates: "/etc/systemd/system/container-monitor.timer"
      # Automates the setup-timer wizard logic

    - name: Final Health Check
      command: "{{ monitor_dest }}/container-monitor.sh --summary"
      register: initial_run
      changed_when: false

    - name: Report Results
      debug:
        var: initial_run.stdout_lines
```

---

### Execute

Once Ansible is installed on local machine, run the following command:

```bash
ansible-playbook -i inventory.ini deploy-monitor.yml
```
