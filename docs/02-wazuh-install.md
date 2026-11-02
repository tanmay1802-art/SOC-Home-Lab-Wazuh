# 02 - Wazuh Installation (Assisted Installer)

Part of my **SOC Home Lab (Wazuh)** project. This note covers preparing the Rocky Linux 9 VM and running the Wazuh assisted installer (`wazuh-install.sh -a`, Wazuh 4.14.9), which installs the indexer, manager and dashboard on one host.

> **Status:** in progress. Pre-install blockers resolved; installer run result is added at the bottom once it finishes.

## Why the assisted installer?

Installing `wazuh-indexer`, `wazuh-manager` and `wazuh-dashboard` one by one with `dnf install` only installs the packages. TLS certificates and configuration files (`config.yml`, `opensearch.yml`, `filebeat.yml`, ...) still have to be created by hand. The assisted installer does all of that automatically.

## Step 1 - Update the system and reboot

```bash
sudo dnf update -y
sudo reboot
uname -r
```

`dnf update` installed a new kernel (`5.14.0-687.61.1`). After the reboot, `uname -r` confirmed the new kernel was running.

## Step 2 - Download and run the installer

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash wazuh-install.sh -a
```

### Challenge 1: typo in the curl flags

I typed `curl s0 ...` instead of `curl -sO ...`. curl treated `s0` as a hostname:

```
curl: (6) Could not resolve host: s0
```

The correct flags are `-s` (silent) and `-O` (capital letter O, save with the remote file name), not the number zero.

### Challenge 2: outdated installer URL

The URL I first used (`https://packages.wazuh.com/4.x/wazuh-install.sh`) returned an XML `AccessDenied` error. The working URL is version-specific (`4.14`), as shown in the official Wazuh quickstart. Lesson: check the vendor's current documentation instead of reusing an old URL.

### Challenge 3: minimum hardware requirements not met

The installer stopped with:

```
ERROR: Your system does not meet the recommended minimum hardware requirements of 4Gb of RAM and 2 CPU cores.
```

The VM was set to 4005 MB in VirtualBox, but `free -m` showed only **3564 MB** total inside Linux (some memory is reserved by the kernel and the virtual hardware), so 4 GB was not enough.

Fix:

1. `sudo poweroff`
2. VirtualBox, Settings, System: Base Memory **6144 MB**, Processors **4**
3. Start the VM and verify:

```bash
free -m    # total 6160 MB
nproc      # 4
```

I did not use the installer's `-i` option, which ignores the requirement check. The indexer needs real memory, and bypassing the check can lead to crashes or a very slow dashboard.

### Challenge 4: port 443 already in use

```
ERROR: Port 443 is being used by another process.
```

The Wazuh dashboard listens on 443. This VM was previously used as a web server (DNS, DHCP, email and web lab), so Apache was already using that port. I found the process with:

```bash
sudo ss -tulpn | grep ':443'
```

Output showed several `httpd` processes listening on `*:443`. I stopped and disabled Apache:

```bash
sudo systemctl stop httpd
sudo systemctl disable httpd
sudo ss -tulpn | grep ':443'    # no output = port is free
```

Trade-off: the old web server no longer starts at boot. To restore it later: `sudo systemctl enable --now httpd` (but it would conflict with the Wazuh dashboard again unless one of them is moved to another port).

### Challenge 5: firewall warning

The installer warned that Firewalld is enabled and the Wazuh ports must be allowed:

| Port | Purpose |
|---|---|
| 443/tcp | Wazuh dashboard (web interface) |
| 1514/tcp | Agent communication |
| 1515/tcp | Agent enrollment |
| 55000/tcp | Wazuh server API |

```bash
sudo firewall-cmd --permanent --add-port=443/tcp
sudo firewall-cmd --permanent --add-port=1514/tcp
sudo firewall-cmd --permanent --add-port=1515/tcp
sudo firewall-cmd --permanent --add-port=55000/tcp
sudo firewall-cmd --reload
```

Each command returned `success`.

### Challenge 6: dashboard installation failed during the installer run

The installer completed the indexer and manager, then failed on the last component:

```
ERROR: Wazuh dashboard installation failed.
```

The installer then rolled everything back automatically (`Installation cleaned`), so no half-installed state was left on the VM.

**Investigation**

The installer log only showed the rollback, so I looked for the real cause step by step:

| Check | Result |
|---|---|
| `df -h` | `/` had 19 GB free (31% used), `/boot` 415 MB free |
| `df -i /` | Inodes 2% used, so no inode exhaustion |
| `sudo dmesg \| tail -30` | No disk I/O, XFS or out-of-memory errors |
| `/var/log/dnf.log` | The visible network errors were from August (an old DNS problem), not from this install |

The log before the failure showed the 286 MB package downloaded and the transaction check passed. It failed at `Error unpacking rpm package wazuh-dashboard-4.14.9-1`, which took about 4.5 minutes. Disk space, inodes, RAM and network were all fine, so the failure was most likely transient.

**Test: install only the dashboard package**

To get a clear error message instead of an installer rollback, I installed the dashboard package on its own, pinned to the same version as the installer:

```bas



### Harmless warning

```
WARNING: The current system does not match the list of recommended systems.
```

This is only a warning (my Rocky Linux version is newer than the installer's list) and does not block the installation.

## Step 3 - Run the installer again

```bash
sudo bash wazuh-install.sh -a
```

*Result: add the summary output here once finished. Do not publish the admin password.*

## Key takeaways

- Read the installer's pre-flight checks. All four blockers (typo, URL, hardware, port) were reported clearly in the output or by the shell.
- Guest RAM is lower than the VirtualBox setting. Always verify with `free -m` inside the VM.
- `ss -tulpn | grep :<port>` is the quick way to find which process owns a port.
- A cloned VM keeps its old services. Check what is already running before installing something new.

## Screenshots

| File | What it shows |
|---|---|
| `screenshots/11-dnf-update-complete.png` | `dnf update` complete, new kernel installed |
| `screenshots/12-curl-typo-and-wrong-url.png` | `curl s0` error and `AccessDenied` from the old URL |
| `screenshots/13-installer-hardware-error.png` | Installer hardware requirement error |
| `screenshots/14-virtualbox-settings-4005mb.png` | VirtualBox settings (4005 MB, 4 CPUs) |
| `screenshots/15-free-m-3564mb.png` | `free -m`: only 3564 MB inside the VM |
| `screenshots/16-free-m-6160mb.png` | `free -m` after increasing to 6144 MB |
| `screenshots/17-port-443-error.png` | Installer error: port 443 in use |
| `screenshots/18-ss-httpd-stop-firewall.png` | `ss` showing `httpd`, stopping it, and opening firewall ports |

## Next

- [ ] Installer finishes, save admin password (not in GitHub)
- [ ] Log in to the dashboard at `https://<VM-IP>`
- [ ] Windows VM: install Sysmon and the Wazuh agent (`03-windows-sysmon-agent.md`)
