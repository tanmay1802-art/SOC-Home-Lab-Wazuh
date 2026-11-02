# 01 - Environment Setup: Expanding the Rocky Linux VM Disk

Part of my **SOC Home Lab (Wazuh)** project. Before installing Wazuh I needed more disk space on my Rocky Linux 9 VM, because the root volume was only 17 GB and Wazuh (indexer + manager + dashboard) needs room for data and logs.

## Lab environment

| Item | Detail |
|---|---|
| Host | Windows 11 with Oracle VirtualBox |
| Guest (SIEM server) | Rocky Linux 9 (hostname `maliserver`) |
| Filesystem | XFS on LVM (`/dev/mapper/rl-root`) |
| Original disk | ~20 GB (root volume 17 GB) |
| Target disk | 30 GB |

## Goal

Grow the VM disk from ~20 GB to 30 GB, and extend the root filesystem so Wazuh has enough space.

## Summary of steps

1. Resize the virtual disk (`.vdi`) on the Windows host with `VBoxManage`.
2. Inside Rocky Linux: grow the partition (`growpart`).
3. Tell LVM about the new space (`pvresize`).
4. Extend the logical volume (`lvextend`).
5. Grow the XFS filesystem (`xfs_growfs`).

---

## Step 1 - Resize the virtual disk (Windows host)

The VM must be powered off. From Command Prompt:

```cmd
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" modifyhd "C:\Users\user\VirtualBox VMs\<VM folder>\<disk>.vdi" --resize 30000
```

`30000` is the new size in MB (about 30 GB). Output ends with `100%` when it succeeds.

> **Challenge: `VERR_FILE_NOT_FOUND`**
> The command failed with `Could not find file for the medium`. The path looked correct, so I listed the folder with `dir "<VM folder>"` and found the real file name had a spelling difference from what I typed (`Rockey` vs `Rocky`). Lesson: when a path with spaces and brackets fails, run `dir` on the folder and copy the exact file name instead of retyping it.

## Step 2 - Check the disk layout (inside the VM)

```bash
lsblk
```

Result: `sda` was 29.3 GB, but `sda2` (the LVM partition) was still 19 GB and `rl-root` 17 GB. So VirtualBox had grown the disk, but the partition and LVM had not grown yet.

> **Challenge: `growpart: command not found`**
> Fixed by installing the package:
> ```bash
> sudo dnf install cloud-utils-growpart -y
> ```

> **Challenge: `growpart /dev/mapper/rl-root 1` failed**
> Error: `does not contain a recognized partition table`. `growpart` works on a **disk partition**, not on an LVM logical volume. The correct target is the partition that holds LVM:
> ```bash
> sudo growpart /dev/sda 2
> ```
> Output `CHANGED: partition=2 ...` confirmed `sda2` was extended.

## Step 3 - Resize the LVM physical volume

```bash
sudo pvresize /dev/sda2
```

> **Challenge: `Cannot use /dev/sda2: device is not in devices file`**
> Rocky Linux 9 uses an LVM *devices file* that lists which devices LVM is allowed to use. After the partition changed, `sda2` was no longer matched in that file, so `pvresize` refused to touch it. `lvmdevices --update` did not fix it.
>
> Fix: add the device back to the devices file.
> ```bash
> <PASTE THE EXACT COMMAND YOU USED HERE, e.g. sudo vgimportdevices --all>
> ```
> Then `pvresize` worked: `Physical volume "/dev/sda2" changed`.

## Step 4 - Extend the logical volume

```bash
sudo lvextend -l +100%FREE /dev/mapper/rl-root
```

> **Challenge: `invalid option -- '1'`**
> I typed `-1` (the number one) instead of `-l` (lowercase L). Small typo, easy to miss in a terminal font.

## Step 5 - Grow the XFS filesystem

```bash
sudo xfs_growfs /
```

Output showed `data blocks changed from 4455424 to 6892544`.

## Verification

```bash
df -h
```

| | Before | After |
|---|---|---|
| `/dev/mapper/rl-root` size | 17 GB | **27 GB** |
| Available | 9.7 GB | **19 GB** |

The root volume now has enough space for the Wazuh installation.

---

## Wazuh repository preparation

Imported the Wazuh GPG key and created the repo file:

```bash
sudo rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH

sudo tee /etc/yum.repos.d/wazuh.repo << 'EOF'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF

sudo dnf update -y
```

The `EL-9 - Wazuh` repository metadata downloaded successfully, which confirms the repo works.

## Key takeaways

- A virtual disk resize happens in **layers**: hypervisor disk, then partition, then LVM physical volume, then logical volume, then filesystem. Each layer needs its own command.
- `growpart` targets a partition (`/dev/sda 2`), not a logical volume.
- On Rocky Linux 9, LVM's devices file can block `pvresize` until the device is re-added.
- Read error messages carefully. Two of my three blockers were simple typos.

## Screenshots

| File | What it shows |
|---|---|
| `screenshots/01a-vboxmanage-typo-path.png` | The command with the wrong file name |
| `screenshots/01-vboxmanage-dir-resize.png` | `dir` output and successful `modifyhd --resize` |
| `screenshots/07-growpart-not-found.png` | `growpart: command not found` |
| `screenshots/08-growpart-wrong-target.png` | `growpart` failing on the LVM volume |
| `screenshots/02-lsblk-before.png` | `sda` 29.3 GB, `sda2` still 19 GB |
| `screenshots/03-growpart-pvresize-error.png` | `growpart /dev/sda 2` success, `pvresize` error, `lvextend` typo |
| `screenshots/09-pvresize-devices-file-error.png` | `Cannot use /dev/sda2: device is not in devices file` |
| `screenshots/10-lvmdevices-update.png` | `lvmdevices --update` did not fix it |
| `screenshots/04-pvresize-success.png` | `pvresize` working after the devices file fix |
| `screenshots/05-df-h-after.png` | Root volume grown to 27 GB |
| `screenshots/06-wazuh-repo.png` | Repo file created and `dnf update` fetching Wazuh metadata |
| `screenshots/11-dnf-update-complete.png` | `dnf update` complete, new kernel installed |

## Next

- [x] Prepare for the Wazuh installation (`02-wazuh-install.md`)
- [ ] Install Sysmon + Wazuh agent on the Windows VM
- [ ] Brute-force detection rule (Event ID 4625)
