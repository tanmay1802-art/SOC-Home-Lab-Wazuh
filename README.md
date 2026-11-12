# AI-Assisted SOC Pipeline on Rocky Linux

## 📌 Overview
A custom, lightweight SOC pipeline on my Rocky Linux lab. It parses Cowrie honeypot and Fail2ban logs, detects brute-force and post-compromise activity, and will use a local LLM (Ollama + RAG playbook) to produce analyst-style incident reports.

All attack traffic is simulated from my own Kali VM against my own lab.

**Why custom instead of Wazuh?** I started a Wazuh SIEM deployment but could not complete it on my 6.6 GB VM (notes in `docs/`). I replaced it with a lightweight pipeline that fits the resources and lets me understand every detection step.

## 📊 Project Status
| Component | Status |
|---|---|
| Rocky Linux lab: BIND9, Apache, Postfix, Fail2ban, WireGuard, Cowrie | ✅ Done |
| Kali attack simulator + Cowrie/Fail2ban log parser | ✅ Done |
| Rule-based detection | ⏳ Planned |
| Local LLM (Ollama) triage + RAG playbook | ⏳ Planned |
| Streamlit dashboard | ⏳ Planned |
| Wazuh SIEM attempt | ❌ Not completed (notes in `docs/`) |

## 🏗️ Architecture
- **Server:** Rocky Linux 9 (192.168.200.4): Cowrie (22 -> 2222), Fail2ban, real SSH on 2200
- **Attacker:** Kali Linux (192.168.200.41), `attack_sim.sh`
- **Pipeline:** logs -> `parser.py` -> detection -> LLM triage -> dashboard

## 📂 Repository
- `ai-soc-pipeline/`: parser, attack simulator, sample logs
- `docs/`: Wazuh attempt and troubleshooting notes
- `screenshots/`: lab screenshots

## 🧠 Challenges & Learnings
- **SELinux and systemd:** Cowrie failed under systemd (`203/EXEC`) because binaries in `/home` carry `user_home_t`. Fixed by moving the install to `/opt/cowrie`.
- **LVM disk resize:** `pvresize` could not find the device. Fixed with `vgimportdevices --all`.
- **Resource limits:** Wazuh's full stack was too heavy for the VM, so I designed a lighter pipeline.

## 🔗 Connect with Me
- [LinkedIn](https://www.linkedin.com/in/tanmay-sarkar-emon-64b46334b)
- [Portfolio](https://tanmaysarkaremon.pages.dev)
