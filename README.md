# SOC Home Lab: Wazuh SIEM & Sysmon Integration

## 📌 Overview
This project documents the deployment of a Security Information and Event Management (SIEM) home lab using **Wazuh** on **Rocky Linux 9**. The goal is to simulate a real-world Security Operations Center (SOC) environment by ingesting logs from both Linux and Windows endpoints, detecting suspicious activity, and visualizing alerts on a centralized dashboard.

## 🏗️ Architecture
- **SIEM Server:** Rocky Linux 9 (Wazuh Manager, Indexer, Dashboard)
- **Endpoint 1:** Linux (Ubuntu Client) - Forwarding `auth.log` and Cowrie Honeypot logs.
- **Endpoint 2:** Windows 10/11 - Forwarding Windows Event Logs and Sysmon data.
- **AI Integration:** Local Ollama LLM (planned) for alert summarization and triage.

## 🛠️ Tech Stack
- Wazuh (SIEM/XDR)
- Sysmon (Windows event monitoring)
- Rocky Linux (Server OS)
- Windows (Endpoint)
- Ollama (AI integration - planned)

## 🚀 Installation Steps
1. **Environment Setup:** Increased VirtualBox disk space and resolved LVM device issues (`vgimportdevices`).
2. **Wazuh Installation:** Installed Wazuh Indexer, Manager, and Dashboard on Rocky Linux.
3. **Agent Configuration:** Installed Wazuh Agent on Windows and configured Sysmon.
4. **Log Ingestion:** Forwarded `auth.log`, Cowrie logs, and Windows Event IDs (4624, 4625).

*(Detailed steps are available in the `docs/` folder.)*

## 📸 Screenshots
*(Check the `screenshots/` folder for visual proof of the lab setup and alerts.)*

## 🧠 Challenges & Learnings
- **LVM Disk Resize:** Faced an issue where `pvresize` could not find the device. Fixed by running `vgimportdevices --all` and then resizing the logical volume.
- **Log Parsing:** Configuring Cowrie JSON logs in Wazuh required custom decoders.
- **AI Integration:** Successfully integrated a local LLM to summarize alerts. 

## 🔗 Connect with Me
- [LinkedIn](https://www.linkedin.com/in/tanmay-sarkar-emon-64b46334b)
- [Portfolio](https://tanmaysarkaremon.pages.dev)
