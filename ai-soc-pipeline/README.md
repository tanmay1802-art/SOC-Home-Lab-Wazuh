# AI-SOC-Pipeline (work in progress)

Custom SOC pipeline on Rocky Linux: Cowrie + Fail2ban logs -> normalized events -> detection -> local LLM triage.

| Component | Status |
|---|---|
| attack_sim.sh (Kali attack simulator) | ✅ Step 1 |
| parser.py (Cowrie JSON + Fail2ban normalizer) | ✅ Step 2 |
| Rule-based detection | ⏳ Planned |
| Ollama LLM triage + RAG playbook | ⏳ Planned |
| Streamlit dashboard | ⏳ Planned |

Note: all traffic is simulated from my own Kali VM against my own lab.

## Run
Kali:   `./attack_sim.sh <rocky_ip> all`
Rocky:  `python3 parser.py --cowrie /opt/cowrie/var/log/cowrie/cowrie.json --fail2ban /var/log/fail2ban.log`
Test without a lab: `python3 parser.py --cowrie sample_logs/cowrie.json --fail2ban sample_logs/fail2ban.log`



