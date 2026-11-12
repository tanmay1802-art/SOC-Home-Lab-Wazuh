#!/usr/bin/env python3
"""Rule-based detector for the AI-SOC pipeline.

Reads normalized events (NDJSON from parser.py) and writes one alert per
(rule, session) with severity, score, evidence and MITRE ATT&CK mapping.
The alert file is the input for the LLM triage step.

Rules
  BRUTE_FORCE          >= N failed logins from one IP within a time window
  SUCCESSFUL_LOGIN     any successful login on the honeypot (escalated after brute force)
  RECON_COMMANDS       >= 3 distinct reconnaissance commands in one session
  MALWARE_DOWNLOAD     wget/curl/tftp or a recorded file download
  PERSISTENCE_ATTEMPT  authorized_keys, crontab, new user, service enable
  FAIL2BAN_BAN         Fail2ban banned the IP (context for correlation)

Usage
  python3 detector.py --events events.ndjson --out alerts.ndjson
  python3 detector.py --events events.ndjson --summary
"""
import argparse
import json
import re
import sys
from collections import defaultdict, deque
from datetime import datetime, timezone

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

RECON_PATTERNS = [
    r"\buname\b", r"\bwhoami\b", r"^id\b", r"/etc/passwd", r"/etc/shadow",
    r"\bps\s+aux\b", r"\bifconfig\b", r"\bip\s+a", r"/proc/cpuinfo",
    r"\bnetstat\b", r"\bss\s+-", r"^ls\b", r"^pwd\b", r"\blsb_release\b",
]
DOWNLOAD_PATTERN = re.compile(r"\b(wget|curl|tftp|ftpget)\b", re.I)
PERSISTENCE_PATTERNS = [
    (re.compile(r"authorized_keys"), "SSH key added", "T1098.004"),
    (re.compile(r"\bcrontab\b|/etc/cron"), "cron job access", "T1053.003"),
    (re.compile(r"\b(useradd|adduser)\b"), "new user created", "T1136.001"),
    (re.compile(r"systemctl\s+enable|rc\.local"), "startup persistence", "T1543.002"),
]
RECON_RE = [re.compile(p) for p in RECON_PATTERNS]


def parse_ts(value):
    """ISO-8601 string -> aware datetime (naive values are treated as UTC)."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def load_events(path):
    events = []
    with open(path, errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            e["_dt"] = parse_ts(e.get("ts"))
            if e["_dt"]:
                events.append(e)
    events.sort(key=lambda e: e["_dt"])
    return events


class Alerts:
    def __init__(self):
        self.items = []

    def add(self, rule, severity, score, src_ip, session, first, last, summary, evidence, mitre):
        self.items.append({
            "rule": rule, "severity": severity, "score": score,
            "src_ip": src_ip, "session": session,
            "first_seen": first.isoformat(), "last_seen": last.isoformat(),
            "summary": summary, "evidence": evidence, "mitre": mitre,
        })


def detect_bruteforce(events, alerts, threshold, window):
    attempts = defaultdict(deque)
    for e in events:
        if e["event"] != "login_failed" or not e.get("src_ip"):
            continue
        ip, dt = e["src_ip"], e["_dt"]
        q = attempts[ip]
        q.append((dt, e.get("username"), e.get("password")))
        while (dt - q[0][0]).total_seconds() > window:
            q.popleft()
        if len(q) >= threshold:
            users = sorted({u for _, u, _ in q if u})
            alerts.add("BRUTE_FORCE", "MEDIUM", 40, ip, e.get("session"), q[0][0], dt,
                       f"{len(q)} failed logins from {ip} within {window}s "
                       f"(usernames tried: {', '.join(users)}).",
                       [f"{u}/{p}" for _, u, p in q], ["T1110"])
            q.clear()


def detect_sessions(events, alerts, bruteforce_ips):
    sessions = defaultdict(list)
    for e in events:
        if e["source"] == "cowrie":
            sessions[e.get("session") or e.get("src_ip")].append(e)

    for sid, evs in sessions.items():
        ip = next((e["src_ip"] for e in evs if e.get("src_ip")), None)
        login = next((e for e in evs if e["event"] == "login_success"), None)
        cmds = [e for e in evs if e["event"] == "command" and e.get("command")]
        downloads = [e for e in evs if e["event"] == "download"]

        if login:
            after_bf = ip in bruteforce_ips
            alerts.add("SUCCESSFUL_LOGIN", "CRITICAL" if after_bf else "HIGH",
                       85 if after_bf else 60, ip, sid, login["_dt"], login["_dt"],
                       f"{ip} logged in as '{login.get('username')}'"
                       + (" after a brute-force burst." if after_bf else "."),
                       [f"{login.get('username')}/{login.get('password')}"],
                       ["T1078", "T1110"] if after_bf else ["T1078"])

        recon = [c for c in cmds if any(r.search(c["command"].strip()) for r in RECON_RE)]
        if len({c["command"] for c in recon}) >= 3:
            alerts.add("RECON_COMMANDS", "MEDIUM", 50, ip, sid, recon[0]["_dt"], recon[-1]["_dt"],
                       f"{len(recon)} reconnaissance commands in one session.",
                       [c["command"] for c in recon], ["T1082", "T1087", "T1016"])

        dl_cmds = [c for c in cmds if DOWNLOAD_PATTERN.search(c["command"])]
        if dl_cmds or downloads:
            ev = dl_cmds + downloads
            first, last = min(x["_dt"] for x in ev), max(x["_dt"] for x in ev)
            urls = sorted({d["url"] for d in downloads if d.get("url")})
            alerts.add("MALWARE_DOWNLOAD", "CRITICAL", 90, ip, sid, first, last,
                       "Attacker tried to download a file"
                       + (f" from {', '.join(urls)}." if urls else "."),
                       [c["command"] for c in dl_cmds] + urls, ["T1105"])

        hits = []
        for c in cmds:
            for rx, label, tech in PERSISTENCE_PATTERNS:
                if rx.search(c["command"]):
                    hits.append((c, label, tech))
        if hits:
            alerts.add("PERSISTENCE_ATTEMPT", "CRITICAL", 90, ip, sid,
                       hits[0][0]["_dt"], hits[-1][0]["_dt"],
                       "Persistence attempt: " + ", ".join(sorted({h[1] for h in hits})) + ".",
                       [h[0]["command"] for h in hits], sorted({h[2] for h in hits}))


def detect_fail2ban(events, alerts):
    for e in events:
        if e["event"] == "f2b_ban":
            alerts.add("FAIL2BAN_BAN", "LOW", 20, e.get("src_ip"), None, e["_dt"], e["_dt"],
                       f"Fail2ban banned {e.get('src_ip')} in jail '{e.get('jail')}'.",
                       [], [])


def run(events, threshold, window):
    alerts = Alerts()
    detect_bruteforce(events, alerts, threshold, window)
    bruteforce_ips = {a["src_ip"] for a in alerts.items if a["rule"] == "BRUTE_FORCE"}
    detect_sessions(events, alerts, bruteforce_ips)
    detect_fail2ban(events, alerts)
    alerts.items.sort(key=lambda a: a["first_seen"])
    for i, a in enumerate(alerts.items, 1):
        a["alert_id"] = f"A{i:04d}"
    return alerts.items


def print_summary(alerts, stream=sys.stderr):
    by_ip = defaultdict(list)
    for a in alerts:
        by_ip[a["src_ip"]].append(a)
    print(f"\n{len(alerts)} alerts from {len(by_ip)} source IP(s)", file=stream)
    for ip, items in sorted(by_ip.items(), key=lambda kv: -max(a["score"] for a in kv[1])):
        worst = max(items, key=lambda a: SEVERITY_ORDER[a["severity"]])["severity"]
        print(f"  {ip}: {worst:<8} {', '.join(sorted({a['rule'] for a in items}))}", file=stream)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--events", required=True, help="NDJSON file produced by parser.py")
    ap.add_argument("--out", help="write alerts as NDJSON (default: stdout)")
    ap.add_argument("--threshold", type=int, default=5, help="failed logins that trigger BRUTE_FORCE")
    ap.add_argument("--window", type=int, default=60, help="brute-force window in seconds")
    ap.add_argument("--summary", action="store_true", help="print a per-IP summary to stderr")
    a = ap.parse_args()

    alerts = run(load_events(a.events), a.threshold, a.window)
    out = open(a.out, "w") if a.out else sys.stdout
    for item in alerts:
        out.write(json.dumps(item) + "\n")
    if a.out:
        out.close()
    if a.summary:
        print_summary(alerts)


if __name__ == "__main__":
    main()
