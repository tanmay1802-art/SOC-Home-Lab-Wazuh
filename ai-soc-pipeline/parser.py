#!/usr/bin/env python3
"""Normalize Cowrie (cowrie.json) and Fail2ban (fail2ban.log) logs into one event schema.

Output: NDJSON, one event per line:
  {ts, source, event, src_ip, session, username, password, command, url, jail, raw_id}

Usage:
  python3 parser.py --cowrie /opt/cowrie/var/log/cowrie/cowrie.json \
                    --fail2ban /var/log/fail2ban.log --out events.ndjson
  python3 parser.py --cowrie ... --follow      # keep reading new lines (like tail -f)
"""
import argparse, json, re, sys, time
from datetime import datetime, timezone

COWRIE_MAP = {
    "cowrie.session.connect": "connect",
    "cowrie.login.failed": "login_failed",
    "cowrie.login.success": "login_success",
    "cowrie.command.input": "command",
    "cowrie.session.file_download": "download",
    "cowrie.session.file_upload": "upload",
    "cowrie.session.closed": "session_closed",
}

F2B_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2}),\d+\s+\S+\s+\[\d+\]:\s+"
    r"\w+\s+\[(?P<jail>[^\]]+)\]\s+(?P<action>Found|Ban|Unban|Restore Ban)\s+(?P<ip>[\d.]+)"
)
F2B_MAP = {"Found": "f2b_found", "Ban": "f2b_ban", "Restore Ban": "f2b_ban", "Unban": "f2b_unban"}


def _event(ts, source, event, **kw):
    base = dict(ts=ts, source=source, event=event, src_ip=None, session=None,
                username=None, password=None, command=None, url=None, jail=None)
    base.update(kw)
    return base


def parse_cowrie_line(line):
    line = line.strip()
    if not line:
        return None
    try:
        d = json.loads(line)
    except json.JSONDecodeError:
        return None
    ev = COWRIE_MAP.get(d.get("eventid"))
    if not ev:
        return None
    return _event(d.get("timestamp"), "cowrie", ev,
                  src_ip=d.get("src_ip"), session=d.get("session"),
                  username=d.get("username"), password=d.get("password"),
                  command=d.get("input"), url=d.get("url"))


def parse_fail2ban_line(line, tz=timezone.utc):
    m = F2B_RE.match(line.strip())
    if not m:
        return None
    ts = datetime.strptime(f"{m['date']} {m['time']}", "%Y-%m-%d %H:%M:%S")
    return _event(ts.replace(tzinfo=tz).isoformat(), "fail2ban", F2B_MAP[m["action"]],
                  src_ip=m["ip"], jail=m["jail"])


def read_all(path, fn):
    with open(path, errors="replace") as f:
        for line in f:
            e = fn(line)
            if e:
                yield e


def follow(path, fn, poll=1.0):
    with open(path, errors="replace") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(poll)
                continue
            e = fn(line)
            if e:
                yield e


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cowrie")
    ap.add_argument("--fail2ban")
    ap.add_argument("--out", help="write NDJSON here (default: stdout)")
    ap.add_argument("--follow", action="store_true", help="tail the files for new events (Cowrie only for now)")
    a = ap.parse_args()
    if not (a.cowrie or a.fail2ban):
        ap.error("give --cowrie and/or --fail2ban")

    out = open(a.out, "a" if a.follow else "w") if a.out else sys.stdout
    try:
        if a.follow:
            if not a.cowrie:
                ap.error("--follow needs --cowrie")
            for e in follow(a.cowrie, parse_cowrie_line):
                out.write(json.dumps(e) + "\n"); out.flush()
        else:
            events = []
            if a.cowrie:
                events += list(read_all(a.cowrie, parse_cowrie_line))
            if a.fail2ban:
                events += list(read_all(a.fail2ban, parse_fail2ban_line))
            events.sort(key=lambda e: e["ts"] or "")
            for e in events:
                out.write(json.dumps(e) + "\n")
    except KeyboardInterrupt:
        pass
    finally:
        if a.out:
            out.close()


if __name__ == "__main__":
    main()
