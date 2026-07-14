#!/usr/bin/env python3
"""
bruteforce_triage.py
--------------------
Automated triage aid for the SafeX Solutions SOC "SSH / RDP Brute Force"
playbook. It ingests authentication logs, detects brute-force patterns,
enriches offending source IPs with PASSIVE OSINT, assigns a severity, and
emits an analyst-ready triage report (console + JSON + Markdown).

This tool does NOT perform any action against the attacker. It is a
detection & analysis aid that maps directly to the Detection & Analysis
phase of the playbook (NIST SP 800-61r2). Containment/eradication remain
human-approved actions per the playbook decision tree.

Supported inputs
    --authlog  PATH   Linux OpenSSH /var/log/auth.log
    --winlog   PATH   Windows Security export (CSV: TimeCreated,EventID,
                      TargetUserName,IpAddress,LogonType,Status)

MITRE ATT&CK: T1110 (Brute Force), T1110.001 (Password Guessing),
              T1078 (Valid Accounts — on successful compromise)

Usage
    python3 bruteforce_triage.py --authlog ../data/sample_auth.log --offline
    python3 bruteforce_triage.py --winlog  ../data/sample_rdp_4625.csv --offline
    python3 bruteforce_triage.py --authlog /var/log/auth.log   # live OSINT

Author : Muhammad Mahad (Reg 242306) | SafeX Solutions Blue Team | Group 17
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

# local module
sys.path.insert(0, str(Path(__file__).resolve().parent))
from osint_enrich import enrich  # noqa: E402

# --------------------------------------------------------------------------- #
# Tunable detection thresholds (documented in the playbook, Appendix B).
# --------------------------------------------------------------------------- #
FAIL_THRESHOLD = 5          # min failed attempts from one IP to flag
WINDOW_SECONDS = 300        # sliding window for "burst" brute force (5 min)
DISTINCT_USER_HINT = 3      # >= distinct usernames = password-spray flavour

# --------------------------------------------------------------------------- #
# Log parsing
# --------------------------------------------------------------------------- #
_SSH_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+"
    r"sshd\[\d+\]:\s+(?P<result>Failed|Accepted)\s+(?:password|publickey)\s+"
    r"for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>[\d.]+)\s+port"
)
_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}


@dataclass
class Event:
    ts: datetime
    ip: str
    user: str
    success: bool


def parse_authlog(path: Path, year: int) -> list[Event]:
    events: list[Event] = []
    for line in path.read_text(errors="ignore").splitlines():
        m = _SSH_RE.search(line)
        if not m:
            continue
        d = m.groupdict()
        try:
            ts = datetime(
                year, _MONTHS[d["mon"]], int(d["day"]),
                *map(int, d["time"].split(":")))
        except (ValueError, KeyError):
            continue
        events.append(Event(ts, d["ip"], d["user"], d["result"] == "Accepted"))
    return events


def parse_winlog(path: Path) -> list[Event]:
    events: list[Event] = []
    with path.open(newline="") as fh:
        for row in csv.DictReader(fh):
            eid = row.get("EventID", "").strip()
            if eid not in ("4624", "4625"):
                continue
            try:
                ts = datetime.fromisoformat(row["TimeCreated"].strip())
            except (ValueError, KeyError):
                continue
            events.append(Event(
                ts=ts,
                ip=(row.get("IpAddress") or "").strip(),
                user=(row.get("TargetUserName") or "").strip(),
                success=(eid == "4624"),
            ))
    return [e for e in events if e.ip and e.ip not in ("-", "::1", "127.0.0.1")]


# --------------------------------------------------------------------------- #
# Detection & scoring
# --------------------------------------------------------------------------- #
@dataclass
class IPFinding:
    ip: str
    failed: int = 0
    succeeded: int = 0
    users: set = field(default_factory=set)
    first_seen: datetime = None
    last_seen: datetime = None
    max_burst: int = 0            # max fails inside WINDOW_SECONDS
    compromised: bool = False     # failures followed by a success
    severity: str = "Info"
    score: int = 0
    att_ck: list = field(default_factory=list)
    osint: dict = field(default_factory=dict)


def _burst(fail_times: list[datetime]) -> int:
    """Largest number of failures within any WINDOW_SECONDS sliding window."""
    if not fail_times:
        return 0
    fail_times.sort()
    best = 1
    left = 0
    for right in range(len(fail_times)):
        while (fail_times[right] - fail_times[left]).total_seconds() > WINDOW_SECONDS:
            left += 1
        best = max(best, right - left + 1)
    return best


def analyse(events: list[Event]) -> dict[str, IPFinding]:
    by_ip: dict[str, IPFinding] = {}
    fail_times: dict[str, list[datetime]] = defaultdict(list)
    first_success_after_fail: dict[str, bool] = {}

    for ev in sorted(events, key=lambda e: e.ts):
        f = by_ip.setdefault(ev.ip, IPFinding(ip=ev.ip))
        f.first_seen = ev.ts if f.first_seen is None else f.first_seen
        f.last_seen = ev.ts
        f.users.add(ev.user)
        if ev.success:
            f.succeeded += 1
            if f.failed >= FAIL_THRESHOLD:
                f.compromised = True
        else:
            f.failed += 1
            fail_times[ev.ip].append(ev.ts)

    for ip, f in by_ip.items():
        f.max_burst = _burst(fail_times[ip])
    return by_ip


def score(f: IPFinding, offline: bool) -> None:
    """Assign a numeric score + severity + ATT&CK tags, then enrich."""
    s = 0
    if f.failed >= FAIL_THRESHOLD:
        s += 30
    if f.max_burst >= FAIL_THRESHOLD:
        s += 20                       # tight burst = automated tooling
    if len(f.users) >= DISTINCT_USER_HINT:
        s += 15                       # spray / dictionary of usernames
    if "root" in f.users or "Administrator" in f.users:
        s += 10                       # privileged account targeted
    if f.compromised:
        s += 60                       # dominant signal: likely valid creds

    # ATT&CK mapping
    if f.failed >= FAIL_THRESHOLD:
        f.att_ck.append("T1110 Brute Force")
    if len(f.users) >= DISTINCT_USER_HINT:
        f.att_ck.append("T1110.001 Password Guessing")
    if f.compromised:
        f.att_ck.append("T1078 Valid Accounts")

    # OSINT enrichment (external IPs only)
    enr = enrich(f.ip, offline=offline)
    f.osint = enr.to_dict()
    if not enr.is_private:
        if "scanner" in (enr.shodan_tags or []):
            s += 10
        if "compromised" in (enr.shodan_tags or []):
            s += 10
    else:
        s = max(0, s - 20)            # internal source: likely misconfig, not attack

    f.score = min(s, 100)
    f.severity = (
        "Critical" if f.score >= 80 else
        "High" if f.score >= 55 else
        "Medium" if f.score >= 30 else
        "Low" if f.score > 0 else "Info"
    )


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def _dur(f: IPFinding) -> str:
    if not (f.first_seen and f.last_seen):
        return "-"
    secs = int((f.last_seen - f.first_seen).total_seconds())
    return f"{secs // 60}m{secs % 60:02d}s"


def console_report(findings: list[IPFinding]) -> None:
    print("\n" + "=" * 78)
    print("  SafeX Solutions SOC — Brute Force Triage Report")
    print("  Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("=" * 78)
    hdr = f"{'SEVERITY':<9}{'SCORE':>5}  {'SOURCE IP':<16}{'FAIL':>5}{'OK':>4}{'USERS':>6}  {'ASN / ORG':<24}CC"
    print(hdr)
    print("-" * 78)
    for f in findings:
        o = f.osint
        org = (o.get("asn_org") or "-")[:22]
        cc = o.get("country") or "-"
        flag = "  <== COMPROMISE" if f.compromised else ""
        print(f"{f.severity:<9}{f.score:>5}  {f.ip:<16}{f.failed:>5}"
              f"{f.succeeded:>4}{len(f.users):>6}  {org:<24}{cc}{flag}")
    print("-" * 78)

    crit = [f for f in findings if f.severity in ("Critical", "High")]
    if crit:
        print("\nPRIORITY DETAIL (Critical / High):")
        for f in crit:
            o = f.osint
            print(f"\n  [{f.severity}] {f.ip}   score={f.score}")
            print(f"    window       : {f.first_seen}  ->  {f.last_seen}  ({_dur(f)})")
            print(f"    failed/burst : {f.failed} total, max {f.max_burst} in "
                  f"{WINDOW_SECONDS//60}m")
            print(f"    users tried  : {', '.join(sorted(f.users))}")
            print(f"    ATT&CK       : {', '.join(f.att_ck) or '-'}")
            print(f"    WHOIS        : {o.get('asn')} {o.get('asn_org')} "
                  f"({o.get('country')})  net={o.get('network')}")
            print(f"    abuse        : {o.get('abuse_email') or '-'}")
            print(f"    Shodan       : ports={o.get('shodan_ports')} "
                  f"tags={o.get('shodan_tags')} seen={o.get('shodan_last_seen')}")
            print(f"    crt.sh hits  : {o.get('crtsh_hits')}")
            action = ("ISOLATE affected host + force credential reset (compromise "
                      "indicators present)") if f.compromised else \
                     "Block source IP at edge FW; monitor for follow-on attempts"
            print(f"    -> ACTION    : {action}")
    print()


def json_report(findings: list[IPFinding], path: Path) -> None:
    out = []
    for f in findings:
        out.append({
            "ip": f.ip, "severity": f.severity, "score": f.score,
            "failed": f.failed, "succeeded": f.succeeded,
            "distinct_users": sorted(f.users), "max_burst": f.max_burst,
            "compromised": f.compromised, "attack": f.att_ck,
            "first_seen": str(f.first_seen), "last_seen": str(f.last_seen),
            "osint": f.osint,
        })
    path.write_text(json.dumps(out, indent=2))


def md_report(findings: list[IPFinding], path: Path) -> None:
    lines = ["# Brute Force Triage Report",
             f"_Generated {datetime.now():%Y-%m-%d %H:%M:%S} — SafeX Solutions SOC_\n",
             "| Severity | Score | Source IP | Fail | OK | Users | ASN/Org | CC | Compromise |",
             "|---|---|---|---|---|---|---|---|---|"]
    for f in findings:
        o = f.osint
        lines.append(f"| {f.severity} | {f.score} | {f.ip} | {f.failed} | "
                     f"{f.succeeded} | {len(f.users)} | {o.get('asn_org') or '-'} | "
                     f"{o.get('country') or '-'} | {'YES' if f.compromised else '-'} |")
    path.write_text("\n".join(lines) + "\n")


# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser(description="SSH/RDP brute-force triage aid.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--authlog", type=Path, help="Linux OpenSSH auth.log")
    src.add_argument("--winlog", type=Path, help="Windows 4625/4624 CSV export")
    ap.add_argument("--year", type=int, default=datetime.now().year,
                    help="Year for syslog timestamps (auth.log has no year)")
    ap.add_argument("--offline", action="store_true",
                    help="Use cached OSINT fixtures (no network/API keys)")
    ap.add_argument("--json", type=Path, help="Write JSON report to path")
    ap.add_argument("--md", type=Path, help="Write Markdown report to path")
    args = ap.parse_args()

    if args.authlog:
        events = parse_authlog(args.authlog, args.year)
    else:
        events = parse_winlog(args.winlog)

    if not events:
        print("No parseable authentication events found.", file=sys.stderr)
        return 2

    findings_map = analyse(events)
    for f in findings_map.values():
        score(f, offline=args.offline)

    # Only report IPs that crossed the detection threshold or succeeded suspiciously
    findings = [f for f in findings_map.values()
                if f.failed >= FAIL_THRESHOLD or f.compromised]
    findings.sort(key=lambda f: (SEV_ORDER[f.severity], -f.score))

    console_report(findings)
    if args.json:
        json_report(findings, args.json)
        print(f"[+] JSON report  -> {args.json}")
    if args.md:
        md_report(findings, args.md)
        print(f"[+] Markdown report -> {args.md}")

    # exit code signals highest severity (useful for SOAR/cron integration)
    if any(f.severity == "Critical" for f in findings):
        return 10
    if any(f.severity == "High" for f in findings):
        return 5
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
