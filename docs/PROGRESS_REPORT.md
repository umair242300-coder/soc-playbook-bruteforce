# Week 2 Progress Report

**Project:** SafeX Solutions Blue Team — Defensive Exercise
**Module:** SOC Playbook Writing — SSH/RDP Brute Force (Individual)
**Author:** Muhammad Mahad (Reg. 242306) · Group 17
**Week:** 2 · **Difficulty:** Advanced

---

## Objective for the week
Design, build, and document a SOC response playbook for a common incident type,
integrate it cleanly with Group 17's Week 1 defensive environment without
duplicating other members' modules, and deliver source code, documentation,
screenshots, and a demo.

## Incident type chosen — and why
**SSH/RDP brute force.** It is one of the two most common SOC incidents, it maps
naturally to the required passive-OSINT tools (source-IP attribution via WHOIS
and Shodan), and it does not overlap with the group's phishing / web-attack /
malware / OSINT-audit modules — keeping each member's contribution distinct.

## What was completed

| Deliverable | Status | Artifact |
|---|---|---|
| Professional playbook (NIST 800-61r2) | ✅ Done | `docs/PLAYBOOK.md` |
| Triage tool (log parse + detection) | ✅ Done | `src/bruteforce_triage.py` |
| Passive OSINT enrichment module | ✅ Done | `src/osint_enrich.py` |
| Sigma rules (SSH + RDP) | ✅ Done | `detection/sigma/` |
| Suricata threshold rules | ✅ Done | `detection/suricata/` |
| Documentation (how it works / run) | ✅ Done | `docs/DOCUMENTATION.md` |
| Working demo + screenshot | ✅ Done | `assets/demo_screenshot_ssh.png` |
| Explanation video (5–15 min) | ⏳ To record | script in `VIDEO_SCRIPT.md` |
| Group Leader feedback form | ⏳ By Friday | weekly form |

## How it maps to the required skills
- **Vulnerability research methodology** → structured detection signatures,
  ATT&CK mapping, and threshold tuning for a real attack class.
- **Responsible disclosure** → WHOIS abuse-contact enrichment feeds the
  Post-Incident phase's evidence-backed abuse reporting.
- **Technical report writing** → the playbook and this report follow a
  professional template.
- **Risk assessment** → the weighted severity/triage matrix and automated
  scoring.

## Demonstrated results
Against the sample SSH log, the tool correctly flagged three offending sources,
identified **203.0.113.45 as a Critical compromise** (12 failures across 9
usernames followed by a successful `oracle` login), enriched it via OSINT
(DigitalOcean ASN, abuse contact, Shodan port/tag data), and recommended host
isolation + credential reset. It correctly ignored a low-and-slow source that
stayed under the burst threshold — which surfaced a real detection gap I then
addressed with a second, longer-window correlation rule.

## Challenges & how I solved them
1. **Documentation IPs mis-classified as internal.** Python 3.12's `is_private`
   now folds RFC 5737 test ranges into "private", which hid the sample
   attackers. Fixed by replacing it with an explicit RFC1918/loopback check.
2. **No live OSINT in a sandbox / no API key.** Built a fail-open design plus an
   `--offline` fixture mode so the tool always runs and is demo-able.
3. **Burst detection missed low-and-slow spraying.** Added an hourly Suricata
   threshold rule and an account-based correlation note in the playbook.

## Next steps
- Record the HD explanation video (architecture, challenges, tools, live demo).
- Submit anonymous Group-Leader feedback via the weekly form by Friday.
- Optional: wire the tool's JSON output into Wazuh active-response for a
  one-click (still human-approved) block action.
