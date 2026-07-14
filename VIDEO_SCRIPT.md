# Explanation Video Script (5–15 min, HD, face visible)

**For:** SafeX Solutions portfolio + HEC/university evaluation
**Module:** SOC Playbook — SSH/RDP Brute Force · Muhammad Mahad · Group 17

> Tips: record in HD, face visible (webcam corner is fine), share your screen
> for the demo, speak to the *why* not just the *what*. Target ~8–10 min.

---

## 0:00–0:45 — Intro (face on camera)
"Assalam-o-alaikum, I'm Muhammad Mahad, Registration 242306, BS Cybersecurity at
Air University's National Centre for Cybersecurity. This is my Week 2 individual
module for the SafeX Solutions Blue Team exercise with Group 17: a SOC playbook
for SSH and RDP brute-force attacks, with an automated triage tool and passive
OSINT enrichment."

State the one-line goal: *turn a noisy brute-force alert into a fast, consistent,
auditable response — and know within seconds whether anyone actually got in.*

## 0:45–2:00 — Why this incident + architecture
- Why brute force: one of the two most common SOC incidents; fits the required
  OSINT tools (attribution via WHOIS/Shodan); doesn't overlap with the group's
  phishing/web/malware modules.
- Show the architecture diagram / the flow: **logs → parse → detect → OSINT
  enrich → score → severity + action → report.**
- Name the three parts: the **playbook** (docs), the **triage tool** (src), and
  **detection content** (Sigma + Suricata).

## 2:00–4:00 — Walk through the playbook (screen share `PLAYBOOK.md`)
- Framework: NIST SP 800-61r2 six-phase lifecycle.
- Show the **decision-tree flowchart** — highlight the fork: *did a login
  succeed from the attacking source?* → Critical vs High.
- Show the **severity/triage matrix** and **MITRE ATT&CK mapping**
  (T1110 → T1078 on compromise).
- Point out the RACI table and the containment steps (block IP vs isolate host).

## 4:00–7:00 — Live demo (screen share terminal)
Run:
```bash
python3 bruteforce_triage.py --authlog ../data/sample_auth.log --offline --year 2026
```
Narrate the output:
- Three offending IPs detected; **203.0.113.45 = Critical, COMPROMISE** — 12
  failures across 9 usernames, then a successful `oracle` login.
- Show the **OSINT enrichment**: DigitalOcean ASN, abuse contact, Shodan ports
  and `cloud/self-signed` tags — explain this is *passive* (no scanning).
- Show the **recommended action**: isolate + credential reset.
- Then run the **RDP** demo:
  `python3 bruteforce_triage.py --winlog ../data/sample_rdp_4625.csv --offline`
- Mention the tool correctly *ignored* the low-and-slow source under threshold —
  and how the playbook/Suricata rule covers that gap.
- Show the exported `report.json` / `report.md`.

## 7:00–8:30 — Challenges & what I learned
1. Python 3.12's `is_private` mis-classified the RFC 5737 documentation IPs as
   internal — fixed with an explicit RFC1918 check.
2. Fail-open OSINT + offline mode so the tool always runs (no key/network).
3. Burst window missed low-and-slow spraying → added an hourly correlation rule.
- Skills: detection engineering, ATT&CK mapping, risk scoring, IR procedure
  writing, responsible disclosure via WHOIS abuse contacts.

## 8:30–9:00 — Wrap-up (face on camera)
- Recap: a complete, integrated brute-force SOC module — playbook + tool +
  detection rules.
- How it fits Group 17's Week 1 environment (Wazuh/Suricata) without overlap.
- "Thank you — code and docs are in the GitHub repository."

---

### Recording checklist
- [ ] HD (1080p) · face visible · clear audio
- [ ] Terminal font large enough to read on screen
- [ ] Show both SSH and RDP demo runs
- [ ] Show the playbook flowchart and severity matrix
- [ ] 5–15 min total (aim ~8–10)
- [ ] Mention Reg ID, group, and framework alignment on camera
