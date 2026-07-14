# SOC Playbook — SSH / RDP Brute Force 🛡️

> \*\*SafeX Solutions Blue Team — Defensive Exercise · Week 2 (Individual)\*\*
> Muhammad Mahad (Reg. 242306) · Air University (NCC) · Group 17

A complete SOC incident-response module for **remote-authentication brute-force
attacks** (OpenSSH \& Windows RDP): a professional NIST SP 800-61r2 playbook, a
Python triage tool with **passive OSINT enrichment** (WHOIS · Shodan · crt.sh),
and ready-to-deploy Sigma + Suricata detection content.

\---

## Why this module

When a brute-force alert fires, an analyst has minutes to answer two questions:
*is this real, and did anyone get in?* This module makes that decision fast,
consistent, and auditable — and enriches every offending IP with passive OSINT
for attribution and responsible abuse reporting.

## Features

* 📖 **Playbook** — NIST 800-61r2 lifecycle, RACI, severity matrix, ATT\&CK
mapping, decision-tree flowchart, phase-by-phase steps.
* 🐍 **Triage tool** — parses SSH `auth.log` and Windows 4625/4624 exports,
detects burst + success-after-failure (compromise), scores severity, tags
MITRE techniques, exports JSON/Markdown.
* 🌐 **Passive OSINT** — WHOIS/RDAP (ASN + abuse contact), Shodan (ports/tags),
crt.sh (CT pivot). Fail-open, with an offline demo mode.
* 🚨 **Detection content** — Sigma (SSH/RDP) + Suricata threshold rules that
plug into a Wazuh/Suricata SOC.

## Quickstart

```bash
git clone <repo-url> \&\& cd soc-playbook-bruteforce/src
pip install -r requirements.txt          # optional: only for live OSINT

# Offline demo — no internet / API keys required
python3 bruteforce\_triage.py --authlog ../data/sample\_auth.log --offline --year 2026
python3 bruteforce\_triage.py --winlog  ../data/sample\_rdp\_4625.csv --offline
```

Live passive OSINT in your own environment:

```bash
export SHODAN\_API\_KEY=your\_key
python3 bruteforce\_triage.py --authlog /var/log/auth.log
```

## Sample output

!\[demo](assets/demo\_screenshot\_ssh.png)

The Critical finding (`203.0.113.45`) shows 12 failures across 9 usernames
followed by a successful login — enriched with ASN, abuse contact, and Shodan
tags, with an automatic *isolate + reset* recommendation.

## Repository layout

|Path|Contents|
|-|-|
|`docs/PLAYBOOK.md`|The core incident-response playbook|
|`docs/DOCUMENTATION.md`|What it is, how it works, how to run|
|`docs/PROGRESS\_REPORT.md`|Week 2 progress report|
|`src/`|Triage engine + OSINT enrichment + requirements|
|`detection/sigma/` · `detection/suricata/`|Detection rules|
|`data/`|Sample SSH/RDP logs for the demo|
|`assets/`|Generated reports + screenshot|

## Scope \& ethics

Detection \& analysis aid only. **All OSINT is passive** (no scanning of the
attacker) and **all containment is human-approved** — the tool recommends,
analysts act. Built for defensive SOC use in a controlled lab/internship
context.

## Framework alignment

NIST SP 800-61r2 · MITRE ATT\&CK (T1110, T1078, T1133) · CIS Controls v8.

\---

*Individual Week 2 deliverable. Integrates with Group 17's Week 1 defensive
environment; scoped to SSH/RDP brute force to avoid overlap with other members'
modules.*



*## Passive OSINT Investigation*



*The project uses passive OSINT techniques to enrich brute-force incident investigations.*



*Tools Used:*

*- WHOIS*

*- nslookup*

*- dig*

*- crt.sh*

*- Shodan*

*- OpenSSL*



*Evidence screenshots are available in the `assets/` directory.*



*## Assets*



*- whois.png*

*- nslookup.png*

*- dig\_A.png*

*- dig\_NS.png*

*- dig\_TXT.png*

*- ssl\_certificate.png*

*- crtsh.png*

*- shodan.png*

