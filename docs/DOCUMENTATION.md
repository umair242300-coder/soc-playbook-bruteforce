# Module Documentation — SSH/RDP Brute-Force SOC Playbook

**Author:** Muhammad Umair · Air University (NCC)
**Programme:** SafeX Solutions Blue Team — Defensive Exercise, Week 2 (Individual)
**Group:** 17

\---

## 1\. What I built

An individual SOC module that answers the question every analyst faces when a
brute-force alert fires: *"is this random internet noise, or did someone
actually get in — and what do I do in the next 15 minutes?"*

It has three parts:

1. **The Playbook** (`docs/PLAYBOOK.md`) — a professional, NIST SP 800-61r2
aligned incident-response procedure for SSH/RDP brute force, with a RACI
matrix, severity/triage matrix, MITRE ATT\&CK mapping, a decision-tree
flowchart, and phase-by-phase steps (Preparation → Post-Incident).
2. **The Triage Tool** (`src/bruteforce\_triage.py` + `src/osint\_enrich.py`) —
a Python aid that turns raw auth logs into an analyst-ready triage report,
automatically enriched with **passive OSINT** (WHOIS, Shodan, crt.sh) and
tagged with MITRE techniques. It automates the tedious Detection \& Analysis
phase of the playbook.
3. **Detection content** (`detection/`) — Sigma rules (SSH + RDP) and Suricata
threshold rules that generate the alerts this playbook responds to, so the
module plugs straight into the group's Wazuh/Suricata stack from Week 1.

## 2\. How it works

### 2.1 Detection → Triage flow

```
auth.log / 4625 CSV  ──▶  parse  ──▶  aggregate per source IP
                                          │
                          failures, burst, users, success?
                                          │
                                   risk scoring  ◀── passive OSINT enrichment
                                          │            (WHOIS / Shodan / crt.sh)
                                          ▼
              severity + MITRE tags + recommended playbook action
                                          │
                        console table + JSON + Markdown report
```

### 2.2 Parsing

* **Linux SSH:** regex over `/var/log/auth.log` extracts timestamp, result
(Failed/Accepted), username (including `invalid user`), and source IP.
* **Windows RDP:** parses a CSV export of Security events **4625** (failed) and
**4624** (success), filtered to LogonType 10 (RemoteInteractive).

### 2.3 Detection logic

Per source IP the tool computes: total failures, the **largest burst** inside a
sliding 5-minute window, the set of distinct usernames tried, and whether a
**success followed a failure burst** (the key credential-compromise signal).

### 2.4 Risk scoring

A weighted score (0–100) combines failure volume, burst tightness, username
diversity (spray behaviour), privileged-account targeting (`root`/
`Administrator`), the success-after-burst flag, and OSINT reputation
(`scanner`/`compromised` Shodan tags). It maps to Critical/High/Medium/Low and
prints the matching playbook action. Internal (RFC1918) sources are
de-weighted, since those are usually misconfiguration, not attack.

### 2.5 Passive OSINT enrichment (`osint\_enrich.py`)

For each external offending IP:

* **WHOIS/RDAP** (`ipwhois`) → ASN, owning org, netblock, country, **abuse
contact** (used for responsible disclosure in the Post-Incident phase).
* **Shodan** (`shodan`, needs `SHODAN\_API\_KEY`) → already-indexed open ports,
tags, hostnames, last-seen. *Passive:* reads Shodan's index, never scans the
attacker.
* **crt.sh** → if the IP reverse-resolves to a hostname, a Certificate
Transparency pivot on the parent domain surfaces related infrastructure.

All lookups **fail open** — a missing API key or a network error degrades
gracefully and never crashes the run. An **`--offline`** mode returns cached
fixtures so the tool can be demonstrated without internet or API keys.

## 3\. How to run

### Setup

```bash
cd soc-playbook-bruteforce/src
pip install -r requirements.txt        # optional: only for live OSINT
```

### Demo (offline — no internet / API keys needed)

```bash
# SSH auth.log
python3 bruteforce\_triage.py --authlog ../data/sample\_auth.log --offline --year 2026

# Windows RDP export
python3 bruteforce\_triage.py --winlog ../data/sample\_rdp\_4625.csv --offline

# Write JSON + Markdown reports
python3 bruteforce\_triage.py --authlog ../data/sample\_auth.log --offline \\
    --json report.json --md report.md
```

### Live (real passive OSINT, in your own environment)

```bash
export SHODAN\_API\_KEY=your\_key\_here
python3 bruteforce\_triage.py --authlog /var/log/auth.log
```

### Exit codes (for SOAR/cron integration)

`10` = Critical present · `5` = High present · `0` = none · `2` = no events parsed.

## 4\. How to view the outputs

* Console: color-free structured table + priority detail for Critical/High.
* `report.json`: machine-readable, ready for SIEM/SOAR ingestion.
* `report.md`: drop straight into a ticket or this report.
* `assets/demo\_screenshot\_ssh.png`: rendered sample run for the write-up.

## 5\. Design decisions \& limitations

* **Human-in-the-loop:** the tool *recommends*; it never blocks or resets
anything automatically. Containment stays analyst-approved (per playbook §7).
* **Low-and-slow gap:** a tight 5-minute burst window misses slow spraying;
the playbook (Appendix B) and Suricata rule `sid:9000103` add a longer
correlation window to compensate.
* **Sample IPs** use the RFC 5737 documentation ranges (203.0.113.0/24 etc.);
the enrichment fixtures are illustrative. Live mode returns real data.

## 6\. File map

```
soc-playbook-bruteforce/
├── README.md                    # GitHub landing + quickstart
├── docs/
│   ├── PLAYBOOK.md              # the core deliverable (playbook)
│   ├── DOCUMENTATION.md         # this file
│   └── PROGRESS\_REPORT.md       # Week 2 progress report
├── src/
│   ├── bruteforce\_triage.py     # main triage engine
│   ├── osint\_enrich.py          # passive OSINT enrichment
│   └── requirements.txt
├── detection/
│   ├── sigma/{ssh,rdp}\_bruteforce.yml
│   └── suricata/bruteforce.rules
├── data/                        # sample logs for the demo
└── assets/                      # generated reports + screenshot





\## Additional Evidence



The following screenshots are included in the assets folder.



\- WHOIS Lookup

\- DNS Lookup

\- A Record

\- NS Record

\- TXT Record

\- SSL Certificate

\- crt.sh

\- Shodan Results



These screenshots demonstrate passive OSINT techniques used during the investigation.



