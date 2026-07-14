"""
osint_enrich.py
---------------
Passive OSINT enrichment for source IPs flagged during brute-force triage.

Data sources (all PASSIVE — no active scanning / no packets to the attacker):
    * WHOIS / RDAP  -> ASN, network owner, country, abuse contact  (ipwhois)
    * Shodan (host) -> already-indexed open ports, tags, hostnames  (shodan)
    * crt.sh        -> Certificate Transparency pivot on any resolved hostname

Design goals
    * Fail-open, never crash the triage run because an API is down / key missing.
    * Offline demo mode (--offline) returns cached fixtures so the tool can be
      demonstrated and screenshotted without internet or API keys.
    * Zero third-party deps required in offline mode (stdlib only).

Author : Muhammad Mahad (Reg 242306) | SafeX Solutions Blue Team | Group 17
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
from dataclasses import dataclass, field, asdict
from typing import Optional


# --------------------------------------------------------------------------- #
# Offline fixtures — realistic sample enrichment used when --offline is set.
# Keyed by IP so the demo output is deterministic and screenshot-friendly.
# --------------------------------------------------------------------------- #
_OFFLINE_FIXTURES = {
    "203.0.113.45": {
        "asn": "AS14061",
        "asn_org": "DIGITALOCEAN-ASN",
        "network": "203.0.113.0/24",
        "country": "US",
        "abuse_email": "abuse@digitalocean.com",
        "reverse_dns": "vps-203-0-113-45.example-cloud.net",
        "shodan_ports": [22, 80, 443, 3389],
        "shodan_tags": ["cloud", "self-signed"],
        "shodan_hostnames": ["vps-203-0-113-45.example-cloud.net"],
        "shodan_last_seen": "2026-01-08",
        "crtsh_hits": 2,
    },
    "198.51.100.23": {
        "asn": "AS9009",
        "asn_org": "M247-EUROPE",
        "network": "198.51.100.0/24",
        "country": "NL",
        "abuse_email": "abuse@m247.com",
        "reverse_dns": None,
        "shodan_ports": [22, 5900],
        "shodan_tags": ["scanner", "compromised"],
        "shodan_hostnames": [],
        "shodan_last_seen": "2026-01-10",
        "crtsh_hits": 0,
    },
    "192.0.2.77": {
        "asn": "AS4134",
        "asn_org": "CHINANET-BACKBONE",
        "network": "192.0.2.0/24",
        "country": "CN",
        "abuse_email": "anti-spam@ns.chinanet.cn.net",
        "reverse_dns": None,
        "shodan_ports": [22],
        "shodan_tags": ["scanner"],
        "shodan_hostnames": [],
        "shodan_last_seen": "2026-01-09",
        "crtsh_hits": 0,
    },
}


@dataclass
class Enrichment:
    ip: str
    is_private: bool = False
    asn: Optional[str] = None
    asn_org: Optional[str] = None
    network: Optional[str] = None
    country: Optional[str] = None
    abuse_email: Optional[str] = None
    reverse_dns: Optional[str] = None
    shodan_ports: list = field(default_factory=list)
    shodan_tags: list = field(default_factory=list)
    shodan_hostnames: list = field(default_factory=list)
    shodan_last_seen: Optional[str] = None
    crtsh_hits: int = 0
    errors: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


# Only these count as "internal" for triage. We deliberately do NOT use the
# stdlib .is_private property: Python 3.12 folds RFC 5737 documentation ranges
# (192.0.2/24, 198.51.100/24, 203.0.113/24) into is_private, which would
# wrongly hide real external attackers that happen to sit in those blocks.
_INTERNAL_NETS = [
    ipaddress.ip_network(n) for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
    )
]


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _INTERNAL_NETS)


# --------------------------------------------------------------------------- #
# Online lookups (used when NOT in offline mode).
# --------------------------------------------------------------------------- #
def _whois_rdap(ip: str, enr: Enrichment) -> None:
    try:
        from ipwhois import IPWhois  # type: ignore
        res = IPWhois(ip).lookup_rdap(depth=1)
        enr.asn = f"AS{res.get('asn')}" if res.get("asn") else None
        enr.asn_org = res.get("asn_description")
        enr.country = res.get("asn_country_code")
        net = res.get("network") or {}
        enr.network = net.get("cidr")
        # abuse contact lives in objects[*].contact.email
        for obj in (res.get("objects") or {}).values():
            contact = obj.get("contact") or {}
            roles = obj.get("roles") or []
            emails = contact.get("email") or []
            if "abuse" in roles and emails:
                enr.abuse_email = emails[0].get("value")
                break
    except Exception as exc:  # noqa: BLE001 — fail open
        enr.errors.append(f"whois: {exc}")


def _reverse_dns(ip: str, enr: Enrichment) -> None:
    try:
        enr.reverse_dns = socket.gethostbyaddr(ip)[0]
    except Exception:  # noqa: BLE001
        enr.reverse_dns = None


def _shodan(ip: str, enr: Enrichment) -> None:
    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
        enr.errors.append("shodan: SHODAN_API_KEY not set (skipped)")
        return
    try:
        import shodan  # type: ignore
        host = shodan.Shodan(api_key).host(ip)
        enr.shodan_ports = sorted(host.get("ports", []))
        enr.shodan_tags = host.get("tags", [])
        enr.shodan_hostnames = host.get("hostnames", [])
        enr.shodan_last_seen = (host.get("last_update") or "")[:10] or None
    except Exception as exc:  # noqa: BLE001
        enr.errors.append(f"shodan: {exc}")


def _crtsh(enr: Enrichment) -> None:
    """CT pivot: if the IP resolves to a hostname, count related certs."""
    host = enr.reverse_dns
    if not host:
        return
    domain = ".".join(host.split(".")[-2:])
    try:
        import requests  # type: ignore
        r = requests.get(
            "https://crt.sh/", params={"q": f"%.{domain}", "output": "json"},
            timeout=15,
        )
        if r.ok:
            enr.crtsh_hits = len(r.json())
    except Exception as exc:  # noqa: BLE001
        enr.errors.append(f"crtsh: {exc}")


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def enrich(ip: str, offline: bool = False) -> Enrichment:
    """Return an Enrichment record for a single IP."""
    enr = Enrichment(ip=ip, is_private=_is_private(ip))

    if enr.is_private:
        enr.asn_org = "RFC1918 / internal"
        enr.country = "INTERNAL"
        return enr

    if offline:
        fx = _OFFLINE_FIXTURES.get(ip)
        if fx:
            for k, v in fx.items():
                setattr(enr, k, v)
        else:
            enr.errors.append("offline: no fixture for this IP")
        return enr

    # Live passive enrichment
    _whois_rdap(ip, enr)
    _reverse_dns(ip, enr)
    _shodan(ip, enr)
    _crtsh(enr)
    return enr


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Enrich a single IP (passive OSINT).")
    ap.add_argument("ip")
    ap.add_argument("--offline", action="store_true")
    args = ap.parse_args()
    print(json.dumps(enrich(args.ip, offline=args.offline).to_dict(), indent=2))
