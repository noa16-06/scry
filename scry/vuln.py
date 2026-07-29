"""Turn a parsed scan into rate-able Findings.

Sources of findings:
  * NSE vuln-category script output (the `--script vuln` results)
  * CVE identifiers mentioned anywhere in script output
  * Notable services (anything with a product/version worth assessing)
"""
from __future__ import annotations

import re

from .models import Finding, HostResult, ScanResult, Service

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# NSE scripts whose presence signals an actual/likely vulnerability.
VULN_SCRIPT_HINTS = ("vuln", "exploit", "cve", "smb-vuln", "http-vuln", "ssl-")

# Services that are almost always interesting on a CTF box.
NOTABLE_SERVICES = {
    "http", "https", "http-proxy", "ftp", "ssh", "telnet", "smb",
    "microsoft-ds", "netbios-ssn", "rpcbind", "mysql", "postgresql",
    "mssql", "ms-sql-s", "redis", "mongodb", "vnc", "rdp", "ms-wbt-server",
    "smtp", "pop3", "imap", "ldap", "nfs", "rmi", "docker", "elasticsearch",
    "jenkins", "tomcat", "ajp13", "irc", "snmp", "memcached",
}


def _cves_from_text(text: str) -> list[str]:
    seen: dict[str, None] = {}
    for m in CVE_RE.findall(text or ""):
        seen[m.upper()] = None
    return list(seen)


def _script_indicates_vuln(script_id: str, output: str) -> bool:
    sid = script_id.lower()
    if any(h in sid for h in VULN_SCRIPT_HINTS):
        # Skip "not vulnerable" / clean results to avoid noise.
        low = output.lower()
        if "vulnerable" in low and "not vulnerable" not in low:
            return True
        if "cve-" in low or "state: likely" in low:
            return True
        # ssl-* and http-* diagnostics without a clear verdict: keep if CVE present
        return bool(CVE_RE.search(output or ""))
    return False


def build_findings(scan: ScanResult, include_services: bool = True) -> ScanResult:
    for host in scan.hosts:
        host.findings = _findings_for_host(host, include_services)
    return scan


def _findings_for_host(host: HostResult, include_services: bool) -> list[Finding]:
    findings: list[Finding] = []
    rated_ports_with_vuln: set[int] = set()

    for svc in host.services:
        # 1. NSE vuln script hits
        for sid, output in svc.scripts.items():
            if _script_indicates_vuln(sid, output):
                cves = _cves_from_text(output)
                findings.append(
                    Finding(
                        title=f"{sid} on {svc.port}/{svc.protocol}",
                        host=host.host,
                        port=svc.port,
                        kind="nse-vuln",
                        detail=output[:2000],
                        cves=cves,
                        service=svc,
                    )
                )
                rated_ports_with_vuln.add(svc.port)

        # 2. Bare CVEs mentioned in any script but not already captured
        all_script_text = "\n".join(svc.scripts.values())
        for cve in _cves_from_text(all_script_text):
            already = any(cve in f.cves for f in findings if f.port == svc.port)
            if not already:
                findings.append(
                    Finding(
                        title=f"{cve} on {svc.port}/{svc.protocol}",
                        host=host.host,
                        port=svc.port,
                        kind="cve",
                        detail=_context_for_cve(all_script_text, cve),
                        cves=[cve],
                        service=svc,
                    )
                )

        # 3. Notable services without an explicit vuln finding — let the LLM assess
        if include_services and svc.port not in rated_ports_with_vuln:
            if _is_notable(svc):
                findings.append(
                    Finding(
                        title=f"{svc.banner or svc.name or 'service'} on {svc.port}/{svc.protocol}",
                        host=host.host,
                        port=svc.port,
                        kind="service",
                        detail=_service_detail(svc),
                        cves=[],
                        service=svc,
                    )
                )

    return findings


def _is_notable(svc: Service) -> bool:
    if svc.name in NOTABLE_SERVICES:
        return True
    # Anything with a concrete product+version is worth a look.
    return bool(svc.product and svc.version)


def _service_detail(svc: Service) -> str:
    lines = [f"Service: {svc.name or 'unknown'}"]
    if svc.product:
        lines.append(f"Product: {svc.product}")
    if svc.version:
        lines.append(f"Version: {svc.version}")
    if svc.extrainfo:
        lines.append(f"Info: {svc.extrainfo}")
    if svc.cpe:
        lines.append(f"CPE: {', '.join(svc.cpe)}")
    return "\n".join(lines)


def _context_for_cve(text: str, cve: str, window: int = 200) -> str:
    idx = text.upper().find(cve.upper())
    if idx == -1:
        return cve
    start = max(0, idx - window)
    end = min(len(text), idx + len(cve) + window)
    return text[start:end].strip()
