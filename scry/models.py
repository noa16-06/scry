"""Data models for Scry scan results and ratings."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "unknown": 0,
}


@dataclass
class Service:
    """A single open port / service detected on a host."""

    port: int
    protocol: str = "tcp"
    state: str = "open"
    name: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    cpe: list[str] = field(default_factory=list)
    scripts: dict[str, str] = field(default_factory=dict)

    @property
    def banner(self) -> str:
        parts = [self.name, self.product, self.version, self.extrainfo]
        return " ".join(p for p in parts if p).strip()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["banner"] = self.banner
        return d


@dataclass
class Exploit:
    """A public exploit match from Exploit-DB (via searchsploit)."""

    edb_id: str
    title: str
    type: str = ""            # remote | webapps | local | dos | shellcode ...
    platform: str = ""
    path: str = ""            # local path in the exploitdb checkout
    date: str = ""
    codes: list[str] = field(default_factory=list)   # CVE / OSVDB ids
    match: str = "cve"        # cve = matched by CVE id; term = matched by name/version

    @property
    def url(self) -> str:
        return f"https://www.exploit-db.com/exploits/{self.edb_id}" if self.edb_id else ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["url"] = self.url
        return d


@dataclass
class Rating:
    """LLM (ollama) or deterministic (raster) assessment of a finding."""

    severity: str = "unknown"
    score: float = 0.0            # 0-10 CVSS-like
    exploitability: str = ""      # short phrase: how hard to exploit
    ctf_relevance: str = ""       # why it matters for a CTF flag
    reasoning: str = ""
    next_steps: list[str] = field(default_factory=list)
    source: str = "ollama"        # ollama | raster

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """Something worth rating: an NSE vuln hit, a CVE, or a notable service."""

    title: str
    host: str
    port: int | None
    kind: str                      # nse-vuln | cve | service
    detail: str = ""
    cves: list[str] = field(default_factory=list)
    service: Service | None = None
    rating: Rating | None = None
    exploits: list[Exploit] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "host": self.host,
            "port": self.port,
            "kind": self.kind,
            "detail": self.detail,
            "cves": self.cves,
            "service": self.service.to_dict() if self.service else None,
            "rating": self.rating.to_dict() if self.rating else None,
            "exploits": [e.to_dict() for e in self.exploits],
        }

    @property
    def sort_key(self) -> tuple[int, float]:
        sev = self.rating.severity if self.rating else "unknown"
        score = self.rating.score if self.rating else 0.0
        return (SEVERITY_ORDER.get(sev.lower(), 0), score)


@dataclass
class HostResult:
    host: str
    hostnames: list[str] = field(default_factory=list)
    state: str = "up"
    os_guess: str = ""
    services: list[Service] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "hostnames": self.hostnames,
            "state": self.state,
            "os_guess": self.os_guess,
            "services": [s.to_dict() for s in self.services],
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class ScanResult:
    target: str
    started: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished: str = ""
    nmap_args: str = ""
    hosts: list[HostResult] = field(default_factory=list)

    def all_findings(self) -> list[Finding]:
        out: list[Finding] = []
        for h in self.hosts:
            out.extend(h.findings)
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "started": self.started,
            "finished": self.finished,
            "nmap_args": self.nmap_args,
            "hosts": [h.to_dict() for h in self.hosts],
        }
