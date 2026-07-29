"""Rate findings with a local Ollama model.

Each finding is rated individually — small local models produce far more
reliable JSON for one item than for a big batch. If Ollama is unreachable the
rater falls back to a simple heuristic so a scan still yields output.
"""
from __future__ import annotations

import json
import os

import requests

from .models import Finding, Rating

DEFAULT_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
DEFAULT_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.1")

VALID_SEVERITY = {"critical", "high", "medium", "low", "info"}

SYSTEM_PROMPT = (
    "You are a penetration-testing assistant helping rate reconnaissance "
    "findings during an authorized Capture-The-Flag (CTF) exercise. You assess "
    "how likely a finding leads to a foothold or a flag, and suggest concrete "
    "next steps. Be precise and practical. Respond ONLY with a JSON object."
)

RATING_SCHEMA_HINT = """Return a JSON object with exactly these fields:
{
  "severity": one of "critical" | "high" | "medium" | "low" | "info",
  "score": number 0-10 (CVSS-like; higher = more dangerous/useful),
  "exploitability": short phrase on how hard this is to exploit,
  "ctf_relevance": one sentence on why this matters for capturing a flag,
  "reasoning": 1-2 sentences justifying the rating,
  "next_steps": array of 2-4 concrete commands or actions to try next
}"""


class Rater:
    def __init__(
        self,
        host: str = DEFAULT_HOST,
        model: str = DEFAULT_MODEL,
        timeout: int = 120,
        enabled: bool = True,
    ):
        self.host = host.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.enabled = enabled
        self._session = requests.Session()

    # ------------------------------------------------------------------ #
    def available(self) -> bool:
        if not self.enabled:
            return False
        try:
            r = self._session.get(f"{self.host}/api/tags", timeout=5)
            return r.status_code == 200
        except requests.RequestException:
            return False

    def ensure_model(self) -> bool:
        """Return True if the configured model is present locally."""
        try:
            r = self._session.get(f"{self.host}/api/tags", timeout=5)
            r.raise_for_status()
            tags = r.json().get("models", [])
            names = {m.get("name", "").split(":")[0] for m in tags}
            return self.model.split(":")[0] in names
        except requests.RequestException:
            return False

    # ------------------------------------------------------------------ #
    def rate(self, finding: Finding) -> Rating:
        if not self.enabled:
            return _heuristic_rating(finding, note="rating disabled")
        try:
            return self._rate_via_ollama(finding)
        except (requests.RequestException, ValueError, KeyError) as exc:
            r = _heuristic_rating(finding, note=f"ollama error: {exc}")
            return r

    def rate_all(self, findings: list[Finding], progress: bool = True) -> None:
        total = len(findings)
        for i, f in enumerate(findings, 1):
            if progress:
                print(f"[rater] rating {i}/{total}: {f.title}", flush=True)
            f.rating = self.rate(f)

    # ------------------------------------------------------------------ #
    def _rate_via_ollama(self, finding: Finding) -> Rating:
        prompt = self._build_prompt(finding)
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.2},
        }
        r = self._session.post(
            f"{self.host}/api/chat", json=payload, timeout=self.timeout
        )
        r.raise_for_status()
        content = r.json()["message"]["content"]
        data = json.loads(content)
        return _rating_from_json(data)

    @staticmethod
    def _build_prompt(finding: Finding) -> str:
        svc = finding.service
        lines = [
            f"Finding type: {finding.kind}",
            f"Host: {finding.host}",
            f"Port: {finding.port}",
        ]
        if svc:
            lines.append(f"Service: {svc.banner or svc.name}")
            if svc.cpe:
                lines.append(f"CPE: {', '.join(svc.cpe)}")
        if finding.cves:
            lines.append(f"CVEs: {', '.join(finding.cves)}")
        if finding.exploits:
            cve_hits = [e for e in finding.exploits if e.match == "cve"]
            lines.append(
                f"Public exploits found on Exploit-DB: {len(finding.exploits)} "
                f"({len(cve_hits)} matched by CVE id)."
            )
            for e in finding.exploits[:6]:
                lines.append(f"  - EDB-{e.edb_id} [{e.match}] {e.title}")
            lines.append(
                "Weigh available public exploits heavily: they raise exploitability "
                "and CTF usefulness."
            )
        if finding.detail:
            lines.append(f"Details:\n{finding.detail}")
        lines.append("")
        lines.append(RATING_SCHEMA_HINT)
        return "\n".join(lines)


# ---------------------------------------------------------------------- #
def _rating_from_json(data: dict) -> Rating:
    severity = str(data.get("severity", "unknown")).lower().strip()
    if severity not in VALID_SEVERITY:
        severity = "unknown"
    try:
        score = float(data.get("score", 0) or 0)
    except (TypeError, ValueError):
        score = 0.0
    score = max(0.0, min(10.0, score))

    steps = data.get("next_steps", [])
    if isinstance(steps, str):
        steps = [steps]
    steps = [str(s).strip() for s in steps if str(s).strip()][:6]

    return Rating(
        severity=severity,
        score=score,
        exploitability=str(data.get("exploitability", "")).strip(),
        ctf_relevance=str(data.get("ctf_relevance", "")).strip(),
        reasoning=str(data.get("reasoning", "")).strip(),
        next_steps=steps,
        source="ollama",
    )


def _heuristic_rating(finding: Finding, note: str = "") -> Rating:
    """Best-effort rating without an LLM, based on finding kind, CVEs, exploits."""
    if finding.kind == "nse-vuln":
        sev, score = "high", 7.0
    elif finding.kind == "cve":
        sev, score = "high", 6.5
    else:
        sev, score = "info", 2.5

    # A public exploit — especially a CVE-matched one — bumps the rating.
    cve_exploits = [e for e in finding.exploits if e.match == "cve"]
    if cve_exploits:
        sev, score = "critical", max(score, 9.0)
    elif finding.exploits:
        # term-only matches are weaker signals; nudge but stay cautious
        if sev in ("info", "low"):
            sev, score = "medium", max(score, 5.0)

    return Rating(
        severity=sev,
        score=score,
        exploitability="unknown (LLM unavailable)",
        ctf_relevance="review manually",
        reasoning=note or "heuristic rating (Ollama not used)",
        next_steps=_default_steps(finding),
        source="heuristic",
    )


def _default_steps(finding: Finding) -> list[str]:
    steps: list[str] = []
    # If we already found exploits, point straight at them.
    for e in finding.exploits[:3]:
        if e.edb_id:
            steps.append(f"searchsploit -x {e.edb_id}  # {e.title}")
            steps.append(f"searchsploit -m {e.edb_id}  # copy exploit locally")
    if not finding.exploits:
        for cve in finding.cves:
            steps.append(f"searchsploit --cve {cve}")
    svc = finding.service
    if svc and svc.name in ("http", "https", "http-proxy"):
        steps.append(f"gobuster dir -u http://{finding.host}:{finding.port}/ -w common.txt")
        steps.append(f"nikto -h {finding.host}:{finding.port}")
    elif svc and svc.name in ("smb", "microsoft-ds", "netbios-ssn"):
        steps.append(f"enum4linux-ng {finding.host}")
    elif svc and svc.name == "ftp":
        steps.append(f"ftp {finding.host}  # try anonymous login")
    return steps[:6] or ["manual investigation"]
