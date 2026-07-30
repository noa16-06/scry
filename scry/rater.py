"""Rate findings in one of two modes.

- "ollama": a local Ollama model rates each finding individually — small local
  models produce far more reliable JSON for one item than for a big batch.
- "raster": a deterministic scoring grid rates findings with no AI at all.

In "ollama" mode, if Ollama is unreachable the rater falls back to the raster
grid so a scan still yields output.
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
        mode: str = "ollama",
    ):
        self.host = host.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.mode = mode  # "ollama" (LLM) | "raster" (deterministic grid)
        self._session = requests.Session()

    @property
    def uses_llm(self) -> bool:
        return self.mode == "ollama"

    # ------------------------------------------------------------------ #
    def available(self) -> bool:
        if not self.uses_llm:
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
        if not self.uses_llm:
            return _raster_rating(finding)
        try:
            return self._rate_via_ollama(finding)
        except (requests.RequestException, ValueError, KeyError) as exc:
            return _raster_rating(finding, note=f"ollama unavailable, used raster grid ({exc})")

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


def _raster_rating(finding: Finding, note: str = "") -> Rating:
    """Deterministic "raster" rating: score a finding on a fixed grid, no LLM.

    The score is built from transparent, additive components so the rating is
    fully explainable and reproducible:
        base(kind) + exploit bonus + cve bonus + service-risk bonus, clamped 0-10.
    """
    # 1. Base score by finding kind.
    base = {"nse-vuln": 6.0, "cve": 5.5}.get(finding.kind, 2.0)
    score = base
    reasons = [f"base {base:.1f} ({finding.kind})"]

    # 2. Public exploit availability — the strongest signal.
    cve_exploits = [e for e in finding.exploits if e.match == "cve"]
    if cve_exploits:
        score += 3.5
        reasons.append(f"+3.5 CVE-matched exploit x{len(cve_exploits)}")
    elif finding.exploits:
        # Term/version matches are weaker: they are hints, not confirmed hits.
        score += 1.5
        reasons.append(f"+1.5 term-matched exploit x{len(finding.exploits)}")

    # 3. Each known CVE id adds a little, capped so it can't dominate.
    if finding.cves:
        bonus = min(1.5, 0.3 * len(finding.cves))
        score += bonus
        reasons.append(f"+{bonus:.1f} {len(finding.cves)} CVE(s)")

    # 4. Historically risky services deserve a nudge.
    risky = {
        "ftp", "telnet", "smb", "microsoft-ds", "netbios-ssn", "rdp",
        "ms-wbt-server", "mysql", "mssql", "vnc", "rlogin", "rexec",
    }
    if finding.service and finding.service.name in risky:
        score += 1.0
        reasons.append(f"+1.0 risky service ({finding.service.name})")

    score = max(0.0, min(10.0, score))
    sev = _severity_for_score(score)

    reasoning = "raster grid: " + " ".join(reasons) + f" = {score:.1f}"
    if note:
        reasoning = f"{note}. {reasoning}"

    return Rating(
        severity=sev,
        score=score,
        exploitability=_exploitability_phrase(finding),
        ctf_relevance="verify manually — scored by fixed grid, not AI",
        reasoning=reasoning,
        next_steps=_default_steps(finding),
        source="raster",
    )


def _severity_for_score(score: float) -> str:
    """Map a 0-10 raster score onto a severity band."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 2.0:
        return "low"
    return "info"


def _exploitability_phrase(finding: Finding) -> str:
    if any(e.match == "cve" for e in finding.exploits):
        return "public CVE-matched exploit available"
    if finding.exploits:
        return "possible public exploit (term match — verify)"
    if finding.cves:
        return "CVE known; no public exploit indexed"
    return "unknown"


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
