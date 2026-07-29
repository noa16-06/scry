"""CVE / exploit enrichment via searchsploit (Exploit-DB).

For every finding we look up public exploits:
  * by CVE id      -> `searchsploit -j --cve CVE-...`   (high confidence)
  * by product ver -> `searchsploit -j <product> <ver>` (hint; verify version)

Matches are attached to the finding so the rater and reports can use them.
searchsploit is optional: if it's missing, enrichment is skipped cleanly.
"""
from __future__ import annotations

import json
import shutil
import subprocess

from .models import Exploit, Finding, ScanResult


class Searchsploit:
    def __init__(self, binary: str = "searchsploit", timeout: int = 45, enabled: bool = True):
        self.binary = binary
        self.timeout = timeout
        self.enabled = enabled
        self._resolved = shutil.which(binary) if binary else None
        # Cache lookups so a CVE/term shared across hosts is queried once.
        self._cache: dict[tuple[str, str], list[Exploit]] = {}

    def available(self) -> bool:
        return bool(self.enabled and self._resolved)

    # ------------------------------------------------------------------ #
    def by_cve(self, cve: str) -> list[Exploit]:
        cve = cve.strip().upper()
        if not cve:
            return []
        return self._lookup(("cve", cve), ["--cve", cve], match="cve")

    def by_terms(self, terms: str) -> list[Exploit]:
        terms = " ".join(terms.split()).strip()
        if not terms:
            return []
        # split terms into args so "Apache 2.4" -> ["Apache", "2.4"]
        return self._lookup(("term", terms.lower()), terms.split(), match="term")

    # ------------------------------------------------------------------ #
    def _lookup(self, cache_key: tuple[str, str], query_args: list[str], match: str) -> list[Exploit]:
        if not self.available():
            return []
        if cache_key in self._cache:
            return self._cache[cache_key]
        data = self._run(["-j", *query_args])
        exploits = _parse_results(data, match=match) if data else []
        self._cache[cache_key] = exploits
        return exploits

    def _run(self, args: list[str]) -> dict | None:
        cmd = [self._resolved or self.binary, *args]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout, check=False
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return None
        out = proc.stdout.strip()
        if not out:
            return None
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            # Some builds emit a banner line before the JSON; grab the JSON body.
            start = out.find("{")
            if start != -1:
                try:
                    return json.loads(out[start:])
                except json.JSONDecodeError:
                    return None
            return None


def _parse_results(data: dict, match: str) -> list[Exploit]:
    out: list[Exploit] = []
    for row in data.get("RESULTS_EXPLOIT", []) or []:
        edb = str(row.get("EDB-ID", "")).strip()
        title = str(row.get("Title", "")).strip()
        if not (edb or title):
            continue
        codes_raw = str(row.get("Codes", "") or "")
        codes = [c.strip() for c in codes_raw.replace(",", ";").split(";") if c.strip()]
        out.append(
            Exploit(
                edb_id=edb,
                title=title,
                type=str(row.get("Type", "")).strip(),
                platform=str(row.get("Platform", "")).strip(),
                path=str(row.get("Path", "")).strip(),
                date=str(row.get("Date_Published", row.get("Date", ""))).strip(),
                codes=codes,
                match=match,
            )
        )
    return out


# ---------------------------------------------------------------------- #
def enrich_findings(
    scan: ScanResult,
    ss: Searchsploit,
    service_search: bool = True,
    max_per_finding: int = 12,
    progress: bool = True,
) -> ScanResult:
    if not ss.available():
        return scan

    findings = scan.all_findings()
    total = len(findings)
    for i, f in enumerate(findings, 1):
        if progress:
            print(f"[enrich] searchsploit {i}/{total}: {f.title}", flush=True)
        _enrich_one(f, ss, service_search, max_per_finding)
    return scan


def _enrich_one(f: Finding, ss: Searchsploit, service_search: bool, cap: int) -> None:
    found: dict[str, Exploit] = {}

    # CVE-based lookups (high confidence).
    for cve in f.cves:
        for e in ss.by_cve(cve):
            found.setdefault(e.edb_id or e.title, e)

    # Version/product term search for plain service findings (hints).
    if service_search and f.service and f.service.product:
        terms = f.service.product
        if f.service.version:
            terms = f"{terms} {f.service.version}"
        for e in ss.by_terms(terms):
            found.setdefault(e.edb_id or e.title, e)

    # CVE matches first, then newest.
    exploits = sorted(found.values(), key=lambda e: (e.match != "cve", e.date), reverse=False)
    f.exploits = exploits[:cap]
