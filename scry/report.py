"""Render a ScanResult to the terminal, JSON, and Markdown."""
from __future__ import annotations

import json
import os
import sys

from .models import ScanResult, Finding, SEVERITY_ORDER

_COLORS = {
    "critical": "\033[1;95m",
    "high": "\033[1;91m",
    "medium": "\033[1;93m",
    "low": "\033[1;94m",
    "info": "\033[1;90m",
    "unknown": "\033[0;90m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


def _use_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(text: str, sev: str) -> str:
    if not _use_color():
        return text
    return f"{_COLORS.get(sev.lower(), '')}{text}{_RESET}"


def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: f.sort_key, reverse=True)


# ---------------------------------------------------------------------- #
def to_terminal(scan: ScanResult) -> None:
    hdr = f"{_BOLD}Scry report — {scan.target}{_RESET}" if _use_color() else f"Scry report — {scan.target}"
    print("\n" + hdr)
    print(f"  scanned: {scan.finished or scan.started}")
    print(f"  nmap:    {scan.nmap_args}\n")

    if not scan.hosts:
        print("  No live hosts found.")
        return

    for host in scan.hosts:
        name = f"{host.host}" + (f" ({', '.join(host.hostnames)})" if host.hostnames else "")
        print(f"■ Host {name}  [{host.state}]")
        if host.os_guess:
            print(f"  OS guess: {host.os_guess}")

        if host.services:
            print("  Open ports:")
            for s in sorted(host.services, key=lambda x: x.port):
                print(f"    {s.port:>5}/{s.protocol:<4} {s.name:<14} {s.banner}")

        findings = _sorted_findings(host.findings)
        if not findings:
            print("  No notable findings.\n")
            continue

        print("  Findings (highest priority first):")
        for f in findings:
            r = f.rating
            sev = r.severity if r else "unknown"
            score = f"{r.score:.1f}" if r else "  ?"
            tag = _c(f"[{sev.upper():^8}]", sev)
            print(f"    {tag} {score:>4}  {f.title}")
            if f.exploits:
                cve_n = sum(1 for e in f.exploits if e.match == "cve")
                print(f"           exploits: {len(f.exploits)} on Exploit-DB ({cve_n} by CVE)")
                for e in f.exploits[:4]:
                    print(f"             EDB-{e.edb_id} [{e.match}] {e.title}")
            if r:
                if r.exploitability:
                    print(f"           exploit: {r.exploitability}")
                if r.ctf_relevance:
                    print(f"           ctf:     {r.ctf_relevance}")
                if r.next_steps:
                    print("           next:    " + f"\n{'':19}".join(r.next_steps))
        print()


# ---------------------------------------------------------------------- #
def to_json(scan: ScanResult) -> str:
    return json.dumps(scan.to_dict(), indent=2)


def to_markdown(scan: ScanResult) -> str:
    lines: list[str] = []
    lines.append(f"# Scry Report — `{scan.target}`\n")
    lines.append(f"- **Scanned:** {scan.finished or scan.started}")
    lines.append(f"- **nmap args:** `{scan.nmap_args}`\n")

    all_findings = _sorted_findings(scan.all_findings())
    counts: dict[str, int] = {}
    for f in all_findings:
        sev = (f.rating.severity if f.rating else "unknown").lower()
        counts[sev] = counts.get(sev, 0) + 1
    if counts:
        summary = ", ".join(
            f"{counts[s]} {s}" for s in sorted(counts, key=lambda x: SEVERITY_ORDER.get(x, 0), reverse=True)
        )
        lines.append(f"**Summary:** {summary}\n")

    for host in scan.hosts:
        title = host.host + (f" ({', '.join(host.hostnames)})" if host.hostnames else "")
        lines.append(f"## Host `{title}`\n")
        if host.os_guess:
            lines.append(f"_OS guess: {host.os_guess}_\n")

        if host.services:
            lines.append("| Port | Proto | Service | Version |")
            lines.append("|------|-------|---------|---------|")
            for s in sorted(host.services, key=lambda x: x.port):
                lines.append(f"| {s.port} | {s.protocol} | {s.name} | {s.banner} |")
            lines.append("")

        findings = _sorted_findings(host.findings)
        if not findings:
            lines.append("_No notable findings._\n")
            continue

        for f in findings:
            r = f.rating
            sev = (r.severity if r else "unknown").upper()
            score = f"{r.score:.1f}" if r else "?"
            lines.append(f"### {sev} ({score}) — {f.title}\n")
            if f.cves:
                lines.append(f"- **CVEs:** {', '.join(f.cves)}")
            if r:
                if r.exploitability:
                    lines.append(f"- **Exploitability:** {r.exploitability}")
                if r.ctf_relevance:
                    lines.append(f"- **CTF relevance:** {r.ctf_relevance}")
                if r.reasoning:
                    lines.append(f"- **Reasoning:** {r.reasoning}")
                if r.next_steps:
                    lines.append("- **Next steps:**")
                    for step in r.next_steps:
                        lines.append(f"  - `{step}`")
            if f.exploits:
                lines.append("- **Public exploits (Exploit-DB):**")
                lines.append("")
                lines.append("  | EDB-ID | Match | Type | Title | Local path |")
                lines.append("  |--------|-------|------|-------|------------|")
                for e in f.exploits:
                    lines.append(
                        f"  | [{e.edb_id}]({e.url}) | {e.match} | {e.type} | "
                        f"{e.title} | `{e.path}` |"
                    )
                lines.append("")
            if f.detail and f.kind != "service":
                snippet = f.detail.strip().splitlines()
                lines.append("\n<details><summary>Raw detail</summary>\n")
                lines.append("```")
                lines.extend(snippet[:30])
                lines.append("```")
                lines.append("</details>")
            lines.append("")

    return "\n".join(lines)


def write_outputs(scan: ScanResult, out_dir: str, fmt: str) -> list[str]:
    os.makedirs(out_dir, exist_ok=True)
    base = scan.target.replace("/", "_").replace(":", "_")
    written: list[str] = []

    if fmt in ("json", "all"):
        path = os.path.join(out_dir, f"{base}.json")
        with open(path, "w") as fh:
            fh.write(to_json(scan))
        written.append(path)

    if fmt in ("md", "markdown", "all"):
        path = os.path.join(out_dir, f"{base}.md")
        with open(path, "w") as fh:
            fh.write(to_markdown(scan))
        written.append(path)

    return written
