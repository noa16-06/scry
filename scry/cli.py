"""Command-line interface for Scry."""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .enrich import Searchsploit, enrich_findings
from .rater import DEFAULT_HOST, DEFAULT_MODEL, Rater
from .report import to_terminal, write_outputs
from .scanner import ScanError, scan
from .vuln import build_findings

BANNER = r"""
 ____    ____   ____  __   __
/ ___|  / ___||  _ \ \ \ / /
\___ \ | |    | |_) | \ V /
 ___) || |___ |  _ <   | |
|____/  \____||_| \_\  |_|    CTF recon + LLM rating
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scry",
        description="Automate CTF recon: scan ports, find vulns, rate them with a local LLM.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("target", help="Host, IP, CIDR, or nmap-style range to scan")

    scan_g = p.add_argument_group("scanning")
    scan_g.add_argument(
        "--profile", choices=["fast", "default", "thorough"], default="default",
        help="fast=top100, default=top1000, thorough=all ports",
    )
    scan_g.add_argument("-p", "--ports", help="Explicit ports (e.g. 22,80,443 or 1-1000). Overrides profile.")
    scan_g.add_argument(
        "--vuln-scripts", action="store_true",
        help="Run nmap's --script vuln (slower, finds more).",
    )
    scan_g.add_argument("--nmap-scripts", help="Extra NSE scripts to run (comma-separated), e.g. vulners.")
    scan_g.add_argument("--os", dest="os_detect", action="store_true", help="Attempt OS detection (needs root).")
    scan_g.add_argument("--no-services", action="store_true", help="Only rate explicit vulns, not notable services.")
    scan_g.add_argument("--timeout", type=int, default=3600, help="nmap timeout in seconds.")

    enrich_g = p.add_argument_group("exploit enrichment (searchsploit / Exploit-DB)")
    enrich_g.add_argument("--no-searchsploit", action="store_true", help="Disable Exploit-DB lookups.")
    enrich_g.add_argument(
        "--no-service-exploits", action="store_true",
        help="Only look up exploits by CVE, skip product/version term searches.",
    )
    enrich_g.add_argument("--searchsploit-bin", default="searchsploit", help="searchsploit executable to use.")

    rate_g = p.add_argument_group("rating (Ollama)")
    rate_g.add_argument("--model", default=DEFAULT_MODEL, help="Ollama model name.")
    rate_g.add_argument("--ollama-host", default=DEFAULT_HOST, help="Ollama base URL.")
    rate_g.add_argument("--no-rate", action="store_true", help="Skip LLM rating (use heuristics only).")
    rate_g.add_argument("--rate-timeout", type=int, default=120, help="Per-finding LLM timeout (s).")

    out_g = p.add_argument_group("output")
    out_g.add_argument("-o", "--output", default="reports", help="Directory for report files.")
    out_g.add_argument("--format", choices=["json", "md", "all", "none"], default="all", help="Report file format(s).")
    out_g.add_argument("-q", "--quiet", action="store_true", help="Suppress the banner and progress logs.")
    out_g.add_argument("-v", "--verbose", action="store_true", help="Show the nmap command and extra logs.")
    out_g.add_argument("--version", action="version", version=f"scry {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.quiet:
        print(BANNER, file=sys.stderr)

    # 1. Scan
    try:
        if not args.quiet:
            print(f"[*] Scanning {args.target} (profile={args.profile}) ...", file=sys.stderr, flush=True)
        result = scan(
            args.target,
            profile=args.profile,
            ports=args.ports,
            vuln_scripts=args.vuln_scripts,
            extra_scripts=args.nmap_scripts,
            os_detect=args.os_detect,
            timeout=args.timeout,
            verbose=args.verbose,
        )
    except ScanError as exc:
        print(f"[!] Scan failed: {exc}", file=sys.stderr)
        return 2

    # 2. Enrich into findings
    build_findings(result, include_services=not args.no_services)
    findings = result.all_findings()
    if not args.quiet:
        print(f"[*] {len(findings)} finding(s) across {len(result.hosts)} host(s).", file=sys.stderr, flush=True)

    # 3. Exploit enrichment via searchsploit (before rating so ratings see it)
    ss = Searchsploit(binary=args.searchsploit_bin, enabled=not args.no_searchsploit)
    if not args.no_searchsploit and findings:
        if not ss.available():
            print("[!] searchsploit not found; skipping Exploit-DB enrichment.", file=sys.stderr)
        else:
            enrich_findings(
                result, ss,
                service_search=not args.no_service_exploits,
                progress=not args.quiet,
            )
            n_expl = sum(len(f.exploits) for f in findings)
            if not args.quiet:
                print(f"[*] {n_expl} exploit match(es) from Exploit-DB.", file=sys.stderr, flush=True)

    # 4. Rate
    rater = Rater(
        host=args.ollama_host,
        model=args.model,
        timeout=args.rate_timeout,
        enabled=not args.no_rate,
    )
    if not args.no_rate and findings:
        if not rater.available():
            print(f"[!] Ollama not reachable at {args.ollama_host}; falling back to heuristics.", file=sys.stderr)
        elif not rater.ensure_model():
            print(f"[!] Model '{args.model}' not found in Ollama. Run: ollama pull {args.model}", file=sys.stderr)
            print("[!] Falling back to heuristic ratings.", file=sys.stderr)
            rater.enabled = False
    rater.rate_all(findings, progress=not args.quiet)

    # 5. Report
    to_terminal(result)
    if args.format != "none":
        written = write_outputs(result, args.output, args.format)
        for path in written:
            print(f"[*] Wrote {path}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
