"""nmap wrapper: run a scan and parse the XML output into models."""
from __future__ import annotations

import os
import shutil
import subprocess
import xml.etree.ElementTree as ET

from .models import HostResult, ScanResult, Service


# Scan profiles map a friendly name to nmap flags. -sV is always added for
# service/version detection since ratings depend on it.
PROFILES: dict[str, list[str]] = {
    "fast": ["-T4", "-F"],                       # top 100 ports
    "default": ["-T4", "--top-ports", "1000"],   # top 1000 ports
    "thorough": ["-T4", "-p-"],                  # all 65535 ports
}


class ScanError(RuntimeError):
    pass


def _have_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:  # non-unix
        return False


def build_command(
    target: str,
    profile: str = "default",
    ports: str | None = None,
    vuln_scripts: bool = False,
    extra_scripts: str | None = None,
    os_detect: bool = False,
    extra_args: list[str] | None = None,
) -> list[str]:
    nmap = shutil.which("nmap")
    if not nmap:
        raise ScanError("nmap not found on PATH. Install nmap or use the Docker image.")

    if profile not in PROFILES:
        raise ScanError(f"Unknown profile '{profile}'. Choose from: {', '.join(PROFILES)}")

    cmd = [nmap, "-sV"]
    # SYN scan is faster but needs raw sockets (root); fall back to connect scan.
    cmd.append("-sS" if _have_root() else "-sT")

    if ports:
        cmd += ["-p", ports]
    else:
        cmd += PROFILES[profile]

    scripts: list[str] = []
    if vuln_scripts:
        scripts.append("vuln")
    if extra_scripts:
        scripts.append(extra_scripts)
    if scripts:
        cmd += ["--script", ",".join(scripts)]

    if os_detect and _have_root():
        cmd.append("-O")

    if extra_args:
        cmd += extra_args

    cmd += ["-oX", "-", target]  # XML to stdout
    return cmd


def _parse_scripts(node: ET.Element) -> dict[str, str]:
    out: dict[str, str] = {}
    for script in node.findall("script"):
        sid = script.get("id", "")
        output = script.get("output", "")
        if sid:
            out[sid] = output.strip()
    return out


def parse_xml(xml_text: str, target: str) -> ScanResult:
    result = ScanResult(target=target)
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ScanError(f"Failed to parse nmap XML output: {exc}") from exc

    result.nmap_args = root.get("args", "")
    runstats = root.find("runstats/finished")
    if runstats is not None:
        result.finished = runstats.get("timestr", "")

    for host_node in root.findall("host"):
        status = host_node.find("status")
        if status is not None and status.get("state") == "down":
            continue

        addr = ""
        for a in host_node.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr", "")
                break
        if not addr:
            addr = target

        host = HostResult(host=addr, state="up")

        for hn in host_node.findall("hostnames/hostname"):
            name = hn.get("name")
            if name:
                host.hostnames.append(name)

        osmatch = host_node.find("os/osmatch")
        if osmatch is not None:
            host.os_guess = osmatch.get("name", "")

        ports_node = host_node.find("ports")
        if ports_node is not None:
            for p in ports_node.findall("port"):
                state_node = p.find("state")
                state = state_node.get("state", "") if state_node is not None else ""
                if state not in ("open", "open|filtered"):
                    continue

                svc = Service(
                    port=int(p.get("portid", 0)),
                    protocol=p.get("protocol", "tcp"),
                    state=state,
                )
                s = p.find("service")
                if s is not None:
                    svc.name = s.get("name", "")
                    svc.product = s.get("product", "")
                    svc.version = s.get("version", "")
                    svc.extrainfo = s.get("extrainfo", "")
                    svc.cpe = [c.text for c in s.findall("cpe") if c.text]
                svc.scripts = _parse_scripts(p)
                host.services.append(svc)

        result.hosts.append(host)

    return result


def run_scan(cmd: list[str], timeout: int = 3600, verbose: bool = False) -> str:
    """Run nmap and return its XML stdout. Raises ScanError on failure."""
    if verbose:
        print(f"[scanner] running: {' '.join(cmd)}", flush=True)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ScanError(f"nmap timed out after {timeout}s") from exc
    except FileNotFoundError as exc:
        raise ScanError("nmap executable not found") from exc

    if proc.returncode != 0 and not proc.stdout.strip():
        raise ScanError(f"nmap failed (exit {proc.returncode}): {proc.stderr.strip()}")
    return proc.stdout


def scan(
    target: str,
    profile: str = "default",
    ports: str | None = None,
    vuln_scripts: bool = False,
    extra_scripts: str | None = None,
    os_detect: bool = False,
    extra_args: list[str] | None = None,
    timeout: int = 3600,
    verbose: bool = False,
) -> ScanResult:
    cmd = build_command(
        target,
        profile=profile,
        ports=ports,
        vuln_scripts=vuln_scripts,
        extra_scripts=extra_scripts,
        os_detect=os_detect,
        extra_args=extra_args,
    )
    xml_text = run_scan(cmd, timeout=timeout, verbose=verbose)
    return parse_xml(xml_text, target)
