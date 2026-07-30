# Scry

Automated **recon for CTFs**: scan ports, surface likely vulnerabilities, and
rate each finding by severity, exploitability, and how useful it is for grabbing
a flag — then hand you concrete next steps.

Two rating modes, picked with `--mode`:

- **`ollama`** (default) — a **local LLM** judges each finding and explains itself.
- **`raster`** — a **deterministic scoring grid**, no AI: same input, same score,
  every time. Also the automatic fallback when Ollama is unreachable.

Runs as a single command or as a self-contained Docker stack (scanner + Ollama).

```
■ Host 10.10.10.5  [up]
  Open ports:
     21/tcp  ftp   vsftpd 2.3.4
     22/tcp  ssh   OpenSSH 7.2p2
     80/tcp  http  Apache httpd 2.4.18
  Findings (highest priority first):
    [ CRITICAL ]  9.8  ftp-vsftpd-backdoor on 21/tcp
           exploit: public Metasploit module, trivial
           ctf:     direct root shell → likely both flags
           next:    msfconsole -q -x "use exploit/unix/ftp/vsftpd_234_backdoor"
                    searchsploit vsftpd 2.3.4
```

> **Scope / ethics.** Built for authorized CTF boxes, lab ranges, and machines
> you own or have written permission to test. Port scanning and vuln probing
> uninvited systems is illegal in most places. You are responsible for staying
> in scope.

---

## How it works

```
 target ─▶ scanner.py ─▶ vuln.py ─▶ enrich.py ─▶ rater.py ─▶ report.py
           (nmap -sV     (findings:  (searchsploit  (ollama LLM  (terminal +
            + NSE vuln)   NSE/CVE/     Exploit-DB     or raster   JSON + Markdown)
                          services)    lookups)       grid)
```

1. **Scan** — wraps `nmap` for port discovery + service/version detection, with
   an optional `--script vuln` pass. Output is parsed straight from nmap XML.
2. **Enrich (findings)** — builds rate-able *findings* from NSE vuln hits, any
   `CVE-…` IDs in script output, and otherwise-notable services.
3. **Enrich (exploits)** — `searchsploit` looks up public Exploit-DB entries for
   each finding: by **CVE id** (high confidence) and by **product/version** term
   (a hint). Matches (EDB-ID, title, local path, CVE codes) are attached.
4. **Rate** — two modes, chosen with `--mode`:
   - **`ollama`** (default) — each finding is sent to a local Ollama model, which
     returns structured JSON (severity, 0–10 score, exploitability, CTF
     relevance, reasoning, next steps). Known public exploits are fed into the
     prompt and weighed heavily. If Ollama is down, Scry falls back to the raster
     grid so a scan still yields output.
   - **`raster`** (`--mode raster`, or the `--no-rate` alias) — a deterministic
     scoring **grid** rates every finding with no AI at all:
     `base(kind) + exploit bonus + CVE bonus + service-risk bonus`, clamped 0–10
     and mapped to a severity band. Fully reproducible and offline; each rating's
     `reasoning` shows the exact component breakdown.
5. **Report** — prints a prioritized summary and writes `reports/<target>.json`
   and `reports/<target>.md`.

---

## Quick start (Docker — recommended)

Bundles the scanner with an Ollama service so you don't install anything but Docker.

```bash
cd Scry
cp .env.example .env                 # optionally pick a different OLLAMA_MODEL

docker compose up -d ollama          # start the LLM service
docker compose run --rm ollama-pull  # one-time: pull the rating model (~4-5 GB)
docker compose build scry       # build the scanner image (bundles Exploit-DB)

# scan a target
docker compose run --rm scry 10.10.10.5 --vuln-scripts
```

> The image bundles `searchsploit` + the full Exploit-DB (~1 GB shallow clone) so
> exploit lookups work offline. To build a lean image without it:
> `docker compose build --build-arg INSTALL_SEARCHSPLOIT=false scry`
> (then run with `--no-searchsploit`, or mount your own exploitdb checkout).

Reports appear in `./reports/`. The scanner container uses host networking so it
can reach targets on your CTF VPN/LAN exactly as host `nmap` would.

### Choosing a model

Any Ollama chat model works. CPU-friendly picks: `llama3.1`, `qwen2.5:7b`,
`mistral`. Set it once in `.env` (`OLLAMA_MODEL=...`) or per run with `--model`.
A GPU makes rating much faster — uncomment the `deploy:` block in
`docker-compose.yml`.

---

## Quick start (local, no Docker)

Requires `nmap` and Python 3.10+ on your PATH, plus an Ollama instance.

```bash
cd Scry
pip install .                        # installs the `scry` command
# or: pip install -r requirements.txt && python -m scry ...

# make sure Ollama is running and the model is pulled:
ollama serve &                       # if not already running
ollama pull llama3.1

scry 10.10.10.5 --vuln-scripts
```

Point at a non-default Ollama with `--ollama-host http://host:11434` or the
`OLLAMA_HOST` env var.

---

## Usage

```
scry <target> [options]
```

`<target>` is anything nmap accepts: `10.10.10.5`, `scanme.nmap.org`,
`192.168.1.0/24`, `10.10.10.1-20`.

| Option | Description |
|--------|-------------|
| `--profile {fast,default,thorough}` | `fast`=top 100 ports, `default`=top 1000, `thorough`=all 65535 |
| `-p, --ports 22,80,443` | Explicit ports/range (overrides `--profile`) |
| `--vuln-scripts` | Run nmap's `--script vuln` (slower, finds more) |
| `--nmap-scripts vulners` | Add extra NSE scripts (comma-separated) |
| `--os` | OS detection (needs root / `NET_RAW`) |
| `--no-services` | Rate only explicit vulns, skip notable-service findings |
| `--no-searchsploit` | Disable Exploit-DB (searchsploit) lookups |
| `--no-service-exploits` | Look up exploits by CVE only; skip product/version term searches |
| `--searchsploit-bin PATH` | Path to the `searchsploit` executable |
| `--mode {ollama,raster}` | Rating mode: `ollama`=local LLM (default), `raster`=deterministic scoring grid, no AI |
| `--model NAME` | Ollama model to rate with (ollama mode) |
| `--ollama-host URL` | Ollama base URL (default `http://localhost:11434`) |
| `--no-rate` | Deprecated alias for `--mode raster` |
| `-o, --output DIR` | Report directory (default `reports/`) |
| `--format {json,md,all,none}` | Which report files to write |
| `-q / -v` | Quiet / verbose |

### Examples

```bash
# Fast triage, no LLM — deterministic raster grid only
scry 10.10.10.5 --profile fast --mode raster

# Full vuln sweep rated by a specific model
scry 10.10.10.5 --profile thorough --vuln-scripts --model qwen2.5:7b

# CVE mapping via the third-party vulners NSE script (install it first),
# then let searchsploit pull matching Exploit-DB entries for each CVE
scry 10.10.10.5 --nmap-scripts vulners

# Trust CVE-based exploit matches only (no fuzzy product/version searches)
scry 10.10.10.5 --vuln-scripts --no-service-exploits

# Just the machine-readable report
scry 10.10.10.5 --format json -q
```

### Exploit enrichment (searchsploit)

Each finding is looked up in **Exploit-DB** via `searchsploit -j`:

- **By CVE** (`searchsploit --cve CVE-…`) — high confidence; a CVE-matched public
  exploit escalates the finding (in raster mode it adds the largest bonus, +3.5).
- **By product + version** (e.g. `vsftpd 2.3.4`) — a weaker hint; verify the
  version yourself. Disable with `--no-service-exploits`.

Matches appear in every output with their **EDB-ID**, type, Exploit-DB URL, and
**local path**, plus ready-to-run `searchsploit -x <id>` (view) and
`searchsploit -m <id>` (copy locally) next steps.

CVE lookups only fire when findings actually carry CVE ids, so pair this with
`--vuln-scripts` or `--nmap-scripts vulners` for the richest results. The Docker
image bundles searchsploit; for local runs install it (Kali: `apt install
exploitdb`, or clone the maintained mirror
`https://gitlab.com/exploit-database/exploitdb`) and run `searchsploit -u` to
update the DB.

> **Tip:** `-sS` (SYN) scans and `--os` need raw-socket privileges. The tool
> auto-uses a TCP connect scan (`-sT`) when not root, so it still works
> unprivileged — just a bit slower and noisier.

### Rating modes

**`--mode ollama`** (default) sends each finding to your local Ollama instance
one at a time — small models produce far more reliable JSON for a single item
than for a batch — and asks for severity, a 0–10 score, exploitability, CTF
relevance, reasoning, and next steps. Attached Exploit-DB matches go into the
prompt and are weighed heavily. If Ollama is unreachable, or the model isn't
pulled, or a response fails validation, Scry falls back to the raster grid.

**`--mode raster`** skips the LLM entirely and scores on a fixed additive grid:

| Component | Value |
|-----------|-------|
| Base — NSE vuln hit | 6.0 |
| Base — CVE finding | 5.5 |
| Base — notable service | 2.0 |
| CVE-matched public exploit | +3.5 |
| Term/version-matched exploit | +1.5 |
| Known CVE ids | +0.3 each, capped at +1.5 |
| Historically risky service (ftp, telnet, smb, rdp, vnc, …) | +1.0 |

The total is clamped to 0–10 and mapped to a band: **critical** ≥ 9,
**high** ≥ 7, **medium** ≥ 4, **low** ≥ 2, otherwise **info**. Every rating's
`reasoning` spells out the components that produced its score, e.g.
`raster grid: base 5.5 (cve) +3.5 CVE-matched exploit x2 +0.6 2 CVE(s) = 9.6`.

Use raster when you want speed, reproducible output for diffing, or a fully
offline run with no model pulled.

---

## Output

- **Terminal** — color-coded, highest-severity findings first.
- **`reports/<target>.json`** — full structured result (hosts → services →
  findings → ratings). Ideal for piping into other tooling.
- **`reports/<target>.md`** — shareable Markdown writeup with a severity summary,
  port tables, per-finding ratings, next steps, and collapsible raw NSE detail.

---

## Project layout

```
Scry/
├── scry/
│   ├── cli.py        # argument parsing + orchestration
│   ├── scanner.py    # nmap invocation + XML parsing
│   ├── vuln.py       # build findings from scan results
│   ├── enrich.py     # searchsploit / Exploit-DB lookups
│   ├── rater.py      # Ollama client + raster scoring grid
│   ├── report.py     # terminal / JSON / Markdown output
│   └── models.py     # dataclasses
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── pyproject.toml
```

## Notes & limitations

- Ratings — LLM opinion or raster score — exist to **triage and prioritize**, not
  to be ground truth. Always verify before firing exploits.
- nmap ships the `vuln` NSE category; `vulners` is third-party — install it into
  nmap's scripts dir if you want version→CVE mapping via `--nmap-scripts vulners`.
- searchsploit **term** matches (product/version) can have false positives —
  they're hints to verify, not confirmed exploits. CVE-matched entries are
  reliable. Keep the DB fresh with `searchsploit -u`.
- Small local models occasionally return imperfect JSON; the rater validates and
  falls back to the raster grid per-finding rather than failing the run. Each
  rating records which mode produced it in its `source` field (`ollama` /
  `raster`).
