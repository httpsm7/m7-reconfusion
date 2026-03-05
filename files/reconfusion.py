#!/usr/bin/env python3
"""
ReconFusion M7 – Modular Recon & Vulnerability Automation Framework
Produced by MilkyWay Intelligence | M7 BATMAN Edition

PIPELINE (har step ka output agla step ka input hai):
──────────────────────────────────────────────────────────────────────
STEP 1  assetfinder + subfinder + amass (parallel)
           raw/assetfinder.txt
           raw/subfinder.txt
           raw/amass.txt
           ↓ merge + dedupe + normalize
        01_subdomains_all.txt          ← sirf domain format: sub.ex.com

STEP 2  httpx  ← 01_subdomains_all.txt
           02_live_hosts_urls.txt      ← URL format: https://sub.ex.com
           02_live_hosts_info.json     ← {url, status, title, server}

STEP 3  Strip https://  ← 02_live_hosts_urls.txt
           03_live_domains_clean.txt   ← domain: sub.ex.com  (nmap input)

STEP 4  naabu/nmap  ← 03_live_domains_clean.txt
           04_open_ports.txt           ← host:port
           04_open_ports.json

STEP 5  katana  ← 02_live_hosts_urls.txt
           05_crawled_urls.txt

STEP 6  ffuf  ← 02_live_hosts_urls.txt + wordlist
           06_fuzz_results.txt
           06_fuzz_results.json

STEP 7  dalfox  ← 05_crawled_urls.txt
           07_xss_findings.txt
           07_xss_findings.json

STEP 8  nuclei  ← 02_live_hosts_urls.txt
           08_nuclei_findings.txt
           08_nuclei_findings.json

STEP 9  Merge + dedupe  ← 07.json + 08.json
           09_all_findings.json

STEP 10 HTML Report  ← all data
           10_final_report.html
──────────────────────────────────────────────────────────────────────
"""

import argparse
import asyncio
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

# ── Bootstrap Python deps ──────────────────────────────────────────────────────
def bootstrap():
    for imp, pkg in [("rich", "rich"), ("jinja2", "jinja2")]:
        try:
            __import__(imp)
        except ImportError:
            print(f"[*] Installing {pkg}...")
            subprocess.run(
                [sys.executable, "-m", "pip", "install", pkg,
                 "--break-system-packages", "-q"],
                check=True,
            )

bootstrap()

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import jinja2

console = Console()

BANNER = """[bold yellow]
\u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2557   \u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2557   \u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2557   \u2588\u2588\u2557
\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d\u2588\u2588\u2554\u2550\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d\u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d\u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2551
\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2551     \u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2554\u2588\u2588\u2557 \u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2551\u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2554\u2588\u2588\u2557 \u2588\u2588\u2551
\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2554\u2550\u2550\u255d  \u2588\u2588\u2551     \u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2551\u255a\u2588\u2588\u2557\u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u255d  \u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u255d  \u2588\u2588\u2551\u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2551\u255a\u2588\u2588\u2557\u2588\u2588\u2551
\u2588\u2588\u2551  \u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2551 \u255a\u2588\u2588\u2588\u2588\u2551\u2588\u2588\u2551     \u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2551\u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2551 \u255a\u2588\u2588\u2588\u2588\u2551
\u255a\u2550\u255d  \u255a\u2550\u255d\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d \u255a\u2550\u2550\u2550\u2550\u2550\u255d \u255a\u2550\u2550\u2550\u2550\u2550\u255d \u255a\u2550\u255d  \u255a\u2550\u2550\u2550\u255d\u255a\u2550\u255d      \u255a\u2550\u2550\u2550\u2550\u2550\u255d\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d\u255a\u2550\u255d \u255a\u2550\u2550\u2550\u2550\u2550\u255d\u255a\u2550\u255d  \u255a\u2550\u2550\u2550\u255d
[/bold yellow][bold cyan]                    \u26a1 Modular Recon & Vulnerability Automation Framework \u26a1[/bold cyan]
[dim]                         Produced by MilkyWay Intelligence | M7 BATMAN Edition[/dim]
"""

# ── Tool install commands ──────────────────────────────────────────────────────
TOOL_INSTALL = {
    "assetfinder": "go install github.com/tomnomnom/assetfinder@latest",
    "subfinder":   "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "amass":       "sudo apt-get install -y amass",
    "httpx":       "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "naabu":       "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "nmap":        "sudo apt-get install -y nmap",
    "katana":      "go install github.com/projectdiscovery/katana/cmd/katana@latest",
    "ffuf":        "go install github.com/ffuf/ffuf/v2@latest",
    "dalfox":      "go install github.com/hahwul/dalfox/v2@latest",
    "nuclei":      "go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
}

WORDLISTS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "/usr/share/wordlists/dirb/small.txt",
]

# ── Helpers ────────────────────────────────────────────────────────────────────

def find_tool(name: str) -> str:
    """
    Find tool binary safely - no PermissionError.
    Checks home go/bin first, then system paths, then which.
    """
    candidates = [
        Path.home() / "go" / "bin" / name,
        Path("/usr/local/bin") / name,
        Path("/usr/bin") / name,
        Path("/snap/bin") / name,
    ]
    for c in candidates:
        try:
            if c.exists() and os.access(str(c), os.X_OK):
                return str(c)
        except (PermissionError, OSError):
            continue
    r = subprocess.run(["which", name], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else name


def tool_exists(name: str) -> bool:
    try:
        path = find_tool(name)
        if path != name:
            return True
        return subprocess.run(["which", name], capture_output=True).returncode == 0
    except Exception:
        return False


def run_cmd(cmd: list, timeout: int = 600, stdin_data: str = None):
    """Run a command. Returns (stdout, stderr, returncode)."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, input=stdin_data,
        )
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", f"TIMEOUT after {timeout}s", 1
    except FileNotFoundError:
        return "", f"NOT FOUND: {cmd[0]}", 127
    except Exception as e:
        return "", str(e), 1


def read_lines(path: Path) -> list:
    if not path.exists():
        return []
    return [l.strip() for l in path.read_text(errors="ignore").splitlines() if l.strip()]


def write_lines(path: Path, lines: list):
    path.write_text("\n".join(lines) + ("\n" if lines else ""))


def url_to_domain(url: str) -> str:
    """https://sub.example.com/any/path?q=1  →  sub.example.com"""
    url = url.strip()
    if not url:
        return ""
    if "://" not in url:
        url = "http://" + url
    try:
        h = urlparse(url).hostname or ""
        return h.lower().strip(".")
    except Exception:
        return url


def find_wordlist():
    for w in WORDLISTS:
        if Path(w).exists():
            return w
    return None


# ── Printing helpers ───────────────────────────────────────────────────────────
def step_banner(n: int, title: str, detail: str = ""):
    body = f"[dim]{detail}[/dim]" if detail else ""
    console.print(Panel(
        body,
        title=f"[bold yellow]STEP {n:02d}  ─  {title}[/bold yellow]",
        border_style="yellow", padding=(0, 2),
    ))

def ok(m):   console.print(f"  [bold green]\u2714[/bold green]  {m}")
def info(m): console.print(f"  [cyan]\u2192[/cyan]  {m}")
def warn(m): console.print(f"  [yellow]\u26a0[/yellow]  {m}")
def fail(m): console.print(f"  [red]\u2718[/red]  {m}")


# ── ReconFusion class ──────────────────────────────────────────────────────────

class ReconFusion:

    def __init__(self, target: str, outdir: str):
        # Normalize target: strip protocol & trailing slash
        t = target.strip().lower()
        t = re.sub(r"^https?://", "", t).rstrip("/")
        self.target    = t
        self.outdir    = Path(outdir)
        self.start_ts  = datetime.now()
        self.log_path  = self.outdir / "reconfusion.log"

        # Pipeline state ─ passed between steps
        self.subdomains:   list = []   # sub.example.com
        self.live_urls:    list = []   # https://sub.example.com
        self.live_info:    list = []   # [{url, status, title, server}]
        self.live_domains: list = []   # sub.example.com  (for nmap)
        self.open_ports:   list = []   # [{host, ip, port, tool}]
        self.crawled_urls: list = []   # all katana output
        self.findings:     list = []   # all vulnerabilities

        self.stats = {
            "subdomains":   0,
            "live_hosts":   0,
            "open_ports":   0,
            "crawled_urls": 0,
            "fuzz_hits":    0,
            "vulns": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        }

    # ── Helpers ──────────────────────────────────────────────────────────────

    def setup_dirs(self):
        self.outdir.mkdir(parents=True, exist_ok=True)
        (self.outdir / "raw").mkdir(exist_ok=True)
        (self.outdir / "raw_fuzz").mkdir(exist_ok=True)
        self.log_path.touch()

    def log(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        with open(self.log_path, "a") as f:
            f.write(f"[{ts}] {msg}\n")

    def p(self, step: int, name: str) -> Path:
        """Numbered output file path: step=2, name=live_hosts_urls.txt → outdir/02_live_hosts_urls.txt"""
        return self.outdir / f"{step:02d}_{name}"

    # ══════════════════════════════════════════════════════════════════════════
    # AUTH
    # ══════════════════════════════════════════════════════════════════════════
    def phase_auth(self) -> bool:
        console.print(Panel(
            "[bold red]\u26a0  LEGAL DISCLAIMER[/bold red]\n\n"
            "[yellow]This tool is for AUTHORIZED security testing ONLY.\n"
            "Unauthorized scanning is ILLEGAL.\n"
            "You must have explicit written permission to test the target.[/yellow]",
            border_style="red",
        ))
        console.print(f"\n  Target : [bold cyan]{self.target}[/bold cyan]")
        console.print(f"  Output : [bold cyan]{self.outdir}[/bold cyan]")
        console.print(f"  Time   : [bold cyan]{self.start_ts.strftime('%Y-%m-%d %H:%M:%S')}[/bold cyan]\n")
        ans = console.input(
            "[bold yellow]  Do you have written authorization to test this target? (yes/no): [/bold yellow]"
        ).strip().lower()
        if ans not in ("yes", "y"):
            console.print("[red]  Exiting — authorization not confirmed.[/red]")
            return False
        self.setup_dirs()
        self.log(f"AUTH OK for: {self.target}")
        ok("Authorization confirmed.")
        return True

    # ══════════════════════════════════════════════════════════════════════════
    # TOOL CHECK
    # ══════════════════════════════════════════════════════════════════════════
    def phase_tools(self):
        console.print(Panel(
            "[bold cyan]Checking all required tools...[/bold cyan]",
            title="[bold yellow]\u2699  TOOL CHECK[/bold yellow]",
            border_style="yellow",
        ))
        for tool, install_cmd in TOOL_INSTALL.items():
            if tool_exists(tool):
                path = find_tool(tool)
                ok(f"[cyan]{tool:15}[/cyan] [dim]{path}[/dim]")
                self.log(f"TOOL OK: {tool} @ {path}")
            else:
                warn(f"[cyan]{tool:15}[/cyan] not found — installing...")
                env = os.environ.copy()
                env["PATH"] = env.get("PATH", "") + ":" + str(Path.home() / "go" / "bin")
                r = subprocess.run(
                    install_cmd, shell=True, capture_output=True,
                    text=True, timeout=180, env=env,
                )
                if r.returncode == 0:
                    ok(f"{tool} installed successfully.")
                else:
                    fail(f"{tool} install failed.\n     Run manually: [dim]{install_cmd}[/dim]")
                self.log(f"INSTALL {tool}: rc={r.returncode}")

    # ══════════════════════════════════════════════════════════════════════════
    # STEP 1 — Subdomain Enumeration
    # OUTPUT : 01_subdomains_all.txt
    # ══════════════════════════════════════════════════════════════════════════
    async def step01_subdomains(self):
        step_banner(1, "SUBDOMAIN ENUMERATION",
                    "assetfinder + subfinder + amass (parallel) → merge → dedupe → 01_subdomains_all.txt")

        raw = self.outdir / "raw"
        await asyncio.gather(
            self._assetfinder(raw),
            self._subfinder(raw),
            self._amass(raw),
        )

        merged: set = set()
        for fname in ["assetfinder.txt", "subfinder.txt", "amass.txt"]:
            for line in read_lines(raw / fname):
                d = url_to_domain(line).strip(".*")
                if d and (d == self.target or d.endswith("." + self.target)):
                    merged.add(d)

        self.subdomains = sorted(merged)
        out = self.p(1, "subdomains_all.txt")
        write_lines(out, self.subdomains)
        self.stats["subdomains"] = len(self.subdomains)
        self.log(f"STEP1: {len(self.subdomains)} unique subdomains")
        ok(f"{len(self.subdomains)} unique subdomains  →  [bold]{out.name}[/bold]")

    async def _assetfinder(self, raw: Path):
        with console.status("  [dim]assetfinder...[/dim]"):
            out, err, rc = run_cmd([find_tool("assetfinder"), "--subs-only", self.target])
            (raw / "assetfinder.txt").write_text(out)
            info(f"assetfinder  → {len(out.splitlines())} lines  (raw/assetfinder.txt)")
            self.log(f"assetfinder rc={rc} err={err[:60]}")

    async def _subfinder(self, raw: Path):
        with console.status("  [dim]subfinder...[/dim]"):
            f = raw / "subfinder.txt"
            # subfinder -d target -o file -silent
            out, err, rc = run_cmd([find_tool("subfinder"), "-d", self.target, "-o", str(f), "-silent"])
            if not f.exists() or f.stat().st_size == 0:
                f.write_text(out)
            info(f"subfinder    → {len(read_lines(f))} lines  (raw/subfinder.txt)")
            self.log(f"subfinder rc={rc} err={err[:60]}")

    async def _amass(self, raw: Path):
        with console.status("  [dim]amass (passive)...[/dim]"):
            f = raw / "amass.txt"
            # amass enum -passive -d target -o file
            out, err, rc = run_cmd(
                ["amass", "enum", "-passive", "-d", self.target, "-o", str(f)],
                timeout=240,
            )
            if not f.exists() or f.stat().st_size == 0:
                f.write_text(out)
            info(f"amass        → {len(read_lines(f))} lines  (raw/amass.txt)")
            self.log(f"amass rc={rc} err={err[:60]}")

    # ══════════════════════════════════════════════════════════════════════════
    # STEP 2 — Live Host Detection
    # INPUT  : 01_subdomains_all.txt   (domain format)
    # OUTPUT : 02_live_hosts_urls.txt  (URL format)
    #          02_live_hosts_info.json
    # ══════════════════════════════════════════════════════════════════════════
    def step02_live_hosts(self):
        step_banner(2, "LIVE HOST DETECTION",
                    "httpx ← 01_subdomains_all.txt  →  02_live_hosts_urls.txt  +  02_live_hosts_info.json")

        in_f = self.p(1, "subdomains_all.txt")
        if not in_f.exists() or in_f.stat().st_size == 0:
            warn("01_subdomains_all.txt is empty. Skipping httpx.")
            return

        httpx = find_tool("httpx")
        info(f"Using: {httpx}")

        # httpx v1.8.x exact flags:
        # -l list  -sc status-code  -title  -server  -ct content-type
        # -json    -silent  -timeout 10  -threads 50  -retries 1
        out, err, rc = run_cmd([
            httpx,
            "-l",       str(in_f),
            "-sc",               # status code
            "-title",            # page title
            "-server",           # server header
            "-ct",               # content-type
            "-json",             # JSON per line
            "-silent",
            "-timeout", "10",
            "-threads", "50",
            "-retries", "1",
        ], timeout=900)

        self.log(f"httpx rc={rc} stderr={err[:100]}")

        urls, records = [], []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
                url    = r.get("url", "")
                status = r.get("status-code", r.get("status_code", 0))
                server = r.get("webserver", r.get("server", ""))
                ct     = r.get("content-type", r.get("content_type", ""))
                title  = r.get("title", "")
                if url:
                    urls.append(url)
                    records.append({"url": url, "status": status,
                                    "server": server, "content_type": ct, "title": title})
            except json.JSONDecodeError:
                if line.startswith("http"):
                    urls.append(line.split()[0])

        # Fallback: plain output mode if JSON gave nothing
        if not urls:
            warn("JSON mode returned 0 results. Retrying in plain mode...")
            out2, _, _ = run_cmd([
                httpx, "-l", str(in_f),
                "-sc", "-title", "-silent",
                "-timeout", "10", "-threads", "50",
            ], timeout=900)
            for line in out2.splitlines():
                line = line.strip()
                if not line or "http" not in line:
                    continue
                parts = line.split()
                url = parts[0]
                try:
                    status = int(parts[1].strip("[]"))
                except (IndexError, ValueError):
                    status = 0
                urls.append(url)
                records.append({"url": url, "status": status,
                                "server": "", "content_type": "", "title": ""})

        self.live_urls = urls
        self.live_info = records
        write_lines(self.p(2, "live_hosts_urls.txt"), urls)
        self.p(2, "live_hosts_info.json").write_text(json.dumps(records, indent=2))
        self.stats["live_hosts"] = len(urls)
        self.log(f"STEP2: {len(urls)} live hosts")
        ok(f"{len(urls)} live hosts  →  [bold]02_live_hosts_urls.txt[/bold]  +  02_live_hosts_info.json")

    # ══════════════════════════════════════════════════════════════════════════
    # STEP 3 — Strip URLs → Clean Domains  (nmap can't take https://)
    # INPUT  : 02_live_hosts_urls.txt
    # OUTPUT : 03_live_domains_clean.txt   ← nmap input
    # ══════════════════════════════════════════════════════════════════════════
    def step03_clean_domains(self):
        step_banner(3, "STRIP URLs  →  CLEAN DOMAINS  (nmap input)",
                    "02_live_hosts_urls.txt  →  03_live_domains_clean.txt")

        urls = read_lines(self.p(2, "live_hosts_urls.txt"))
        domains = sorted(set(url_to_domain(u) for u in urls if u))
        self.live_domains = domains
        write_lines(self.p(3, "live_domains_clean.txt"), domains)
        self.log(f"STEP3: {len(domains)} clean domains")
        ok(f"{len(domains)} clean domains  →  [bold]03_live_domains_clean.txt[/bold]")

    # ══════════════════════════════════════════════════════════════════════════
    # STEP 4 — Port Scanning
    # INPUT  : 03_live_domains_clean.txt  (domain format, NO https://)
    # OUTPUT : 04_open_ports.txt  |  04_open_ports.json
    # ══════════════════════════════════════════════════════════════════════════
    def step04_ports(self):
        step_banner(4, "PORT SCANNING",
                    "naabu/nmap ← 03_live_domains_clean.txt  →  04_open_ports.txt  +  04_open_ports.json")

        in_f = self.p(3, "live_domains_clean.txt")
        if not in_f.exists() or in_f.stat().st_size == 0:
            warn("03_live_domains_clean.txt is empty. Skipping port scan.")
            return

        records = []

        if tool_exists("naabu"):
            info(f"Using naabu: {find_tool('naabu')}")
            # naabu -list domains.txt -json -silent -top-ports 1000
            out, err, rc = run_cmd([
                find_tool("naabu"),
                "-list",      str(in_f),
                "-json",
                "-silent",
                "-top-ports", "1000",
            ], timeout=600)
            self.log(f"naabu rc={rc} err={err[:80]}")
            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                    # naabu JSON: {"ip":"1.2.3.4","port":80,"host":"sub.example.com"}
                    records.append({
                        "host": r.get("host", r.get("ip", "")),
                        "ip":   r.get("ip", ""),
                        "port": str(r.get("port", "")),
                        "tool": "naabu",
                    })
                except json.JSONDecodeError:
                    pass
        else:
            info("naabu not found, using nmap.")
            # nmap -iL domains.txt --top-ports 1000 --open -T4 -oN file
            nmap_raw = self.outdir / "raw" / "nmap_raw.txt"
            out, err, rc = run_cmd([
                "nmap", "-iL", str(in_f),
                "--top-ports", "1000",
                "--open", "-T4",
                "-oN", str(nmap_raw),
            ], timeout=900)
            self.log(f"nmap rc={rc} err={err[:80]}")
            current_host = ""
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("Nmap scan report for"):
                    # "Nmap scan report for sub.example.com (1.2.3.4)"
                    parts = line.split()
                    current_host = parts[-1].strip("()")
                elif "/tcp" in line or "/udp" in line:
                    p = line.split()
                    if len(p) >= 2 and p[1] == "open":
                        port = p[0].split("/")[0]
                        records.append({
                            "host": current_host,
                            "ip":   current_host,
                            "port": port,
                            "tool": "nmap",
                        })

        write_lines(self.p(4, "open_ports.txt"),
                    [f"{r['host']}:{r['port']}" for r in records])
        self.p(4, "open_ports.json").write_text(json.dumps(records, indent=2))
        self.open_ports = records
        self.stats["open_ports"] = len(records)
        self.log(f"STEP4: {len(records)} open ports")
        ok(f"{len(records)} open ports  →  [bold]04_open_ports.txt[/bold]  +  04_open_ports.json")

    # ══════════════════════════════════════════════════════════════════════════
    # STEP 5 — URL Crawling (katana)
    # INPUT  : 02_live_hosts_urls.txt
    # OUTPUT : 05_crawled_urls.txt
    # ══════════════════════════════════════════════════════════════════════════
    def step05_katana(self):
        step_banner(5, "URL CRAWLING  —  katana",
                    "katana ← 02_live_hosts_urls.txt  →  05_crawled_urls.txt")

        in_f  = self.p(2, "live_hosts_urls.txt")
        out_f = self.p(5, "crawled_urls.txt")

        if not in_f.exists() or in_f.stat().st_size == 0:
            warn("02_live_hosts_urls.txt is empty. Skipping katana.")
            write_lines(out_f, [])
            return

        katana = find_tool("katana")
        info(f"Using: {katana}")

        # katana -list file -o out -silent -d 3 -jc -timeout 10 -retry 1
        out, err, rc = run_cmd([
            katana,
            "-list",    str(in_f),
            "-o",       str(out_f),
            "-silent",
            "-d",       "3",
            "-jc",               # JS file crawling
            "-timeout", "10",
            "-retry",   "1",
        ], timeout=600)

        # If -o didn't write (older katana), use stdout
        if not out_f.exists() or out_f.stat().st_size == 0:
            out_f.write_text(out)

        self.crawled_urls = read_lines(out_f)
        self.stats["crawled_urls"] = len(self.crawled_urls)
        self.log(f"STEP5: {len(self.crawled_urls)} crawled URLs rc={rc}")
        ok(f"{len(self.crawled_urls)} URLs crawled  →  [bold]05_crawled_urls.txt[/bold]")

    # ══════════════════════════════════════════════════════════════════════════
    # STEP 6 — Directory Fuzzing (ffuf)
    # INPUT  : 02_live_hosts_urls.txt  (first 10 hosts)
    # OUTPUT : 06_fuzz_results.txt  |  06_fuzz_results.json
    # ══════════════════════════════════════════════════════════════════════════
    def step06_fuzz(self):
        step_banner(6, "DIRECTORY FUZZING  —  ffuf",
                    "ffuf ← 02_live_hosts_urls.txt + wordlist  →  06_fuzz_results.txt")

        if not tool_exists("ffuf"):
            warn("ffuf not found. Skipping.")
            return

        wordlist = find_wordlist()
        if not wordlist:
            warn("No wordlist found. Install: sudo apt install wordlists seclists")
            return

        in_f    = self.p(2, "live_hosts_urls.txt")
        out_txt = self.p(6, "fuzz_results.txt")
        out_json= self.p(6, "fuzz_results.json")
        raw_dir = self.outdir / "raw_fuzz"

        urls = read_lines(in_f)
        if not urls:
            warn("No URLs to fuzz.")
            return

        ffuf      = find_tool("ffuf")
        all_hits  = []
        info(f"Using: {ffuf}  |  Wordlist: {wordlist}")
        info(f"Fuzzing {min(10, len(urls))} hosts...")

        for url in urls[:10]:
            base      = url.rstrip("/")
            safe_name = re.sub(r"[^\w]", "_", base)[:50]
            j_out     = raw_dir / f"{safe_name}.json"

            # ffuf -u URL/FUZZ -w wordlist -o out.json -of json
            #      -mc 200,201,204,301,302,307,401,403  -t 50 -timeout 10 -s
            out, err, rc = run_cmd([
                ffuf,
                "-u",  f"{base}/FUZZ",
                "-w",  wordlist,
                "-o",  str(j_out),
                "-of", "json",
                "-mc", "200,201,204,301,302,307,401,403",
                "-t",  "50",
                "-timeout", "10",
                "-s",       # silent
            ], timeout=180)
            self.log(f"ffuf {base}: rc={rc} err={err[:60]}")

            if j_out.exists():
                try:
                    data = json.loads(j_out.read_text())
                    for r in data.get("results", []):
                        all_hits.append({
                            "url":    r.get("url", ""),
                            "status": r.get("status", 0),
                            "length": r.get("length", 0),
                        })
                except Exception:
                    pass

        out_json.write_text(json.dumps(all_hits, indent=2))
        write_lines(out_txt, [f"{h['status']}  {h['url']}" for h in all_hits])
        self.stats["fuzz_hits"] = len(all_hits)
        self.log(f"STEP6: {len(all_hits)} fuzz hits")
        ok(f"{len(all_hits)} directories found  →  [bold]06_fuzz_results.txt[/bold]  +  06_fuzz_results.json")

    # ══════════════════════════════════════════════════════════════════════════
    # STEP 7 — XSS Scanning (dalfox)
    # INPUT  : 05_crawled_urls.txt
    # OUTPUT : 07_xss_findings.txt  |  07_xss_findings.json
    # ══════════════════════════════════════════════════════════════════════════
    def step07_dalfox(self):
        step_banner(7, "XSS SCANNING  —  dalfox",
                    "dalfox ← 05_crawled_urls.txt  →  07_xss_findings.txt  +  07_xss_findings.json")

        in_f    = self.p(5, "crawled_urls.txt")
        out_txt = self.p(7, "xss_findings.txt")
        out_json= self.p(7, "xss_findings.json")

        if not in_f.exists() or in_f.stat().st_size == 0:
            warn("05_crawled_urls.txt is empty. Skipping dalfox.")
            out_json.write_text("[]")
            write_lines(out_txt, [])
            return

        dalfox = find_tool("dalfox")
        info(f"Using: {dalfox}")

        # dalfox file <input> -o <out> --silence --format json --timeout 10 --mass
        out, err, rc = run_cmd([
            dalfox,
            "file",       str(in_f),
            "-o",         str(out_txt),
            "--silence",
            "--format",   "json",
            "--timeout",  "10",
            "--mass",
        ], timeout=600)
        self.log(f"dalfox rc={rc} err={err[:100]}")

        raw_text = ""
        if out_txt.exists():
            raw_text = out_txt.read_text(errors="ignore")
        raw_text += "\n" + out

        hits = []
        for line in raw_text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
                hits.append({
                    "type":      "XSS",
                    "url":       r.get("data", {}).get("url", r.get("url", "")),
                    "parameter": r.get("data", {}).get("param", r.get("param", "")),
                    "payload":   r.get("data", {}).get("payload", ""),
                    "severity":  "high",
                    "tool":      "dalfox",
                    "detail":    "",
                })
            except json.JSONDecodeError:
                if "[POC]" in line or "XSS" in line.upper():
                    hits.append({
                        "type": "XSS", "url": line,
                        "parameter": "", "payload": "",
                        "severity": "high", "tool": "dalfox", "detail": "",
                    })

        out_json.write_text(json.dumps(hits, indent=2))
        self.findings.extend(hits)
        self.stats["vulns"]["high"] += len(hits)
        self.log(f"STEP7: {len(hits)} XSS findings")
        ok(f"{len(hits)} XSS findings  →  [bold]07_xss_findings.txt[/bold]  +  07_xss_findings.json")

    # ══════════════════════════════════════════════════════════════════════════
    # STEP 8 — Nuclei Template Scan
    # INPUT  : 02_live_hosts_urls.txt
    # OUTPUT : 08_nuclei_findings.txt  |  08_nuclei_findings.json
    # ══════════════════════════════════════════════════════════════════════════
    def step08_nuclei(self):
        step_banner(8, "VULNERABILITY SCAN  —  nuclei",
                    "nuclei ← 02_live_hosts_urls.txt  →  08_nuclei_findings.txt  +  08_nuclei_findings.json")

        in_f    = self.p(2, "live_hosts_urls.txt")
        out_txt = self.p(8, "nuclei_findings.txt")
        out_json= self.p(8, "nuclei_findings.json")

        if not in_f.exists() or in_f.stat().st_size == 0:
            warn("02_live_hosts_urls.txt is empty. Skipping nuclei.")
            out_json.write_text("[]")
            return

        nuclei = find_tool("nuclei")
        info(f"Using: {nuclei}")

        with console.status("  [dim]Updating nuclei templates...[/dim]"):
            run_cmd([nuclei, "-update-templates", "-silent"], timeout=120)

        # nuclei -l file -o out -j -silent -s critical,high,medium,low -timeout 10 -retries 1 -rate-limit 100
        out, err, rc = run_cmd([
            nuclei,
            "-l",          str(in_f),
            "-o",          str(out_txt),
            "-j",                         # JSON output
            "-silent",
            "-s",          "critical,high,medium,low",
            "-timeout",    "10",
            "-retries",    "1",
            "-rate-limit", "100",
        ], timeout=1800)
        self.log(f"nuclei rc={rc} err={err[:100]}")

        raw_text = ""
        if out_txt.exists():
            raw_text = out_txt.read_text(errors="ignore")
        raw_text += "\n" + out

        hits = []
        for line in raw_text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r   = json.loads(line)
                inf = r.get("info", {})
                sev = inf.get("severity", "info").lower()
                hits.append({
                    "type":      inf.get("name", r.get("template-id", "unknown")),
                    "url":       r.get("matched-at", r.get("host", "")),
                    "parameter": "",
                    "payload":   str(r.get("extracted-results", "")),
                    "severity":  sev,
                    "tool":      "nuclei",
                    "detail":    r.get("template-id", ""),
                })
                bucket = sev if sev in self.stats["vulns"] else "info"
                self.stats["vulns"][bucket] += 1
            except json.JSONDecodeError:
                pass

        out_json.write_text(json.dumps(hits, indent=2))
        self.findings.extend(hits)
        self.log(f"STEP8: {len(hits)} nuclei findings")
        ok(f"{len(hits)} findings  →  [bold]08_nuclei_findings.txt[/bold]  +  08_nuclei_findings.json")

    # ══════════════════════════════════════════════════════════════════════════
    # STEP 9 — Merge & Dedupe All Findings
    # INPUT  : 07_xss_findings.json  +  08_nuclei_findings.json
    # OUTPUT : 09_all_findings.json
    # ══════════════════════════════════════════════════════════════════════════
    def step09_merge(self):
        step_banner(9, "MERGE & DEDUPE",
                    "07_xss + 08_nuclei  →  09_all_findings.json")

        seen, unique = set(), []
        for f in self.findings:
            key = (f.get("type", ""), f.get("url", ""), f.get("parameter", ""))
            if key not in seen:
                seen.add(key)
                unique.append(f)

        self.findings = unique
        self.p(9, "all_findings.json").write_text(json.dumps(unique, indent=2))

        # Recount severity stats
        for k in self.stats["vulns"]:
            self.stats["vulns"][k] = 0
        for f in unique:
            b = f.get("severity", "info")
            if b in self.stats["vulns"]:
                self.stats["vulns"][b] += 1
            else:
                self.stats["vulns"]["info"] += 1

        self.log(f"STEP9: {len(unique)} unique findings")
        ok(f"{len(unique)} unique findings  →  [bold]09_all_findings.json[/bold]")

        t = Table(title="\U0001f4ca Scan Summary", border_style="yellow", header_style="bold yellow")
        t.add_column("Metric",  style="cyan")
        t.add_column("Count",   justify="right", style="bold white")
        t.add_row("Subdomains",   str(self.stats["subdomains"]))
        t.add_row("Live Hosts",   str(self.stats["live_hosts"]))
        t.add_row("Open Ports",   str(self.stats["open_ports"]))
        t.add_row("Crawled URLs", str(self.stats["crawled_urls"]))
        t.add_row("Fuzz Hits",    str(self.stats["fuzz_hits"]))
        t.add_row("[red]Critical[/red]",  f"[red]{self.stats['vulns']['critical']}[/red]")
        t.add_row("[orange1]High[/orange1]",    f"[orange1]{self.stats['vulns']['high']}[/orange1]")
        t.add_row("[yellow]Medium[/yellow]",  f"[yellow]{self.stats['vulns']['medium']}[/yellow]")
        t.add_row("[blue]Low[/blue]",       f"[blue]{self.stats['vulns']['low']}[/blue]")
        t.add_row("[dim]Info[/dim]",         f"[dim]{self.stats['vulns']['info']}[/dim]")
        console.print(t)

    # ══════════════════════════════════════════════════════════════════════════
    # STEP 10 — HTML Report
    # OUTPUT : 10_final_report.html
    # ══════════════════════════════════════════════════════════════════════════
    def step10_report(self) -> Path:
        step_banner(10, "HTML REPORT GENERATOR",
                    "Jinja2 + Bootstrap  →  10_final_report.html")

        tv = {}
        for t in ["httpx", "nuclei", "subfinder", "katana", "dalfox", "ffuf", "nmap", "naabu"]:
            p = find_tool(t)
            o1, _, _ = run_cmd([p, "-version"],  timeout=5)
            o2, _, _ = run_cmd([p, "--version"], timeout=5)
            tv[t] = ((o1 or o2 or "").strip().split("\n")[0])[:60] or "N/A"

        html = jinja2.Template(HTML_TEMPLATE).render(
            target        = self.target,
            scan_date     = self.start_ts.strftime("%Y-%m-%d %H:%M:%S"),
            end_time      = datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            stats         = self.stats,
            subdomains    = self.subdomains,
            live_info     = self.live_info,
            open_ports    = self.open_ports,
            crawled_count = self.stats["crawled_urls"],
            findings      = self.findings,
            tool_versions = tv,
        )
        out = self.p(10, "final_report.html")
        out.write_text(html)
        self.log(f"STEP10: report saved → {out.name}")
        ok(f"Report  →  [bold green]{out}[/bold green]")
        return out

    # ══════════════════════════════════════════════════════════════════════════
    # MAIN
    # ══════════════════════════════════════════════════════════════════════════
    async def run(self):
        console.print(BANNER)
        console.print(Panel(
            f"[bold]Target :[/bold] [cyan]{self.target}[/cyan]\n"
            f"[bold]Output :[/bold] [cyan]{self.outdir}[/cyan]\n"
            f"[bold]Started:[/bold] [cyan]{self.start_ts.strftime('%Y-%m-%d %H:%M:%S')}[/cyan]",
            title="[bold yellow]\U0001f987 ReconFusion M7 \u2013 Mission Briefing[/bold yellow]",
            border_style="yellow",
        ))

        if not self.phase_auth():
            return
        self.phase_tools()

        await self.step01_subdomains()   # raw → 01_subdomains_all.txt
        self.step02_live_hosts()         # 01  → 02_live_hosts_urls.txt + .json
        self.step03_clean_domains()      # 02  → 03_live_domains_clean.txt
        self.step04_ports()              # 03  → 04_open_ports.txt + .json
        self.step05_katana()             # 02  → 05_crawled_urls.txt
        self.step06_fuzz()               # 02  → 06_fuzz_results.txt + .json
        self.step07_dalfox()             # 05  → 07_xss_findings.txt + .json
        self.step08_nuclei()             # 02  → 08_nuclei_findings.txt + .json
        self.step09_merge()              # 07+08 → 09_all_findings.json
        report = self.step10_report()   # all → 10_final_report.html

        dur = int((datetime.now() - self.start_ts).total_seconds())
        console.print(Panel(
            f"[bold green]\U0001f3af Mission Complete![/bold green]\n\n"
            f"[bold]Duration:[/bold] {dur}s\n"
            f"[bold]Report  :[/bold] [cyan]{report}[/cyan]\n"
            f"[bold]Output  :[/bold] [cyan]{self.outdir}[/cyan]",
            title="[bold yellow]\U0001f987 ReconFusion \u2013 Mission Complete[/bold yellow]",
            border_style="green",
        ))


# ── HTML Template ──────────────────────────────────────────────────────────────
HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ReconFusion M7 \u2013 {{ target }}</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<style>
:root{--y:#FFD700;--d:#07070a;--g:#111118;--l:#1a1a24;}
body{background:var(--d);color:#ccc;font-family:'Courier New',monospace;}
.nb{background:#0a0a0e!important;border-bottom:2px solid var(--y);}
.nbb{color:var(--y)!important;font-weight:700;letter-spacing:3px;}
.card{background:var(--g);border:1px solid #222;}
.ch{background:var(--l)!important;border-bottom:1px solid var(--y);color:var(--y);font-weight:700;}
.table{color:#ccc;}.td{background:var(--g);}
.sc{border-top:3px solid var(--y);text-align:center;padding:16px;}
.sn{font-size:2rem;font-weight:900;color:var(--y);}
.sl{font-size:.7rem;color:#666;text-transform:uppercase;letter-spacing:2px;}
.sc.cr{border-top-color:#dc3545;}.sc.cr .sn{color:#dc3545;}
.sc.hi{border-top-color:#fd7e14;}.sc.hi .sn{color:#fd7e14;}
.ab{background:var(--l)!important;color:#ddd!important;}
.abo{background:var(--g)!important;}
.ai{border:1px solid #222!important;}
footer{border-top:2px solid var(--y);padding:20px;text-align:center;margin-top:40px;}
code{color:var(--y);}
</style>
</head>
<body>
<nav class="navbar nb sticky-top"><div class="container">
<span class="nbb">\U0001f987 ReconFusion M7</span>
<span class="text-muted small">MilkyWay Intelligence \u2014 {{ scan_date }}</span>
</div></nav>
<div class="container py-4">

<div class="row g-3 mb-4">
<div class="col-6 col-md-3"><div class="card sc"><div class="sn">{{ stats.subdomains }}</div><div class="sl">Subdomains</div></div></div>
<div class="col-6 col-md-3"><div class="card sc"><div class="sn">{{ stats.live_hosts }}</div><div class="sl">Live Hosts</div></div></div>
<div class="col-6 col-md-3"><div class="card sc"><div class="sn">{{ stats.open_ports }}</div><div class="sl">Open Ports</div></div></div>
<div class="col-6 col-md-3"><div class="card sc"><div class="sn">{{ stats.crawled_urls }}</div><div class="sl">Crawled URLs</div></div></div>
<div class="col-6 col-md-3"><div class="card sc"><div class="sn">{{ stats.fuzz_hits }}</div><div class="sl">Fuzz Hits</div></div></div>
<div class="col-6 col-md-3"><div class="card sc cr"><div class="sn">{{ stats.vulns.critical }}</div><div class="sl">Critical</div></div></div>
<div class="col-6 col-md-3"><div class="card sc hi"><div class="sn">{{ stats.vulns.high }}</div><div class="sl">High</div></div></div>
<div class="col-6 col-md-3"><div class="card sc"><div class="sn">{{ stats.vulns.medium }}</div><div class="sl">Medium</div></div></div>
</div>

<div class="card mb-4"><div class="card-header ch">\U0001f4cb Scope</div><div class="card-body">
<p><b>Target:</b> <code>{{ target }}</code> &nbsp; <b>Start:</b> {{ scan_date }} &nbsp; <b>End:</b> {{ end_time }}</p>
</div></div>

<div class="card mb-4"><div class="card-header ch">\U0001f30d Live Hosts ({{ live_info|length }})</div>
<div class="card-body p-0"><div class="table-responsive">
<table class="table td table-hover mb-0 small">
<thead><tr><th>URL</th><th>Status</th><th>Server</th><th>Title</th></tr></thead><tbody>
{% for h in live_info %}
<tr>
<td><a href="{{ h.url }}" target="_blank" class="text-warning">{{ h.url }}</a></td>
<td><span class="badge {% if h.status==200 %}bg-success{% elif h.status in [301,302,307] %}bg-warning text-dark{% elif h.status==403 %}bg-secondary{% else %}bg-dark border{% endif %}">{{ h.status }}</span></td>
<td>{{ h.server or '-' }}</td><td>{{ h.title or '-' }}</td>
</tr>
{% else %}<tr><td colspan="4" class="text-center text-muted py-3">No live hosts found</td></tr>{% endfor %}
</tbody></table></div></div></div>

<div class="card mb-4"><div class="card-header ch">\U0001f50e Open Ports ({{ open_ports|length }})</div>
<div class="card-body p-0"><div class="table-responsive">
<table class="table td table-hover mb-0 small">
<thead><tr><th>Host</th><th>IP</th><th>Port</th><th>Tool</th></tr></thead><tbody>
{% for p in open_ports %}
<tr><td>{{ p.host }}</td><td>{{ p.ip }}</td>
<td><span class="badge bg-info text-dark">{{ p.port }}</span></td>
<td>{{ p.tool }}</td></tr>
{% else %}<tr><td colspan="4" class="text-center text-muted py-3">No open ports found</td></tr>{% endfor %}
</tbody></table></div></div></div>

<div class="card mb-4"><div class="card-header ch">\U0001f9ea Findings ({{ findings|length }})</div>
<div class="card-body">
<div class="accordion" id="va">
{% for f in findings %}
<div class="accordion-item ai mb-1">
<h2 class="accordion-header">
<button class="accordion-button ab collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#fi{{ loop.index }}">
<span class="badge me-2 {% if f.severity=='critical' %}bg-danger{% elif f.severity=='high' %}bg-warning text-dark{% elif f.severity=='medium' %}bg-warning text-dark{% elif f.severity=='low' %}bg-primary{% else %}bg-secondary{% endif %}">
{{ (f.severity or 'info')|upper }}</span>
[{{ f.tool }}] {{ f.type }} \u2014 {{ (f.url or '')[:80] }}
</button></h2>
<div id="fi{{ loop.index }}" class="accordion-collapse collapse">
<div class="accordion-body abo">
<table class="table td table-sm small mb-0">
<tr><th width="100">Type</th><td>{{ f.type }}</td></tr>
<tr><th>URL</th><td><a href="{{ f.url }}" class="text-warning" target="_blank">{{ f.url }}</a></td></tr>
<tr><th>Parameter</th><td>{{ f.parameter or '-' }}</td></tr>
<tr><th>Severity</th><td>{{ (f.severity or 'info')|upper }}</td></tr>
<tr><th>Tool</th><td>{{ f.tool }}</td></tr>
<tr><th>Detail</th><td><code>{{ f.detail or f.payload or '-' }}</code></td></tr>
</table></div></div></div>
{% else %}<p class="text-muted text-center py-3">No vulnerabilities found</p>{% endfor %}
</div></div></div>

<div class="card mb-4"><div class="card-header ch">\U0001f310 Subdomains ({{ subdomains|length }})</div>
<div class="card-body" style="max-height:220px;overflow-y:auto">
{% for s in subdomains %}<code class="d-block small text-warning">{{ s }}</code>
{% else %}<span class="text-muted">None</span>{% endfor %}
</div></div>

<div class="card mb-4"><div class="card-header ch">\u2699\ufe0f Tool Versions</div>
<div class="card-body p-0"><table class="table td table-sm mb-0 small">
<thead><tr><th>Tool</th><th>Version</th></tr></thead><tbody>
{% for t,v in tool_versions.items() %}
<tr><td><b>{{ t }}</b></td><td><code>{{ v or 'N/A' }}</code></td></tr>
{% endfor %}
</tbody></table></div></div>

</div>
<footer>
<p style="color:var(--y);font-weight:700;">\U0001f987 ReconFusion M7</p>
<p class="text-muted small">Produced by MilkyWay Intelligence \u2014 Authorized testing only \u2014 {{ end_time }}</p>
</footer>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body></html>
"""


# ── Entry point ────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="\U0001f987 ReconFusion M7 \u2013 Modular Recon & Vulnerability Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 reconfusion.py -d example.com -o pentest-2024\n"
            "  python3 reconfusion.py -d 192.168.1.1 -o internal-scan\n\n"
            "\u26a0  For AUTHORIZED security testing ONLY.\n"
            "  Produced by MilkyWay Intelligence | M7 BATMAN Edition"
        ),
    )
    ap.add_argument("-d", "--domain", required=True,
                    help="Target domain or IP  (e.g. example.com)")
    ap.add_argument("-o", "--output", default="reconfusion-output",
                    help="Output folder name  (default: reconfusion-output)")
    args = ap.parse_args()
    asyncio.run(ReconFusion(args.domain, args.output).run())


if __name__ == "__main__":
    main()
