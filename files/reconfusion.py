#!/usr/bin/env python3
"""
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███████╗██╗   ██╗███████╗██╗ ██████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔════╝██║   ██║██╔════╝██║██╔═══██╗████╗  ██║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║█████╗  ██║   ██║███████╗██║██║   ██║██╔██╗ ██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔══╝  ██║   ██║╚════██║██║██║   ██║██║╚██╗██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║     ╚██████╔╝███████║██║╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝
                        Produced by MilkyWay Intelligence | M7 BATMAN Edition
"""

import argparse
import asyncio
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# Auto-install dependencies
def auto_install():
    packages = ["rich", "jinja2", "httpx"]
    for pkg in packages:
        try:
            __import__(pkg.replace("-", "_"))
        except ImportError:
            print(f"[*] Installing {pkg}...")
            subprocess.run([sys.executable, "-m", "pip", "install", pkg, "--break-system-packages", "-q"], check=True)

auto_install()

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.align import Align
from rich import print as rprint
from rich.style import Style
import jinja2

console = Console()

BATMAN_LOGO = r"""
         .
        ":"
      ___:____     |"\/"|
    ,'        `.    \  /
    |  O        \___/  |
   ~|_  ,--.  ,    -'~|
    |___|'._ `|  |     |   
    |   |  |  `|  |     |
   /|   |  |   |  |     |\
  / |   |  |   |  |     | \
 /  |___|  |___|  |_____|  \
/___________________________\
   M 7   B A T M A N
"""

BANNER = """
[bold yellow]
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███████╗██╗   ██╗███████╗██╗ ██████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔════╝██║   ██║██╔════╝██║██╔═══██╗████╗  ██║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║█████╗  ██║   ██║███████╗██║██║   ██║██╔██╗ ██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔══╝  ██║   ██║╚════██║██║██║   ██║██║╚██╗██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║     ╚██████╔╝███████║██║╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝
[/bold yellow]
[bold cyan]                    ⚡ Modular Recon & Vulnerability Automation Framework ⚡[/bold cyan]
[dim]                         Produced by MilkyWay Intelligence | M7 BATMAN Edition[/dim]
"""

TOOLS_REQUIRED = {
    "assetfinder": "go install github.com/tomnomnom/assetfinder@latest",
    "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "amass": "sudo apt install amass -y",
    "httpx": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "naabu": "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "nmap": "sudo apt install nmap -y",
    "katana": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
    "dalfox": "go install github.com/hahwul/dalfox/v2@latest",
    "nuclei": "go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
}

class ReconFusion:
    def __init__(self, target: str, output_dir: str):
        self.target = target
        self.output_dir = Path(output_dir)
        self.start_time = datetime.now()
        self.stats = {
            "subdomains": 0,
            "live_hosts": 0,
            "open_ports": 0,
            "vulnerabilities": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        }
        self.findings = []
        self.live_hosts = []
        self.open_ports = []
        self.all_subdomains = []

    def setup_dirs(self):
        dirs = ["raw", "processed", "scans", "reports", "logs"]
        for d in dirs:
            (self.output_dir / d).mkdir(parents=True, exist_ok=True)

    def log(self, message: str, level: str = "info"):
        log_file = self.output_dir / "logs" / "reconfusion.log"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(log_file, "a") as f:
            f.write(f"[{timestamp}] [{level.upper()}] {message}\n")

    def check_tool(self, tool: str) -> bool:
        result = subprocess.run(["which", tool], capture_output=True, text=True)
        return result.returncode == 0

    def auto_install_tools(self):
        console.print("\n[bold cyan]⚙️  Checking & Installing Required Tools...[/bold cyan]")
        missing = []
        for tool in TOOLS_REQUIRED:
            if not self.check_tool(tool):
                missing.append(tool)

        if not missing:
            console.print("[bold green]✅ All tools are already installed![/bold green]")
            return

        console.print(f"[yellow]⚠️  Missing tools: {', '.join(missing)}[/yellow]")
        console.print("[cyan]🚀 Auto-installing missing tools...[/cyan]\n")

        for tool in missing:
            with console.status(f"[bold yellow]Installing {tool}...[/bold yellow]"):
                try:
                    cmd = TOOLS_REQUIRED[tool]
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
                    if result.returncode == 0:
                        console.print(f"  [green]✅ {tool} installed successfully[/green]")
                    else:
                        console.print(f"  [red]❌ Failed to install {tool}[/red]")
                        console.print(f"     [dim]Manual: {cmd}[/dim]")
                except Exception as e:
                    console.print(f"  [red]❌ {tool}: {e}[/red]")

    def run_command(self, cmd: list, timeout: int = 300) -> tuple:
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Timeout", 1
        except FileNotFoundError:
            return "", f"Tool not found: {cmd[0]}", 1
        except Exception as e:
            return "", str(e), 1

    # ─── PHASE 0: Scope Validation ────────────────────────────────────────────
    def phase0_scope_validation(self) -> bool:
        console.print(Panel(
            "[bold red]⚠️  LEGAL DISCLAIMER & SCOPE VALIDATION[/bold red]\n\n"
            "[yellow]This tool is intended for AUTHORIZED security testing ONLY.\n"
            "Unauthorized scanning is ILLEGAL and may result in criminal prosecution.\n"
            "By proceeding, you confirm that you have explicit written permission\n"
            "to test the target system.[/yellow]",
            title="[bold red]🔐 Phase 0 – Authorization Check[/bold red]",
            border_style="red"
        ))

        console.print(f"\n[bold]Target:[/bold] [cyan]{self.target}[/cyan]")
        console.print(f"[bold]Output:[/bold] [cyan]{self.output_dir}[/cyan]")
        console.print(f"[bold]Timestamp:[/bold] [cyan]{self.start_time.strftime('%Y-%m-%d %H:%M:%S')}[/cyan]\n")

        confirm = console.input(
            "[bold yellow]Do you have explicit authorization to test this target? (yes/no): [/bold yellow]"
        ).strip().lower()

        if confirm not in ("yes", "y"):
            console.print("[bold red]❌ Authorization not confirmed. Exiting.[/bold red]")
            return False

        self.setup_dirs()
        scope_log = {
            "target": self.target,
            "timestamp": self.start_time.isoformat(),
            "authorized": True,
            "output_directory": str(self.output_dir)
        }
        with open(self.output_dir / "logs" / "scope.json", "w") as f:
            json.dump(scope_log, f, indent=2)

        self.log(f"Scope validated for target: {self.target}")
        console.print("[bold green]✅ Scope validated. Starting recon pipeline...[/bold green]\n")
        return True

    # ─── PHASE 1: Subdomain Enumeration ───────────────────────────────────────
    async def phase1_subdomain_enum(self):
        console.print(Panel(
            "[bold cyan]Running: assetfinder | subfinder | amass (passive)[/bold cyan]",
            title="[bold cyan]🌐 Phase 1 – Subdomain Enumeration[/bold cyan]",
            border_style="cyan"
        ))

        tasks = [
            self._run_assetfinder(),
            self._run_subfinder(),
            self._run_amass(),
        ]
        await asyncio.gather(*tasks)

        # Merge & deduplicate
        all_subs = set()
        for fname in ["assetfinder.txt", "subfinder.txt", "amass.txt"]:
            fpath = self.output_dir / "raw" / fname
            if fpath.exists():
                with open(fpath) as f:
                    for line in f:
                        line = line.strip().lower()
                        if line and self.target in line:
                            all_subs.add(line)

        sorted_subs = sorted(all_subs)
        self.all_subdomains = sorted_subs

        with open(self.output_dir / "processed" / "all_subdomains.txt", "w") as f:
            f.write("\n".join(sorted_subs))

        self.stats["subdomains"] = len(sorted_subs)
        self.log(f"Total unique subdomains: {len(sorted_subs)}")
        console.print(f"  [green]✅ Total unique subdomains: [bold]{len(sorted_subs)}[/bold][/green]")

    async def _run_assetfinder(self):
        with console.status("[yellow]  Running assetfinder...[/yellow]"):
            out, err, code = self.run_command(["assetfinder", "--subs-only", self.target])
            with open(self.output_dir / "raw" / "assetfinder.txt", "w") as f:
                f.write(out)
            count = len([l for l in out.splitlines() if l.strip()])
            console.print(f"  [dim]assetfinder → {count} results[/dim]")

    async def _run_subfinder(self):
        with console.status("[yellow]  Running subfinder...[/yellow]"):
            out, err, code = self.run_command(["subfinder", "-d", self.target, "-silent"])
            with open(self.output_dir / "raw" / "subfinder.txt", "w") as f:
                f.write(out)
            count = len([l for l in out.splitlines() if l.strip()])
            console.print(f"  [dim]subfinder → {count} results[/dim]")

    async def _run_amass(self):
        with console.status("[yellow]  Running amass (passive)...[/yellow]"):
            out, err, code = self.run_command(
                ["amass", "enum", "-passive", "-d", self.target],
                timeout=180
            )
            with open(self.output_dir / "raw" / "amass.txt", "w") as f:
                f.write(out)
            count = len([l for l in out.splitlines() if l.strip()])
            console.print(f"  [dim]amass → {count} results[/dim]")

    # ─── PHASE 2: Live Host Detection ─────────────────────────────────────────
    def phase2_live_hosts(self):
        console.print(Panel(
            "[bold cyan]Running: httpx for live host detection[/bold cyan]",
            title="[bold cyan]🌍 Phase 2 – Live Host Detection[/bold cyan]",
            border_style="cyan"
        ))

        subs_file = self.output_dir / "processed" / "all_subdomains.txt"
        if not subs_file.exists() or subs_file.stat().st_size == 0:
            console.print("[yellow]  ⚠️ No subdomains to probe[/yellow]")
            return

        out, err, code = self.run_command([
            "httpx", "-l", str(subs_file),
            "-status-code", "-title", "-server", "-content-type",
            "-json", "-silent", "-timeout", "10"
        ], timeout=300)

        txt_lines = []
        json_records = []

        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                url = record.get("url", "")
                status = record.get("status-code", "")
                server = record.get("webserver", "")
                ct = record.get("content-type", "")
                title = record.get("title", "")
                txt_lines.append(f"{url} | {status} | {server} | {ct} | {title}")
                json_records.append({
                    "url": url, "status_code": status,
                    "server": server, "content_type": ct, "title": title
                })
                self.live_hosts.append({"url": url, "status": status, "title": title, "server": server})
            except json.JSONDecodeError:
                txt_lines.append(line)

        with open(self.output_dir / "processed" / "live_hosts.txt", "w") as f:
            f.write("\n".join(txt_lines))
        with open(self.output_dir / "processed" / "live_hosts.json", "w") as f:
            json.dump(json_records, f, indent=2)

        self.stats["live_hosts"] = len(json_records)
        self.log(f"Live hosts found: {len(json_records)}")
        console.print(f"  [green]✅ Live hosts detected: [bold]{len(json_records)}[/bold][/green]")

    # ─── PHASE 3: Port Scanning ────────────────────────────────────────────────
    def phase3_port_scan(self):
        console.print(Panel(
            "[bold cyan]Running: naabu / nmap port scanning[/bold cyan]",
            title="[bold cyan]🔎 Phase 3 – Port Scanning[/bold cyan]",
            border_style="cyan"
        ))

        subs_file = self.output_dir / "processed" / "all_subdomains.txt"
        if not subs_file.exists():
            return

        # Try naabu first, fallback to nmap
        if self.check_tool("naabu"):
            out, err, code = self.run_command([
                "naabu", "-l", str(subs_file), "-json", "-silent", "-top-ports", "100"
            ], timeout=300)
            tool_used = "naabu"
        else:
            out, err, code = self.run_command([
                "nmap", "-iL", str(subs_file), "--top-ports", "100", "-oX", "-"
            ], timeout=300)
            tool_used = "nmap"

        txt_lines = []
        json_records = []

        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                ip = record.get("ip", "")
                port = record.get("port", "")
                host = record.get("host", "")
                txt_lines.append(f"{ip} | {port} | {host}")
                json_records.append({"ip": ip, "port": port, "host": host, "tool": tool_used})
                self.open_ports.append({"ip": ip, "port": port, "host": host})
            except json.JSONDecodeError:
                if line:
                    txt_lines.append(line)

        with open(self.output_dir / "scans" / "open_ports.txt", "w") as f:
            f.write("\n".join(txt_lines))
        with open(self.output_dir / "scans" / "open_ports.json", "w") as f:
            json.dump(json_records, f, indent=2)

        self.stats["open_ports"] = len(json_records)
        self.log(f"Open ports found: {len(json_records)}")
        console.print(f"  [green]✅ Open ports found: [bold]{len(json_records)}[/bold][/green]")

    # ─── PHASE 4: Advanced Scanning ────────────────────────────────────────────
    def phase4_advanced_scan(self):
        console.print(Panel(
            "[bold cyan]Running: katana → dalfox → nuclei[/bold cyan]",
            title="[bold cyan]🧪 Phase 4 – Advanced Scanning Pipeline[/bold cyan]",
            border_style="cyan"
        ))

        live_file = self.output_dir / "processed" / "live_hosts.txt"
        if not live_file.exists():
            console.print("[yellow]  ⚠️ No live hosts to scan[/yellow]")
            return

        # Extract URLs
        urls = []
        with open(live_file) as f:
            for line in f:
                parts = line.strip().split(" | ")
                if parts:
                    urls.append(parts[0])

        # Katana
        self._run_katana(urls)
        # Dalfox
        self._run_dalfox()
        # Nuclei
        self._run_nuclei(live_file)

    def _run_katana(self, urls: list):
        with console.status("[yellow]  Running katana (URL crawling)...[/yellow]"):
            url_file = self.output_dir / "scans" / "katana_input.txt"
            with open(url_file, "w") as f:
                f.write("\n".join(urls[:50]))  # Limit for performance

            out, err, code = self.run_command([
                "katana", "-list", str(url_file), "-silent", "-depth", "2"
            ], timeout=300)

            with open(self.output_dir / "scans" / "katana_urls.txt", "w") as f:
                f.write(out)
            count = len([l for l in out.splitlines() if l.strip()])
            console.print(f"  [dim]katana → {count} URLs crawled[/dim]")

    def _run_dalfox(self):
        with console.status("[yellow]  Running dalfox (XSS testing)...[/yellow]"):
            katana_file = self.output_dir / "scans" / "katana_urls.txt"
            if not katana_file.exists() or katana_file.stat().st_size == 0:
                with open(self.output_dir / "scans" / "dalfox_results.txt", "w") as f:
                    f.write("")
                return

            out, err, code = self.run_command([
                "dalfox", "file", str(katana_file), "--silence", "--format", "json"
            ], timeout=300)

            with open(self.output_dir / "scans" / "dalfox_results.txt", "w") as f:
                f.write(out)

            # Parse findings
            for line in out.splitlines():
                try:
                    rec = json.loads(line)
                    self.findings.append({
                        "type": "XSS",
                        "url": rec.get("data", {}).get("url", ""),
                        "parameter": rec.get("data", {}).get("param", ""),
                        "severity": "high",
                        "tool": "dalfox",
                        "detail": str(rec)
                    })
                    self.stats["vulnerabilities"]["high"] += 1
                except:
                    pass

            count = len([l for l in out.splitlines() if l.strip()])
            console.print(f"  [dim]dalfox → {count} potential XSS findings[/dim]")

    def _run_nuclei(self, live_file: Path):
        with console.status("[yellow]  Running nuclei (template scanning)...[/yellow]"):
            out, err, code = self.run_command([
                "nuclei", "-l", str(live_file), "-json", "-silent",
                "-severity", "critical,high,medium,low"
            ], timeout=600)

            with open(self.output_dir / "scans" / "nuclei_results.txt", "w") as f:
                f.write(out)

            for line in out.splitlines():
                try:
                    rec = json.loads(line)
                    sev = rec.get("info", {}).get("severity", "info").lower()
                    self.findings.append({
                        "type": rec.get("template-id", "unknown"),
                        "url": rec.get("matched-at", ""),
                        "parameter": "",
                        "severity": sev,
                        "tool": "nuclei",
                        "detail": rec.get("info", {}).get("name", "")
                    })
                    if sev in self.stats["vulnerabilities"]:
                        self.stats["vulnerabilities"][sev] += 1
                    else:
                        self.stats["vulnerabilities"]["info"] += 1
                except:
                    pass

            console.print(f"  [dim]nuclei → {len(self.findings)} total vulnerabilities found[/dim]")

    # ─── PHASE 5: Analysis ─────────────────────────────────────────────────────
    def phase5_analysis(self):
        console.print(Panel(
            "[bold cyan]Analyzing & grouping findings...[/bold cyan]",
            title="[bold cyan]📊 Phase 5 – Analysis Engine[/bold cyan]",
            border_style="cyan"
        ))

        # Deduplicate findings
        seen = set()
        deduped = []
        for f in self.findings:
            key = (f["type"], f["url"], f["parameter"])
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        self.findings = deduped

        # Group by severity
        grouped = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        for finding in self.findings:
            sev = finding.get("severity", "info")
            grouped.setdefault(sev, []).append(finding)

        analysis = {
            "summary": self.stats,
            "findings_by_severity": {k: len(v) for k, v in grouped.items()},
            "total_findings": len(self.findings),
            "grouped_findings": grouped
        }

        with open(self.output_dir / "processed" / "analysis.json", "w") as f:
            json.dump(analysis, f, indent=2)

        # Print summary table
        table = Table(title="📊 Scan Summary", border_style="yellow")
        table.add_column("Metric", style="bold cyan")
        table.add_column("Count", style="bold white", justify="right")

        table.add_row("Total Subdomains", str(self.stats["subdomains"]))
        table.add_row("Live Hosts", str(self.stats["live_hosts"]))
        table.add_row("Open Ports", str(self.stats["open_ports"]))
        table.add_row("Critical Vulns", f"[red]{self.stats['vulnerabilities']['critical']}[/red]")
        table.add_row("High Vulns", f"[orange1]{self.stats['vulnerabilities']['high']}[/orange1]")
        table.add_row("Medium Vulns", f"[yellow]{self.stats['vulnerabilities']['medium']}[/yellow]")
        table.add_row("Low Vulns", f"[blue]{self.stats['vulnerabilities']['low']}[/blue]")
        table.add_row("Info", f"[dim]{self.stats['vulnerabilities']['info']}[/dim]")

        console.print(table)
        self.log("Analysis complete")

    # ─── PHASE 6: HTML Report ──────────────────────────────────────────────────
    def phase6_html_report(self):
        console.print(Panel(
            "[bold cyan]Generating HTML report...[/bold cyan]",
            title="[bold cyan]📄 Phase 6 – HTML Report Generator[/bold cyan]",
            border_style="cyan"
        ))

        template_str = HTML_TEMPLATE
        template = jinja2.Template(template_str)

        tool_versions = {}
        for tool in ["nmap", "nuclei", "subfinder", "httpx", "katana", "dalfox"]:
            out, _, _ = self.run_command([tool, "-version"], timeout=5)
            if not out:
                out, _, _ = self.run_command([tool, "--version"], timeout=5)
            tool_versions[tool] = out.strip().split("\n")[0] if out else "N/A"

        html = template.render(
            target=self.target,
            scan_date=self.start_time.strftime("%Y-%m-%d %H:%M:%S"),
            stats=self.stats,
            subdomains=self.all_subdomains[:100],
            live_hosts=self.live_hosts[:100],
            open_ports=self.open_ports[:100],
            findings=self.findings,
            tool_versions=tool_versions,
            end_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        report_path = self.output_dir / "reports" / "final_report.html"
        with open(report_path, "w") as f:
            f.write(html)

        self.log(f"HTML report generated: {report_path}")
        console.print(f"  [green]✅ Report saved: [bold]{report_path}[/bold][/green]")
        return report_path

    # ─── MAIN PIPELINE ─────────────────────────────────────────────────────────
    async def run(self):
        console.print(BANNER)
        console.print(Panel(
            f"[bold]Target:[/bold] [cyan]{self.target}[/cyan]\n"
            f"[bold]Output:[/bold] [cyan]{self.output_dir}[/cyan]\n"
            f"[bold]Started:[/bold] [cyan]{self.start_time.strftime('%Y-%m-%d %H:%M:%S')}[/cyan]",
            title="[bold yellow]🦇 ReconFusion M7 – Mission Briefing[/bold yellow]",
            border_style="yellow"
        ))

        # Phase 0
        if not self.phase0_scope_validation():
            return

        # Auto-install tools
        self.auto_install_tools()

        # Phase 1
        await self.phase1_subdomain_enum()
        # Phase 2
        self.phase2_live_hosts()
        # Phase 3
        self.phase3_port_scan()
        # Phase 4
        self.phase4_advanced_scan()
        # Phase 5
        self.phase5_analysis()
        # Phase 6
        report_path = self.phase6_html_report()

        duration = (datetime.now() - self.start_time).seconds
        console.print(Panel(
            f"[bold green]🎯 Mission Complete![/bold green]\n\n"
            f"[bold]Duration:[/bold] {duration}s\n"
            f"[bold]Report:[/bold] [cyan]{report_path}[/cyan]\n"
            f"[bold]Output:[/bold] [cyan]{self.output_dir}[/cyan]",
            title="[bold yellow]🦇 ReconFusion – Mission Complete[/bold yellow]",
            border_style="green"
        ))


HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ReconFusion Report – {{ target }}</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<style>
  :root {
    --batman-yellow: #FFD700;
    --batman-dark: #0a0a0a;
    --batman-gray: #1a1a1a;
    --batman-light: #2a2a2a;
    --critical: #dc3545;
    --high: #fd7e14;
    --medium: #ffc107;
    --low: #0d6efd;
    --info: #6c757d;
  }
  body { background: var(--batman-dark); color: #e0e0e0; font-family: 'Courier New', monospace; }
  .navbar { background: #111 !important; border-bottom: 2px solid var(--batman-yellow); }
  .navbar-brand { color: var(--batman-yellow) !important; font-weight: bold; font-size: 1.5rem; letter-spacing: 2px; }
  .card { background: var(--batman-gray); border: 1px solid #333; }
  .card-header { background: var(--batman-light); border-bottom: 1px solid var(--batman-yellow); color: var(--batman-yellow); font-weight: bold; }
  .table { color: #e0e0e0; }
  .table-dark { background: var(--batman-gray); }
  .badge-critical { background: var(--critical); }
  .badge-high { background: var(--high); }
  .badge-medium { background: var(--medium); color: #000; }
  .badge-low { background: var(--low); }
  .badge-info { background: var(--info); }
  .stat-card { border-top: 3px solid var(--batman-yellow); text-align: center; padding: 20px; }
  .stat-num { font-size: 2.5rem; font-weight: bold; color: var(--batman-yellow); }
  .stat-label { color: #aaa; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 1px; }
  .section-title { color: var(--batman-yellow); border-bottom: 1px solid var(--batman-yellow); padding-bottom: 8px; margin-bottom: 20px; }
  .accordion-button { background: var(--batman-light) !important; color: #e0e0e0 !important; }
  .accordion-body { background: var(--batman-gray); }
  .accordion-item { border: 1px solid #333; }
  .bat-logo { font-size: 3rem; }
  footer { border-top: 2px solid var(--batman-yellow); padding: 20px 0; margin-top: 40px; }
  .severity-critical { color: var(--critical); font-weight: bold; }
  .severity-high { color: var(--high); font-weight: bold; }
  .severity-medium { color: var(--medium); font-weight: bold; }
  .severity-low { color: var(--low); }
  .severity-info { color: var(--info); }
</style>
</head>
<body>
<nav class="navbar navbar-dark sticky-top">
  <div class="container">
    <span class="navbar-brand">🦇 ReconFusion M7 – Security Report</span>
    <span class="text-muted small">Produced by MilkyWay Intelligence</span>
  </div>
</nav>

<div class="container py-4">

  <!-- Executive Summary -->
  <div class="card mb-4">
    <div class="card-header">📋 Executive Summary</div>
    <div class="card-body">
      <div class="row">
        <div class="col-md-6">
          <p><strong>Target:</strong> <code class="text-warning">{{ target }}</code></p>
          <p><strong>Scan Date:</strong> {{ scan_date }}</p>
          <p><strong>Completed:</strong> {{ end_time }}</p>
        </div>
        <div class="col-md-6">
          <p><strong>Status:</strong> <span class="badge bg-success">Completed</span></p>
          <p><strong>Authorization:</strong> <span class="badge bg-warning text-dark">Confirmed</span></p>
        </div>
      </div>
    </div>
  </div>

  <!-- Stats Cards -->
  <div class="row mb-4">
    <div class="col-md-3"><div class="card stat-card"><div class="stat-num">{{ stats.subdomains }}</div><div class="stat-label">Subdomains</div></div></div>
    <div class="col-md-3"><div class="card stat-card"><div class="stat-num">{{ stats.live_hosts }}</div><div class="stat-label">Live Hosts</div></div></div>
    <div class="col-md-3"><div class="card stat-card"><div class="stat-num">{{ stats.open_ports }}</div><div class="stat-label">Open Ports</div></div></div>
    <div class="col-md-3"><div class="card stat-card">
      <div class="stat-num text-danger">{{ stats.vulnerabilities.critical }}</div>
      <div class="stat-label">Critical Vulns</div>
    </div></div>
  </div>

  <!-- Vulnerability Breakdown -->
  <div class="card mb-4">
    <div class="card-header">🔴 Vulnerability Breakdown</div>
    <div class="card-body">
      <table class="table table-dark">
        <thead><tr><th>Severity</th><th>Count</th><th>Bar</th></tr></thead>
        <tbody>
          <tr><td><span class="severity-critical">● Critical</span></td><td>{{ stats.vulnerabilities.critical }}</td><td><div class="progress" style="height:8px"><div class="progress-bar bg-danger" style="width:{{ [stats.vulnerabilities.critical * 10, 100]|min }}%"></div></div></td></tr>
          <tr><td><span class="severity-high">● High</span></td><td>{{ stats.vulnerabilities.high }}</td><td><div class="progress" style="height:8px"><div class="progress-bar bg-warning" style="width:{{ [stats.vulnerabilities.high * 10, 100]|min }}%"></div></div></td></tr>
          <tr><td><span class="severity-medium">● Medium</span></td><td>{{ stats.vulnerabilities.medium }}</td><td><div class="progress" style="height:8px"><div class="progress-bar bg-warning" style="width:{{ [stats.vulnerabilities.medium * 10, 100]|min }}%"></div></div></td></tr>
          <tr><td><span class="severity-low">● Low</span></td><td>{{ stats.vulnerabilities.low }}</td><td><div class="progress" style="height:8px"><div class="progress-bar bg-primary" style="width:{{ [stats.vulnerabilities.low * 10, 100]|min }}%"></div></div></td></tr>
          <tr><td><span class="severity-info">● Info</span></td><td>{{ stats.vulnerabilities.info }}</td><td><div class="progress" style="height:8px"><div class="progress-bar bg-secondary" style="width:{{ [stats.vulnerabilities.info * 5, 100]|min }}%"></div></div></td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- Live Hosts -->
  <div class="card mb-4">
    <div class="card-header">🌍 Live Hosts ({{ live_hosts|length }})</div>
    <div class="card-body p-0">
      <div class="table-responsive">
        <table class="table table-dark table-hover mb-0">
          <thead><tr><th>URL</th><th>Status</th><th>Server</th><th>Title</th></tr></thead>
          <tbody>
            {% for h in live_hosts %}
            <tr>
              <td><a href="{{ h.url }}" target="_blank" class="text-warning">{{ h.url }}</a></td>
              <td><span class="badge {% if h.status == 200 %}bg-success{% elif h.status == 403 %}bg-warning text-dark{% else %}bg-secondary{% endif %}">{{ h.status }}</span></td>
              <td><code>{{ h.server or '-' }}</code></td>
              <td>{{ h.title or '-' }}</td>
            </tr>
            {% else %}
            <tr><td colspan="4" class="text-center text-muted">No live hosts found</td></tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Open Ports -->
  <div class="card mb-4">
    <div class="card-header">🔎 Open Ports ({{ open_ports|length }})</div>
    <div class="card-body p-0">
      <table class="table table-dark table-hover mb-0">
        <thead><tr><th>IP</th><th>Port</th><th>Host</th></tr></thead>
        <tbody>
          {% for p in open_ports %}
          <tr><td>{{ p.ip }}</td><td><span class="badge bg-info text-dark">{{ p.port }}</span></td><td>{{ p.host }}</td></tr>
          {% else %}
          <tr><td colspan="3" class="text-center text-muted">No open ports found</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>

  <!-- Detailed Findings -->
  <div class="card mb-4">
    <div class="card-header">🧪 Detailed Findings ({{ findings|length }})</div>
    <div class="card-body">
      <div class="accordion" id="findingsAccordion">
        {% for f in findings %}
        <div class="accordion-item mb-2">
          <h2 class="accordion-header">
            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#finding{{ loop.index }}">
              <span class="badge me-2 {% if f.severity == 'critical' %}bg-danger{% elif f.severity == 'high' %}bg-warning text-dark{% elif f.severity == 'medium' %}bg-warning text-dark{% elif f.severity == 'low' %}bg-primary{% else %}bg-secondary{% endif %}">
                {{ f.severity|upper }}
              </span>
              [{{ f.tool }}] {{ f.type }} – {{ f.url[:80] }}
            </button>
          </h2>
          <div id="finding{{ loop.index }}" class="accordion-collapse collapse">
            <div class="accordion-body">
              <table class="table table-dark table-sm">
                <tr><th>Type</th><td>{{ f.type }}</td></tr>
                <tr><th>URL</th><td><a href="{{ f.url }}" class="text-warning">{{ f.url }}</a></td></tr>
                <tr><th>Parameter</th><td>{{ f.parameter or '-' }}</td></tr>
                <tr><th>Severity</th><td class="severity-{{ f.severity }}">{{ f.severity|upper }}</td></tr>
                <tr><th>Tool</th><td>{{ f.tool }}</td></tr>
                <tr><th>Detail</th><td><code>{{ f.detail }}</code></td></tr>
              </table>
            </div>
          </div>
        </div>
        {% else %}
        <p class="text-muted text-center">No vulnerabilities found</p>
        {% endfor %}
      </div>
    </div>
  </div>

  <!-- Subdomains -->
  <div class="card mb-4">
    <div class="card-header">🌐 Discovered Subdomains ({{ subdomains|length }})</div>
    <div class="card-body">
      <div style="max-height: 300px; overflow-y: auto;">
        {% for sub in subdomains %}
        <code class="text-warning d-block small">{{ sub }}</code>
        {% else %}
        <p class="text-muted">No subdomains found</p>
        {% endfor %}
      </div>
    </div>
  </div>

  <!-- Tool Versions -->
  <div class="card mb-4">
    <div class="card-header">⚙️ Tool Versions</div>
    <div class="card-body">
      <table class="table table-dark table-sm">
        <thead><tr><th>Tool</th><th>Version Info</th></tr></thead>
        <tbody>
          {% for tool, ver in tool_versions.items() %}
          <tr><td><strong>{{ tool }}</strong></td><td><code>{{ ver or 'N/A' }}</code></td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>

</div>

<footer class="text-center text-muted">
  <div class="container">
    <span class="bat-logo">🦇</span>
    <p class="mb-0 mt-2"><strong style="color: var(--batman-yellow)">ReconFusion M7</strong> – Produced by MilkyWay Intelligence</p>
    <p class="small">For authorized security testing use only. Generated: {{ end_time }}</p>
    <p class="small text-warning">⚠️ This report is confidential. Handle according to your organization's data classification policy.</p>
  </div>
</footer>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
'''


def main():
    parser = argparse.ArgumentParser(
        description="🦇 ReconFusion M7 – Modular Recon & Vulnerability Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python reconfusion.py -d example.com -o my-project
  python reconfusion.py -d 192.168.1.1 -o pentest-2024

⚠️  For authorized security testing ONLY.
    Produced by MilkyWay Intelligence | M7 BATMAN Edition
        """
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain or IP")
    parser.add_argument("-o", "--output", default="reconfusion-output", help="Output directory name")
    parser.add_argument("--skip-install", action="store_true", help="Skip auto tool installation")
    args = parser.parse_args()

    rf = ReconFusion(target=args.domain, output_dir=args.output)
    asyncio.run(rf.run())


if __name__ == "__main__":
    main()
