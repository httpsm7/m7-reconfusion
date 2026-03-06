 🦇 ReconFusion M7
### Modular Recon & Vulnerability Automation Framework
**Produced by MilkyWay Intelligence | M7 BATMAN Edition**

```
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███████╗██╗   ██╗███████╗██╗ ██████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔════╝██║   ██║██╔════╝██║██╔═══██╗████╗  ██║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║█████╗  ██║   ██║███████╗██║██║   ██║██╔██╗ ██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔══╝  ██║   ██║╚════██║██║██║   ██║██║╚██╗██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║     ╚██████╔╝███████║██║╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝
```

---

## ⚠️ LEGAL DISCLAIMER

> **This tool is intended for AUTHORIZED security testing ONLY.**  
> Unauthorized use against systems you do not own or have explicit written permission to test is **ILLEGAL** and may result in criminal prosecution.  
> The developers and contributors assume NO liability for misuse.  
> Always obtain proper written authorization before scanning any target.

---

## 🎯 Features

| Phase | Description | Tools |
|-------|-------------|-------|
| 0 | Scope Validation & Auth Check | Built-in |
| 1 | Subdomain Enumeration | assetfinder, subfinder, amass |
| 2 | Live Host Detection | httpx |
| 3 | Port Scanning | naabu / nmap |
| 4 | Advanced Scanning | katana, dalfox, nuclei |
| 5 | Analysis Engine | Built-in parser |
| 6 | HTML Report Generator | Jinja2 + Bootstrap |

---

## 🚀 Quick Start

### 1. Install (Auto)
```bash
sudo bash setup.sh
```

### 2. Run
```bash
python3 reconfusion.py -d example.com -o project-folder
```

### 3. View Report
```bash
firefox project-folder/reports/final_report.html
```

---

## 📦 Manual Installation

### Python deps
```bash
pip3 install -r requirements.txt --break-system-packages
```

### Go tools (Kali Linux)
```bash
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

### System tools
```bash
sudo apt install nmap amass -y
```

---

## 📂 Output Structure

```
project-folder/
├── raw/
│   ├── assetfinder.txt
│   ├── subfinder.txt
│   └── amass.txt
├── processed/
│   ├── all_subdomains.txt
│   ├── live_hosts.txt
│   ├── live_hosts.json
│   └── analysis.json
├── scans/
│   ├── open_ports.txt
│   ├── open_ports.json
│   ├── katana_urls.txt
│   ├── dalfox_results.txt
│   └── nuclei_results.txt
├── reports/
│   └── final_report.html  ← 📊 Main report
└── logs/
    ├── reconfusion.log
    └── scope.json
```

---

## 🔧 CLI Options

```
usage: reconfusion.py [-h] -d DOMAIN [-o OUTPUT] [--skip-install]

options:
  -h, --help       show this help message and exit
  -d, --domain     Target domain or IP (required)
  -o, --output     Output directory name (default: reconfusion-output)
  --skip-install   Skip auto tool installation check
```

---

## 🛡️ Report Features

- Executive Summary
- Scope & Authorization Details  
- Recon Results (Subdomains)
- Live Hosts Table
- Open Ports Table
- Vulnerability Breakdown with color-coded severity
- Detailed Findings (collapsible)
- Tool Versions & Timestamps

### Severity Colors
| Severity | Color |
|----------|-------|
| 🔴 Critical | Red |
| 🟠 High | Orange |
| 🟡 Medium | Yellow |
| 🔵 Low | Blue |
| ⚪ Info | Gray |

---

## 📋 Requirements

- **OS**: Kali Linux (recommended) / Any Debian-based Linux
- **Python**: 3.8+
- **Go**: 1.18+ (for Go-based tools)
- **Root**: Required for naabu/nmap

---

*🦇 ReconFusion M7 – Produced by MilkyWay Intelligence*  
*For authorized security testing ONLY.*
