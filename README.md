# 🦇 ReconFusion M7

### Modular Recon & Vulnerability Automation Framework

**Produced by MilkyWay Intelligence | M7 BATMAN Edition**

![Python](https://img.shields.io/badge/python-3.8+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Security](https://img.shields.io/badge/security-reconnaissance-red)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey)

ReconFusion M7 is an **automated reconnaissance and vulnerability scanning framework** designed for **bug bounty hunters, penetration testers, and security researchers**.

It combines multiple powerful open-source tools into a **single modular pipeline** to automate:

* Subdomain discovery
* Live host detection
* Port scanning
* Web crawling
* Vulnerability scanning
* Security reporting

All results are consolidated into a **professional HTML security report**.

---

# ⚠️ Legal Disclaimer

This tool is intended **ONLY for authorized security testing**.

Unauthorized scanning of systems without permission may be illegal.

The developers assume **no responsibility for misuse**.

Always ensure you have **written authorization** before testing any target.

---

# 🎯 Key Features

| Feature                   | Description                              |
| ------------------------- | ---------------------------------------- |
| 🔍 Subdomain Enumeration  | Uses multiple tools for maximum coverage |
| 🌐 Live Host Detection    | Identifies active hosts and technologies |
| 🚪 Port Scanning          | Detects open ports and exposed services  |
| 🕷️ Web Crawling          | Discovers endpoints using Katana         |
| 💉 Vulnerability Scanning | XSS detection via Dalfox                 |
| 🛡️ Security Scanning     | CVE detection using Nuclei               |
| 📊 Automated Reporting    | Generates HTML vulnerability report      |
| 🧩 Modular Pipeline       | Each phase can be extended               |

---

# 🔧 Tools Integrated

ReconFusion integrates industry-standard recon tools:

* **assetfinder**
* **subfinder**
* **amass**
* **httpx**
* **naabu**
* **nmap**
* **katana**
* **dalfox**
* **nuclei**

These tools work together to build a **complete attack surface map**.

---

# ⚡ Recon Workflow

```
Scope Validation
        ↓
Subdomain Enumeration
        ↓
Live Host Detection
        ↓
Port Scanning
        ↓
Endpoint Crawling
        ↓
Vulnerability Scanning
        ↓
Automated Security Report
```

---

# 🚀 Quick Start

### 1️⃣ Install dependencies

```
sudo bash setup.sh
```

### 2️⃣ Run scan

```
python3 reconfusion.py -d example.com -o project-folder
```

### 3️⃣ Open report

```
firefox project-folder/reports/final_report.html
```

---

# 📦 Manual Installation

### Python Dependencies

```
pip3 install -r requirements.txt --break-system-packages
```

### Install Go Tools

```
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

### System Packages

```
sudo apt install nmap amass -y
```

---

# 📂 Project Output Structure

```
project-folder/
│
├── raw/
│   ├── assetfinder.txt
│   ├── subfinder.txt
│   └── amass.txt
│
├── processed/
│   ├── all_subdomains.txt
│   ├── live_hosts.txt
│   ├── live_hosts.json
│   └── analysis.json
│
├── scans/
│   ├── open_ports.txt
│   ├── open_ports.json
│   ├── katana_urls.txt
│   ├── dalfox_results.txt
│   └── nuclei_results.txt
│
├── reports/
│   └── final_report.html
│
└── logs/
    ├── reconfusion.log
    └── scope.json
```

---

# 🛠 CLI Options

```
usage: reconfusion.py [-h] -d DOMAIN [-o OUTPUT] [--skip-install]

options:
  -h, --help       Show help message
  -d, --domain     Target domain or IP (required)
  -o, --output     Output directory
  --skip-install   Skip dependency check
```

---

# 📊 Security Report

ReconFusion generates a **professional vulnerability report** including:

* Executive Summary
* Scope Information
* Discovered Subdomains
* Live Hosts
* Open Ports
* Vulnerability Findings
* Severity Classification
* Tool Versions
* Scan Timeline

### Severity Levels

| Level    | Color     |
| -------- | --------- |
| Critical | 🔴 Red    |
| High     | 🟠 Orange |
| Medium   | 🟡 Yellow |
| Low      | 🔵 Blue   |
| Info     | ⚪ Gray    |

---

# 📋 Requirements

| Requirement | Version                  |
| ----------- | ------------------------ |
| Python      | 3.8+                     |
| Go          | 1.18+                    |
| OS          | Linux (Kali Recommended) |

Root privileges may be required for **naabu and nmap**.

---

# 🤝 Contributing

Pull requests are welcome.

If you find bugs or have feature suggestions, open an issue.

---

# ⭐ Support

If you find this project useful:

⭐ **Star the repository**
🐛 **Report bugs**
🔧 **Submit improvements**

---

# 👨‍💻 Author

MilkyWay Intelligence

---

# 🛡️ Security Notice

This project is designed for:

* Bug bounty hunters
* Security researchers
* Penetration testers

Use responsibly and **only within authorized scope**.

