# 🛡️ Linux Security Audit Tool (CIS-Based)

A Python-based, command-line tool for auditing the security configuration of Debian 12 systems. This script automates checks based on the CIS (Center for Internet Security) Debian Linux 12 Benchmark to provide a security score, detailed results, and actionable recommendations for hardening your system.

## ✨ Key Features

- `CIS Benchmark Alignment` : *Checks are based on high-impact recommendations from the official CIS Debian 12 Benchmark.*
- `User-Friendly Output` : *Color-coded, icon-based reports make it easy to see the security posture of your system at a glance.*
- `Actionable Recommendations` : *For every failed check, the tool provides the exact command or steps needed to fix the issue.*
- `Scoring System` : *Quantifies your system's security with a score and a letter grade, helping you track hardening progress over time.*
- `JSON Reporting` : *Option to export the full audit results to a JSON file for automation, record-keeping, or integration with other tools.*
- `Categorized Results` : *Checks are grouped by category (e.g., File System Security, SSH Security) for better organization.*

## 🚀 Getting Started

Follow these instructions to get the audit tool running on your system.

Prerequisites
```
- A Debian-based Linux system (tested on Debian 12).
- Python 3.6 or higher.
- Root (sudo) privileges to run the script.
```

## Installation & Usage

- Download the Script: *Save the code provided in our previous conversation as audit.py on your Linux system.*

#### Make it Executable :
```
chmod +x audit.py
```

Run the Audit:

- You must run the script with sudo because it needs to read system-level configuration files.

- Standard Audit:
```
sudo python3 audit.py
```

- Save Report to JSON:
```
sudo python3 audit.py --output security_report.json
```

- Quiet Mode (Summary and Recommendations Only):
```
sudo python3 audit.py --quiet
```

### 📊 Sample Output (Screenshots)



---

