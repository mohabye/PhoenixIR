# PhoenixIR
Linuxir.py - Unified Linux Incident Response and Threat Hunting Tool
A comprehensive Python-based incident response and threat hunting tool designed for Linux systems. This tool combines artifact collection and threat analysis capabilities into a unified workflow for cybersecurity professionals and system administrators.

🚀 Features
Module 1: Artifact Collection
System Logs: Collects syslog, auth logs, kernel logs, and boot logs

Authentication Artifacts: Gathers wtmp, btmp, utmp, passwd, shadow files

Bash History: Extracts command history for all users

System Information: Captures running processes, network connections, installed packages

Cron Jobs: Collects scheduled tasks and cron configurations

Network Artifacts: Gathers network configurations and routing tables

Web Server Logs: Collects Apache, Nginx, and other web server logs

Persistence Mechanisms: Identifies startup scripts and systemd services

File Timeline: Creates timeline of recently modified files

SSH Artifacts: Collects SSH configurations and keys

Temporary Files: Analyzes /tmp, /var/tmp, and /dev/shm contents

Module 2: Threat Hunting and Analysis
Log Analysis: Automated analysis of system and authentication logs

Command History Analysis: Identifies suspicious commands and patterns

Process Analysis: Detects unusual or malicious processes

Network Analysis: Examines network connections and routing anomalies

Package Analysis: Identifies potentially malicious installed software

Timeline Analysis: Correlates file modification times with suspicious activities

Risk Assessment: Provides overall security risk evaluation

🎯 Use Cases
Incident Response: Rapid collection and analysis of forensic artifacts

Threat Hunting: Proactive search for indicators of compromise

Security Auditing: Regular security assessments of Linux systems

Compliance: Evidence collection for regulatory requirements

Forensic Analysis: Digital forensics investigations

📋 Requirements
Operating System: Linux (Ubuntu/Debian or CentOS/RHEL)

Python Version: Python 3.6+

Privileges: Root access recommended for complete artifact collection

Dependencies: Standard Python libraries (no external packages required)

🛠️ Installation
Clone the repository:

bash
git clone https://github.com/yourusername/linuxir.git
cd linuxir
Make the script executable:

bash
chmod +x Linuxir.py
Run with Python 3:

bash
sudo python3 Linuxir.py
💻 Usage
Basic Usage
bash
# Run with default settings
sudo python3 Linuxir.py

# Specify custom output directory
sudo python3 Linuxir.py -o /path/to/output

# Skip archive creation
sudo python3 Linuxir.py --no-archive

# Enable verbose output
sudo python3 Linuxir.py -v
Command Line Options
Option	Description	Default
-o, --output	Output directory for results	unified_ir_results
--no-archive	Skip creating compressed archive	False
-v, --verbose	Enable verbose output	False
-h, --help	Show help message	-
Example Commands
bash
# Standard incident response collection and analysis
sudo python3 Linuxir.py -o incident_2024_01_15

# Quick analysis without archiving
sudo python3 Linuxir.py --no-archive -v

# Custom output location with verbose logging
sudo python3 Linuxir.py -o /forensics/case001 -v
📂 Output Structure
The tool creates a structured output directory containing:

text
unified_ir_results/
├── artifacts_YYYYMMDD_HHMMSS/
│   ├── logs/                    # System and application logs
│   ├── authentication/          # Auth-related files
│   ├── bash_history/           # Command histories
│   ├── system_info/            # System information
│   ├── cron_jobs/              # Scheduled tasks
│   ├── network/                # Network configurations
│   ├── web_logs/               # Web server logs
│   ├── persistence/            # Startup mechanisms
│   ├── timeline/               # File timelines
│   ├── audit/                  # Audit logs
│   ├── ssh/                    # SSH configurations
│   ├── tmp_artifacts/          # Temporary file analysis
│   └── collection_report.json  # Collection summary
├── analysis_YYYYMMDD_HHMMSS/
│   ├── threat_hunt_results_YYYYMMDD_HHMMSS.csv
│   └── threat_hunt_results_YYYYMMDD_HHMMSS.json
├── artifacts_YYYYMMDD_HHMMSS.tar.gz
└── artifacts_YYYYMMDD_HHMMSS.md5
🔍 Analysis Categories
The tool analyzes collected artifacts across multiple categories:

High Severity Indicators
Failed authentication attempts (>10)

Suspicious command execution (netcat, base64 decoding)

Processes running from temporary directories

History clearing commands

Unauthorized privilege escalation

Medium Severity Indicators
Moderate failed login attempts (1-10)

Sudo usage to root

Suspicious installed packages

Large bash history files

Recent file modifications in sensitive locations

Low Severity Indicators
Unusual network routes

Analysis errors or missing artifacts

General system anomalies

Informational Findings
SSH connection logs

Cron job executions

System statistics and counts

🎨 Output Features
Color-coded terminal output for easy identification of findings

Severity-based classification (HIGH, MEDIUM, LOW, INFO)

Detailed CSV and JSON reports for further analysis

Compressed archives with MD5 checksums for integrity

Comprehensive logging of all collection activities

⚠️ Important Notes
Permissions
Root access required for complete artifact collection

Some artifacts may be inaccessible without proper privileges

The tool will warn if not running as root

System Impact
Read-only operations - no system modifications

Minimal performance impact during collection

Timeout protection for long-running commands (60 seconds)

Privacy and Legal
Tool collects sensitive system information

Ensure compliance with organizational policies

Obtain proper authorization before use

Handle collected data according to privacy regulations

🔧 Customization
The tool can be easily customized by modifying:

Collection paths in artifact collection methods

Analysis patterns in threat hunting functions

Severity thresholds for different finding types

Output formats and reporting mechanisms

📊 Sample Output
text
=== THREAT HUNT ANALYSIS SUMMARY ===
Total Findings: 15
High Severity: 2
Medium Severity: 8
Low Severity: 3
Informational: 2

Findings by Category:
 Authentication: 5
 Bash History: 4
 System Logs: 3
 Processes: 2
 Network Routes: 1

Overall Risk Level: MEDIUM
🤝 Contributing
Contributions are welcome! Please feel free to submit:

Bug reports and feature requests

Pull requests with improvements

Documentation enhancements

Additional analysis modules
