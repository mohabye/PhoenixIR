LinuxIR.py - Unified Linux Incident Response and Threat Hunting Tool
A powerful, Python-based tool designed for incident response and threat hunting on Linux systems. LinuxIR.py streamlines forensic artifact collection and threat analysis, providing cybersecurity professionals and system administrators with a comprehensive, unified workflow.
🚀 Features
Module 1: Artifact Collection

System Logs: Collects syslog, auth, kernel, and boot logs
Authentication Artifacts: Gathers wtmp, btmp, utmp, passwd, and shadow files
Bash History: Extracts command history for all users
System Information: Captures running processes, network connections, and installed packages
Cron Jobs: Collects scheduled tasks and cron configurations
Network Artifacts: Gathers network configurations and routing tables
Web Server Logs: Collects Apache, Nginx, and other web server logs
Persistence Mechanisms: Identifies startup scripts and systemd services
File Timeline: Creates a timeline of recently modified files
SSH Artifacts: Collects SSH configurations and keys
Temporary Files: Analyzes contents of /tmp, /var/tmp, and /dev/shm

Module 2: Threat Hunting and Analysis

Log Analysis: Automated parsing of system and authentication logs
Command History Analysis: Identifies suspicious commands and patterns
Process Analysis: Detects unusual or malicious processes
Network Analysis: Examines network connections and routing anomalies
Package Analysis: Identifies potentially malicious installed software
Timeline Analysis: Correlates file modification times with suspicious activities
Risk Assessment: Provides a comprehensive security risk evaluation

🎯 Use Cases

Incident Response: Rapidly collect and analyze forensic artifacts
Threat Hunting: Proactively search for indicators of compromise
Security Auditing: Perform regular security assessments
Compliance: Gather evidence for regulatory requirements
Forensic Analysis: Conduct in-depth digital forensics investigations

📋 Requirements

Operating System: Linux (Ubuntu/Debian or CentOS/RHEL)
Python Version: Python 3.6 or higher
Privileges: Root access recommended for full artifact collection
Dependencies: Uses standard Python libraries (no external packages required)

🛠️ Installation

Clone the repository:git clone https://github.com/yourusername/linuxir.git
cd linuxir


Make the script executable:chmod +x LinuxIR.py


Run with Python 3:sudo python3 LinuxIR.py



💻 Usage
Basic Usage
# Run with default settings
sudo python3 LinuxIR.py

# Specify custom output directory
sudo python3 LinuxIR.py -o /path/to/output

# Skip archive creation
sudo python3 LinuxIR.py --no-archive

# Enable verbose output
sudo python3 LinuxIR.py -v

Command Line Options



Option
Description
Default



-o, --output
Output directory for results
unified_ir_results


--no-archive
Skip creating compressed archive
False


-v, --verbose
Enable verbose output
False


-h, --help
Show help message
-


Example Commands
# Standard incident response collection and analysis
sudo python3 LinuxIR.py -o incident_2024_01_15

# Quick analysis without archiving
sudo python3 LinuxIR.py --no-archive -v

# Custom output location with verbose logging
sudo python3 LinuxIR.py -o /forensics/case001 -v

📂 Output Structure
The tool generates a structured output directory:
unified_ir_results/
├── artifacts_YYYYMMDD_HHMMSS/
│   ├── logs/                    # System and application logs
│   ├── authentication/          # Authentication-related files
│   ├── bash_history/           # User command histories
│   ├── system_info/            # System configuration and status
│   ├── cron_jobs/              # Scheduled tasks
│   ├── network/                # Network configurations
│   ├── web_logs/               # Web server logs
│   ├── persistence/            # Startup mechanisms
│   ├── timeline/               # File modification timelines
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
The tool evaluates artifacts across multiple severity levels:
High Severity Indicators

Failed authentication attempts (>10)
Suspicious command execution (e.g., netcat, base64 decoding)
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

Color-Coded Output: Easily identify findings with color-coded terminal output
Severity-Based Classification: Categorizes findings as HIGH, MEDIUM, LOW, or INFO
Detailed Reports: Generates CSV and JSON reports for further analysis
Compressed Archives: Includes MD5 checksums for integrity verification
Comprehensive Logging: Tracks all collection activities

⚠️ Important Notes
Permissions

Root access is required for complete artifact collection
The tool will warn if not run with sufficient privileges
Some artifacts may be inaccessible without proper permissions

System Impact

Performs read-only operations with no system modifications
Minimal performance impact during collection
Includes timeout protection for long-running commands (60 seconds)

Privacy and Legal

Collects sensitive system information; ensure compliance with organizational policies
Obtain proper authorization before use
Handle collected data in accordance with privacy regulations

🔧 Customization
Customize the tool by modifying:

Collection paths in artifact collection methods
Analysis patterns in threat hunting functions
Severity thresholds for different finding types
Output formats and reporting mechanisms

📊 Sample Output
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
We welcome contributions! Please submit:

Bug reports and feature requests
Pull requests with improvements
Documentation enhancements
Additional analysis modules
