#!/usr/bin/env python3
"""
Unified Linux Incident Response and Threat Hunting Script
Module 1: Artifact Collection
Module 2: Threat Hunting and Analysis
Enhanced with automatic workflow execution
"""

import os
import subprocess
import csv
import json
import datetime
import re
import sys
import shutil
import tarfile
import hashlib
from pathlib import Path
import argparse

class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'      # Green for INFO and SUCCESS
    RED = '\033[91m'        # Red for ERROR and HIGH severity
    BLUE = '\033[94m'       # Blue for CHECKING and MEDIUM severity
    YELLOW = '\033[93m'     # Yellow for WARNING
    CYAN = '\033[96m'       # Cyan for headers
    MAGENTA = '\033[95m'    # Magenta for LOW severity
    WHITE = '\033[97m'      # White for emphasis
    RESET = '\033[0m'       # Reset to default color
    BOLD = '\033[1m'        # Bold text

class UnifiedLinuxIR:
    def __init__(self, output_dir="unified_ir_results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Collection-related attributes
        self.artifacts_dir = self.output_dir / f"artifacts_{self.timestamp}"
        self.artifacts_dir.mkdir(exist_ok=True)
        self.collection_log = []
        
        # Analysis-related attributes
        self.findings = []
        self.analysis_results_dir = self.output_dir / f"analysis_{self.timestamp}"
        self.analysis_results_dir.mkdir(exist_ok=True)
        
        # System detection
        self.os_type = self.detect_os()
        print(f"{Colors.GREEN}[INFO]{Colors.RESET} Detected OS: {Colors.WHITE}{self.os_type}{Colors.RESET}")
        print(f"{Colors.GREEN}[INFO]{Colors.RESET} Unified IR directory: {Colors.WHITE}{self.output_dir}{Colors.RESET}")
        
    def detect_os(self):
        """Detect if system is CentOS/RHEL or Ubuntu/Debian"""
        try:
            with open('/etc/os-release', 'r') as f:
                content = f.read().lower()
                if 'centos' in content or 'rhel' in content or 'red hat' in content:
                    return 'centos'
                elif 'ubuntu' in content or 'debian' in content:
                    return 'ubuntu'
        except:
            pass
        return 'unknown'
    
    def run_command(self, command, description=""):
        """Execute system command and return output"""
        if description:
            print(f"{Colors.BLUE}[EXECUTING]{Colors.RESET} {description}")
        
        try:
            result = subprocess.run(command, shell=True, capture_output=True, 
                                  text=True, timeout=60)
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} Command timed out: {command}")
            return "", "Command timed out", 1
        except Exception as e:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Command failed: {command} - {str(e)}")
            return "", str(e), 1
    
    # ==================== MODULE 1: ARTIFACT COLLECTION ====================
    
    def log_collection(self, artifact_type, source, destination, status, details=""):
        """Log artifact collection activity"""
        entry = {
            'timestamp': datetime.datetime.now().isoformat(),
            'artifact_type': artifact_type,
            'source': source,
            'destination': str(destination),
            'status': status,
            'details': details
        }
        self.collection_log.append(entry)
        
        color = Colors.GREEN if status == "SUCCESS" else Colors.RED
        print(f"{color}[{status}]{Colors.RESET} {artifact_type}: {source}")
    
    def safe_copy(self, source, destination, artifact_type):
        """Safely copy files/directories preserving metadata"""
        try:
            source_path = Path(source)
            if not source_path.exists():
                self.log_collection(artifact_type, source, destination, "MISSING", "Source not found")
                return False
            
            dest_path = Path(destination)
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            
            if source_path.is_file():
                shutil.copy2(source, destination)
            elif source_path.is_dir():
                shutil.copytree(source, destination, dirs_exist_ok=True)
            
            self.log_collection(artifact_type, source, destination, "SUCCESS")
            return True
            
        except Exception as e:
            self.log_collection(artifact_type, source, destination, "ERROR", str(e))
            return False
    
    def collect_system_logs(self):
        """Collect system logs"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}=== COLLECTING SYSTEM LOGS ==={Colors.RESET}")
        
        log_dir = self.artifacts_dir / "logs"
        log_dir.mkdir(exist_ok=True)
        
        # Primary system logs
        if self.os_type == 'centos':
            system_logs = ['/var/log/messages', '/var/log/secure']
        else:
            system_logs = ['/var/log/syslog', '/var/log/auth.log']
        
        # Common logs for all systems
        common_logs = [
            '/var/log/kern.log', '/var/log/dmesg', '/var/log/boot.log',
            '/var/log/cron', '/var/log/maillog', '/var/log/mail.log'
        ]
        
        all_logs = system_logs + common_logs
        
        for log_file in all_logs:
            if os.path.exists(log_file):
                dest = log_dir / Path(log_file).name
                self.safe_copy(log_file, dest, "System Logs")
    
    def collect_authentication_artifacts(self):
        """Collect authentication-related artifacts"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}=== COLLECTING AUTHENTICATION ARTIFACTS ==={Colors.RESET}")
        
        auth_dir = self.artifacts_dir / "authentication"
        auth_dir.mkdir(exist_ok=True)
        
        # Binary logs
        binary_logs = ['/var/log/wtmp', '/var/log/btmp', '/var/run/utmp']
        for log_file in binary_logs:
            if os.path.exists(log_file):
                dest = auth_dir / Path(log_file).name
                self.safe_copy(log_file, dest, "Binary Logs")
        
        # User account files
        account_files = ['/etc/passwd', '/etc/shadow', '/etc/group', '/etc/gshadow']
        for file_path in account_files:
            if os.path.exists(file_path):
                dest = auth_dir / Path(file_path).name
                self.safe_copy(file_path, dest, "Account Files")
    
    def collect_bash_history(self):
        """Collect bash history for all users"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}=== COLLECTING BASH HISTORY ==={Colors.RESET}")
        
        history_dir = self.artifacts_dir / "bash_history"
        history_dir.mkdir(exist_ok=True)
        
        # Root bash history
        root_history = '/root/.bash_history'
        if os.path.exists(root_history):
            dest = history_dir / "root_bash_history"
            self.safe_copy(root_history, dest, "Bash History")
        
        # User bash histories
        home_base = Path('/home')
        if home_base.exists():
            for user_dir in home_base.iterdir():
                if user_dir.is_dir():
                    history_file = user_dir / '.bash_history'
                    if history_file.exists():
                        dest = history_dir / f"{user_dir.name}_bash_history"
                        self.safe_copy(history_file, dest, "Bash History")
    
    def collect_system_info(self):
        """Collect system information"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}=== COLLECTING SYSTEM INFORMATION ==={Colors.RESET}")
        
        sysinfo_dir = self.artifacts_dir / "system_info"
        sysinfo_dir.mkdir(exist_ok=True)
        
        # System information commands
        commands = {
            'uname_info': 'uname -a',
            'os_release': 'cat /etc/os-release',
            'hostname': 'hostname',
            'uptime': 'uptime',
            'date': 'date',
            'timezone': 'timedatectl',
            'kernel_modules': 'lsmod',
            'installed_packages_deb': 'dpkg -l',
            'installed_packages_rpm': 'rpm -qa',
            'running_processes': 'ps -auxww',
            'process_tree': 'pstree -p',
            'network_connections': 'netstat -nap',
            'listening_ports': 'ss -tulpn',
            'network_routes': 'ip route show',
            'network_interfaces': 'ip addr show',
            'arp_table': 'arp -a',
            'environment_vars': 'env',
            'mounted_filesystems': 'mount',
            'disk_usage': 'df -h',
            'memory_info': 'free -h',
            'cpu_info': 'lscpu',
            'pci_devices': 'lspci',
            'usb_devices': 'lsusb',
            'systemd_services': 'systemctl list-unit-files --type=service',
            'active_services': 'systemctl list-units --type=service --state=active'
        }
        
        for filename, command in commands.items():
            stdout, stderr, returncode = self.run_command(command, f"Collecting {filename}")
            
            if stdout or stderr:
                output_file = sysinfo_dir / f"{filename}.txt"
                with open(output_file, 'w') as f:
                    if stdout:
                        f.write("=== STDOUT ===\n")
                        f.write(stdout)
                    if stderr:
                        f.write("\n=== STDERR ===\n")
                        f.write(stderr)
                
                self.log_collection("System Info", command, output_file, "SUCCESS")
    
    def collect_cron_jobs(self):
        """Collect cron jobs and scheduled tasks"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}=== COLLECTING CRON JOBS ==={Colors.RESET}")
        
        cron_dir = self.artifacts_dir / "cron_jobs"
        cron_dir.mkdir(exist_ok=True)
        
        # System cron directories
        cron_locations = [
            '/etc/cron.d/', '/etc/cron.daily/', '/etc/cron.hourly/',
            '/etc/cron.monthly/', '/etc/cron.weekly/', '/var/spool/cron/',
            '/var/spool/cron/crontabs/'
        ]
        
        for location in cron_locations:
            if os.path.exists(location):
                dest = cron_dir / Path(location).name
                self.safe_copy(location, dest, "Cron Jobs")
        
        # Individual user crontabs
        stdout, stderr, _ = self.run_command('cut -d: -f1 /etc/passwd', "Getting user list")
        if stdout:
            users = stdout.strip().split('\n')
            for user in users:
                if user and not user.startswith('#'):
                    crontab_output, _, _ = self.run_command(f'crontab -l -u {user} 2>/dev/null')
                    if crontab_output:
                        crontab_file = cron_dir / f"{user}_crontab.txt"
                        with open(crontab_file, 'w') as f:
                            f.write(crontab_output)
                        self.log_collection("User Crontab", f"crontab -l -u {user}", crontab_file, "SUCCESS")
    
    def collect_network_artifacts(self):
        """Collect network-related artifacts"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}=== COLLECTING NETWORK ARTIFACTS ==={Colors.RESET}")
        
        network_dir = self.artifacts_dir / "network"
        network_dir.mkdir(exist_ok=True)
        
        # Network configuration files
        network_files = [
            '/etc/hosts', '/etc/hostname', '/etc/resolv.conf', '/etc/nsswitch.conf',
            '/etc/network/interfaces', '/etc/sysconfig/network-scripts/',
            '/etc/NetworkManager/system-connections/'
        ]
        
        for net_file in network_files:
            if os.path.exists(net_file):
                dest = network_dir / Path(net_file).name
                self.safe_copy(net_file, dest, "Network Config")
    
    def collect_web_artifacts(self):
        """Collect web server artifacts"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}=== COLLECTING WEB ARTIFACTS ==={Colors.RESET}")
        
        web_dir = self.artifacts_dir / "web_logs"
        web_dir.mkdir(exist_ok=True)
        
        # Web server logs
        web_log_paths = [
            '/var/log/apache2/', '/var/log/httpd/',
            '/var/log/nginx/', '/var/log/lighttpd/'
        ]
        
        for log_path in web_log_paths:
            if os.path.exists(log_path):
                dest = web_dir / Path(log_path).name
                self.safe_copy(log_path, dest, "Web Logs")
    
    def collect_persistence_artifacts(self):
        """Collect persistence mechanism artifacts"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}=== COLLECTING PERSISTENCE ARTIFACTS ==={Colors.RESET}")
        
        persistence_dir = self.artifacts_dir / "persistence"
        persistence_dir.mkdir(exist_ok=True)
        
        # Startup and init files
        startup_locations = [
            '/etc/init.d/', '/etc/rc.local', '/etc/rc.d/',
            '/etc/systemd/system/', '/lib/systemd/system/', '/usr/lib/systemd/system/',
            '/etc/profile', '/etc/profile.d/', '/etc/bash.bashrc', '/etc/environment'
        ]
        
        for location in startup_locations:
            if os.path.exists(location):
                dest = persistence_dir / Path(location).name
                self.safe_copy(location, dest, "Persistence")
    
    def collect_file_timeline(self):
        """Create file timeline"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}=== CREATING FILE TIMELINE ==={Colors.RESET}")
        
        timeline_dir = self.artifacts_dir / "timeline"
        timeline_dir.mkdir(exist_ok=True)
        
        # Create timeline for recently modified files
        commands = {
            'recent_files_24h': 'find / -type f -mtime -1 -printf "%T@ %Tc %p\\n" 2>/dev/null | sort -n',
            'recent_files_7d': 'find / -type f -mtime -7 -printf "%T@ %Tc %p\\n" 2>/dev/null | sort -n | head -1000',
            'suid_sgid_files': 'find / -type f \\( -perm -4000 -o -perm -2000 \\) -printf "%T@ %Tc %p %m\\n" 2>/dev/null | sort -n'
        }
        
        for filename, command in commands.items():
            stdout, stderr, _ = self.run_command(command, f"Creating {filename} timeline")
            if stdout:
                timeline_file = timeline_dir / f"{filename}.txt"
                with open(timeline_file, 'w') as f:
                    f.write(stdout)
                self.log_collection("Timeline", command, timeline_file, "SUCCESS")
    
    def collect_audit_logs(self):
        """Collect audit logs"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}=== COLLECTING AUDIT LOGS ==={Colors.RESET}")
        
        audit_dir = self.artifacts_dir / "audit"
        audit_dir.mkdir(exist_ok=True)
        
        # Audit log files
        audit_files = ['/var/log/audit/', '/etc/audit/']
        
        for audit_path in audit_files:
            if os.path.exists(audit_path):
                dest = audit_dir / Path(audit_path).name
                self.safe_copy(audit_path, dest, "Audit Logs")
    
    def collect_ssh_artifacts(self):
        """Collect SSH-related artifacts"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}=== COLLECTING SSH ARTIFACTS ==={Colors.RESET}")
        
        ssh_dir = self.artifacts_dir / "ssh"
        ssh_dir.mkdir(exist_ok=True)
        
        # SSH configuration and keys
        ssh_locations = ['/etc/ssh/', '/root/.ssh/']
        
        for location in ssh_locations:
            if os.path.exists(location):
                dest = ssh_dir / Path(location).name
                self.safe_copy(location, dest, "SSH Config")
        
        # User SSH directories
        home_base = Path('/home')
        if home_base.exists():
            for user_dir in home_base.iterdir():
                if user_dir.is_dir():
                    ssh_path = user_dir / '.ssh'
                    if ssh_path.exists():
                        dest = ssh_dir / f"{user_dir.name}_ssh"
                        self.safe_copy(ssh_path, dest, "SSH Config")
    
    def collect_tmp_artifacts(self):
        """Collect temporary directory artifacts"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}=== COLLECTING TEMPORARY ARTIFACTS ==={Colors.RESET}")
        
        tmp_dir = self.artifacts_dir / "tmp_artifacts"
        tmp_dir.mkdir(exist_ok=True)
        
        # Temporary directories
        tmp_locations = ['/tmp/', '/var/tmp/', '/dev/shm/']
        
        for location in tmp_locations:
            if os.path.exists(location):
                # List contents
                stdout, stderr, _ = self.run_command(f'ls -la {location}', f"Listing {location}")
                if stdout:
                    listing_file = tmp_dir / f"{location.replace('/', '_')}_listing.txt"
                    with open(listing_file, 'w') as f:
                        f.write(stdout)
                    self.log_collection("Temp Artifacts", f"ls -la {location}", listing_file, "SUCCESS")
                
                # Copy small files only (< 10MB)
                stdout, stderr, _ = self.run_command(
                    f'find {location} -type f -size -10M -exec ls -la {{}} \\; 2>/dev/null | head -50'
                )
                if stdout:
                    small_files = tmp_dir / f"{location.replace('/', '_')}_small_files.txt"
                    with open(small_files, 'w') as f:
                        f.write(stdout)
                    self.log_collection("Temp Artifacts", f"Small files in {location}", small_files, "SUCCESS")
    
    def create_collection_report(self):
        """Create collection report"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}=== CREATING COLLECTION REPORT ==={Colors.RESET}")
        
        report_file = self.artifacts_dir / "collection_report.json"
        
        report = {
            'collection_timestamp': self.timestamp,
            'collector_version': '2.0',
            'system_info': {
                'os_type': self.os_type,
                'hostname': os.uname().nodename,
                'collection_time': datetime.datetime.now().isoformat()
            },
            'artifacts_collected': len(self.collection_log),
            'collection_log': self.collection_log,
            'summary': {
                'successful': len([x for x in self.collection_log if x['status'] == 'SUCCESS']),
                'failed': len([x for x in self.collection_log if x['status'] == 'ERROR']),
                'missing': len([x for x in self.collection_log if x['status'] == 'MISSING'])
            }
        }
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"{Colors.GREEN}[SUCCESS]{Colors.RESET} Collection report saved to: {Colors.WHITE}{report_file}{Colors.RESET}")
        return report_file
    
    def create_archive(self):
        """Create compressed archive of collected artifacts"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}=== CREATING ARCHIVE ==={Colors.RESET}")
        
        archive_file = self.output_dir / f"artifacts_{self.timestamp}.tar.gz"
        
        try:
            with tarfile.open(archive_file, 'w:gz') as tar:
                tar.add(self.artifacts_dir, arcname=f"artifacts_{self.timestamp}")
            
            # Calculate hash of archive
            hash_md5 = hashlib.md5()
            with open(archive_file, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            
            hash_file = self.output_dir / f"artifacts_{self.timestamp}.md5"
            with open(hash_file, 'w') as f:
                f.write(f"{hash_md5.hexdigest()}  {archive_file.name}\n")
            
            print(f"{Colors.GREEN}[SUCCESS]{Colors.RESET} Archive created: {Colors.WHITE}{archive_file}{Colors.RESET}")
            print(f"{Colors.GREEN}[SUCCESS]{Colors.RESET} MD5 hash: {Colors.WHITE}{hash_file}{Colors.RESET}")
            
            return archive_file, hash_file
            
        except Exception as e:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Failed to create archive: {str(e)}")
            return None, None
    
    # ==================== MODULE 2: THREAT HUNTING & ANALYSIS ====================
    
    def add_finding(self, category, description, severity, details):
        """Add finding to results with colorized output"""
        finding = {
            'timestamp': datetime.datetime.now().isoformat(),
            'category': category,
            'description': description,
            'severity': severity,
            'details': details
        }
        self.findings.append(finding)
        
        # Color code based on severity
        if severity == "HIGH":
            color = Colors.RED
        elif severity == "MEDIUM":
            color = Colors.BLUE
        elif severity == "LOW":
            color = Colors.MAGENTA
        else:  # INFO
            color = Colors.GREEN
        
        print(f"{color}[{severity}]{Colors.RESET} {Colors.WHITE}{category}{Colors.RESET}: {description}")
    
    def get_artifact_file(self, relative_path):
        """Get path to collected artifact file"""
        # Map system paths to collected artifact paths
        path_mappings = {
            '/var/log/syslog': 'logs/syslog',
            '/var/log/messages': 'logs/messages',
            '/var/log/auth.log': 'logs/auth.log',
            '/var/log/secure': 'logs/secure',
            '/var/log/wtmp': 'authentication/wtmp',
            '/var/log/btmp': 'authentication/btmp',
            '/var/run/utmp': 'authentication/utmp',
            '/etc/passwd': 'authentication/passwd',
        }
        
        if relative_path in path_mappings:
            artifact_path = self.artifacts_dir / path_mappings[relative_path]
            if artifact_path.exists():
                return artifact_path
        
        return None
    
    def analyze_collected_system_logs(self):
        """Analyze collected system logs"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}=== ANALYZING COLLECTED SYSTEM LOGS ==={Colors.RESET}")
        
        if self.os_type == 'centos':
            log_file = self.artifacts_dir / "logs" / "messages"
        else:
            log_file = self.artifacts_dir / "logs" / "syslog"
        
        if not log_file.exists():
            self.add_finding("System Logs", f"Primary log file not found in collected artifacts", 
                           "MEDIUM", f"Expected log file missing: {log_file}")
            return
        
        # Read and analyze log file
        try:
            with open(log_file, 'r') as f:
                log_content = f.read()
            
            # Check for suspicious root activities
            root_lines = [line for line in log_content.split('\n') if 'root' in line.lower()]
            suspicious_patterns = ['failed', 'error', 'denied', 'invalid']
            
            for line in root_lines[-20:]:  # Last 20 root-related lines
                if any(pattern in line.lower() for pattern in suspicious_patterns):
                    self.add_finding("System Logs", "Suspicious root activity detected", 
                                   "HIGH", line.strip())
            
            # Check for cron job activities
            cron_lines = [line for line in log_content.split('\n') if 'CMD' in line]
            for line in cron_lines[-10:]:  # Last 10 cron executions
                if line.strip():
                    self.add_finding("System Logs", "Cron job execution found", 
                                   "INFO", line.strip())
                    
        except Exception as e:
            self.add_finding("System Logs", f"Failed to analyze system logs", 
                           "MEDIUM", f"Error: {str(e)}")
    
    def analyze_collected_authentication_logs(self):
        """Analyze collected authentication logs"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}=== ANALYZING COLLECTED AUTHENTICATION LOGS ==={Colors.RESET}")
        
        if self.os_type == 'centos':
            auth_log = self.artifacts_dir / "logs" / "secure"
        else:
            auth_log = self.artifacts_dir / "logs" / "auth.log"
        
        if not auth_log.exists():
            self.add_finding("Auth Logs", f"Authentication log not found in collected artifacts", 
                           "MEDIUM", f"Expected auth log missing: {auth_log}")
            return
        
        try:
            with open(auth_log, 'r') as f:
                auth_content = f.read()
            
            # Check for failed login attempts
            failed_lines = [line for line in auth_content.split('\n') if 'failed' in line.lower()]
            failed_logins = len(failed_lines)
            
            if failed_logins > 10:
                self.add_finding("Authentication", f"High number of failed logins: {failed_logins}", 
                               "HIGH", '\n'.join(failed_lines[-10:]))
            elif failed_logins > 0:
                self.add_finding("Authentication", f"Failed login attempts detected: {failed_logins}", 
                               "MEDIUM", '\n'.join(failed_lines[-5:]))
            
            # Check for sudo usage
            sudo_lines = [line for line in auth_content.split('\n') if 'sudo' in line.lower()]
            for line in sudo_lines[-15:]:
                if 'root' in line.lower() and line.strip():
                    self.add_finding("Authentication", "Sudo to root detected", 
                                   "MEDIUM", line.strip())
            
            # Check for SSH connections
            ssh_lines = [line for line in auth_content.split('\n') if 'ssh' in line.lower()]
            ssh_ips = set()
            for line in ssh_lines:
                if 'from' in line.lower():
                    ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        ssh_ips.add(ip_match.group(1))
            
            if ssh_ips:
                self.add_finding("Authentication", f"SSH connections from IPs: {', '.join(ssh_ips)}", 
                               "INFO", '\n'.join(ssh_lines[-15:]))
                
        except Exception as e:
            self.add_finding("Auth Logs", f"Failed to analyze authentication logs", 
                           "MEDIUM", f"Error: {str(e)}")
    
    def analyze_collected_bash_history(self):
        """Analyze collected bash history"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}=== ANALYZING COLLECTED BASH HISTORY ==={Colors.RESET}")
        
        history_dir = self.artifacts_dir / "bash_history"
        if not history_dir.exists():
            self.add_finding("Bash History", "No bash history collected", 
                           "MEDIUM", "Bash history directory not found")
            return
        
        for history_file in history_dir.glob("*_bash_history"):
            user = history_file.name.replace('_bash_history', '')
            self._analyze_single_bash_history(history_file, user)
    
    def _analyze_single_bash_history(self, history_file, user):
        """Analyze a single bash history file"""
        try:
            with open(history_file, 'r') as f:
                commands = f.readlines()
            
            suspicious_patterns = [
                'wget', 'curl', 'nc ', 'netcat', 'ncat', 'socat',
                'python -c', 'perl -e', 'ruby -e', 'php -r',
                'base64 -d', 'echo.*base64', '/tmp/', '/dev/shm/',
                'chmod +x', 'nohup', 'screen -d', 'tmux',
                'sudo su', 'su -', 'passwd', 'useradd', 'usermod',
                'iptables', 'ufw', 'firewall', 'systemctl stop',
                'history -c', 'unset HISTFILE', 'export HISTSIZE=0'
            ]
            
            for i, command in enumerate(commands):
                command = command.strip()
                if command:
                    for pattern in suspicious_patterns:
                        if pattern in command.lower():
                            severity = "HIGH" if pattern in ['nc ', 'netcat', 'base64 -d', 'history -c'] else "MEDIUM"
                            self.add_finding("Bash History", 
                                           f"Suspicious command in {user}'s history: {pattern}", 
                                           severity, 
                                           f"Line {i+1}: {command}")
            
            # Check for unusual command frequency
            if len(commands) > 10000:
                self.add_finding("Bash History", 
                               f"Unusually large bash history for {user}: {len(commands)} commands", 
                               "MEDIUM", 
                               f"History file: {history_file}")
                
        except Exception as e:
            self.add_finding("Bash History", 
                           f"Failed to analyze bash history for {user}", 
                           "LOW", 
                           f"Error: {str(e)}")
    
    def analyze_collected_system_info(self):
        """Analyze collected system information"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}=== ANALYZING COLLECTED SYSTEM INFO ==={Colors.RESET}")
        
        sysinfo_dir = self.artifacts_dir / "system_info"
        if not sysinfo_dir.exists():
            self.add_finding("System Info", "No system info collected", 
                           "MEDIUM", "System info directory not found")
            return
        
        # Analyze installed packages
        if self.os_type == 'ubuntu':
            pkg_file = sysinfo_dir / "installed_packages_deb.txt"
        else:
            pkg_file = sysinfo_dir / "installed_packages_rpm.txt"
        
        if pkg_file.exists():
            with open(pkg_file, 'r') as f:
                packages = f.read()
            self._analyze_package_list(packages)
        
        # Analyze kernel modules
        modules_file = sysinfo_dir / "kernel_modules.txt"
        if modules_file.exists():
            with open(modules_file, 'r') as f:
                modules = f.read()
            self._analyze_module_list(modules)
        
        # Analyze network routes
        routes_file = sysinfo_dir / "network_routes.txt"
        if routes_file.exists():
            with open(routes_file, 'r') as f:
                routes = f.read()
            self._analyze_routes(routes)
        
        # Analyze running processes
        processes_file = sysinfo_dir / "running_processes.txt"
        if processes_file.exists():
            with open(processes_file, 'r') as f:
                processes = f.read()
            self._analyze_processes(processes)
    
    def _analyze_package_list(self, packages):
        """Analyze package list for suspicious packages"""
        suspicious_packages = [
            'netcat', 'ncat', 'socat', 'nmap', 'masscan', 'zmap',
            'john', 'hashcat', 'hydra', 'medusa', 'aircrack',
            'metasploit', 'msfconsole', 'beef', 'sqlmap',
            'tor', 'proxychains', 'torsocks'
        ]
        
        installed_suspicious = []
        for package in suspicious_packages:
            if package in packages.lower():
                installed_suspicious.append(package)
        
        if installed_suspicious:
            self.add_finding("Installed Packages", 
                           f"Potentially suspicious packages found: {', '.join(installed_suspicious)}", 
                           "MEDIUM", 
                           f"Packages: {installed_suspicious}")
        
        # Count total packages
        package_count = len(packages.split('\n'))
        self.add_finding("Installed Packages", 
                       f"Total packages installed: {package_count}", 
                       "INFO", 
                       f"Package count: {package_count}")
    
    def _analyze_module_list(self, modules):
        """Analyze kernel module list"""
        suspicious_modules = [
            'rootkit', 'keylogger', 'packet_capture', 'hidden',
            'stealth', 'backdoor', 'trojan'
        ]
        
        lines = modules.split('\n')
        loaded_modules = []
        
        for line in lines[1:]:  # Skip header
            if line.strip():
                module_name = line.split()[0]
                loaded_modules.append(module_name)
                
                # Check for suspicious module names
                for suspicious in suspicious_modules:
                    if suspicious in module_name.lower():
                        self.add_finding("Kernel Modules", 
                                       f"Suspicious kernel module: {module_name}", 
                                       "HIGH", 
                                       f"Module: {line.strip()}")
        
        self.add_finding("Kernel Modules", 
                       f"Total loaded modules: {len(loaded_modules)}", 
                       "INFO", 
                       f"Modules: {', '.join(loaded_modules[:10])}...")
    
    def _analyze_routes(self, routes):
        """Analyze routing table"""
        lines = routes.split('\n')
        route_count = len([line for line in lines if line.strip()])
        
        # Look for unusual routes
        for line in lines:
            if line.strip():
                # Check for routes to private networks that might be suspicious
                if any(net in line for net in ['10.0.0.0', '172.16.0.0', '192.168.0.0']):
                    if 'via' in line:  # Routes via specific gateways
                        self.add_finding("Network Routes", 
                                       "Route to private network via gateway", 
                                       "LOW", 
                                       line.strip())
        
        self.add_finding("Network Routes", 
                       f"Total routes: {route_count}", 
                       "INFO", 
                       f"Route count: {route_count}")
    
    def _analyze_processes(self, processes):
        """Analyze running processes"""
        lines = processes.split('\n')
        suspicious_processes = []
        
        for line in lines:
            if any(keyword in line.lower() for keyword in ['nc ', 'netcat', 'ncat', '/tmp/', '/dev/shm']):
                suspicious_processes.append(line.strip())
        
        if suspicious_processes:
            self.add_finding("Processes", "Suspicious processes detected", 
                           "HIGH", '\n'.join(suspicious_processes))
        
        process_count = len([line for line in lines if line.strip()])
        self.add_finding("Processes", 
                       f"Total running processes: {process_count}", 
                       "INFO", 
                       f"Process count: {process_count}")
    
    def analyze_collected_cron_jobs(self):
        """Analyze collected cron jobs"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}=== ANALYZING COLLECTED CRON JOBS ==={Colors.RESET}")
        
        cron_dir = self.artifacts_dir / "cron_jobs"
        if not cron_dir.exists():
            self.add_finding("Cron Jobs", "No cron jobs collected", 
                           "MEDIUM", "Cron jobs directory not found")
            return
        
        # Analyze system cron directories
        for cron_file in cron_dir.glob("*"):
            if cron_file.is_file():
                try:
                    with open(cron_file, 'r') as f:
                        content = f.read()
                    
                    if content.strip():
                        # Check for suspicious cron entries
                        suspicious_patterns = ['/tmp/', '/dev/shm/', 'wget', 'curl', 'nc ', 'netcat']
                        for pattern in suspicious_patterns:
                            if pattern in content.lower():
                                self.add_finding("Cron Jobs", 
                                               f"Suspicious cron job pattern: {pattern}", 
                                               "HIGH", 
                                               f"File: {cron_file.name}\nContent: {content}")
                        
                        self.add_finding("Cron Jobs", 
                                       f"Cron job found: {cron_file.name}", 
                                       "INFO", 
                                       content)
                except Exception as e:
                    self.add_finding("Cron Jobs", 
                                   f"Failed to analyze cron file: {cron_file.name}", 
                                   "LOW", 
                                   f"Error: {str(e)}")
    
    def analyze_collected_timeline(self):
        """Analyze collected file timeline"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}=== ANALYZING COLLECTED TIMELINE ==={Colors.RESET}")
        
        timeline_dir = self.artifacts_dir / "timeline"
        if not timeline_dir.exists():
            self.add_finding("Timeline", "No timeline data collected", 
                           "MEDIUM", "Timeline directory not found")
            return
        
        # Analyze recent files
        recent_files = timeline_dir / "recent_files_24h.txt"
        if recent_files.exists():
            try:
                with open(recent_files, 'r') as f:
                    files = f.readlines()
                
                file_count = len(files)
                if file_count > 100:
                    self.add_finding("Timeline", 
                                   f"High number of recently modified files: {file_count}", 
                                   "MEDIUM", 
                                   f"Files modified in last 24h: {file_count}")
                
                # Check for modifications in suspicious locations
                suspicious_locations = ['/tmp/', '/dev/shm/', '/var/tmp/']
                for line in files:
                    for location in suspicious_locations:
                        if location in line:
                            self.add_finding("Timeline", 
                                           f"File modified in suspicious location: {location}", 
                                           "HIGH", 
                                           line.strip())
                            
            except Exception as e:
                self.add_finding("Timeline", 
                               "Failed to analyze timeline data", 
                               "LOW", 
                               f"Error: {str(e)}")
        
        # Analyze SUID/SGID files
        suid_files = timeline_dir / "suid_sgid_files.txt"
        if suid_files.exists():
            try:
                with open(suid_files, 'r') as f:
                    files = f.readlines()
                
                suid_count = len(files)
                self.add_finding("Timeline", 
                               f"SUID/SGID files found: {suid_count}", 
                               "MEDIUM", 
                               f"SUID/SGID count: {suid_count}")
                
            except Exception as e:
                self.add_finding("Timeline", 
                               "Failed to analyze SUID/SGID files", 
                               "LOW", 
                               f"Error: {str(e)}")
    
    def export_analysis_results(self):
        """Export analysis findings to CSV and JSON"""
        csv_file = self.analysis_results_dir / f"threat_hunt_results_{self.timestamp}.csv"
        
        print(f"\n{Colors.CYAN}{Colors.BOLD}=== EXPORTING ANALYSIS RESULTS ==={Colors.RESET}")
        print(f"{Colors.GREEN}[INFO]{Colors.RESET} Exporting {Colors.WHITE}{len(self.findings)}{Colors.RESET} findings to {Colors.WHITE}{csv_file}{Colors.RESET}")
        
        with open(csv_file, 'w', newline='', encoding='utf-8') as file:
            if self.findings:
                fieldnames = ['timestamp', 'category', 'description', 'severity', 'details']
                writer = csv.DictWriter(file, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(self.findings)
            else:
                # Write headers even if no findings
                writer = csv.writer(file)
                writer.writerow(['timestamp', 'category', 'description', 'severity', 'details'])
                writer.writerow([datetime.datetime.now().isoformat(), 'Info', 'No threats detected', 'INFO', 'System appears clean'])
        
        # Also export as JSON for better structure
        json_file = self.analysis_results_dir / f"threat_hunt_results_{self.timestamp}.json"
        with open(json_file, 'w', encoding='utf-8') as file:
            json.dump({
                'scan_timestamp': self.timestamp,
                'total_findings': len(self.findings),
                'findings': self.findings
            }, file, indent=2)
        
        print(f"{Colors.GREEN}[INFO]{Colors.RESET} Results also exported to {Colors.WHITE}{json_file}{Colors.RESET}")
        return csv_file, json_file
    
    def generate_analysis_summary(self):
        """Generate summary of analysis findings"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}=== THREAT HUNT ANALYSIS SUMMARY ==={Colors.RESET}")
        
        severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        category_counts = {}
        
        for finding in self.findings:
            severity = finding['severity']
            category = finding['category']
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            category_counts[category] = category_counts.get(category, 0) + 1
        
        print(f"{Colors.WHITE}Total Findings: {Colors.BOLD}{len(self.findings)}{Colors.RESET}")
        print(f"{Colors.RED}High Severity: {Colors.BOLD}{severity_counts['HIGH']}{Colors.RESET}")
        print(f"{Colors.BLUE}Medium Severity: {Colors.BOLD}{severity_counts['MEDIUM']}{Colors.RESET}")
        print(f"{Colors.MAGENTA}Low Severity: {Colors.BOLD}{severity_counts['LOW']}{Colors.RESET}")
        print(f"{Colors.GREEN}Informational: {Colors.BOLD}{severity_counts['INFO']}{Colors.RESET}")
        
        print(f"\n{Colors.WHITE}Findings by Category:{Colors.RESET}")
        for category, count in category_counts.items():
            print(f"  {Colors.CYAN}{category}{Colors.RESET}: {Colors.BOLD}{count}{Colors.RESET}")
        
        # Risk assessment
        risk_level = "LOW"
        risk_color = Colors.GREEN
        if severity_counts['HIGH'] > 0:
            risk_level = "HIGH"
            risk_color = Colors.RED
        elif severity_counts['MEDIUM'] > 2:
            risk_level = "MEDIUM"
            risk_color = Colors.BLUE
        
        print(f"\n{Colors.WHITE}Overall Risk Level: {risk_color}{Colors.BOLD}{risk_level}{Colors.RESET}")
        
        return {
            'total_findings': len(self.findings),
            'severity_counts': severity_counts,
            'category_counts': category_counts,
            'risk_level': risk_level
        }
    
    # ==================== UNIFIED WORKFLOW ====================
    
    def run_unified_ir(self):
        """Execute unified IR workflow: Collection -> Analysis"""
        print(f"{Colors.CYAN}{'='*70}{Colors.RESET}")
        print(f"{Colors.CYAN}{Colors.BOLD}UNIFIED LINUX INCIDENT RESPONSE AND THREAT HUNTING{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*70}{Colors.RESET}")
        print(f"{Colors.GREEN}[INFO]{Colors.RESET} Starting unified IR workflow at {Colors.WHITE}{datetime.datetime.now()}{Colors.RESET}")
        print(f"{Colors.GREEN}[INFO]{Colors.RESET} Output directory: {Colors.WHITE}{self.output_dir}{Colors.RESET}")
        
        try:
            # ==================== PHASE 1: ARTIFACT COLLECTION ====================
            print(f"\n{Colors.YELLOW}{Colors.BOLD}{'='*50}{Colors.RESET}")
            print(f"{Colors.YELLOW}{Colors.BOLD}PHASE 1: ARTIFACT COLLECTION{Colors.RESET}")
            print(f"{Colors.YELLOW}{Colors.BOLD}{'='*50}{Colors.RESET}")
            
            # Execute all collection modules
            self.collect_system_logs()
            self.collect_authentication_artifacts()
            self.collect_bash_history()
            self.collect_system_info()
            self.collect_cron_jobs()
            self.collect_network_artifacts()
            self.collect_web_artifacts()
            self.collect_persistence_artifacts()
            self.collect_file_timeline()
            self.collect_audit_logs()
            self.collect_ssh_artifacts()
            self.collect_tmp_artifacts()
            
            # Create collection report and archive
            collection_report = self.create_collection_report()
            archive_file, hash_file = self.create_archive()
            
            print(f"\n{Colors.GREEN}[SUCCESS]{Colors.RESET} Artifact collection completed!")
            print(f"{Colors.GREEN}[INFO]{Colors.RESET} Collected {Colors.WHITE}{len(self.collection_log)}{Colors.RESET} artifacts")
            
            # ==================== PHASE 2: THREAT HUNTING & ANALYSIS ====================
            print(f"\n{Colors.YELLOW}{Colors.BOLD}{'='*50}{Colors.RESET}")
            print(f"{Colors.YELLOW}{Colors.BOLD}PHASE 2: THREAT HUNTING & ANALYSIS{Colors.RESET}")
            print(f"{Colors.YELLOW}{Colors.BOLD}{'='*50}{Colors.RESET}")
            
            # Execute all analysis modules on collected artifacts
            self.analyze_collected_system_logs()
            self.analyze_collected_authentication_logs()
            self.analyze_collected_bash_history()
            self.analyze_collected_system_info()
            self.analyze_collected_cron_jobs()
            self.analyze_collected_timeline()
            
            # Generate analysis summary and export results
            analysis_summary = self.generate_analysis_summary()
            csv_file, json_file = self.export_analysis_results()
            
            print(f"\n{Colors.GREEN}[SUCCESS]{Colors.RESET} Threat hunting analysis completed!")
            print(f"{Colors.GREEN}[INFO]{Colors.RESET} Analysis results saved to: {Colors.WHITE}{csv_file}{Colors.RESET}")
            
            # ==================== FINAL SUMMARY ====================
            print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*70}{Colors.RESET}")
            print(f"{Colors.CYAN}{Colors.BOLD}UNIFIED IR WORKFLOW COMPLETED{Colors.RESET}")
            print(f"{Colors.CYAN}{Colors.BOLD}{'='*70}{Colors.RESET}")
            
            collection_summary = {
                'successful': len([x for x in self.collection_log if x['status'] == 'SUCCESS']),
                'failed': len([x for x in self.collection_log if x['status'] == 'ERROR']),
                'missing': len([x for x in self.collection_log if x['status'] == 'MISSING'])
            }
            
            print(f"{Colors.WHITE}COLLECTION SUMMARY:{Colors.RESET}")
            print(f"  {Colors.GREEN}Successful: {Colors.BOLD}{collection_summary['successful']}{Colors.RESET}")
            print(f"  {Colors.RED}Failed: {Colors.BOLD}{collection_summary['failed']}{Colors.RESET}")
            print(f"  {Colors.YELLOW}Missing: {Colors.BOLD}{collection_summary['missing']}{Colors.RESET}")
            
            print(f"\n{Colors.WHITE}ANALYSIS SUMMARY:{Colors.RESET}")
            print(f"  {Colors.WHITE}Total Findings: {Colors.BOLD}{analysis_summary['total_findings']}{Colors.RESET}")
            risk_color = Colors.RED if analysis_summary['risk_level'] == 'HIGH' else Colors.BLUE if analysis_summary['risk_level'] == 'MEDIUM' else Colors.GREEN
            print(f"  {Colors.WHITE}Risk Level: {risk_color}{Colors.BOLD}{analysis_summary['risk_level']}{Colors.RESET}")
            
            print(f"\n{Colors.WHITE}OUTPUT FILES:{Colors.RESET}")
            print(f"  {Colors.CYAN}Artifacts Archive: {Colors.WHITE}{archive_file}{Colors.RESET}")
            print(f"  {Colors.CYAN}Collection Report: {Colors.WHITE}{collection_report}{Colors.RESET}")
            print(f"  {Colors.CYAN}Analysis Results: {Colors.WHITE}{csv_file}{Colors.RESET}")
            print(f"  {Colors.CYAN}Analysis JSON: {Colors.WHITE}{json_file}{Colors.RESET}")
            
            return {
                'collection_summary': collection_summary,
                'analysis_summary': analysis_summary,
                'output_files': {
                    'artifacts_archive': archive_file,
                    'collection_report': collection_report,
                    'analysis_csv': csv_file,
                    'analysis_json': json_file
                }
            }
            
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[WARNING]{Colors.RESET} Unified IR workflow interrupted by user")
            return None
        except Exception as e:
            print(f"\n{Colors.RED}[ERROR]{Colors.RESET} Unified IR workflow failed: {str(e)}")
            return None

def main():
    parser = argparse.ArgumentParser(description='Unified Linux IR and Threat Hunting Script')
    parser.add_argument('-o', '--output', default='unified_ir_results', 
                       help='Output directory for results (default: unified_ir_results)')
    parser.add_argument('--no-archive', action='store_true', 
                       help='Skip creating compressed archive')
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Check if running as root
    if os.geteuid() != 0:
        print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} This script should be run as root for complete access to system artifacts")
        response = input("Continue anyway? (y/N): ")
        if response.lower() != 'y':
            sys.exit(1)
    
    # Initialize and run unified IR workflow
    unified_ir = UnifiedLinuxIR(output_dir=args.output)
    result = unified_ir.run_unified_ir()
    
    if result:
        print(f"\n{Colors.GREEN}[FINAL]{Colors.RESET} Unified IR workflow completed successfully!")
        print(f"{Colors.GREEN}[FINAL]{Colors.RESET} Check output directory: {Colors.WHITE}{unified_ir.output_dir}{Colors.RESET}")
    else:
        print(f"\n{Colors.RED}[FINAL]{Colors.RESET} Unified IR workflow did not complete successfully")

if __name__ == "__main__":
    main()
