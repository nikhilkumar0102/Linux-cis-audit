#!/usr/bin/env python3
"""
Linux Security Audit Tool - CIS Benchmark Based
==============================================

This script performs comprehensive security audits based on CIS (Center for Internet Security)
benchmarks. It checks various system configurations including file permissions, SSH settings,
password policies, and more.

Author: Security Team
Version: 2.0
Requirements: Linux OS, Python 3.6+, Root privileges
Usage: sudo python3 audit.py [--output filename.json] [--quiet]
"""

import os
import subprocess
import sys
import json
import platform
import pwd
import grp
import argparse
from datetime import datetime
from typing import Dict, List, Tuple, Optional

# ========================================
# CONSTANTS AND CONFIGURATION
# ========================================

class Colors:
    """ANSI color codes for terminal output styling"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    PURPLE = '\033[35m'
    YELLOW = '\033[33m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'

class Icons:
    """Unicode icons for better visual representation"""
    SUCCESS = "✅"
    FAILURE = "❌"
    WARNING = "⚠️"
    INFO = "ℹ️"
    SHIELD = "🛡️"
    WRENCH = "🔧"
    MAGNIFYING_GLASS = "🔍"
    LOCK = "🔒"
    KEY = "🔑"
    COMPUTER = "💻"

# ========================================
# GLOBAL STATE MANAGEMENT
# ========================================

class AuditResults:
    """Centralized storage for audit results and statistics"""

    def __init__(self):
        self.checks: List[Dict] = []
        self.recommendations: List[Dict] = []
        self.start_time: datetime = datetime.now()
        self.end_time: Optional[datetime] = None
        self.metadata: Dict = {
            "hostname": platform.node(),
            "os": f"{platform.system()} {platform.release()}",
            "architecture": platform.machine(),
            "python_version": platform.python_version(),
            "audit_version": "2.0"
        }

    @property
    def total_checks(self) -> int:
        return len(self.checks)

    @property
    def passed_checks(self) -> int:
        return sum(1 for check in self.checks if check["passed"])

    @property
    def failed_checks(self) -> int:
        return self.total_checks - self.passed_checks

    @property
    def score(self) -> float:
        if self.total_checks == 0:
            return 0.0
        return (self.passed_checks / self.total_checks) * 100

    @property
    def grade(self) -> str:
        """Return letter grade based on score"""
        score = self.score
        if score >= 90: return "A"
        elif score >= 80: return "B"
        elif score >= 70: return "C"
        elif score >= 60: return "D"
        else: return "F"

    def add_check(self, name: str, passed: bool, details: str = "",
                  recommendation: str = "", category: str = "General") -> None:
        """Add a security check result"""
        self.checks.append({
            "name": name,
            "passed": passed,
            "details": details,
            "category": category,
            "timestamp": datetime.now().isoformat()
        })
        if not passed and recommendation:
            self.recommendations.append({
                "check": name,
                "fix": recommendation,
                "category": category
            })

    def finalize(self) -> None:
        """Mark audit as complete"""
        self.end_time = datetime.now()

# Global results instance
audit_results = AuditResults()

# ========================================
# UTILITY FUNCTIONS
# ========================================

def print_banner():
    """Display attractive application banner"""
    banner = f"""
{Colors.BOLD}{Colors.HEADER}╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║  {Icons.SHIELD} LINUX SECURITY AUDIT TOOL {Icons.SHIELD}                                 ║
║                                                              ║
║  CIS Benchmark Based Security Assessment                     ║
║  Version 2.0 | Enhanced Edition                              ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝{Colors.ENDC}

{Colors.OKCYAN}System Information:{Colors.ENDC}
├─ Hostname: {Colors.WHITE}{audit_results.metadata['hostname']}{Colors.ENDC}
├─ OS: {Colors.WHITE}{audit_results.metadata['os']}{Colors.ENDC}
├─ Architecture: {Colors.WHITE}{audit_results.metadata['architecture']}{Colors.ENDC}
└─ Scan Time: {Colors.WHITE}{audit_results.start_time.strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}

{Colors.WARNING}⚡ Running comprehensive security audit...{Colors.ENDC}
"""
    print(banner)

def is_root() -> bool:
    """Check if running with root privileges"""
    if platform.system() != "Linux":
        print(f"{Colors.FAIL}❌ Unsupported OS: {platform.system()}. This script requires Linux.{Colors.ENDC}")
        sys.exit(1)
    return os.geteuid() == 0

def run_command(cmd: str) -> Tuple[str, bool]:
    """
    Execute shell command safely and return output with success status
    """
    try:
        output = subprocess.check_output(
            cmd,
            shell=True,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30
        ).strip()
        return output, True
    except subprocess.CalledProcessError as e:
        return e.output.strip() if e.output else "", False
    except subprocess.TimeoutExpired:
        return "Command timed out", False

def get_config_value(config_output: str, key: str) -> Optional[str]:
    """
    Parse configuration output to find a specific key's value
    """
    for line in config_output.splitlines():
        line = line.strip()
        if line.lower().startswith(key.lower() + " "):
            parts = line.split(maxsplit=1)
            return parts[1] if len(parts) > 1 else None
    return None

# ========================================
# SECURITY CHECK IMPLEMENTATIONS
# ========================================

def check_file_permissions():
    """
    CIS 7.1 - Verify permissions on critical system files
    """
    critical_files = {
        "/etc/passwd": {"owner": "root", "group": "root", "mode": "644", "desc": "User account information"},
        "/etc/shadow": {"owner": "root", "group": "shadow", "mode": "640", "desc": "Password hashes"},
        "/etc/group": {"owner": "root", "group": "root", "mode": "644", "desc": "Group information"},
        "/etc/sudoers": {"owner": "root", "group": "root", "mode": "440", "desc": "Sudo configuration"},
        "/etc/ssh/sshd_config": {"owner": "root", "group": "root", "mode": "600", "desc": "SSH server config"},
    }

    for file_path, expected in critical_files.items():
        check_name = f"File Permissions: {os.path.basename(file_path)}"
        if not os.path.exists(file_path):
            audit_results.add_check(
                check_name, False,
                f"File not found: {file_path}",
                f"Ensure '{file_path}' exists with proper configuration",
                "File System Security"
            )
            continue

        try:
            stat = os.stat(file_path)
            mode = oct(stat.st_mode)[-3:]
            owner_name = pwd.getpwuid(stat.st_uid).pw_name
            group_name = grp.getgrgid(stat.st_gid).gr_name

            is_correct = (
                owner_name == expected["owner"] and
                group_name == expected["group"] and
                mode == expected["mode"]
            )

            if is_correct:
                details = f"{expected['desc']} - Correct permissions ({owner_name}:{group_name} {mode})"
                audit_results.add_check(check_name, True, details, category="File System Security")
            else:
                details = f"{expected['desc']} - Expected: {expected['owner']}:{expected['group']} {expected['mode']}, Found: {owner_name}:{group_name} {mode}"
                fix = f"Fix with: sudo chown {expected['owner']}:{expected['group']} {file_path} && sudo chmod {expected['mode']} {file_path}"
                audit_results.add_check(check_name, False, details, fix, "File System Security")

        except (KeyError, FileNotFoundError, PermissionError) as e:
            audit_results.add_check(
                check_name, False,
                f"Error checking {file_path}: {str(e)}",
                "Review file permissions and ownership manually",
                "File System Security"
            )

def check_partition_mounts():
    """
    CIS 1.1 - Verify security mount options for critical partitions
    """
    partitions_config = {
        "/tmp": {"options": ["nodev", "nosuid", "noexec"], "desc": "Temporary files directory"},
        "/var/tmp": {"options": ["nodev", "nosuid", "noexec"], "desc": "Variable temporary files"},
        "/dev/shm": {"options": ["nodev", "nosuid", "noexec"], "desc": "Shared memory filesystem"},
        "/home": {"options": ["nodev"], "desc": "User home directories"}
    }

    for partition, config in partitions_config.items():
        check_name = f"Mount Security: {partition}"
        expected_opts = config["options"]
        if not os.path.exists(partition):
            continue # Skip if the directory doesn't exist, e.g., /home on a server.
        
        if not os.path.ismount(partition):
            audit_results.add_check(check_name, False, f"{partition} is not a separate mount point", f"For higher security, create a separate partition for {partition} with options: {','.join(expected_opts)}", "File System Security")
            continue

        output, success = run_command(f"findmnt -kn -o OPTIONS {partition}")
        if not success:
            audit_results.add_check(check_name, False, f"Could not retrieve mount options for {partition}", f"Check mount status manually: findmnt {partition}", "File System Security")
            continue

        mounted_opts = output.split(',')
        missing_opts = [opt for opt in expected_opts if opt not in mounted_opts]

        if not missing_opts:
            details = f"{config['desc']} - Secured with: {','.join(expected_opts)}"
            audit_results.add_check(check_name, True, details, category="File System Security")
        else:
            details = f"{config['desc']} - Missing security options: {', '.join(missing_opts)}"
            fix = f"Edit /etc/fstab for {partition}, add '{','.join(missing_opts)}' to options, then remount"
            audit_results.add_check(check_name, False, details, fix, "File System Security")

def check_ssh_configuration():
    """
    CIS 5.1 - Comprehensive SSH Server Configuration Security
    """
    if not run_command("command -v sshd")[1]:
        audit_results.add_check("SSH Server", True, "SSH server not installed - Attack surface reduced", category="SSH Security")
        return

    ssh_config, success = run_command("sshd -T")
    if not success:
        audit_results.add_check("SSH Configuration", False, "Cannot read SSH configuration - Server may not be running", "Ensure SSH server is running: sudo systemctl status sshd", "SSH Security")
        return

    ssh_checks = [
        {"name": "SSH Root Login", "key": "PermitRootLogin", "expected": "no", "check_func": lambda val: val.lower() == "no", "desc": "Root login disabled for security"},
        {"name": "SSH Empty Passwords", "key": "PermitEmptyPasswords", "expected": "no", "check_func": lambda val: val.lower() == "no", "desc": "Empty passwords prohibited"},
        {"name": "SSH Max Auth Tries", "key": "MaxAuthTries", "expected": "≤4", "check_func": lambda val: val and int(val) <= 4, "desc": "Limited authentication attempts"},
        {"name": "SSH Log Level", "key": "LogLevel", "expected": "INFO/VERBOSE", "check_func": lambda val: val and val.upper() in ["VERBOSE", "INFO"], "desc": "Adequate logging enabled"}
    ]

    for check_config in ssh_checks:
        value = get_config_value(ssh_config, check_config["key"])
        passed = check_config["check_func"](value)
        if passed:
            details = f"{check_config['desc']} - Set to '{value}'"
            audit_results.add_check(check_config["name"], True, details, category="SSH Security")
        else:
            details = f"Current: '{value}', Expected: {check_config['expected']}"
            fix = f"Set '{check_config['key']} {check_config['expected'].split('/')[0].replace('≤', '')}' in /etc/ssh/sshd_config"
            audit_results.add_check(check_config["name"], False, details, fix, "SSH Security")

    weak_ciphers = ["3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "arcfour"]
    ciphers = get_config_value(ssh_config, "Ciphers") or ""
    found_weak = [c for c in weak_ciphers if c in ciphers.lower()]
    if not found_weak:
        audit_results.add_check("SSH Cipher Strength", True, "No weak ciphers detected in configuration", category="SSH Security")
    else:
        details = f"Weak ciphers found: {', '.join(found_weak)}"
        fix = "Configure strong ciphers only, e.g., 'Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com'"
        audit_results.add_check("SSH Cipher Strength", False, details, fix, "SSH Security")

def check_password_policies():
    """
    CIS 5.3 & 5.4 - Password and Account Security Policies
    """
    # Password aging policy
    pass_max_days, _ = run_command(r"grep -Po '^\s*PASS_MAX_DAYS\s+\K(\d+)' /etc/login.defs")
    if pass_max_days and int(pass_max_days) <= 365:
        details = f"Maximum password age: {pass_max_days} days"
        audit_results.add_check("Password Aging Policy", True, details, category="Password & Account Policy")
    else:
        current = pass_max_days or "not set"
        details = f"Current: {current}, Should be ≤365 days"
        fix = "Set 'PASS_MAX_DAYS 365' in /etc/login.defs and update existing users with 'chage'"
        audit_results.add_check("Password Aging Policy", False, details, fix, "Password & Account Policy")

    # Minimum password length
    minlen, _ = run_command(r"grep -Po '^\s*minlen\s*=\s*\K(\d+)' /etc/security/pwquality.conf")
    if minlen and int(minlen) >= 14:
        details = f"Minimum password length: {minlen} characters"
        audit_results.add_check("Password Length Policy", True, details, category="Password & Account Policy")
    else:
        current = minlen or "not configured"
        details = f"Current: {current}, Should be ≥14 characters"
        fix = "Set 'minlen = 14' in /etc/security/pwquality.conf"
        audit_results.add_check("Password Length Policy", False, details, fix, "Password & Account Policy")

def check_system_accounts():
    """
    CIS 5.4.2 - System Account Security
    """
    # Check for multiple UID 0 accounts
    uid_zero_accounts, _ = run_command("awk -F: '($3 == 0) { print $1 }' /etc/passwd")
    accounts = [acc.strip() for acc in uid_zero_accounts.splitlines() if acc.strip()]
    if len(accounts) == 1 and accounts[0] == "root":
        audit_results.add_check("Unique Root Account", True, "Only 'root' account has UID 0 - Proper privilege isolation", category="Password & Account Policy")
    else:
        details = f"Multiple UID 0 accounts found: {', '.join(accounts)}"
        fix = "Ensure only 'root' has UID 0. Remove or change UID for other accounts."
        audit_results.add_check("Unique Root Account", False, details, fix, "Password & Account Policy")

    # Check system accounts for valid login shells
    invalid_shells, _ = run_command(r"awk -F: '($3 < 1000 && $1 != \"root\" && $7 !~ /(\/sbin\/nologin|\/usr\/sbin\/nologin|\/bin\/false)/) {print $1}' /etc/passwd")
    if not invalid_shells.strip():
        audit_results.add_check("System Account Shells", True, "All system accounts have non-login shells - Service accounts secured", category="Password & Account Policy")
    else:
        users = ', '.join([user.strip() for user in invalid_shells.splitlines() if user.strip()])
        details = f"System accounts with login shells: {users}"
        fix = "Set shell to '/usr/sbin/nologin' for system accounts: sudo usermod -s /usr/sbin/nologin <username>"
        audit_results.add_check("System Account Shells", False, details, fix, "Password & Account Policy")

# ========================================
# REPORTING AND OUTPUT
# ========================================

def print_summary_stats():
    """Display comprehensive audit statistics"""
    audit_results.finalize()
    duration = (audit_results.end_time - audit_results.start_time).total_seconds()
    
    score = audit_results.score
    grade_color = Colors.OKGREEN if score >= 80 else Colors.WARNING if score >= 50 else Colors.FAIL
    
    print(f"\n\n{Colors.BOLD}{Colors.HEADER}╔══════════════════════════════════════════════════════════════╗")
    print(f"║                      AUDIT COMPLETED                     ║")
    print(f"╚══════════════════════════════════════════════════════════════╝{Colors.ENDC}")
    
    print(f"\n{Colors.BOLD}{Icons.MAGNIFYING_GLASS} EXECUTIVE SUMMARY{Colors.ENDC}")
    print(f"┌─ Overall Security Score: {grade_color}{score:.1f}/100 (Grade: {audit_results.grade}){Colors.ENDC}")
    print(f"├─ Total Checks: {Colors.WHITE}{audit_results.total_checks}{Colors.ENDC}")
    print(f"├─ Passed: {Colors.OKGREEN}{audit_results.passed_checks} {Icons.SUCCESS}{Colors.ENDC}")
    print(f"├─ Failed: {Colors.FAIL}{audit_results.failed_checks} {Icons.FAILURE}{Colors.ENDC}")
    print(f"└─ Audit Duration: {Colors.WHITE}{duration:.2f} seconds{Colors.ENDC}")

def print_detailed_results():
    """Display detailed results by category"""
    print(f"\n{Colors.BOLD}{Icons.SHIELD} DETAILED SECURITY ASSESSMENT{Colors.ENDC}")
    
    categories = {}
    for check in audit_results.checks:
        category = check.get("category", "General")
        if category not in categories:
            categories[category] = []
        categories[category].append(check)
        
    for category, checks in categories.items():
        passed_count = sum(1 for chk in checks if chk["passed"])
        total_count = len(checks)
        print(f"\n{Colors.BOLD}{Colors.OKCYAN}📁 {category} ({passed_count}/{total_count} passed){Colors.ENDC}")
        print("─" * 60)
        
        for check in checks:
            if check["passed"]:
                print(f"  {Colors.OKGREEN}{Icons.SUCCESS}{Colors.ENDC} {Colors.WHITE}{check['name']}{Colors.ENDC}")
                if check["details"]: print(f"    {Colors.OKCYAN}└─{Colors.ENDC} {check['details']}")
            else:
                print(f"  {Colors.FAIL}{Icons.FAILURE}{Colors.ENDC} {Colors.WHITE}{check['name']}{Colors.ENDC}")
                if check["details"]: print(f"    {Colors.FAIL}└─{Colors.ENDC} {check['details']}")

def print_recommendations():
    """Display actionable security recommendations"""
    if not audit_results.recommendations:
        print(f"\n{Colors.OKGREEN}{Icons.SUCCESS} Excellent! No security recommendations at this time.{Colors.ENDC}")
        return
    
    print(f"\n{Colors.BOLD}{Colors.WARNING}{Icons.WRENCH} SECURITY RECOMMENDATIONS{Colors.ENDC}")
    print(f"{Colors.WARNING}The following issues require attention:{Colors.ENDC}")
    
    for i, rec in enumerate(audit_results.recommendations, 1):
        print(f"\n  {Colors.WARNING}{i}.{Colors.ENDC} {Colors.BOLD}{rec['check']}{Colors.ENDC}")
        print(f"     {Colors.OKCYAN}Solution:{Colors.ENDC} {rec['fix']}")

def save_json_report(filename: str) -> bool:
    """Save comprehensive audit results to JSON file"""
    try:
        report_data = {
            "metadata": audit_results.metadata,
            "summary": {
                "score": audit_results.score,
                "grade": audit_results.grade,
                "total_checks": audit_results.total_checks,
                "passed_checks": audit_results.passed_checks,
                "failed_checks": audit_results.failed_checks,
                "start_time": audit_results.start_time.isoformat(),
                "end_time": audit_results.end_time.isoformat() if audit_results.end_time else None,
                "duration_seconds": (audit_results.end_time - audit_results.start_time).total_seconds() if audit_results.end_time else None
            },
            "checks": audit_results.checks,
            "recommendations": audit_results.recommendations
        }
        
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2, sort_keys=True)
        return True
    except IOError as e:
        print(f"\n{Colors.FAIL}{Icons.FAILURE} Error saving report to {filename}: {e}{Colors.ENDC}")
        return False

# ========================================
# MAIN EXECUTION LOGIC
# ========================================

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description="Linux Security Audit Tool - CIS Benchmark Based")
    parser.add_argument("--output", help="Save detailed report to a JSON file")
    parser.add_argument("--quiet", action="store_true", help="Minimal console output, only shows summary and recommendations")
    args = parser.parse_args()

    if not args.quiet:
        print_banner()

    # Define all audit functions to be executed
    audit_functions = [
        check_file_permissions,
        check_partition_mounts,
        check_ssh_configuration,
        check_password_policies,
        check_system_accounts
    ]

    for i, audit_func in enumerate(audit_functions, 1):
        if not args.quiet:
            print(f"{Colors.BOLD}{Colors.PURPLE}Running Check [{i}/{len(audit_functions)}]: {audit_func.__name__}{Colors.ENDC}")
        audit_func()
    
    audit_results.finalize()

    # Generate Reports
    print_summary_stats()
    if not args.quiet:
        print_detailed_results()
    print_recommendations()

    if args.output:
        if save_json_report(args.output):
            print(f"\n{Colors.OKGREEN}Successfully saved JSON report to {args.output}{Colors.ENDC}")

if __name__ == "__main__":
    if not is_root():
        print(f"{Colors.FAIL}{Icons.FAILURE} This script requires root privileges. Please run with sudo.{Colors.ENDC}")
        sys.exit(1)
    
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}Audit interrupted by user. Exiting.{Colors.ENDC}")
        sys.exit(1)
