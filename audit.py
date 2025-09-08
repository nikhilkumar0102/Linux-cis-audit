#!/usr/bin/env python3
"""
Linux Security Audit Tool - CIS Benchmark Based (AI-Enhanced)
==============================================================
This script performs comprehensive security audits based on CIS (Center for Internet Security)
benchmarks. It checks various system configurations including file permissions, SSH settings,
password policies, and more, and uses AI to provide detailed explanations for remediation steps.

Author: Security Team
Version: 2.1
Requirements: Linux OS, Python 3.6+, Root privileges
Usage: sudo python3 audit.py [--output filename.json]
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
import textwrap

# --- AI Integration ---
# Ensure you have run 'pip install google-generativeai' in your virtual environment
# and set your API key: 'export GOOGLE_API_KEY="YOUR_API_KEY"'
try:
    import google.generativeai as genai
    AI_ENABLED = True
except ImportError:
    AI_ENABLED = False

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
    WHITE = '\033[37m'
    GRAY = '\033[90m'
    YELLOW = '\033[33m'
    CYAN = '\033[36m'

class Icons:
    """Unicode icons for better visual representation"""
    SUCCESS = "✅"
    FAILURE = "❌"
    WARNING = "⚠️"
    INFO = "ℹ️"
    SHIELD = "🛡️"
    WRENCH = "🔧"
    AI = "🤖"
    MAGNIFYING_GLASS = "🔍"
    LOCK = "🔒"
    KEY = "🔑"
    COMPUTER = "💻"
    TARGET = "🎯"
    LIGHTBULB = "💡"
    CHART = "📊"
    ARROW_RIGHT = "➤"
    BULLET = "•"

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
            "audit_version": "2.1"
        }
        self.categories: Dict[str, Dict] = {}

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

    @property
    def risk_level(self) -> Tuple[str, str]:
        """Return risk level and color based on score"""
        score = self.score
        if score >= 90: return ("LOW", Colors.OKGREEN)
        elif score >= 70: return ("MEDIUM", Colors.WARNING)
        else: return ("HIGH", Colors.FAIL)

    def add_check(self, name: str, passed: bool, details: str = "",
                  recommendation: str = "", category: str = "General", severity: str = "medium") -> None:
        """Add a security check result"""
        self.checks.append({
            "name": name,
            "passed": passed,
            "details": details,
            "category": category,
            "severity": severity,
            "timestamp": datetime.now().isoformat()
        })
        
        # Update category statistics
        if category not in self.categories:
            self.categories[category] = {"total": 0, "passed": 0, "failed": 0}
        
        self.categories[category]["total"] += 1
        if passed:
            self.categories[category]["passed"] += 1
        else:
            self.categories[category]["failed"] += 1
            
        if not passed and recommendation:
            self.recommendations.append({
                "check": name,
                "fix": recommendation,
                "category": category,
                "severity": severity
            })

    def finalize(self) -> None:
        """Mark audit as complete"""
        self.end_time = datetime.now()

    def get_duration(self) -> str:
        """Get audit duration in human readable format"""
        if self.end_time:
            duration = self.end_time - self.start_time
            seconds = int(duration.total_seconds())
            if seconds < 60:
                return f"{seconds}s"
            else:
                minutes = seconds // 60
                remaining_seconds = seconds % 60
                return f"{minutes}m {remaining_seconds}s"
        return "In progress..."

# Global results instance
audit_results = AuditResults()

# ========================================
# UTILITY FUNCTIONS
# ========================================

def is_root() -> bool:
    """Check if running with root privileges"""
    if platform.system() != "Linux":
        print(f"{Colors.FAIL}{Icons.FAILURE} Unsupported OS: {platform.system()}. This script requires Linux.{Colors.ENDC}")
        sys.exit(1)
    return os.geteuid() == 0

def run_command(cmd: str) -> Tuple[str, bool]:
    """Execute shell command safely and return output with success status"""
    try:
        output = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT, text=True, timeout=30
        ).strip()
        return output, True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        return getattr(e, 'output', 'Command failed or timed out').strip(), False

def get_config_value(config_output: str, key: str) -> Optional[str]:
    """Parse configuration output to find a specific key's value"""
    for line in config_output.splitlines():
        line = line.strip()
        if line.lower().startswith(key.lower() + " "):
            parts = line.split(maxsplit=1)
            return parts[1] if len(parts) > 1 else None
    return None

def format_text_box(text: str, width: int = 80, padding: int = 2) -> str:
    """Format text in a nice box"""
    lines = textwrap.wrap(text, width - (padding * 2) - 2)
    border = "─" * (width - 2)
    content_lines = [f"│{' ' * padding}{line:<{width - (padding * 2) - 2}}{' ' * padding}│" for line in lines]
    
    return f"┌{border}┐\n" + "\n".join(content_lines) + f"\n└{border}┘"

def print_section_header(title: str, icon: str = Icons.INFO):
    """Print a formatted section header"""
    print(f"\n{Colors.BOLD}{Colors.HEADER}{'=' * 20} {icon} {title.upper()} {'=' * 20}{Colors.ENDC}")

def print_progress_bar(current: int, total: int, prefix: str = "Progress"):
    """Print a simple progress bar"""
    percent = (current / total) * 100
    filled_length = int(50 * current // total)
    bar = '█' * filled_length + '-' * (50 - filled_length)
    print(f'\r{Colors.OKCYAN}{prefix}: |{bar}| {percent:.1f}% Complete{Colors.ENDC}', end='')
    if current == total:
        print()  # New line on completion

# ========================================
# AI ENHANCEMENT FUNCTION
# ========================================

def get_ai_explanation(check_name: str, details: str, fix: str, severity: str = "medium") -> Optional[str]:
    """Uses the Gemini API to generate a detailed explanation for a failed security check."""
    if not AI_ENABLED or not os.getenv("GOOGLE_API_KEY"):
        return None
    try:
        genai.configure(api_key=os.environ["GOOGLE_API_KEY"])
        model = genai.GenerativeModel('gemini-2.0-flash')
        
        severity_context = {
            "low": "This is a low-risk security issue that should be addressed when convenient.",
            "medium": "This is a medium-risk security issue that should be addressed promptly.",
            "high": "This is a high-risk security issue that requires immediate attention."
        }
        
        prompt = f"""
         As a cybersecurity expert, analyze this failed CIS Benchmark check for a Debian Linux system.
        Provide a response with three sections: Risk, Impact, and Fix.
        Use simple bullet points for each section. Be concise.

        - **Failed Check:** "{check_name}"
        - **Details:** "{details}" 
        """
        
        response = model.generate_content(prompt, safety_settings={'HARM_CATEGORY_HARASSMENT':'BLOCK_NONE'})
        return response.text.strip()
    except Exception as e:
        return f"AI explanation unavailable: {str(e)}"

# ========================================
# SECURITY CHECK IMPLEMENTATIONS
# ========================================

def check_file_permissions():
    """CIS 7.1 - Verify permissions on critical system files"""
    critical_files = {
        "/etc/passwd": {"owner": "root", "group": "root", "mode": "644", "desc": "User account information", "severity": "high"},
        "/etc/shadow": {"owner": "root", "group": "shadow", "mode": "640", "desc": "Password hashes", "severity": "high"},
        "/etc/group": {"owner": "root", "group": "root", "mode": "644", "desc": "Group information", "severity": "medium"},
        "/etc/sudoers": {"owner": "root", "group": "root", "mode": "440", "desc": "Sudo configuration", "severity": "high"},
        "/etc/ssh/sshd_config": {"owner": "root", "group": "root", "mode": "600", "desc": "SSH server config", "severity": "high"},
    }
    
    for i, (file_path, expected) in enumerate(critical_files.items(), 1):
        print_progress_bar(i, len(critical_files), "File Permissions")
        
        check_name = f"File Permissions: {os.path.basename(file_path)}"
        if not os.path.exists(file_path):
            audit_results.add_check(
                check_name, False, 
                f"File not found: {file_path}", 
                f"Ensure '{file_path}' exists and is properly configured.", 
                "File System Security", expected["severity"]
            )
            continue
            
        try:
            stat = os.stat(file_path)
            mode = oct(stat.st_mode)[-3:]
            owner_name = pwd.getpwuid(stat.st_uid).pw_name
            group_name = grp.getgrgid(stat.st_gid).gr_name
            
            is_correct = (owner_name == expected["owner"] and 
                          group_name == expected["group"] and 
                          mode == expected["mode"])
            
            if is_correct:
                details = f"{expected['desc']} - Correct permissions ({owner_name}:{group_name} {mode})"
                audit_results.add_check(check_name, True, details, category="File System Security")
            else:
                details = f"{expected['desc']} - Expected: {expected['owner']}:{expected['group']} {expected['mode']}, Found: {owner_name}:{group_name} {mode}"
                fix = f"sudo chown {expected['owner']}:{expected['group']} {file_path} && sudo chmod {expected['mode']} {file_path}"
                audit_results.add_check(check_name, False, details, fix, "File System Security", expected["severity"])
        except (KeyError, FileNotFoundError, PermissionError) as e:
            audit_results.add_check(check_name, False, f"Error checking {file_path}: {e}", "Review manually.", "File System Security", "medium")

def check_partition_mounts():
    """CIS 1.1 - Verify security mount options for critical partitions"""
    partitions_config = {
        "/tmp": {"options": ["nodev", "nosuid", "noexec"], "desc": "Temporary files", "severity": "medium"},
        "/var/tmp": {"options": ["nodev", "nosuid", "noexec"], "desc": "Variable temporary files", "severity": "medium"},
        "/dev/shm": {"options": ["nodev", "nosuid", "noexec"], "desc": "Shared memory", "severity": "high"},
        "/home": {"options": ["nodev"], "desc": "User home directories", "severity": "low"}
    }
    
    for i, (partition, config) in enumerate(partitions_config.items(), 1):
        print_progress_bar(i, len(partitions_config), "Mount Security  ")
        
        check_name = f"Mount Security: {partition}"
        expected_opts = config["options"]
        
        if not os.path.exists(partition): 
            continue
            
        if not os.path.ismount(partition):
            audit_results.add_check(
                check_name, False, 
                f"{partition} is not a separate mount point.", 
                f"For higher security, create a separate partition for {partition}.", 
                "File System Security", config["severity"]
            )
            continue
            
        output, success = run_command(f"findmnt -kn -o OPTIONS {partition}")
        if not success:
            audit_results.add_check(
                check_name, False, 
                f"Could not retrieve mount options for {partition}.", 
                f"Check manually: findmnt {partition}", 
                "File System Security", "medium"
            )
            continue
            
        mounted_opts = output.split(',')
        missing_opts = [opt for opt in expected_opts if opt not in mounted_opts]
        
        if not missing_opts:
            audit_results.add_check(
                check_name, True, 
                f"{config['desc']} - Secured with: {','.join(expected_opts)}", 
                category="File System Security"
            )
        else:
            details = f"{config['desc']} - Missing security options: {', '.join(missing_opts)}"
            fix = f"Edit /etc/fstab for {partition}, add '{','.join(missing_opts)}' to options, then remount"
            audit_results.add_check(check_name, False, details, fix, "File System Security", config["severity"])

def check_ssh_configuration():
    """CIS 5.1 - SSH Server Configuration Security"""
    if not run_command("command -v sshd")[1]:
        audit_results.add_check("SSH Server", True, "SSH server is not installed.", category="SSH Security")
        return
        
    ssh_config, success = run_command("sshd -T")
    if not success:
        audit_results.add_check("SSH Config", False, "Could not get running SSH config.", "Ensure sshd is running and properly configured.", "SSH Security", "high")
        return
        
    ssh_checks = [
        {"name": "SSH Root Login", "key": "PermitRootLogin", "expected": "no", "check_func": lambda v: v.lower() == "no", "severity": "high"},
        {"name": "SSH Empty Passwords", "key": "PermitEmptyPasswords", "expected": "no", "check_func": lambda v: v.lower() == "no", "severity": "high"},
        {"name": "SSH Max Auth Tries", "key": "MaxAuthTries", "expected": "≤4", "check_func": lambda v: int(v) <= 4, "severity": "medium"},
        {"name": "SSH Log Level", "key": "LogLevel", "expected": "INFO or VERBOSE", "check_func": lambda v: v.upper() in ["VERBOSE", "INFO"], "severity": "low"},
    ]
    
    for i, check in enumerate(ssh_checks, 1):
        print_progress_bar(i, len(ssh_checks), "SSH Configuration")
        
        value = get_config_value(ssh_config, check["key"])
        passed = value and check["check_func"](value)
        details = f"Current: '{value or 'not set'}', Expected: {check['expected']}"
        fix = f"Set '{check['key']} {check['expected'].split('/')[0].replace('≤', '')}' in /etc/ssh/sshd_config and restart SSH service" if not passed else ""
        audit_results.add_check(check["name"], passed, details, fix, "SSH Security", check["severity"])

def check_password_policies():
    """CIS 5.3 & 5.4 - Password and Account Security Policies"""
    # Check password max age
    print_progress_bar(1, 2, "Password Policies")
    pass_max_days, _ = run_command(r"grep -Po '^\s*PASS_MAX_DAYS\s+\K(\d+)' /etc/login.defs")
    passed_max = pass_max_days and int(pass_max_days) <= 365
    details = f"PASS_MAX_DAYS is set to {pass_max_days or 'not configured'} days"
    audit_results.add_check(
        "Password Max Age", passed_max, details, 
        "Set 'PASS_MAX_DAYS 365' in /etc/login.defs to ensure password expiration.", 
        "Password & Account Policy", "medium"
    )

    # Check minimum password length
    print_progress_bar(2, 2, "Password Policies")
    minlen, _ = run_command(r"grep -Po '^\s*minlen\s*=\s*\K(\d+)' /etc/security/pwquality.conf")
    passed_minlen = minlen and int(minlen) >= 14
    details = f"Minimum password length is set to {minlen or 'not configured'} characters"
    audit_results.add_check(
        "Password Min Length", passed_minlen, details,
        "Set 'minlen = 14' in /etc/security/pwquality.conf for stronger passwords.", 
        "Password & Account Policy", "medium"
    )

def check_system_accounts():
    """CIS 5.4.2 - System Account Security"""
    # Check for unique root UID
    print_progress_bar(1, 2, "System Accounts  ")
    uid_zero_users, _ = run_command("awk -F: '($3 == 0) { print $1 }' /etc/passwd")
    passed_uid_zero = uid_zero_users.strip() == "root"
    details = f"Accounts with UID 0: {uid_zero_users.replace(chr(10), ', ') if uid_zero_users else 'none'}"
    audit_results.add_check(
        "Unique Root UID", passed_uid_zero, details,
        "Ensure only 'root' account has UID 0. Remove or change UID for other accounts.", 
        "Password & Account Policy", "high"
    )

    # Check system account shells
    print_progress_bar(2, 2, "System Accounts  ")
    shells, _ = run_command(r"awk -F: '($3 < 1000 && $1 != \"root\" && $7 !~ /(\/sbin\/nologin|\/usr\/sbin\/nologin|\/bin\/false)/) {print $1}' /etc/passwd")
    passed_shells = not shells.strip()
    details = f"System accounts with login shells: {shells.replace(chr(10), ', ') if shells else 'none'}"
    audit_results.add_check(
        "System Account Shells", passed_shells, details,
        "Set shell to '/usr/sbin/nologin' for system accounts to prevent login.", 
        "Password & Account Policy", "medium"
    )

# ========================================
# ENHANCED REPORTING AND OUTPUT
# ========================================

def print_banner():
    """Display attractive application banner"""
    banner = f"""
{Colors.BOLD}{Colors.HEADER}╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║  {Icons.SHIELD} {Colors.WHITE}LINUX SECURITY AUDIT TOOL{Colors.HEADER} {Icons.SHIELD}                                  ║
║                                                                    ║
║  {Colors.CYAN}CIS Benchmark Based Security Assessment{Colors.HEADER}                             ║
║  {Colors.PURPLE}Version 2.1 | AI-Enhanced Edition{Colors.HEADER}                                 ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝{Colors.ENDC}

{Colors.BOLD}{Colors.OKCYAN}{Icons.COMPUTER} System Information:{Colors.ENDC}
{Colors.GRAY}├─ Hostname:{Colors.ENDC} {Colors.WHITE}{audit_results.metadata['hostname']}{Colors.ENDC}
{Colors.GRAY}├─ Operating System:{Colors.ENDC} {Colors.WHITE}{audit_results.metadata['os']}{Colors.ENDC}
{Colors.GRAY}├─ Architecture:{Colors.ENDC} {Colors.WHITE}{audit_results.metadata['architecture']}{Colors.ENDC}
{Colors.GRAY}└─ Scan Started:{Colors.ENDC} {Colors.WHITE}{audit_results.start_time.strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}
"""
    print(banner)

def print_category_summary():
    """Print summary by category"""
    print_section_header("SECURITY ASSESSMENT BY CATEGORY", Icons.CHART)
    
    for category, stats in audit_results.categories.items():
        score = (stats["passed"] / stats["total"]) * 100 if stats["total"] > 0 else 0
        
        if score >= 80:
            color = Colors.OKGREEN
            status = "GOOD"
        elif score >= 60:
            color = Colors.WARNING
            status = "NEEDS ATTENTION"
        else:
            color = Colors.FAIL
            status = "CRITICAL"
            
        print(f"\n{Colors.BOLD}{color}{Icons.TARGET} {category}{Colors.ENDC}")
        print(f"    {Colors.GRAY}Score:{Colors.ENDC} {color}{score:.1f}%{Colors.ENDC} ({status})")
        print(f"    {Colors.GRAY}Checks:{Colors.ENDC} {Colors.OKGREEN}{stats['passed']} passed{Colors.ENDC}, {Colors.FAIL}{stats['failed']} failed{Colors.ENDC} out of {stats['total']} total")

def print_detailed_results():
    """Print detailed results organized by category"""
    print_section_header("DETAILED SECURITY CHECK RESULTS", Icons.MAGNIFYING_GLASS)
    
    for category in audit_results.categories.keys():
        category_checks = [check for check in audit_results.checks if check["category"] == category]
        if not category_checks:
            continue
            
        print(f"\n{Colors.BOLD}{Colors.OKCYAN}📁 {category}{Colors.ENDC}")
        print(f"{Colors.GRAY}{'─' * (len(category) + 3)}{Colors.ENDC}")
        
        for check in category_checks:
            if check["passed"]:
                symbol = f"{Colors.OKGREEN}{Icons.SUCCESS}{Colors.ENDC}"
                name_color = Colors.OKGREEN
            else:
                symbol = f"{Colors.FAIL}{Icons.FAILURE}{Colors.ENDC}"
                name_color = Colors.FAIL
                
            print(f"  {symbol} {name_color}{check['name']}{Colors.ENDC}")
            
            # Indent and wrap the details
            details_lines = textwrap.wrap(check['details'], width=70)
            for line in details_lines:
                print(f"      {Colors.GRAY}{line}{Colors.ENDC}")

def print_recommendations_enhanced():
    """Print enhanced recommendations with AI explanations"""
    if not audit_results.recommendations:
        return
        
    print_section_header("SECURITY RECOMMENDATIONS & AI INSIGHTS", Icons.LIGHTBULB)
    
    # Group recommendations by severity
    severity_order = ["high", "medium", "low"]
    severity_colors = {"high": Colors.FAIL, "medium": Colors.WARNING, "low": Colors.OKCYAN}
    severity_icons = {"high": "🚨", "medium": "⚠️", "low": "ℹ️"}
    
    for severity in severity_order:
        severity_recs = [rec for rec in audit_results.recommendations if rec.get("severity", "medium") == severity]
        if not severity_recs:
            continue
            
        print(f"\n{Colors.BOLD}{severity_colors[severity]}{severity_icons[severity]} {severity.upper()} PRIORITY ISSUES{Colors.ENDC}")
        print(f"{Colors.GRAY}{'═' * 50}{Colors.ENDC}")
        
        for i, rec in enumerate(severity_recs, 1):
            print(f"\n{Colors.BOLD}{severity_colors[severity]}{i}. {rec['check']}{Colors.ENDC}")
            
            # Print the fix
            fix_lines = textwrap.wrap(f"Fix: {rec['fix']}", width=70)
            print(f"\n    {Colors.OKCYAN}{Icons.WRENCH} Solution:{Colors.ENDC}")
            for line in fix_lines:
                print(f"    {Colors.GRAY}{Icons.ARROW_RIGHT}{Colors.ENDC} {line}")
            
            # Get and display AI explanation
            failed_check = next((c for c in audit_results.checks if c["name"] == rec["check"]), None)
            if failed_check:
                ai_explanation = get_ai_explanation(
                    rec['check'], 
                    failed_check['details'], 
                    rec['fix'], 
                    rec.get('severity', 'medium')
                )
                
                if ai_explanation and "AI explanation unavailable" not in ai_explanation:
                    print(f"\n    {Colors.PURPLE}{Icons.AI} AI Security Analysis:{Colors.ENDC}")
                    
                    # --- CORRECTED CODE BLOCK ---
                    # Split the AI response by lines and print each one indented
                    for line in ai_explanation.split('\n'):
                        # Add color to markdown headers for better readability
                        if line.strip().startswith('**Risk'):
                            line = f"{Colors.FAIL}{line}{Colors.ENDC}"
                        elif line.strip().startswith('**Impact'):
                            line = f"{Colors.WARNING}{line}{Colors.ENDC}"
                        elif line.strip().startswith('**Fix'):
                            line = f"{Colors.OKCYAN}{line}{Colors.ENDC}"
                    
                        wrapped_lines = textwrap.wrap(line.strip().replace('**', ''), width=70)
                        
                        for i, sub_line in enumerate(wrapped_lines):
                            if i == 0:
                                # Print the first line with a bullet
                                print(f"      {Colors.GRAY}{Icons.BULLET}{Colors.ENDC} {sub_line}")
                            else:
                                # Print subsequent wrapped lines with extra indentation for alignment
                                print(f"        {Colors.GRAY}{sub_line}{Colors.ENDC}")
                    # Format AI explanation nicely
                    

def print_final_summary():
    """Print final summary with security score and recommendations"""
    audit_results.finalize()
    risk_level, risk_color = audit_results.risk_level
    
    print_section_header("FINAL SECURITY ASSESSMENT", Icons.SHIELD)
    
    # Create a nice summary box
    summary_text = f"""
{Icons.CHART} OVERALL SECURITY SCORE: {audit_results.score:.1f}/100 (Grade: {audit_results.grade})
{Icons.TARGET} RISK LEVEL: {risk_level}
{Icons.SUCCESS} CHECKS PASSED: {audit_results.passed_checks}/{audit_results.total_checks}
{Icons.FAILURE} CHECKS FAILED: {audit_results.failed_checks}/{audit_results.total_checks}
{Icons.WRENCH} TOTAL RECOMMENDATIONS: {len(audit_results.recommendations)}
{Icons.COMPUTER} AUDIT DURATION: {audit_results.get_duration()}
    """.strip()
    
    # Print colored summary
    lines = summary_text.split('\n')
    for line in lines:
        if "SECURITY SCORE" in line:
            grade_color = Colors.OKGREEN if audit_results.score >= 80 else Colors.WARNING if audit_results.score >= 60 else Colors.FAIL
            print(f"{Colors.BOLD}{grade_color}{line}{Colors.ENDC}")
        elif "RISK LEVEL" in line:
            print(f"{Colors.BOLD}{risk_color}{line}{Colors.ENDC}")
        elif "PASSED" in line:
            print(f"{Colors.BOLD}{Colors.OKGREEN}{line}{Colors.ENDC}")
        elif "FAILED" in line:
            print(f"{Colors.BOLD}{Colors.FAIL}{line}{Colors.ENDC}")
        else:
            print(f"{Colors.BOLD}{Colors.OKCYAN}{line}{Colors.ENDC}")
    
    # Add security recommendations
    if audit_results.failed_checks > 0:
        print(f"\n{Colors.BOLD}{Colors.WARNING}{Icons.WARNING} ACTION REQUIRED:{Colors.ENDC}")
        print(f"    Your system has {Colors.FAIL}{audit_results.failed_checks} security issues{Colors.ENDC} that need attention.")
        print(f"    Review the recommendations above to improve your security posture.")
    else:
        print(f"\n{Colors.BOLD}{Colors.OKGREEN}{Icons.SUCCESS} EXCELLENT:{Colors.ENDC}")
        print(f"    Your system passed all security checks! Keep up the good work.")

def print_report(quiet_mode=False):
    """Generate and print the complete, enhanced and organized report."""
    if not quiet_mode:
        print_category_summary()
        print_detailed_results()
    
    print_recommendations_enhanced()
    print_final_summary()

def save_json_report(filename: str):
    """Save detailed audit results to JSON file"""
    try:
        report_data = {
            "metadata": audit_results.metadata,
            "summary": {
                "total_checks": audit_results.total_checks,
                "passed_checks": audit_results.passed_checks,
                "failed_checks": audit_results.failed_checks,
                "score": audit_results.score,
                "grade": audit_results.grade,
                "risk_level": audit_results.risk_level[0],
                "duration": audit_results.get_duration(),
                "start_time": audit_results.start_time.isoformat(),
                "end_time": audit_results.end_time.isoformat() if audit_results.end_time else None
            },
            "categories": audit_results.categories,
            "detailed_results": audit_results.checks,
            "recommendations": audit_results.recommendations,
            "generation_info": {
                "ai_enabled": AI_ENABLED,
                "timestamp": datetime.now().isoformat()
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2)
            
        print(f"\n{Colors.OKGREEN}{Icons.SUCCESS} Detailed report saved to: {Colors.BOLD}{filename}{Colors.ENDC}")
        
    except Exception as e:
        print(f"\n{Colors.FAIL}{Icons.FAILURE} Error saving report: {str(e)}{Colors.ENDC}")

# ========================================
# MAIN EXECUTION LOGIC
# ========================================

def run_security_checks():
    """Execute all security checks with progress indication"""
    audit_functions = [
        ("File Permissions", check_file_permissions),
        ("Mount Security", check_partition_mounts),
        ("SSH Configuration", check_ssh_configuration),
        ("Password Policies", check_password_policies),
        ("System Accounts", check_system_accounts)
    ]
    
    print(f"\n{Colors.BOLD}{Colors.WARNING}{Icons.MAGNIFYING_GLASS} STARTING COMPREHENSIVE SECURITY AUDIT{Colors.ENDC}")
    print(f"{Colors.GRAY}Running {len(audit_functions)} security check categories...{Colors.ENDC}\n")
    
    for i, (name, func) in enumerate(audit_functions, 1):
        print(f"{Colors.BOLD}{Colors.OKCYAN}[{i}/{len(audit_functions)}] {name}{Colors.ENDC}")
        try:
            func()
        except Exception as e:
            print(f"{Colors.FAIL}{Icons.FAILURE} Error in {name}: {str(e)}{Colors.ENDC}")
        print()  # Add spacing between checks

def main():
    """Main execution function with enhanced user experience"""
    parser = argparse.ArgumentParser(
        description="Linux Security Audit Tool - CIS Benchmark Based (AI-Enhanced)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  sudo -E venv/bin/python3 audit.py          # Full interactive audit (With AI Scan)
  sudo python3 audit.py                      # Full interactive audit (Without AI Scan)
  sudo python3 audit.py --quiet              # Summary and recommendations only
  sudo python3 audit.py --output report.json # Save detailed JSON report
 
{Colors.BOLD}Note:{Colors.ENDC} This tool requires root privileges to access system configurations.
{Colors.BOLD}AI Features:{Colors.ENDC} Set GOOGLE_API_KEY environment variable for AI explanations.
        """
    )
    parser.add_argument("--output", metavar="FILE", help="Save detailed report to a JSON file")
    parser.add_argument("--quiet", action="store_true", help="Minimal console output (summary and recommendations only)")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    args = parser.parse_args()

    # Disable colors if requested
    if args.no_color:
        for attr in dir(Colors):
            if not attr.startswith('_'):
                setattr(Colors, attr, '')

    # Print banner unless in quiet mode
    if not args.quiet:
        print_banner()
    
    # Show AI status
    if AI_ENABLED and os.getenv("GOOGLE_API_KEY"):
        ai_status = f"{Colors.OKGREEN}{Icons.AI} AI explanations enabled{Colors.ENDC}"
    elif AI_ENABLED and not os.getenv("GOOGLE_API_KEY"):
        ai_status = f"{Colors.WARNING}{Icons.WARNING} AI disabled: GOOGLE_API_KEY not set{Colors.ENDC}"
    else:
        ai_status = f"{Colors.WARNING}{Icons.WARNING} AI disabled: google-generativeai not installed{Colors.ENDC}"
    
    if not args.quiet:
        print(f"\n{Colors.BOLD}Configuration:{Colors.ENDC}")
        print(f"├─ {ai_status}")
        print(f"└─ {Colors.OKCYAN}Output mode: {'Quiet' if args.quiet else 'Full'}{Colors.ENDC}")
    
    # Run the security audit
    run_security_checks()
    
    # Generate and display report
    print_report(quiet_mode=args.quiet)
    
    # Save JSON report if requested
    if args.output:
        save_json_report(args.output)
    
    # Final message based on results
    if audit_results.failed_checks == 0:
        print(f"\n{Colors.BOLD}{Colors.OKGREEN}{Icons.SHIELD} Security audit completed successfully! Your system is well-configured.{Colors.ENDC}")
    else:
        print(f"\n{Colors.BOLD}{Colors.WARNING}{Icons.SHIELD} Security audit completed. Please review and address the {audit_results.failed_checks} security issues found above.{Colors.ENDC}")

if __name__ == "__main__":
    # Check for root privileges
    if not is_root():
        print(f"{Colors.FAIL}{Icons.FAILURE} {Colors.BOLD}Root privileges required{Colors.ENDC}")
        print(f"{Colors.GRAY}This script needs root access to check system configurations.{Colors.ENDC}")
        print(f"{Colors.OKCYAN}Please run: {Colors.BOLD}sudo python3 {sys.argv[0]}{Colors.ENDC}")
        sys.exit(1)
    
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.WARNING}{Icons.WARNING} Audit interrupted by user.{Colors.ENDC}")
        if audit_results.checks:
            print(f"{Colors.GRAY}Partial results: {audit_results.passed_checks}/{len(audit_results.checks)} checks completed.{Colors.ENDC}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.FAIL}{Icons.FAILURE} Unexpected error: {str(e)}{Colors.ENDC}")
        print(f"{Colors.GRAY}Please report this issue to the development team.{Colors.ENDC}")
        sys.exit(1)
