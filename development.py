import nmap  # For network scanning
import os    # For file operations
import re    # For pattern matching
import subprocess  # For executing system commands
from datetime import datetime  # Fix: Corrected datetime import

# Log file for storing all results
log_file = "security_scan.log"

def log_message(message):
    """Helper function to log messages to the file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, "a") as file:
        file.write(f"[{timestamp}] {message}\n")

# =========================== PHASE 1: NETWORK MONITORING & INTRUSION DETECTION ===========================

def scan_network():
    """ Scans the network for active devices and open ports """
    network_range = "192.168.1.0/24"
    scanner = nmap.PortScanner()

    print(f"Scanning network: {network_range}... This may take some time.")
    scanner.scan(hosts=network_range, arguments="-sn")

    for host in scanner.all_hosts():
        if host in scanner.all_hosts() and 'status' in scanner[host] and scanner[host]['status']['state'] == "up":
            open_ports = []
            scanner.scan(host, arguments="-p 1-1024")
            if "tcp" in scanner[host]:
                open_ports = [port for port in scanner[host]["tcp"] if scanner[host]["tcp"][port]["state"] == "open"]
            
            log_message(f"[ACTIVE DEVICE] IP: {host} Open Ports: {', '.join(map(str, open_ports))}")
    print("Network scan completed.")

# ====================== PHASE 2: LOG ANALYSIS & THREAT HUNTING ======================

def detect_password_leaks():
    """ Scans logs and system files for password leaks """
    suspicious_files = ["/var/log/auth.log", "/var/log/syslog", "/home/kali/.bash_history"]
    password_patterns = [
        r"password\s*=\s*['\"]?([^'\"]+)['\"]?",
        r"LOGIN\s*FAILED",
        r"invalid\s*user",
        r"root\s*login\s*attempt",
        r"brute-force\s*attack",
        r"su\s*authentication\s*failure"
    ]

    for filename in suspicious_files:
        if os.path.exists(filename) and os.access(filename, os.R_OK):
            with open(filename, "r", errors="ignore") as f:
                for line in f:
                    for pattern in password_patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            log_message(f"⚠ WARNING: Possible password leak in {filename}: {line.strip()}")
        else:
            log_message(f"⚠ WARNING: Skipping {filename} due to permission restrictions.")
    print("Password leak detection completed.")

# ============================ PHASE 3: INCIDENT RESPONSE & AUTOMATED DEFENSE ============================

def block_suspicious_ips():
    """ Blocks IPs with repeated failed login attempts """
    auth_log = "/var/log/auth.log"
    failed_login_ips = {}

    if os.path.exists(auth_log) and os.access(auth_log, os.R_OK):
        with open(auth_log, "r", errors="ignore") as f:
            for line in f:
                match = re.search(r"Failed password for .* from ([\d.]+) port", line)
                if match:
                    ip = match.group(1)
                    failed_login_ips[ip] = failed_login_ips.get(ip, 0) + 1
                    
                    if failed_login_ips[ip] > 3:  # Threshold for blocking
                        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
                        log_message(f"⚠ WARNING: Blocking IP {ip} due to multiple failed login attempts")
    else:
        log_message(f"⚠ WARNING: Skipping {auth_log} due to permission restrictions.")
    print("IP blocking completed.")

# ============================ PHASE 4: SECURITY HARDENING & COMPLIANCE REPORTING ============================

def generate_compliance_report():
    """ Generates a security compliance report """
    compliance_report = "compliance_report.txt"
    with open(compliance_report, "w") as file:
        file.write("Security Compliance Report\n")
        file.write("="*60 + "\n")
        file.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        file.write("- Network Scan Results:\n")
        with open(log_file, "r") as log:
            file.write(log.read())
    print(f"Compliance report saved as {compliance_report}")

if __name__ == "__main__":
    print("\n=== Starting Security Automation Suite ===\n")
    scan_network()
    detect_password_leaks()
    block_suspicious_ips()
    generate_compliance_report()
    print("\n=== Security Automation Suite Completed ===")
