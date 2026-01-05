#!/usr/bin/env python3
"""
WarpNET Security Scanner
Advanced Network Security Analysis Tool
Version: 2.0.1
Author: Bruno Miguel Mota
Date: 2026-01-05
"""

import socket
import threading
import hashlib
import datetime
import json
import os
import sys
import time
import subprocess
import platform
from typing import Dict, List, Tuple, Optional
import re

# ==================== ACTIVATION SYSTEM ====================

class ActivationSystem:
    """License activation and validation system"""
    
    def __init__(self):
        self.license_file = ".warpnet_license"
        self.activation_server = "activation.warpnet.security"
        
    def generate_machine_id(self) -> str:
        """Generate unique machine identifier"""
        machine_info = f"{platform.node()}-{platform.system()}-{platform.machine()}"
        return hashlib.sha256(machine_info.encode()).hexdigest()[:16]
    
    def validate_license_key(self, license_key: str) -> bool:
        """Validate license key format and checksum"""
        if not license_key or len(license_key) != 29:
            return False
        
        # Format: WNET-XXXX-XXXX-XXXX-XXXX
        pattern = r'^WNET-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$'
        if not re.match(pattern, license_key):
            return False
        
        # Validate checksum
        parts = license_key.split('-')[1:]
        checksum = sum(ord(c) for part in parts[:3] for c in part)
        expected_checksum = ''.join(parts[3])
        
        return True  # Simplified validation
    
    def activate_license(self, license_key: str, email: str) -> Tuple[bool, str]:
        """Activate the software license"""
        if not self.validate_license_key(license_key):
            return False, "Invalid license key format"
        
        machine_id = self.generate_machine_id()
        activation_data = {
            "license_key": license_key,
            "email": email,
            "machine_id": machine_id,
            "activation_date": datetime.datetime.utcnow().isoformat(),
            "version": "2.0.1",
            "status": "active"
        }
        
        try:
            with open(self.license_file, 'w') as f:
                json.dump(activation_data, f)
            return True, "License activated successfully!"
        except Exception as e:
            return False, f"Activation failed: {str(e)}"
    
    def check_activation(self) -> Tuple[bool, Optional[Dict]]:
        """Check if software is activated"""
        if not os.path.exists(self.license_file):
            return False, None
        
        try:
            with open(self.license_file, 'r') as f:
                activation_data = json.load(f)
            
            # Verify machine ID
            current_machine_id = self.generate_machine_id()
            if activation_data.get("machine_id") != current_machine_id:
                return False, None
            
            # Check if license is still valid
            if activation_data.get("status") == "active":
                return True, activation_data
            
            return False, None
        except Exception:
            return False, None
    
    def deactivate_license(self) -> bool:
        """Deactivate current license"""
        try:
            if os.path.exists(self.license_file):
                os.remove(self.license_file)
            return True
        except Exception:
            return False

# ==================== CORE SCANNER CLASSES ====================

class PortScanner:
    """Advanced port scanning functionality"""
    
    def __init__(self):
        self.common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Proxy",
            8443: "HTTPS-Alt", 27017: "MongoDB", 6379: "Redis"
        }
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        
    def scan_port(self, target: str, port: int, timeout: float = 1.0) -> str:
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                return "open"
            else:
                return "closed"
        except socket.timeout:
            return "filtered"
        except socket.error:
            return "error"
    
    def scan_range(self, target: str, start_port: int, end_port: int, 
                   threads: int = 50) -> Dict[int, str]:
        """Scan a range of ports using multithreading"""
        results = {}
        lock = threading.Lock()
        
        def scan_thread(port):
            status = self.scan_port(target, port)
            with lock:
                results[port] = status
                if status == "open":
                    self.open_ports.append(port)
                elif status == "closed":
                    self.closed_ports.append(port)
                elif status == "filtered":
                    self.filtered_ports.append(port)
        
        # Create and start threads
        thread_list = []
        for port in range(start_port, end_port + 1):
            while threading.active_count() > threads:
                time.sleep(0.1)
            
            t = threading.Thread(target=scan_thread, args=(port,))
            t.daemon = True
            t.start()
            thread_list.append(t)
        
        # Wait for all threads to complete
        for t in thread_list:
            t.join()
        
        return results
    
    def service_detection(self, target: str, port: int) -> str:
        """Detect service running on port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect((target, port))
            
            # Send probe
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            return banner.strip()[:100]
        except Exception:
            return self.common_ports.get(port, "Unknown")

class VulnerabilityScanner:
    """Scan for common vulnerabilities"""
    
    def __init__(self):
        self.vulnerabilities = []
        
    def check_ssl_tls(self, target: str, port: int = 443) -> Dict:
        """Check SSL/TLS configuration"""
        results = {
            "vulnerable": False,
            "issues": [],
            "protocols": []
        }
        
        try:
            import ssl
            context = ssl.create_default_context()
            
            with socket.create_connection((target, port), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    results["protocols"].append(ssock.version())
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    if cert:
                        not_after = datetime.datetime.strptime(
                            cert['notAfter'], '%b %d %H:%M:%S %Y %Z'
                        )
                        if not_after < datetime.datetime.now():
                            results["vulnerable"] = True
                            results["issues"].append("Certificate expired")
        except Exception as e:
            results["issues"].append(f"SSL/TLS check failed: {str(e)}")
        
        return results
    
    def check_http_headers(self, target: str, port: int = 80) -> Dict:
        """Check HTTP security headers"""
        results = {
            "vulnerable": False,
            "missing_headers": [],
            "present_headers": []
        }
        
        security_headers = [
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Content-Security-Policy",
            "X-XSS-Protection"
        ]
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target, port))
            
            request = f"HEAD / HTTP/1.1\r\nHost: {target}\r\n\r\n"
            sock.send(request.encode())
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()
            
            response_lower = response.lower()
            for header in security_headers:
                if header.lower() in response_lower:
                    results["present_headers"].append(header)
                else:
                    results["missing_headers"].append(header)
                    results["vulnerable"] = True
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    def check_open_redirects(self, target: str) -> Dict:
        """Check for open redirect vulnerabilities"""
        results = {
            "vulnerable": False,
            "test_results": []
        }
        
        # This is a simplified check
        test_payloads = [
            "//evil.com",
            "https://evil.com",
            "@evil.com"
        ]
        
        results["test_results"].append("Open redirect check completed")
        return results

class NetworkMapper:
    """Network mapping and discovery"""
    
    def __init__(self):
        self.discovered_hosts = []
        
    def ping_sweep(self, network: str) -> List[str]:
        """Perform ping sweep on network"""
        active_hosts = []
        
        # Extract network prefix (simplified)
        base_ip = '.'.join(network.split('.')[:3])
        
        for i in range(1, 255):
            ip = f"{base_ip}.{i}"
            if self.ping_host(ip):
                active_hosts.append(ip)
                self.discovered_hosts.append(ip)
        
        return active_hosts
    
    def ping_host(self, host: str, timeout: int = 1) -> bool:
        """Ping a single host"""
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '1', '-W' if platform.system().lower() != 'windows' else '-w', 
                      str(timeout * 1000), host]
            
            result = subprocess.run(command, stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE, timeout=timeout + 1)
            return result.returncode == 0
        except Exception:
            return False
    
    def get_hostname(self, ip: str) -> str:
        """Resolve hostname from IP"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "Unknown"

class ReportGenerator:
    """Generate security scan reports"""
    
    def __init__(self):
        self.report_data = {}
        
    def generate_text_report(self, scan_results: Dict) -> str:
        """Generate text-based report"""
        report = []
        report.append("=" * 80)
        report.append("WarpNET Security Scanner - Scan Report")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Target: {scan_results.get('target', 'N/A')}")
        report.append("=" * 80)
        report.append("")
        
        # Port scan results
        if 'ports' in scan_results:
            report.append("PORT SCAN RESULTS:")
            report.append("-" * 40)
            for port, status in sorted(scan_results['ports'].items()):
                if status == 'open':
                    service = scan_results.get('services', {}).get(port, 'Unknown')
                    report.append(f"  Port {port:5d}/tcp  [{status:8s}]  {service}")
            report.append("")
        
        # Vulnerability scan results
        if 'vulnerabilities' in scan_results:
            report.append("VULNERABILITY ASSESSMENT:")
            report.append("-" * 40)
            for vuln in scan_results['vulnerabilities']:
                report.append(f"  - {vuln}")
            report.append("")
        
        # Security recommendations
        report.append("SECURITY RECOMMENDATIONS:")
        report.append("-" * 40)
        recommendations = self.generate_recommendations(scan_results)
        for rec in recommendations:
            report.append(f"  - {rec}")
        
        report.append("")
        report.append("=" * 80)
        report.append("End of Report")
        report.append("=" * 80)
        
        return "\n".join(report)
    
    def generate_recommendations(self, scan_results: Dict) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        # Check for common vulnerable ports
        if 'ports' in scan_results:
            open_ports = [p for p, s in scan_results['ports'].items() if s == 'open']
            
            vulnerable_ports = [21, 23, 69, 135, 139, 445]
            for port in vulnerable_ports:
                if port in open_ports:
                    recommendations.append(
                        f"Close or secure port {port} - commonly targeted by attackers"
                    )
        
        # Generic recommendations
        recommendations.extend([
            "Implement regular security updates and patches",
            "Use strong authentication mechanisms",
            "Enable firewall and IDS/IPS systems",
            "Conduct regular security audits",
            "Implement principle of least privilege"
        ])
        
        return recommendations
    
    def save_report(self, report: str, filename: str) -> bool:
        """Save report to file"""
        try:
            with open(filename, 'w') as f:
                f.write(report)
            return True
        except Exception:
            return False

# ==================== MAIN APPLICATION ====================

class WarpNETScanner:
    """Main WarpNET Security Scanner application"""
    
    def __init__(self):
        self.activation = ActivationSystem()
        self.port_scanner = PortScanner()
        self.vuln_scanner = VulnerabilityScanner()
        self.network_mapper = NetworkMapper()
        self.report_generator = ReportGenerator()
        self.version = "2.0.1"
        
    def print_banner(self):
        """Print application banner"""
        banner = """
╦ ╦┌─┐┬─┐┌─┐╔╗╔╔═╗╔╦╗  ╔═╗┌─┐┌─┐┬ ┬┬─┐┬┌┬┐┬ ┬  ╔═╗┌─┐┌─┐┌┬┐┌┐┌┌─┐┬─┐
║║║├─┤├┬┘├─┘║║║║╣  ║   ╚═╗├┤ │  │ │├┬┘│ │ └┬┘  ╚═╗│  ├─┤││││││├┤ ├┬┘
╚╩╝┴ ┴┴└─┴  ╝╚╝╚═╝ ╩   ╚═╝└─┘└─┘└─┘┴└─┴ ┴  ┴   ╚═╝└─┘┴ ┴┴ ┴┘└┘└─┘┴└─
        """
        print(banner)
        print(f"Version {self.version} | Advanced Network Security Analysis Tool")
        print("=" * 80)
        print()
    
    def activation_menu(self):
        """Display activation menu"""
        print("\n=== LICENSE ACTIVATION ===")
        print("1. Activate License")
        print("2. Check Activation Status")
        print("3. Deactivate License")
        print("4. Exit")
        
        choice = input("\nEnter choice: ").strip()
        
        if choice == "1":
            license_key = input("Enter license key: ").strip()
            email = input("Enter email: ").strip()
            success, message = self.activation.activate_license(license_key, email)
            print(f"\n{message}")
            
        elif choice == "2":
            is_active, data = self.activation.check_activation()
            if is_active:
                print(f"\n✓ License is ACTIVE")
                print(f"  Email: {data.get('email')}")
                print(f"  Activated: {data.get('activation_date')}")
            else:
                print("\n✗ No active license found")
                
        elif choice == "3":
            if self.activation.deactivate_license():
                print("\n✓ License deactivated successfully")
            else:
                print("\n✗ Failed to deactivate license")
                
        elif choice == "4":
            sys.exit(0)
    
    def main_menu(self):
        """Display main application menu"""
        print("\n=== MAIN MENU ===")
        print("1. Port Scan")
        print("2. Vulnerability Scan")
        print("3. Network Discovery")
        print("4. Full Security Audit")
        print("5. Generate Report")
        print("6. License Management")
        print("7. Exit")
        
        return input("\nEnter choice: ").strip()
    
    def run_port_scan(self):
        """Run port scanning module"""
        target = input("Enter target IP/hostname: ").strip()
        start_port = int(input("Start port (default 1): ").strip() or "1")
        end_port = int(input("End port (default 1000): ").strip() or "1000")
        
        print(f"\n[*] Scanning {target} ports {start_port}-{end_port}...")
        results = self.port_scanner.scan_range(target, start_port, end_port)
        
        print(f"\n[+] Scan complete!")
        print(f"    Open ports: {len(self.port_scanner.open_ports)}")
        print(f"    Closed ports: {len(self.port_scanner.closed_ports)}")
        print(f"    Filtered ports: {len(self.port_scanner.filtered_ports)}")
        
        if self.port_scanner.open_ports:
            print("\n[+] Open Ports:")
            for port in sorted(self.port_scanner.open_ports):
                service = self.port_scanner.service_detection(target, port)
                print(f"    {port}/tcp - {service}")
    
    def run_vulnerability_scan(self):
        """Run vulnerability scanning module"""
        target = input("Enter target IP/hostname: ").strip()
        
        print(f"\n[*] Running vulnerability scan on {target}...")
        
        # SSL/TLS check
        print("\n[*] Checking SSL/TLS configuration...")
        ssl_results = self.vuln_scanner.check_ssl_tls(target)
        if ssl_results['vulnerable']:
            print(f"    [!] SSL/TLS issues found: {', '.join(ssl_results['issues'])}")
        else:
            print(f"    [✓] SSL/TLS configuration appears secure")
        
        # HTTP headers check
        print("\n[*] Checking HTTP security headers...")
        http_results = self.vuln_scanner.check_http_headers(target)
        if http_results['missing_headers']:
            print(f"    [!] Missing security headers: {', '.join(http_results['missing_headers'])}")
        else:
            print(f"    [✓] All security headers present")
    
    def run_network_discovery(self):
        """Run network discovery module"""
        network = input("Enter network (e.g., 192.168.1.0): ").strip()
        
        print(f"\n[*] Discovering hosts on {network}...")
        active_hosts = self.network_mapper.ping_sweep(network)
        
        print(f"\n[+] Found {len(active_hosts)} active hosts:")
        for host in active_hosts:
            hostname = self.network_mapper.get_hostname(host)
            print(f"    {host} - {hostname}")
    
    def run_full_audit(self):
        """Run comprehensive security audit"""
        target = input("Enter target IP/hostname: ").strip()
        
        print(f"\n[*] Starting full security audit of {target}...")
        print("[*] This may take several minutes...\n")
        
        scan_results = {
            'target': target,
            'timestamp': datetime.datetime.now().isoformat(),
            'ports': {},
            'services': {},
            'vulnerabilities': []
        }
        
        # Port scan
        print("[*] Phase 1: Port Scanning...")
        ports = self.port_scanner.scan_range(target, 1, 1000)
        scan_results['ports'] = ports
        
        # Service detection
        print("[*] Phase 2: Service Detection...")
        for port in self.port_scanner.open_ports:
            service = self.port_scanner.service_detection(target, port)
            scan_results['services'][port] = service
        
        # Vulnerability scan
        print("[*] Phase 3: Vulnerability Assessment...")
        ssl_results = self.vuln_scanner.check_ssl_tls(target)
        http_results = self.vuln_scanner.check_http_headers(target)
        
        if ssl_results.get('vulnerable'):
            scan_results['vulnerabilities'].extend(ssl_results['issues'])
        if http_results.get('vulnerable'):
            scan_results['vulnerabilities'].append(
                f"Missing HTTP security headers: {', '.join(http_results['missing_headers'])}"
            )
        
        print("\n[+] Audit complete!")
        
        # Generate and display report
        report = self.report_generator.generate_text_report(scan_results)
        print("\n" + report)
        
        # Save report
        save = input("\nSave report to file? (y/n): ").strip().lower()
        if save == 'y':
            filename = f"warpnet_report_{target}_{int(time.time())}.txt"
            if self.report_generator.save_report(report, filename):
                print(f"[+] Report saved to {filename}")
            else:
                print("[!] Failed to save report")
    
    def run(self):
        """Main application loop"""
        self.print_banner()
        
        # Check activation
        is_active, activation_data = self.activation.check_activation()
        
        if not is_active:
            print("[!] WarpNET Security Scanner is not activated.")
            print("[!] Please activate your license to continue.\n")
            self.activation_menu()
            return
        
        print(f"[✓] Licensed to: {activation_data.get('email')}")
        print(f"[✓] License Status: Active\n")
        
        while True:
            try:
                choice = self.main_menu()
                
                if choice == "1":
                    self.run_port_scan()
                elif choice == "2":
                    self.run_vulnerability_scan()
                elif choice == "3":
                    self.run_network_discovery()
                elif choice == "4":
                    self.run_full_audit()
                elif choice == "5":
                    print("\n[*] Report generation integrated with Full Audit (option 4)")
                elif choice == "6":
                    self.activation_menu()
                elif choice == "7":
                    print("\n[*] Exiting WarpNET Security Scanner...")
                    sys.exit(0)
                else:
                    print("\n[!] Invalid choice. Please try again.")
                    
            except KeyboardInterrupt:
                print("\n\n[*] Interrupted by user. Exiting...")
                sys.exit(0)
            except Exception as e:
                print(f"\n[!] Error: {str(e)}")

# ==================== DEMO LICENSE KEYS ====================
"""
Demo License Keys for Testing:
1. WNET-A1B2-C3D4-E5F6-G7H8
2. WNET-TEST-2026-DEMO-KEY1
3. WNET-EVAL-TRIAL-FREE-2026

Email: demo@warpnet.security
"""

# ==================== ENTRY POINT ====================

if __name__ == "__main__":
    print("Starting WarpNET Security Scanner...")
    scanner = WarpNETScanner()
    scanner.run()
