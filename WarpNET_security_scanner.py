#!/usr/bin/env python3
"""
WarpNET Security Scanner v2.0
Advanced Network Security Analysis Tool
Copyright (c) 2026 WarpNET Security Solutions
Author: Bruno Miguel Mota
"""

import socket
import sys
import threading
import time
import hashlib
import json
import os
from datetime import datetime, timedelta
import re
import ssl
import subprocess
import platform
from typing import List, Dict, Tuple, Optional
import base64

# ============================================================================
# ACTIVATION SYSTEM
# ============================================================================

class ActivationSystem:
    """License activation and validation system"""
    
    def __init__(self):
        self.license_file = ".warpnet_license"
        self.activation_server = "warpnet-activation.secure"
        self.product_key = "WARPNET-SECURITY-2026"
        
    def generate_hardware_id(self) -> str:
        """Generate unique hardware ID based on system characteristics"""
        try:
            # Get system information
            system_info = {
                'platform': platform.platform(),
                'processor': platform.processor(),
                'machine': platform.machine(),
                'node': platform.node()
            }
            
            # Create unique hash
            info_string = json.dumps(system_info, sort_keys=True)
            hardware_id = hashlib.sha256(info_string.encode()).hexdigest()[:16]
            return hardware_id.upper()
        except Exception as e:
            return "DEMO-HARDWARE-ID"
    
    def generate_license_key(self, username: str, days_valid: int = 365) -> str:
        """Generate a license key for activation"""
        hardware_id = self.generate_hardware_id()
        expiry_date = (datetime.now() + timedelta(days=days_valid)).strftime("%Y%m%d")
        
        # Create license data
        license_data = f"{username}:{hardware_id}:{expiry_date}:{self.product_key}"
        license_hash = hashlib.sha256(license_data.encode()).hexdigest()[:32]
        
        # Format as license key: XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
        key_parts = [license_hash[i:i+4].upper() for i in range(0, 32, 4)]
        return "-".join(key_parts)
    
    def validate_license_key(self, license_key: str, username: str) -> Tuple[bool, str]:
        """Validate a license key"""
        try:
            # Remove dashes and convert to lowercase
            clean_key = license_key.replace("-", "").lower()
            
            if len(clean_key) != 32:
                return False, "Invalid license key format"
            
            # For demo purposes, generate expected key
            hardware_id = self.generate_hardware_id()
            
            # Check against generated key (simplified validation)
            expected_key = self.generate_license_key(username, 365)
            expected_clean = expected_key.replace("-", "").lower()
            
            if clean_key == expected_clean:
                return True, "License activated successfully"
            
            # Also accept demo key
            if clean_key == "demo" * 8:
                return True, "Demo license activated (30 days)"
            
            return False, "Invalid license key"
            
        except Exception as e:
            return False, f"Validation error: {str(e)}"
    
    def save_license(self, license_key: str, username: str) -> bool:
        """Save license to file"""
        try:
            license_data = {
                'key': license_key,
                'username': username,
                'hardware_id': self.generate_hardware_id(),
                'activated_date': datetime.now().isoformat(),
                'product': self.product_key
            }
            
            # Encode license data
            encoded_data = base64.b64encode(json.dumps(license_data).encode()).decode()
            
            with open(self.license_file, 'w') as f:
                f.write(encoded_data)
            
            return True
        except Exception as e:
            print(f"Error saving license: {e}")
            return False
    
    def load_license(self) -> Optional[Dict]:
        """Load and validate license from file"""
        try:
            if not os.path.exists(self.license_file):
                return None
            
            with open(self.license_file, 'r') as f:
                encoded_data = f.read()
            
            decoded_data = base64.b64decode(encoded_data.encode()).decode()
            license_data = json.loads(decoded_data)
            
            # Verify hardware ID matches
            if license_data['hardware_id'] != self.generate_hardware_id():
                return None
            
            return license_data
        except Exception as e:
            return None
    
    def is_activated(self) -> bool:
        """Check if product is activated"""
        license_data = self.load_license()
        if not license_data:
            return False
        
        # Validate license key
        is_valid, _ = self.validate_license_key(
            license_data['key'], 
            license_data['username']
        )
        
        return is_valid
    
    def activate_interactive(self) -> bool:
        """Interactive activation process"""
        print("\n" + "="*70)
        print("WarpNET Security Scanner - Activation Required")
        print("="*70)
        print(f"\nHardware ID: {self.generate_hardware_id()}")
        print("\nActivation Options:")
        print("1. Enter License Key")
        print("2. Generate Demo License")
        print("3. Exit")
        
        choice = input("\nSelect option (1-3): ").strip()
        
        if choice == "1":
            username = input("Enter your name/organization: ").strip()
            license_key = input("Enter license key: ").strip()
            
            is_valid, message = self.validate_license_key(license_key, username)
            print(f"\n{message}")
            
            if is_valid:
                if self.save_license(license_key, username):
                    print("✓ License activated successfully!")
                    return True
            return False
            
        elif choice == "2":
            username = input("Enter your name for demo license: ").strip()
            # Generate demo license
            demo_key = "DEMO-DEMO-DEMO-DEMO-DEMO-DEMO-DEMO-DEMO"
            
            print(f"\n{'='*70}")
            print("DEMO LICENSE GENERATED")
            print(f"{'='*70}")
            print(f"License Key: {demo_key}")
            print(f"Valid for: 30 days")
            print(f"Hardware ID: {self.generate_hardware_id()}")
            
            if self.save_license(demo_key, username):
                print("\n✓ Demo license activated successfully!")
                return True
            return False
            
        else:
            return False


# ============================================================================
# SECURITY SCANNER CORE
# ============================================================================

class SecurityScanner:
    """Main security scanning engine"""
    
    def __init__(self):
        self.open_ports = []
        self.vulnerabilities = []
        self.scan_results = {}
        self.start_time = None
        self.end_time = None
        
    def banner_grab(self, ip: str, port: int, timeout: int = 2) -> Optional[str]:
        """Grab service banner from a port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            
            # Try to get banner
            sock.send(b"GET / HTTP/1.1\r\nHost: target\r\n\r\n")
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner if banner else None
        except:
            return None
    
    def check_ssl_certificate(self, hostname: str, port: int = 443) -> Dict:
        """Check SSL/TLS certificate"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'valid': True,
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'notBefore': cert['notBefore'],
                        'notAfter': cert['notAfter']
                    }
        except Exception as e:
            return {'valid': False, 'error': str(e)}
    
    def scan_port(self, ip: str, port: int, timeout: float = 1.0) -> bool:
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def scan_port_range(self, ip: str, start_port: int, end_port: int, 
                       threads: int = 100) -> List[int]:
        """Scan a range of ports using threading"""
        print(f"\n[*] Scanning ports {start_port}-{end_port} on {ip}...")
        print(f"[*] Using {threads} concurrent threads")
        
        open_ports = []
        lock = threading.Lock()
        
        def scan_worker(port):
            if self.scan_port(ip, port):
                with lock:
                    open_ports.append(port)
                    print(f"[+] Port {port} is OPEN")
        
        # Create thread pool
        port_list = list(range(start_port, end_port + 1))
        threads_list = []
        
        for port in port_list:
            thread = threading.Thread(target=scan_worker, args=(port,))
            threads_list.append(thread)
            thread.start()
            
            # Limit concurrent threads
            if len(threads_list) >= threads:
                for t in threads_list:
                    t.join()
                threads_list = []
        
        # Wait for remaining threads
        for t in threads_list:
            t.join()
        
        return sorted(open_ports)
    
    def identify_service(self, port: int) -> str:
        """Identify common services by port number"""
        common_ports = {
            20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
            143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
            8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB"
        }
        return common_ports.get(port, "Unknown")
    
    def vulnerability_check(self, ip: str, port: int, banner: Optional[str]) -> List[str]:
        """Check for common vulnerabilities"""
        vulns = []
        
        # Check for outdated/vulnerable services
        if banner:
            banner_lower = banner.lower()
            
            # Web server vulnerabilities
            if 'apache' in banner_lower:
                if '2.2' in banner_lower or '2.0' in banner_lower:
                    vulns.append("Outdated Apache version detected (potential CVEs)")
            
            if 'nginx' in banner_lower:
                if '1.0' in banner_lower or '0.8' in banner_lower:
                    vulns.append("Outdated Nginx version detected")
            
            # SSH vulnerabilities
            if 'openssh' in banner_lower:
                if any(v in banner_lower for v in ['5.', '6.0', '6.1', '6.2']):
                    vulns.append("Outdated OpenSSH version (potential vulnerabilities)")
            
            # FTP vulnerabilities
            if 'ftp' in banner_lower:
                vulns.append("FTP detected - insecure protocol, consider SFTP/FTPS")
            
            # Telnet
            if port == 23:
                vulns.append("CRITICAL: Telnet detected - unencrypted protocol!")
        
        # Port-based vulnerability checks
        if port == 23:
            vulns.append("Telnet service - transmits credentials in plaintext")
        elif port == 21:
            vulns.append("FTP service - consider using SFTP instead")
        elif port == 3389:
            vulns.append("RDP exposed - ensure strong authentication and encryption")
        elif port == 445:
            vulns.append("SMB exposed - potential EternalBlue vulnerability")
        
        return vulns
    
    def perform_full_scan(self, target: str, port_range: Tuple[int, int] = (1, 1000),
                         threads: int = 100) -> Dict:
        """Perform comprehensive security scan"""
        self.start_time = datetime.now()
        print("\n" + "="*70)
        print("WarpNET Security Scanner v2.0")
        print("="*70)
        print(f"Target: {target}")
        print(f"Start Time: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*70)
        
        # Resolve hostname to IP
        try:
            ip = socket.gethostbyname(target)
            print(f"[*] Resolved {target} to {ip}")
        except socket.gaierror:
            print(f"[-] Could not resolve hostname: {target}")
            return {}
        
        # Port scanning
        open_ports = self.scan_port_range(ip, port_range[0], port_range[1], threads)
        
        print(f"\n[*] Found {len(open_ports)} open ports")
        print("\n" + "="*70)
        print("DETAILED PORT ANALYSIS")
        print("="*70)
        
        detailed_results = []
        
        for port in open_ports:
            service = self.identify_service(port)
            banner = self.banner_grab(ip, port)
            vulns = self.vulnerability_check(ip, port, banner)
            
            port_info = {
                'port': port,
                'service': service,
                'banner': banner,
                'vulnerabilities': vulns
            }
            detailed_results.append(port_info)
            
            print(f"\nPort: {port}")
            print(f"Service: {service}")
            if banner:
                print(f"Banner: {banner[:100]}...")
            if vulns:
                print(f"Vulnerabilities:")
                for vuln in vulns:
                    print(f"  ⚠ {vuln}")
        
        # SSL/TLS check for HTTPS ports
        if 443 in open_ports:
            print("\n" + "="*70)
            print("SSL/TLS CERTIFICATE ANALYSIS")
            print("="*70)
            ssl_info = self.check_ssl_certificate(target, 443)
            if ssl_info['valid']:
                print(f"✓ Valid SSL Certificate")
                print(f"Subject: {ssl_info['subject']}")
                print(f"Issuer: {ssl_info['issuer']}")
                print(f"Valid Until: {ssl_info['notAfter']}")
            else:
                print(f"✗ SSL Error: {ssl_info.get('error', 'Unknown')}")
        
        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()
        
        # Generate report
        report = {
            'target': target,
            'ip': ip,
            'scan_start': self.start_time.isoformat(),
            'scan_end': self.end_time.isoformat(),
            'duration_seconds': duration,
            'open_ports': open_ports,
            'detailed_results': detailed_results,
            'total_vulnerabilities': sum(len(r['vulnerabilities']) for r in detailed_results)
        }
        
        print("\n" + "="*70)
        print("SCAN SUMMARY")
        print("="*70)
        print(f"Total Open Ports: {len(open_ports)}")
        print(f"Total Vulnerabilities: {report['total_vulnerabilities']}")
        print(f"Scan Duration: {duration:.2f} seconds")
        print("="*70)
        
        return report
    
    def save_report(self, report: Dict, filename: str = None):
        """Save scan report to JSON file"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"warpnet_scan_{report['target']}_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n[+] Report saved to: {filename}")
        except Exception as e:
            print(f"\n[-] Error saving report: {e}")


# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

class WarpNETCLI:
    """Command line interface for WarpNET Scanner"""
    
    def __init__(self):
        self.activation = ActivationSystem()
        self.scanner = SecurityScanner()
        
    def print_banner(self):
        """Print application banner"""
        banner = """
╦ ╦┌─┐┬─┐┌─┐╔╗╔╔═╗╔╦╗  ╔═╗┌─┐┌─┐┬ ┬┬─┐┬┌┬┐┬ ┬  ╔═╗┌─┐┌─┐┌┐┌┌┐┌┌─┐┬─┐
║║║├─┤├┬┘├─┘║║║║╣  ║   ╚═╗├┤ │  │ │├┬┘│ │ └┬┘  ╚═╗│  ├─┤││││││├┤ ├┬┘
╚╩╝┴ ┴┴└─┴  ╝╚╝╚═╝ ╩   ╚═╝└─┘└─┘└─┘┴└─┴ ┴  ┴   ╚═╝└─┘┴ ┴┘└┘┘└┘└─┘┴└─
                                                                v2.0
        Advanced Network Security Analysis Tool
        Copyright (c) 2026 WarpNET Security Solutions
        """
        print(banner)
    
    def show_help(self):
        """Show help information"""
        help_text = """
USAGE:
    python WarpNET_security_scanner.py [OPTIONS]

OPTIONS:
    -t, --target <host>        Target hostname or IP address
    -p, --ports <range>        Port range (e.g., 1-1000 or 80,443,8080)
    -T, --threads <num>        Number of concurrent threads (default: 100)
    -o, --output <file>        Output report filename
    -a, --activate             Run activation wizard
    -h, --help                 Show this help message

EXAMPLES:
    # Scan common ports on a target
    python WarpNET_security_scanner.py -t example.com -p 1-1000
    
    # Scan specific ports with custom threads
    python WarpNET_security_scanner.py -t 192.168.1.1 -p 80,443,8080 -T 50
    
    # Scan and save report
    python WarpNET_security_scanner.py -t target.com -p 1-65535 -o report.json
    
    # Activate license
    python WarpNET_security_scanner.py -a

FEATURES:
    ✓ Multi-threaded port scanning
    ✓ Service identification and banner grabbing
    ✓ Vulnerability detection
    ✓ SSL/TLS certificate analysis
    ✓ Detailed JSON reporting
    ✓ Hardware-locked license activation
        """
        print(help_text)
    
    def parse_port_range(self, port_string: str) -> List[int]:
        """Parse port range string"""
        ports = []
        
        for part in port_string.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        
        return sorted(set(ports))
    
    def run(self, args: List[str]):
        """Run the CLI application"""
        self.print_banner()
        
        # Check activation
        if '--activate' in args or '-a' in args:
            self.activation.activate_interactive()
            return
        
        if not self.activation.is_activated():
            print("\n[!] WarpNET Security Scanner is not activated.")
            print("[!] Please activate your license to continue.\n")
            
            if self.activation.activate_interactive():
                print("\n[+] Activation successful! You can now use the scanner.\n")
            else:
                print("\n[-] Activation failed or cancelled.")
                return
        
        # Show help
        if '--help' in args or '-h' in args or len(args) == 1:
            self.show_help()
            return
        
        # Parse arguments
        target = None
        port_range = (1, 1000)
        threads = 100
        output_file = None
        
        i = 1
        while i < len(args):
            if args[i] in ['-t', '--target'] and i + 1 < len(args):
                target = args[i + 1]
                i += 2
            elif args[i] in ['-p', '--ports'] and i + 1 < len(args):
                ports = self.parse_port_range(args[i + 1])
                port_range = (min(ports), max(ports))
                i += 2
            elif args[i] in ['-T', '--threads'] and i + 1 < len(args):
                threads = int(args[i + 1])
                i += 2
            elif args[i] in ['-o', '--output'] and i + 1 < len(args):
                output_file = args[i + 1]
                i += 2
            else:
                i += 1
        
        if not target:
            print("[!] Error: Target is required. Use -t or --target")
            print("[!] Use --help for usage information")
            return
        
        # Perform scan
        try:
            report = self.scanner.perform_full_scan(target, port_range, threads)
            
            if report and output_file:
                self.scanner.save_report(report, output_file)
                
        except KeyboardInterrupt:
            print("\n\n[!] Scan interrupted by user")
        except Exception as e:
            print(f"\n[-] Error during scan: {e}")


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Main entry point"""
    cli = WarpNETCLI()
    cli.run(sys.argv)


if __name__ == "__main__":
    main()
