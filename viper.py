import socket
import argparse
import threading
import time
import json
import platform
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

BANNER = rf"""{CYAN}
____   ____.__                     
\   \ /   /|__|_____   ___________ 
 \   Y   / |  \____ \_/ __ \_  __ \
  \     /  |  |  |_> >  ___/|  | \/
   \___/   |__|   __/ \___  >__|   
              |__|        \/       {RESET}{YELLOW}v1.3{RESET}
"""

COMMON_PORTS = {
    7: "Echo", 20: "FTP Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 88: "Kerberos", 110: "POP3", 111: "RPCbind",
    135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 464: "kpasswd5", 465: "SMTPS", 587: "SMTP-Submission",
    593: "RPC over HTTP", 631: "IPP", 636: "LDAPS", 873: "rsync", 990: "FTPS",
    993: "IMAPS", 995: "POP3S", 1025: "NFS", 1080: "SOCKS Proxy", 1194: "OpenVPN",
    1433: "MSSQL", 1434: "MSSQL Ping", 1521: "Oracle DB", 1723: "PPTP", 2049: "NFS",
    2082: "cPanel", 2083: "cPanel SSL", 2086: "WebHost Manager", 2087: "WebHost Manager SSL",
    2222: "SSH-Alt", 2375: "Docker", 2376: "Docker SSL", 3000: "Node.js", 3128: "Squid Proxy",
    3268: "Global Catalog LDAP", 3269: "Global Catalog LDAPS", 3306: "MySQL", 3389: "RDP",
    3478: "STUN", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM HTTP", 5986: "WinRM HTTPS",
    6379: "Redis", 6443: "Kubernetes API", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    9000: "Portainer", 9090: "Prometheus", 9092: "Kafka", 9200: "Elasticsearch", 11211: "Memcached",
    27017: "MongoDB"
}

TOP_PORTS = [
    7, 20, 21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 389, 443, 445,
    464, 465, 587, 593, 631, 636, 873, 990, 993, 995, 1025, 1026, 1080, 1194, 1433, 1434,
    1521, 1723, 2049, 2082, 2083, 2086, 2087, 2222, 2375, 2376, 3000, 3128,
    3268, 3269, 3306, 3389, 3478, 5432, 5900, 5985, 5986, 6379, 6443, 8080, 8443, 8888, 9000,
    9090, 9092, 9200, 11211, 27017
]

HTTP_PORTS = [80, 5985, 8080, 8443, 8888, 3000]

print_lock = threading.Lock()

def detect_os(target_ip: str) -> str:
    is_windows = platform.system().lower() == "windows"
    param = '-n' if is_windows else '-c'
    command = ['ping', param, '1', target_ip]
    
    try:
        output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=3)
        if output.returncode == 0:
            match = re.search(r'[Tt][Tt][Ll]=\s*(\d+)', output.stdout)
            if match:
                ttl = int(match.group(1))
                if ttl >= 200:
                    return f"Network Device (Cisco/Router) (TTL: {ttl})"
                elif 100 <= ttl <= 128:
                    return f"Windows (TTL: {ttl})"
                elif ttl <= 64:
                    return f"Linux/Unix (TTL: {ttl})"
                else:
                    return f"Unknown OS (TTL: {ttl})"
            return "Unknown (No TTL in ping response)"
        return "Host seems down or blocks ICMP ping"
    except Exception:
        return "Ping command failed/timeout"

def grab_banner(target_ip: str, port: int) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.5)
            s.connect((target_ip, port))
            
            if port in HTTP_PORTS:
                s.send(b"GET / HTTP/1.0\r\nHost: " + target_ip.encode() + b"\r\n\r\n")
            
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            
            if banner:
                if "HTTP/" in banner:
                    for line in banner.split('\n'):
                        if line.lower().startswith("server:"):
                            return line.split(':', 1)[1].strip()[:60]
                return banner.split('\n')[0].strip()[:60]
    except Exception:
        pass
    return ""

def scan_port(target_ip: str, port: int, detect_service: bool, verbose: bool) -> tuple[int, str] | None:
    if verbose:
        with print_lock:
            print(f"{YELLOW}[*] Scanning port {port}...{RESET}", end='\r')
            
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            result = s.connect_ex((target_ip, port))
            if result == 0:
                service = ""
                if detect_service:
                    service = grab_banner(target_ip, port)
                    if not service:
                        service = COMMON_PORTS.get(port, "Unknown")
                return port, service
    except socket.error:
        pass
    return None

def parse_ports(port_str: str) -> list[int]:
    ports = set()
    for part in port_str.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(list(ports))

def main():
    parser = argparse.ArgumentParser(description="Fast Python Port Scanner")
    parser.add_argument("target", help="Target IP address or domain name")
    parser.add_argument("-p", "--ports", help="Port range (e.g., 1-1024 or 22,80,443). Defaults to top ports.")
    parser.add_argument("-sV", action="store_true", help="Enable service detection (banner grabbing)")
    parser.add_argument("-O", action="store_true", help="Enable OS detection via ICMP TTL fingerprinting")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (live scanning progress)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of concurrent threads (default: 100)")
    parser.add_argument("-oN", metavar="FILE", help="Save scan results to a text file")
    parser.add_argument("-oJ", metavar="FILE", help="Save scan results to a JSON file")
    args = parser.parse_args()

    print(BANNER)

    try:
        target_ip = socket.gethostbyname(args.target)
        print(f"{CYAN}[*] Starting scan on {args.target} ({target_ip}){RESET}")
        print(f"{CYAN}[*] Thread count set to {args.threads}{RESET}\n")
    except socket.gaierror:
        print(f"{RED}[!] Error: Cannot resolve hostname '{args.target}'{RESET}")
        return

    os_info = None
    if args.O:
        print(f"{YELLOW}[*] Performing OS detection via ICMP...{RESET}", end='')
        os_info = detect_os(target_ip)
        print(f"\r{GREEN}[*] OS Detection: {os_info}{RESET}")

    if args.ports:
        ports = parse_ports(args.ports)
        print(f"[*] Scanning {len(ports)} specified ports...")
    else:
        ports = TOP_PORTS
        print(f"[*] Scanning top {len(ports)} common ports... (Use -p to specify a range)")

    open_ports = []
    
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_port = {
            executor.submit(scan_port, target_ip, port, args.sV, args.verbose): port 
            for port in ports
        }
        for future in as_completed(future_to_port):
            result = future.result()
            if result:
                open_ports.append(result)

    end_time = time.time()
    elapsed_time = end_time - start_time
    
    if args.verbose:
        print(" " * 40, end='\r')

    print("\n" + "="*50)
    print(f"{CYAN}SCAN RESULTS{RESET}")
    print("="*50)

    if os_info:
        print(f"{CYAN}OS DETECTION:{RESET} {os_info}")
        print("="*50)

    output_lines = []
    
    if open_ports:
        if args.sV:
            header = f"{'PORT':<10} {'STATE':<10} {'SERVICE'}"
            output_lines.append(header)
            output_lines.append("-" * len(header))
            for port, service in sorted(open_ports):
                output_lines.append(f"{port:<10} {GREEN}open{RESET:<4} {service}")
        else:
            header = f"{'PORT':<10} {'STATE'}"
            output_lines.append(header)
            output_lines.append("-" * len(header))
            for port, _ in sorted(open_ports):
                output_lines.append(f"{port:<10} {GREEN}open{RESET}")
    else:
        output_lines.append(f"{RED}No open ports found.{RESET}")
        
    for line in output_lines:
        print(line)
        
    print("="*50)
    print(f"{CYAN}Scan completed in {elapsed_time:.2f} seconds{RESET}")
        
    if args.oN:
        try:
            clean_lines = [line.replace(GREEN, "").replace(RED, "").replace(YELLOW, "").replace(CYAN, "").replace(RESET, "") for line in output_lines]
            with open(args.oN, 'w') as f:
                f.write(f"Scan results for: {args.target} ({target_ip})\n")
                if os_info:
                    f.write(f"OS Detection: {os_info}\n")
                f.write(f"Completed in: {elapsed_time:.2f} seconds\n\n")
                f.write("\n".join(clean_lines) + "\n")
            print(f"{GREEN}[+] Text results saved to {args.oN}{RESET}")
        except IOError as e:
            print(f"{RED}[!] Error writing to text file: {e}{RESET}")

    if args.oJ:
        try:
            json_data = {
                "target": args.target,
                "ip": target_ip,
                "os_detection": os_info if os_info else "N/A",
                "scan_time_seconds": round(elapsed_time, 2),
                "open_ports": [{"port": p, "service": s} for p, s in sorted(open_ports)]
            }
            with open(args.oJ, 'w') as f:
                json.dump(json_data, f, indent=4)
            print(f"{GREEN}[+] JSON results saved to {args.oJ}{RESET}")
        except IOError as e:
            print(f"{RED}[!] Error writing to JSON file: {e}{RESET}")

if __name__ == "__main__":
    main()
