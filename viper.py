import socket
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = {
    20: "FTP Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
}

TOP_PORTS = [
    7, 20, 21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 443, 445,
    465, 587, 631, 873, 990, 993, 995, 1025, 1026, 1080, 1194, 1433, 1434,
    1521, 1723, 2049, 2082, 2083, 2086, 2087, 2222, 2375, 2376, 3000, 3128,
    3306, 3389, 3478, 5432, 5900, 5985, 6379, 6443, 8080, 8443, 8888, 9000,
    9090, 9092, 9200, 11211, 27017
]

print_lock = threading.Lock()

def grab_banner(target_ip: str, port: int) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.5)
            s.connect((target_ip, port))
            
            if port in [80, 8080, 8443]:
                s.send(b"GET / HTTP/1.0\r\nHost: " + target_ip.encode() + b"\r\n\r\n")
            
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            
            if banner:
                return banner.split('\n')[0].strip()[:60]
    except Exception:
        pass
    return ""

def scan_port(target_ip: str, port: int, detect_service: bool, verbose: bool) -> tuple[int, str] | None:
    if verbose:
        with print_lock:
            print(f"[*] Scanning port {port}...")
            
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
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (live scanning progress)")
    parser.add_argument("-oN", metavar="FILE", help="Save scan results to a text file")
    args = parser.parse_args()

    try:
        target_ip = socket.gethostbyname(args.target)
        print(f"\nStarting scan on {args.target} ({target_ip})...\n")
    except socket.gaierror:
        print(f"\nError: Cannot resolve hostname '{args.target}'")
        return

    if args.ports:
        ports = parse_ports(args.ports)
        print(f"Scanning {len(ports)} specified ports...")
    else:
        ports = TOP_PORTS
        print(f"Scanning top {len(ports)} common ports... (Use -p to specify a range)")

    open_ports = []
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        future_to_port = {
            executor.submit(scan_port, target_ip, port, args.sV, args.verbose): port 
            for port in ports
        }
        for future in as_completed(future_to_port):
            result = future.result()
            if result:
                open_ports.append(result)

    print("\n" + "="*40)
    print("SCAN RESULTS")
    print("="*40)

    output_lines = []
    
    if open_ports:
        if args.sV:
            header = f"{'PORT':<10} {'STATE':<10} {'SERVICE'}"
            output_lines.append(header)
            output_lines.append("-" * len(header))
            for port, service in sorted(open_ports):
                output_lines.append(f"{port:<10} {'open':<10} {service}")
        else:
            header = f"{'PORT':<10} {'STATE'}"
            output_lines.append(header)
            output_lines.append("-" * len(header))
            for port, _ in sorted(open_ports):
                output_lines.append(f"{port:<10} {'open'}")
    else:
        output_lines.append("No open ports found.")
        
    for line in output_lines:
        print(line)
        
    if args.oN:
        try:
            with open(args.oN, 'w') as f:
                f.write(f"Scan results for: {args.target} ({target_ip})\n")
                f.write("\n".join(output_lines) + "\n")
            print(f"\n[+] Results saved to {args.oN}")
        except IOError as e:
            print(f"\n[!] Error writing to file: {e}")
        
    print("\nScan complete.")

if __name__ == "__main__":
    main()
