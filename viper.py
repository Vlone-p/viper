import argparse
import time
import json
import sys
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils import *
from network import ping_host, detect_os, load_targets
from scanner import execute_scan

BANNER = rf"""{CYAN}
____   ____.__                     
\   \ /   /|__|_____   ___________ 
 \   Y   / |  \____ \_/ __ \_  __ \
  \     /  |  |  |_> >  ___/|  | \/
   \___/   |__|   __/ \___  >__|   
              |__|        \/       {RESET}{YELLOW}v2.0{RESET}
"""

def main():
    parser = argparse.ArgumentParser(description="Fast Python Port Scanner")
    parser.add_argument("target", nargs='?', help="Target IP, domain, or CIDR subnet")
    parser.add_argument("-iL", metavar="FILE", help="Read targets from a text file")
    parser.add_argument("-p", "--ports", help="Port range (e.g., 1-1024 or 22,80,443). Use -p- for all ports.")
    parser.add_argument("--exclude", help="Exclude specific ports (e.g., 80,443)")
    parser.add_argument("-sV", action="store_true", help="Enable service detection (banner grabbing)")
    parser.add_argument("-O", action="store_true", help="Enable OS detection via ICMP TTL fingerprinting")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (progress bar)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of concurrent threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout in seconds (default: 1.0)")
    parser.add_argument("--delay", type=float, default=0.0, help="Add a random delay in seconds between probes (e.g., 0.5)")
    parser.add_argument("--safe", action="store_true", help="Enable safe mode (limits threads to 10, adds 0.5s delay)")
    parser.add_argument("--randomize", action="store_true", help="Randomize target IPs and ports to evade firewalls")
    parser.add_argument("-oN", metavar="FILE", help="Save scan results to a text file")
    parser.add_argument("-oJ", metavar="FILE", help="Save scan results to a JSON file")
    parser.add_argument("-oG", metavar="FILE", help="Save scan results to a grepable text file")
    parser.add_argument("-sn", action="store_true", help="Perform a ping sweep only (disable port scanning)")
    args = parser.parse_args()

    print(BANNER)

    if not args.target and not args.iL:
        print(f"{RED}[!] Error: You must specify a target or provide an input file (-iL).{RESET}")
        return

    if args.safe:
        print(f"{YELLOW}[!] Safe mode enabled. Throttling scan speed.{RESET}")
        args.threads = min(args.threads, 10)
        args.delay = max(args.delay, 0.5)

    target_ips = load_targets(args.target, args.iL)
    if not target_ips:
        return

    print(f"{CYAN}[*] Loaded {len(target_ips)} target(s){RESET}")
    print(f"{CYAN}[*] Thread count set to {args.threads}{RESET}\n")

    if args.sn:
        print(f"{YELLOW}[*] Running host discovery (ping sweep)...{RESET}")
        alive_hosts = []
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_ip = {executor.submit(ping_host, ip): ip for ip in target_ips}
            for future in as_completed(future_to_ip):
                if future.result():
                    alive_hosts.append(future_to_ip[future])
        
        print(f"{GREEN}[*] Discovered {len(alive_hosts)} live hosts.{RESET}\n")
        print(f"{CYAN}Live Hosts:{RESET}")
        for ip in sorted(alive_hosts):
            print(f"  [+] {ip}")
        return

    os_info = {}
    if args.O:
        print(f"{YELLOW}[*] Performing OS detection via ICMP...{RESET}")
        for ip in target_ips:
            os_info[ip] = detect_os(ip)
        print(f"{GREEN}[*] OS Detection complete.{RESET}\n")

    if args.ports:
        ports = parse_ports(args.ports)
    else:
        ports = TOP_PORTS

    if args.exclude:
        exclude_set = set(parse_ports(args.exclude))
        ports = [p for p in ports if p not in exclude_set]

    if args.randomize:
        print(f"{YELLOW}[*] Randomizing target and port order...{RESET}")
        random.shuffle(target_ips)
        random.shuffle(ports)

    print(f"[*] Scanning {len(ports)} ports on {len(target_ips)} hosts...")

    start_time = time.time()
    
    all_results = {}
    try:
        all_results = execute_scan(target_ips, ports, args)
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Scan interrupted by user. Proceeding to output partial results.{RESET}")
        
    end_time = time.time()
    elapsed_time = end_time - start_time
    
    if args.verbose:
        print(" " * 80, end='\r')

    print("\n" + "="*50)
    print(f"{CYAN}SCAN RESULTS{RESET}")
    print("="*50)

    output_lines = []
    json_data = {
        "scan_time_seconds": round(elapsed_time, 2),
        "hosts": []
    }

    if not all_results:
        output_lines.append(f"{RED}No open ports found.{RESET}")
        for ip in target_ips:
            json_data["hosts"].append({"ip": ip, "os": os_info.get(ip, "N/A"), "open_ports": []})
    else:
        for ip, open_ports in all_results.items():
            output_lines.append(f"\nTarget: {ip}")
            if ip in os_info:
                output_lines.append(f"OS Detection: {os_info[ip]}")
            
            host_data = {"ip": ip, "os": os_info.get(ip, "N/A"), "open_ports": []}

            if args.sV:
                header = f"{'PORT':<10} {'STATE':<10} {'SERVICE'}"
                output_lines.append(header)
                output_lines.append("-" * len(header))
                for port, service in sorted(open_ports):
                    output_lines.append(f"{port:<10} {GREEN}open{RESET:<4} {service}")
                    host_data["open_ports"].append({"port": port, "service": service})
            else:
                header = f"{'PORT':<10} {'STATE'}"
                output_lines.append(header)
                output_lines.append("-" * len(header))
                for port, _ in sorted(open_ports):
                    output_lines.append(f"{port:<10} {GREEN}open{RESET}")
                    host_data["open_ports"].append({"port": port, "service": COMMON_PORTS.get(port, "Unknown")})
            
            json_data["hosts"].append(host_data)

    for line in output_lines:
        print(line)
        
    print("\n" + "="*50)
    print(f"{CYAN}Scan completed in {elapsed_time:.2f} seconds{RESET}")
        
    if args.oN:
        try:
            clean_lines = [line.replace(GREEN, "").replace(RED, "").replace(YELLOW, "").replace(CYAN, "").replace(RESET, "") for line in output_lines]
            with open(args.oN, 'w') as f:
                f.write(f"Scan results for: {args.target}\n")
                f.write(f"Completed in: {elapsed_time:.2f} seconds\n\n")
                f.write("\n".join(clean_lines) + "\n")
            print(f"{GREEN}[+] Text results saved to {args.oN}{RESET}")
        except IOError as e:
            print(f"{RED}[!] Error writing to text file: {e}{RESET}")

    if args.oJ:
        try:
            with open(args.oJ, 'w') as f:
                json.dump(json_data, f, indent=4)
            print(f"{GREEN}[+] JSON results saved to {args.oJ}{RESET}")
        except IOError as e:
            print(f"{RED}[!] Error writing to JSON file: {e}{RESET}")

    if args.oG:
        try:
            with open(args.oG, 'w') as f:
                for ip, open_ports in all_results.items():
                    os_str = os_info.get(ip, "Unknown")
                    if open_ports:
                        ports_str = ", ".join([f"{p}/open/tcp//{s}" for p, s in sorted(open_ports)])
                        f.write(f"Host: {ip} ({os_str}) Ports: {ports_str}\n")
                    else:
                        f.write(f"Host: {ip} ({os_str}) Status: Up\n")
            print(f"{GREEN}[+] Grepable results saved to {args.oG}{RESET}")
        except IOError as e:
            print(f"{RED}[!] Error writing to grepable file: {e}{RESET}")

if __name__ == "__main__":
    main()
