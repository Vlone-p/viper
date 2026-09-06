
import socket
import time
import random
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from banners import grab_banner
from utils import COMMON_PORTS, YELLOW, RED, RESET

print_lock = threading.Lock()

def scan_port(target_ip: str, port: int, detect_service: bool, delay: float, timeout: float) -> tuple[int, str] | None:
    if delay > 0:
        time.sleep(random.uniform(0, delay))
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target_ip, port))
            if result == 0:
                service = ""
                if detect_service:
                    service = grab_banner(s, target_ip, port, timeout)
                    if not service:
                        service = COMMON_PORTS.get(port, "Unknown")
                return port, service
    except socket.error:
        pass
    return None

def execute_scan(target_ips: list[str], ports: list[int], args) -> dict:
    all_results = {}
    total_scans = len(target_ips) * len(ports)
    scanned_count = 0
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_scan = {}
        for ip in target_ips:
            for port in ports:
                future = executor.submit(scan_port, ip, port, args.sV, args.delay, args.timeout)
                future_to_scan[future] = (ip, port)
                
        try:
            for future in as_completed(future_to_scan):
                ip, port = future_to_scan[future]
                result = future.result()
                
                if args.verbose:
                    with print_lock:
                        scanned_count += 1
                        progress = int((scanned_count / total_scans) * 100)
                        bar_length = 20
                        filled = int(bar_length * progress / 100)
                        bar = '#' * filled + '-' * (bar_length - filled)
                        print(f"{YELLOW}\r[*] [{bar}] {progress}% | Scanning {ip}:{port}{RESET}", end='')
                    
                if result:
                    if ip not in all_results:
                        all_results[ip] = []
                    all_results[ip].append(result)
                    
        except KeyboardInterrupt:
            print(f"\n{RED}[!] Scan interrupted by user. Cancelling pending tasks...{RESET}")
            for future in future_to_scan:
                future.cancel()
            print(f"{YELLOW}[*] Returning partial results.{RESET}")
            
    return all_results
