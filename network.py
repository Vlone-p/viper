import socket
import platform
import subprocess
import re
import ipaddress
from utils import RED, RESET

def ping_host(target_ip: str) -> bool:
    is_windows = platform.system().lower() == "windows"
    param = '-n' if is_windows else '-c'
    wait_param = '-w' if is_windows else '-W'
    wait_time = '1000' if is_windows else '1'
    command = ['ping', param, '1', wait_param, wait_time, target_ip]
    try:
        output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2)
        return output.returncode == 0
    except Exception:
        return False

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
        return "Ping command failed or timeout"

def load_targets(target_arg: str, file_arg: str) -> list[str]:
    targets = set()
    if file_arg:
        try:
            with open(file_arg, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        targets.add(line)
        except IOError:
            print(f"{RED}[!] Error reading file: {file_arg}{RESET}")
    if target_arg:
        targets.add(target_arg)

    resolved_ips = set()
    for t in targets:
        if '/' in t:
            try:
                network = ipaddress.ip_network(t, strict=False)
                for ip in network.hosts():
                    resolved_ips.add(str(ip))
            except ValueError:
                print(f"{RED}[!] Invalid CIDR: {t}{RESET}")
        else:
            try:
                resolved_ips.add(socket.gethostbyname(t))
            except socket.gaierror:
                print(f"{RED}[!] Cannot resolve hostname: {t}{RESET}")
    return sorted(list(resolved_ips))
