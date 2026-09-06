import sys

GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

COMMON_PORTS = {
    7: "Echo", 20: "FTP Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 88: "Kerberos", 110: "POP3", 111: "RPCbind",
    135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 389: "LDAP", 443: "HTTPS",
    445: "microsoft-ds(SMB)", 464: "kpasswd5", 465: "SMTPS", 587: "SMTP Submission",
    593: "RPC over HTTP", 631: "IPP", 636: "LDAPS", 873: "rsync", 990: "FTPS",
    993: "IMAPS", 995: "POP3S", 1025: "NFS", 1080: "SOCKS Proxy", 1194: "OpenVPN",
    1433: "MSSQL", 1434: "MSSQL Ping", 1521: "Oracle DB", 1723: "PPTP", 2049: "NFS",
    2082: "cPanel", 2083: "cPanel SSL", 2086: "WebHost Manager", 2087: "WebHost Manager SSL",
    2222: "SSH Alt", 2375: "Docker", 2376: "Docker SSL", 3000: "Node.js", 3128: "Squid Proxy",
    3268: "Global Catalog LDAP", 3269: "Global Catalog LDAPS", 3306: "MySQL", 3389: "RDP",
    3478: "STUN", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM HTTP", 5986: "WinRM HTTPS",
    6379: "Redis", 6443: "Kubernetes API", 8080: "HTTP Proxy", 8443: "HTTPS Alt", 8888: "HTTP Alt",
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

def parse_ports(port_str: str) -> list[int]:
    if port_str == "-":
        return list(range(1, 65536))

    ports = set()
    for part in port_str.split(','):
        part = part.strip()
        if '-' in part:
            parts = part.split('-')
            if len(parts) != 2:
                print(f"{RED}[!] Invalid port range format: {part}{RESET}", file=sys.stderr)
                sys.exit(1)
            try:
                start, end = int(parts[0]), int(parts[1])
            except ValueError:
                print(f"{RED}[!] Port range must be numbers: {part}{RESET}", file=sys.stderr)
                sys.exit(1)
            
            if start > end:
                print(f"{RED}[!] Start port cannot be greater than end port: {part}{RESET}", file=sys.stderr)
                sys.exit(1)
                
            for p in range(start, end + 1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            try:
                p = int(part)
            except ValueError:
                print(f"{RED}[!] Invalid port number: {part}{RESET}", file=sys.stderr)
                sys.exit(1)
            if 1 <= p <= 65535:
                ports.add(p)
                
    return sorted(list(ports))
