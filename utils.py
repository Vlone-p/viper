import sys
import re

GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

COMMON_PORTS = {
    7: "Echo", 20: "FTP Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 81: "HTTP Alt", 88: "Kerberos", 110: "POP3", 111: "RPCbind",
    113: "Ident", 119: "NNTP", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 179: "BGP",
    199: "SMUX", 389: "LDAP", 427: "SLP", 443: "HTTPS", 444: "SNPP", 445: "microsoft-ds(SMB)",
    465: "SMTPS", 513: "Rlogin", 514: "Syslog", 515: "LPD", 540: "UUCP", 548: "AFP",
    554: "RTSP", 587: "SMTP Submission", 631: "IPP", 646: "LDP", 873: "rsync", 990: "FTPS",
    993: "IMAPS", 995: "POP3S", 1025: "NFS", 1080: "SOCKS Proxy", 1194: "OpenVPN",
    1433: "MSSQL", 1434: "MSSQL Ping", 1521: "Oracle DB", 1723: "PPTP", 1900: "UPnP",
    2000: "Cisco SCCP", 2049: "NFS", 2082: "cPanel", 2083: "cPanel SSL", 2086: "WebHost Manager", 2087: "WebHost Manager SSL",
    2222: "SSH Alt", 2375: "Docker", 2376: "Docker SSL", 3000: "Node.js", 3128: "Squid Proxy",
    3268: "Global Catalog LDAP", 3269: "Global Catalog LDAPS", 3306: "MySQL", 3389: "RDP",
    4000: "Remote Anything", 4040: "HTTP Proxy", 4369: "Erlang", 5000: "UPnP", 5060: "SIP",
    5432: "PostgreSQL", 5900: "VNC", 5984: "CouchDB", 5985: "WinRM HTTP", 5986: "WinRM HTTPS",
    6379: "Redis", 6443: "Kubernetes API", 7001: "WebLogic", 7077: "Jolokia", 8000: "HTTP Alt",
    8008: "HTTP Alt", 8009: "AJP", 8080: "HTTP Proxy", 8081: "HTTP Alt", 8088: "HTTP Alt",
    8443: "HTTPS Alt", 8888: "HTTP Alt", 9000: "Portainer", 9001: "Tor", 9042: "Cassandra",
    9090: "Prometheus", 9092: "Kafka", 9200: "Elasticsearch", 9300: "Elasticsearch", 9418: "Git",
    9999: "UWSD", 11211: "Memcached", 15672: "RabbitMQ", 27017: "MongoDB", 27018: "MongoDB",
    28017: "MongoDB Web", 50070: "Hadoop", 50090: "Hadoop"
}

TOP_PORTS = [
    7, 20, 21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 113, 119, 135, 139, 143, 179,
    199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 540, 548, 554, 587, 631, 646,
    873, 990, 993, 995, 1025, 1026, 1080, 1194, 1433, 1434, 1521, 1723, 1900, 2000,
    2049, 2082, 2083, 2086, 2087, 2222, 2375, 2376, 3000, 3128, 3268, 3269, 3306,
    3389, 4000, 4040, 4369, 5000, 5060, 5432, 5900, 5984, 5985, 5986, 6379, 6443,
    7001, 7077, 8000, 8008, 8009, 8080, 8081, 8088, 8443, 8888, 9000, 9001, 9042,
    9090, 9092, 9200, 9300, 9418, 9999, 11211, 15672, 27017, 27018, 28017, 50070
]

def clean_banner(banner: str) -> str:
    if banner.startswith("SSH-"):
        parts = banner.split('-', 2)
        if len(parts) == 3:
            return parts[2].replace('_', ' ', 1)
    return banner

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
