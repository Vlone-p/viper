import socket
import ssl
import re
from utils import clean_banner

HTTPS_PORTS = [443, 8443, 9443]
HTTP_PORTS = [80, 5985, 8080, 8888, 3000, 8000, 8008, 8081, 8088]

def _read_banner(sock: socket.socket, ip: str, port: int, timeout: float) -> str:
    try:
        if port in HTTP_PORTS + HTTPS_PORTS:
            sock.send(f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode())
        
        sock.settimeout(timeout)
        data = sock.recv(4096)
            
        if data:
            decoded = data.decode('utf-8', errors='ignore').strip()
            if "HTTP/" in decoded:
                server = ""
                powered_by = ""
                title = ""
                auth = ""
                
                for line in decoded.split('\n'):
                    low_line = line.lower()
                    if low_line.startswith("server:"):
                        server = line.split(':', 1)[1].strip()
                    elif low_line.startswith("x-powered-by:"):
                        powered_by = line.split(':', 1)[1].strip()
                    elif low_line.startswith("www-authenticate:"):
                        auth = line.split(':', 1)[1].strip()
                
                title_match = re.search(r'<title>(.*?)</title>', decoded, re.IGNORECASE | re.DOTALL)
                if title_match:
                    title = title_match.group(1).strip()
                    
                parts = []
                if server: parts.append(server)
                if powered_by: parts.append(f"Powered by: {powered_by}")
                if auth: parts.append(f"Auth: {auth}")
                if title: parts.append(f"Title: {title}")
                
                if parts:
                    return " | ".join(parts)[:100]
                    
            return clean_banner(decoded.split('\n')[0].strip()[:60])
    except socket.timeout:
        pass
    except Exception:
        pass
    return ""

def grab_banner(sock: socket.socket, target_ip: str, port: int, timeout: float = 1.0) -> str:
    try:
        if port in HTTPS_PORTS:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with context.wrap_socket(sock, server_hostname=target_ip) as ss:
                return _read_banner(ss, target_ip, port, timeout)
        
        return _read_banner(sock, target_ip, port, timeout)
    except Exception:
        return ""
