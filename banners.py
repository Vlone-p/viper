import socket
import ssl
import re

HTTPS_PORTS = [443, 8443, 9443]
HTTP_PORTS = [80, 5985, 8080, 8888, 3000]

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
                title = ""
                
                for line in decoded.split('\n'):
                    if line.lower().startswith("server:"):
                        server = line.split(':', 1)[1].strip()[:60]
                
                title_match = re.search(r'<title>(.*?)</title>', decoded, re.IGNORECASE | re.DOTALL)
                if title_match:
                    title = title_match.group(1).strip()[:60]
                
                if title and server:
                    return f"{server} ({title})"
                elif title:
                    return title
                elif server:
                    return server
                    
            return decoded.split('\n')[0].strip()[:60]
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
