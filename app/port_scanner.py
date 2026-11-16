"""Bounded TCP service discovery for explicitly authorized private LAN ranges."""
from __future__ import annotations

import concurrent.futures
import ipaddress
import re
import socket

from app.network_discovery import validate_network

DEFAULT_TCP_PORTS = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    465, 587, 993, 995, 1433, 1521, 2049, 2375, 3000, 3306,
    3389, 5432, 5900, 5985, 5986, 6379, 8000, 8080, 8443, 8888,
    9200, 27017,
)

SERVICE_BY_PORT = {
    21: ("ftp", "FTP"), 22: ("ssh", "SSH"), 23: ("telnet", "Telnet"),
    25: ("smtp", "SMTP"), 53: ("domain", "DNS"), 80: ("http", "HTTP"),
    110: ("pop3", "POP3"), 111: ("rpcbind", "RPCBind"), 135: ("msrpc", "MS-RPC"),
    139: ("netbios-ssn", "NetBIOS"), 143: ("imap", "IMAP"), 443: ("https", "HTTPS"),
    445: ("microsoft-ds", "SMB"), 465: ("smtps", "SMTPS"), 587: ("submission", "SMTP Submission"),
    993: ("imaps", "IMAPS"), 995: ("pop3s", "POP3S"), 1433: ("ms-sql-s", "Microsoft SQL Server"),
    1521: ("oracle", "Oracle"), 2049: ("nfs", "NFS"), 2375: ("docker", "Docker API"),
    3000: ("http-alt", "HTTP alternate"), 3306: ("mysql", "MySQL"), 3389: ("ms-wbt-server", "RDP"),
    5432: ("postgresql", "PostgreSQL"), 5900: ("vnc", "VNC"), 5985: ("wsman", "WinRM HTTP"),
    5986: ("wsmans", "WinRM HTTPS"), 6379: ("redis", "Redis"), 8000: ("http-alt", "HTTP alternate"),
    8080: ("http-proxy", "HTTP alternate"), 8443: ("https-alt", "HTTPS alternate"),
    8888: ("http-alt", "HTTP alternate"), 9200: ("http", "Elasticsearch HTTP"),
    27017: ("mongodb", "MongoDB"),
}

BANNER_PATTERNS = (
    (re.compile(rb"OpenSSH[_-]([0-9A-Za-z.p]+)", re.I), "OpenSSH"),
    (re.compile(rb"Apache[/ ]([0-9][0-9A-Za-z._-]+)", re.I), "Apache HTTP Server"),
    (re.compile(rb"nginx[/ ]([0-9][0-9A-Za-z._-]+)", re.I), "nginx"),
    (re.compile(rb"Microsoft-IIS[/ ]([0-9][0-9A-Za-z._-]+)", re.I), "Microsoft IIS"),
    (re.compile(rb"vsFTPd[ ]([0-9][0-9A-Za-z._-]+)", re.I), "vsftpd"),
    (re.compile(rb"ProFTPD[ ]([0-9][0-9A-Za-z._-]+)", re.I), "ProFTPD"),
    (re.compile(rb"Postfix", re.I), "Postfix"),
)

def _probe(ip: str, port: int, timeout: float) -> dict | None:
    service, label = SERVICE_BY_PORT.get(port, ("unknown", "Unknown"))
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(0.25)
            if port in (80, 3000, 8000, 8080, 8888, 9200):
                try:
                    sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode("ascii"))
                except OSError:
                    pass
            try:
                banner = sock.recv(512)
            except (OSError, TimeoutError):
                banner = b""
    except (OSError, TimeoutError):
        return None

    product = ""
    version = ""
    for pattern, detected_product in BANNER_PATTERNS:
        match = pattern.search(banner)
        if match:
            product = detected_product
            version = match.group(1).decode("ascii", "replace") if match.lastindex else ""
            break
    if not product and port in (80, 3000, 8000, 8080, 8888, 9200):
        server = re.search(rb"(?im)^Server:\s*([^\r\n]+)", banner)
        if server:
            value = server.group(1).decode("latin-1", "replace").strip()[:160]
            product = value.split("/")[0].strip()
            version = value.split("/", 1)[1].strip() if "/" in value else ""
    if not product:
        product = label if banner else ""
    return {
        "ip_address": ip,
        "protocol": "tcp",
        "port": port,
        "state": "open",
        "service_name": service,
        "product": product[:160],
        "version": version[:100],
        "banner": banner.decode("latin-1", "replace")[:512],
        "confidence": 0.9 if banner else 0.75,
    }

def scan_network_ports(cidr: str, *, timeout: float = 0.35, ports: tuple[int, ...] = DEFAULT_TCP_PORTS) -> dict:
    """Scan only a validated private network (maximum 256 addresses) and a fixed safe TCP port list."""
    network = validate_network(cidr)
    targets = [str(ip) for ip in network.hosts()]
    if network.num_addresses <= 2:
        targets = [str(ip) for ip in network]
    jobs = ((ip, port) for ip in targets for port in ports)
    found: dict[str, list[dict]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=96) as pool:
        futures = [pool.submit(_probe, ip, port, timeout) for ip, port in jobs]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                found.setdefault(result["ip_address"], []).append(result)
    hosts = []
    for ip in sorted(found, key=ipaddress.ip_address):
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except (OSError, socket.herror):
            hostname = ""
        hosts.append({"ip_address": ip, "hostname": hostname, "open_ports": sorted(found[ip], key=lambda x: x["port"])})
    return {
        "network_cidr": str(network),
        "targets_checked": len(targets),
        "ports_checked_per_target": len(ports),
        "open_ports_total": sum(len(x["open_ports"]) for x in hosts),
        "hosts_with_open_ports": len(hosts),
        "hosts": hosts,
        "protocol_scope": "TCP only; UDP requires a separate protocol-aware probe",
        "limitations": "Versions are reported only when a service voluntarily exposes a recognizable banner. An open port is not proof of a vulnerability.",
    }
