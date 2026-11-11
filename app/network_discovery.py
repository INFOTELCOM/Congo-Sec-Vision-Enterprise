"""Explicit, bounded ICMP discovery for authorized private lab networks."""
import concurrent.futures
import ipaddress
import platform
import shutil
import socket
import subprocess


def validate_network(cidr):
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError("CIDR invalide.") from exc
    if not network.is_private or network.is_loopback or network.is_link_local or network.is_multicast:
        raise ValueError("La découverte est limitée aux réseaux privés autorisés.")
    if network.num_addresses > 256:
        raise ValueError("Réseau trop large : limite actuelle de 256 adresses par scan.")
    return network


def _probe(ip):
    if platform.system().lower() == "windows":
        command = ["ping", "-n", "1", "-w", "900", str(ip)]
    else:
        command = ["ping", "-c", "1", "-W", "1", str(ip)]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=2, check=False)
        if result.returncode != 0:
            return None
    except (OSError, subprocess.TimeoutExpired):
        return None
    try:
        hostname = socket.gethostbyaddr(str(ip))[0]
    except (OSError, socket.herror):
        hostname = ""
    return {"ip_address": str(ip), "hostname": hostname}


def discover_network(cidr, workers=32):
    network = validate_network(cidr)
    if not shutil.which("ping"):
        raise RuntimeError("La commande ping est absente du serveur ; installez iputils-ping puis redémarrez l’API.")
    hosts = list(network.hosts()) if network.num_addresses > 2 else list(network)
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(max(1, workers), 32)) as pool:
        results = list(pool.map(_probe, hosts))
    return sorted((item for item in results if item), key=lambda item: ipaddress.ip_address(item["ip_address"]))
