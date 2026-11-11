"""Read-only inventory adapters for VMware, Proxmox, VirtualBox and Hyper-V."""
from __future__ import annotations
import base64, json, os, re, shutil, ssl, subprocess, urllib.error, urllib.request
from typing import Any

class HypervisorError(RuntimeError):
    """Sanitized provider connection or inventory error."""

def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()

def _bool_env(name: str, default: bool = True) -> bool:
    return _env(name, "true" if default else "false").lower() not in {"0", "false", "no", "off"}

def _request(url: str, *, method: str = "GET", headers: dict[str, str] | None = None,
             body: bytes | None = None, verify_tls: bool = True, timeout: int = 15) -> tuple[int, bytes]:
    request = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    context = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(request, context=context, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        raise HypervisorError(f"Provider returned HTTP {exc.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", None)
        if isinstance(reason, ssl.SSLError):
            raise HypervisorError("TLS validation failed; verify certificate and CA") from None
        raise HypervisorError("Provider unreachable or connection timed out") from None

def _json_request(url: str, **kwargs: Any) -> Any:
    _, payload = _request(url, **kwargs)
    try:
        return json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HypervisorError("Provider returned invalid JSON") from None

def _normal_vm(provider: str, source_id: str, name: str, state: str, **metadata: Any) -> dict[str, Any]:
    return {"provider": provider, "id": str(source_id), "name": str(name),
            "state": str(state or "unknown").lower(), "read_only": True, "metadata": metadata}

def configured_providers() -> list[dict[str, Any]]:
    specs = [
        ("vmware", ("CSV_VMWARE_URL", "CSV_VMWARE_USERNAME", "CSV_VMWARE_PASSWORD")),
        ("proxmox", ("CSV_PROXMOX_URL", "CSV_PROXMOX_TOKEN_ID", "CSV_PROXMOX_TOKEN_SECRET")),
        ("virtualbox", ("CSV_VBOXMANAGE_PATH",)),
        ("hyperv", ("CSV_HYPERV_HOST", "CSV_HYPERV_USERNAME", "CSV_HYPERV_PASSWORD")),
    ]
    result = []
    for provider, required in specs:
        ready = all(_env(key) for key in required)
        host_collector = False
        if provider == "virtualbox":
            host_collector = bool(_env("CSV_VBOX_COLLECTOR_TOKEN"))
            ready = bool(shutil.which(_env("CSV_VBOXMANAGE_PATH", "VBoxManage"))) or host_collector
        result.append({"provider": provider, "configured": ready, "mode": "read-only",
                       "host_collector": host_collector if provider == "virtualbox" else False})
    return result

class VMwareConnector:
    def inventory(self) -> list[dict[str, Any]]:
        base = _env("CSV_VMWARE_URL").rstrip("/")
        username, password = _env("CSV_VMWARE_USERNAME"), _env("CSV_VMWARE_PASSWORD")
        if not (base and username and password):
            raise HypervisorError("VMware connector is not configured")
        verify = _bool_env("CSV_VMWARE_VERIFY_TLS", True)
        basic = base64.b64encode(f"{username}:{password}".encode()).decode()
        _, body = _request(base + "/api/session", method="POST",
            headers={"Authorization": "Basic " + basic, "Accept": "application/json"}, verify_tls=verify)
        try:
            token = json.loads(body.decode("utf-8"))
            if not isinstance(token, str): raise ValueError
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            token = body.decode("utf-8").strip().strip('"')
        if not token: raise HypervisorError("VMware did not issue a session token")
        try:
            rows = _json_request(base + "/api/vcenter/vm",
                headers={"vmware-api-session-id": token, "Accept": "application/json"}, verify_tls=verify)
        finally:
            try: _request(base + "/api/session", method="DELETE",
                headers={"vmware-api-session-id": token}, verify_tls=verify)
            except HypervisorError: pass
        if not isinstance(rows, list): raise HypervisorError("Unexpected VMware inventory")
        return [_normal_vm("vmware", x.get("vm", ""), x.get("name", ""), x.get("power_state", "unknown"),
            cpu_count=x.get("cpu_count"), memory_size_MiB=x.get("memory_size_MiB"),
            guest_OS=x.get("guest_OS"), hardware_version=x.get("hardware_version"))
            for x in rows if isinstance(x, dict)]

class ProxmoxConnector:
    def inventory(self) -> list[dict[str, Any]]:
        base = _env("CSV_PROXMOX_URL").rstrip("/")
        token_id, secret = _env("CSV_PROXMOX_TOKEN_ID"), _env("CSV_PROXMOX_TOKEN_SECRET")
        if not (base and token_id and secret): raise HypervisorError("Proxmox connector is not configured")
        raw = _json_request(base + "/api2/json/cluster/resources?type=vm",
            headers={"Authorization": f"PVEAPIToken={token_id}={secret}", "Accept": "application/json"},
            verify_tls=_bool_env("CSV_PROXMOX_VERIFY_TLS", True))
        rows = raw.get("data") if isinstance(raw, dict) else None
        if not isinstance(rows, list): raise HypervisorError("Unexpected Proxmox inventory")
        return [_normal_vm("proxmox", x.get("vmid", ""), x.get("name") or x.get("vmid", ""),
            x.get("status", "unknown"), node=x.get("node"), vm_type=x.get("type"), cpu=x.get("cpu"),
            memory_bytes=x.get("mem"), max_memory_bytes=x.get("maxmem"),
            disk_bytes=x.get("disk"), max_disk_bytes=x.get("maxdisk"))
            for x in rows if isinstance(x, dict)]

def _integer(value: str | None) -> int | None:
    match = re.search(r"\d+", value or "")
    return int(match.group()) if match else None

def _parse_vbox_list(raw: str) -> list[dict[str, Any]]:
    machines, current = [], {}
    for line in raw.splitlines() + [""]:
        if not line.strip():
            if current:
                machines.append(_normal_vm("virtualbox", current.get("UUID", ""),
                    current.get("Name", current.get("UUID", "")),
                    current.get("State", "unknown").split(" (", 1)[0],
                    guest_os=current.get("Guest OS", ""), memory_mb=_integer(current.get("Memory size")),
                    cpu_count=_integer(current.get("Number of CPUs")), groups=current.get("Groups", "")))
                current = {}
            continue
        match = re.match(r"^\s*([^:]+):\s*(.*?)\s*$", line)
        if match: current[match.group(1)] = match.group(2)
    return machines

class VirtualBoxConnector:
    def inventory(self) -> list[dict[str, Any]]:
        executable = _env("CSV_VBOXMANAGE_PATH", "VBoxManage")
        path = shutil.which(executable)
        if not path: raise HypervisorError("VBoxManage unavailable on API host")
        try:
            result = subprocess.run([path, "list", "vms", "--long"], capture_output=True,
                text=True, timeout=20, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise HypervisorError("VirtualBox inventory command failed or timed out") from None
        if result.returncode: raise HypervisorError("VirtualBox inventory command returned an error")
        return _parse_vbox_list(result.stdout)

class HyperVConnector:
    def inventory(self) -> list[dict[str, Any]]:
        host = _env("CSV_HYPERV_HOST")
        username, password = _env("CSV_HYPERV_USERNAME"), _env("CSV_HYPERV_PASSWORD")
        if not (host and username and password): raise HypervisorError("Hyper-V connector is not configured")
        endpoint = host if host.startswith(("http://", "https://")) else f"https://{host}:5986/wsman"
        if not endpoint.startswith("https://"):
            raise HypervisorError("Hyper-V WinRM must use HTTPS; plaintext HTTP is refused")
        try: import winrm
        except ImportError: raise HypervisorError("Hyper-V connector requires pywinrm") from None
        try:
            session = winrm.Session(endpoint, auth=(username, password),
                transport=_env("CSV_HYPERV_TRANSPORT", "ntlm"),
                server_cert_validation="validate", read_timeout_sec=25, operation_timeout_sec=20)
            result = session.run_ps("Get-VM | Select-Object Name,Id,State,CPUUsage,MemoryAssigned,Uptime,Version | ConvertTo-Json -Compress")
        except Exception: raise HypervisorError("Hyper-V WinRM connection failed; check HTTPS, credentials and firewall") from None
        if result.status_code != 0: raise HypervisorError("Hyper-V inventory command failed")
        try: rows = json.loads(result.std_out.decode("utf-8-sig") or "[]")
        except (UnicodeDecodeError, json.JSONDecodeError): raise HypervisorError("Invalid Hyper-V inventory response") from None
        if isinstance(rows, dict): rows = [rows]
        if not isinstance(rows, list): raise HypervisorError("Unexpected Hyper-V inventory")
        return [_normal_vm("hyperv", x.get("Id", ""), x.get("Name", ""), x.get("State", "unknown"),
            cpu_usage=x.get("CPUUsage"), memory_assigned_bytes=x.get("MemoryAssigned"),
            uptime=x.get("Uptime"), version=x.get("Version")) for x in rows if isinstance(x, dict)]

CONNECTORS = {"vmware": VMwareConnector, "proxmox": ProxmoxConnector,
              "virtualbox": VirtualBoxConnector, "hyperv": HyperVConnector}

def inventory(provider: str) -> list[dict[str, Any]]:
    """Collect one provider inventory. No mutating API is exposed."""
    connector = CONNECTORS.get(provider.strip().lower())
    if connector is None: raise HypervisorError("Unsupported hypervisor provider")
    return connector().inventory()
