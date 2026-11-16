import argparse, json, os, platform, socket, time, urllib.request, subprocess, shutil, ipaddress, concurrent.futures
from datetime import datetime, timezone
import psutil

def run(cmd, timeout=12):
    try:
        command = list(cmd)
        if command and os.path.basename(str(command[0])).lower().startswith("powershell"):
            command[-1] = "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding; $OutputEncoding = [Console]::OutputEncoding; " + str(command[-1])
        return subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=timeout, errors="replace").stdout
    except Exception: return ""
def local_interfaces():
    result=[]
    for name, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if getattr(a.family,"name","")=="AF_INET" and not a.address.startswith("127."):
                result.append({"interface":name,"address":a.address,"netmask":a.netmask})
    return result
_network_scan_cache = {}

def discover_connected_networks(force=False):
    """Discover only bounded private LANs; throttle each subnet to one scan per 10 minutes."""
    discovered = []
    current_time = time.time()
    networks = {}
    for iface in local_interfaces():
        try:
            interface = ipaddress.ip_interface(f"{iface['address']}/{iface['netmask']}")
            network = interface.network
            if (not network.is_private or network.is_loopback or network.is_link_local
                    or network.is_multicast or network.num_addresses > 256):
                continue
            networks[str(network)] = str(interface.ip)
        except (ValueError, TypeError):
            continue
    for cidr, own_ip in networks.items():
        if not force and current_time - _network_scan_cache.get(cidr, 0) < 600:
            continue
        _network_scan_cache[cidr] = current_time
        hosts = [str(ip) for ip in ipaddress.ip_network(cidr).hosts() if str(ip) != own_ip]
        def probe(ip):
            command = ["ping", "-n", "1", "-w", "700", ip] if platform.system() == "Windows" else ["ping", "-c", "1", "-W", "1", ip]
            try:
                result = subprocess.run(command, capture_output=True, timeout=2, check=False)
                if result.returncode:
                    return None
            except (OSError, subprocess.TimeoutExpired):
                return None
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except OSError:
                hostname = ""
            return {"ip_address": ip, "hostname": hostname, "cidr": cidr}
        with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
            discovered.extend(item for item in pool.map(probe, hosts) if item)
    return discovered


def os_installation_info():
    """Return an installation date only when the OS exposes a defensible source."""
    if platform.system() == "Windows":
        script = "$o=Get-CimInstance Win32_OperatingSystem; [pscustomobject]@{InstallDate=$o.InstallDate.ToUniversalTime().ToString('o')} | ConvertTo-Json -Compress"
        raw = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], 12)
        try:
            value = json.loads(raw or "{}").get("InstallDate")
            if value:
                parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
                return {"date": parsed.date().isoformat(), "source": "Win32_OperatingSystem.InstallDate", "confidence": 0.85}
        except (ValueError, TypeError, AttributeError):
            pass
        return {"date": None, "source": "unavailable", "confidence": 0.0}
    if platform.system() == "Linux":
        candidates = ("/var/log/installer/initial-status.gz", "/var/log/installer/lsb-release")
        for candidate in candidates:
            try:
                value = run(["stat", "-c", "%w", candidate], 4).strip()
                if value and value != "-":
                    parsed = datetime.fromisoformat(value.replace(" ", "T").split(".")[0])
                    return {"date": parsed.date().isoformat(), "source": "installer-file-birthtime", "confidence": 0.55}
            except (OSError, ValueError):
                continue
    return {"date": None, "source": "unavailable", "confidence": 0.0}


def software_inventory():
    items = []
    if platform.system() == "Windows":
        script = r"Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object DisplayName | Select-Object -First 500 DisplayName,DisplayVersion,Publisher,InstallDate,InstallLocation,PSChildName | ConvertTo-Json -Compress"
        raw = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], 25)
        try:
            data = json.loads(raw or "[]")
            if isinstance(data, dict):
                data = [data]
            for x in data:
                raw_date = str(x.get("InstallDate") or "").strip()
                installed_at = ""
                if len(raw_date) == 8 and raw_date.isdigit():
                    try:
                        installed_at = datetime.strptime(raw_date, "%Y%m%d").date().isoformat()
                    except ValueError:
                        pass
                items.append({
                    "name": x.get("DisplayName", ""), "version": x.get("DisplayVersion", ""),
                    "vendor": x.get("Publisher", ""), "installed_at": installed_at,
                    "install_location": x.get("InstallLocation", "") or "",
                    "install_scope": "machine", "package_id": x.get("PSChildName", "") or ""
                })
        except (ValueError, TypeError):
            pass
    elif shutil.which("dpkg-query"):
        install_dates = {}
        for log_path in ("/var/log/dpkg.log", "/var/log/dpkg.log.1"):
            try:
                with open(log_path, "r", encoding="utf-8", errors="replace") as log_file:
                    for log_line in log_file:
                        fields = log_line.split()
                        if len(fields) >= 4 and fields[2] == "install":
                            package = fields[3]
                            try:
                                installed = datetime.strptime(fields[0] + " " + fields[1], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).isoformat()
                                install_dates[package] = installed
                                install_dates[package.split(":")[0]] = installed
                            except ValueError:
                                continue
            except OSError:
                continue
        format_string = "-f=" + chr(36) + "{binary:Package}\\t" + chr(36) + "{Version}\\t" + chr(36) + "{Maintainer}\\n"
        raw = run(["dpkg-query", "-W", format_string], 25)
        for line in raw.splitlines()[:1500]:
            p = line.split(chr(9))
            if len(p) >= 2:
                installed_at = install_dates.get(p[0]) or install_dates.get(p[0].split(":")[0]) or ""
                items.append({"name": p[0], "version": p[1], "vendor": p[2] if len(p) > 2 else "",
                              "installed_at": installed_at, "install_location": "", "install_scope": "system",
                              "package_id": p[0]})
    elif shutil.which("rpm"):
        raw = run(["rpm", "-qa", "--qf", "%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{VENDOR}\\t%{INSTALLTIME:date}\\n"], 25)
        for line in raw.splitlines()[:1500]:
            p = line.split(chr(9))
            if len(p) >= 2:
                installed_at = ""
                if len(p) > 3:
                    try:
                        installed_at = datetime.strptime(p[3].strip(), "%a %b %d %H:%M:%S %Y").date().isoformat()
                    except ValueError:
                        pass
                items.append({"name": p[0], "version": p[1], "vendor": p[2] if len(p) > 2 else "",
                              "installed_at": installed_at, "install_location": "", "install_scope": "system",
                              "package_id": p[0]})
    return items


def endpoint_protection():
    """Collect native protection state; never claim a clean scan when none was run."""
    if platform.system() == "Windows":
        script = "$s=Get-MpComputerStatus -ErrorAction SilentlyContinue; $d=@(Get-MpThreatDetection -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ThreatID=$_.ThreatID;ThreatName=$_.ThreatName;InitialDetectionTime=if($_.InitialDetectionTime){$_.InitialDetectionTime.ToUniversalTime().ToString('o')}else{$null};ActionSuccess=$_.ActionSuccess;Resources=@($_.Resources)}}); $p=@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | Select-Object displayName,pathToSignedProductExe,productState); [pscustomobject]@{Defender=if($s){[pscustomobject]@{AntivirusEnabled=$s.AntivirusEnabled;AntispywareEnabled=$s.AntispywareEnabled;RealTimeProtectionEnabled=$s.RealTimeProtectionEnabled;BehaviorMonitorEnabled=$s.BehaviorMonitorEnabled;SignatureVersion=$s.AntivirusSignatureVersion;SignatureUpdated=if($s.AntivirusSignatureLastUpdated){$s.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('o')}else{$null};QuickScanEndTime=if($s.QuickScanEndTime){$s.QuickScanEndTime.ToUniversalTime().ToString('o')}else{$null};FullScanEndTime=if($s.FullScanEndTime){$s.FullScanEndTime.ToUniversalTime().ToString('o')}else{$null}}}else{$null};Products=$p;Detections=$d} | ConvertTo-Json -Depth 5 -Compress"
        raw = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], 20)
        try:
            data = json.loads(raw or "{}")
            defender = data.get("Defender") or {}
            products = data.get("Products") or []
            detections = data.get("Detections") or []
            if isinstance(products, dict): products = [products]
            if isinstance(detections, dict): detections = [detections]
            return {
                "provider": "Microsoft Defender" if defender else "Windows Security Center",
                "antivirus_enabled": defender.get("AntivirusEnabled"),
                "antispyware_enabled": defender.get("AntispywareEnabled"),
                "real_time_enabled": defender.get("RealTimeProtectionEnabled"),
                "behavior_monitoring_enabled": defender.get("BehaviorMonitorEnabled"),
                "definitions_version": str(defender.get("SignatureVersion") or ""),
                "definitions_updated_at": str(defender.get("SignatureUpdated") or ""),
                "last_scan_at": str(defender.get("FullScanEndTime") or defender.get("QuickScanEndTime") or ""),
                "last_scan_type": "full" if defender.get("FullScanEndTime") else ("quick" if defender.get("QuickScanEndTime") else ""),
                "health_status": "protected" if defender.get("AntivirusEnabled") and defender.get("RealTimeProtectionEnabled") else ("at_risk" if defender else "unknown"),
                "products": products[:20], "detections": detections[:100],
                "collection_source": "Windows Defender / SecurityCenter2"
            }
        except (ValueError, TypeError, AttributeError):
            return {"provider": "Windows Security", "health_status": "unknown", "detections": [], "collection_source": "powershell_unavailable"}
    if platform.system() == "Linux":
        if shutil.which("clamscan") or shutil.which("clamdscan"):
            binary = shutil.which("clamdscan") or shutil.which("clamscan")
            version = run([binary, "--version"], 5).strip()[:160]
            return {"provider": "ClamAV", "health_status": "installed_not_scanned", "product_version": version,
                    "antivirus_enabled": None, "antispyware_enabled": None, "real_time_enabled": None,
                    "detections": [], "collection_source": "clamav_binary"}
    return {"provider": "not_detected", "health_status": "unknown", "detections": [], "collection_source": "native_inventory"}


def collect_listening_ports():
    """Collect ports listening locally on this endpoint, distinct from remote network scans."""
    items = []
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError):
        connections = []
    for c in connections[:1000]:
        try:
            if not c.laddr:
                continue
            is_tcp = c.type == socket.SOCK_STREAM
            if is_tcp and c.status != psutil.CONN_LISTEN:
                continue
            if not is_tcp and c.raddr:
                continue
            pname = ""
            if c.pid:
                try:
                    pname = psutil.Process(c.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            items.append({"protocol": "tcp" if is_tcp else "udp", "ip_address": c.laddr.ip,
                          "port": int(c.laddr.port), "state": "LISTEN" if is_tcp else "BOUND",
                          "pid": int(c.pid or 0), "process_name": pname[:255]})
        except (AttributeError, OSError, ValueError):
            continue
    return items


def collect_logs():
    logs = []
    if platform.system() == "Windows":
        ps = "$logs=@('System','Application','Security','Microsoft-Windows-Windows Defender/Operational'); $events=@(); foreach($log in $logs){try{$events+=Get-WinEvent -FilterHashtable @{LogName=$log;StartTime=(Get-Date).AddMinutes(-3)} -MaxEvents 35 -ErrorAction Stop}catch{}}; $events | Sort-Object TimeCreated -Descending | Select-Object -First 100 | ForEach-Object {[pscustomobject]@{TimeCreatedUtc=$_.TimeCreated.ToUniversalTime().ToString('o');Id=$_.Id;RecordId=$_.RecordId;LevelDisplayName=$_.LevelDisplayName;ProviderName=$_.ProviderName;Channel=$_.LogName;Machine=$_.MachineName;Message=$_.Message}} | ConvertTo-Json -Depth 4 -Compress"
        raw = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], 22)
        try:
            data = json.loads(raw or "[]")
            if isinstance(data, dict):
                data = [data]
            severity_map = {
                "critical": "critical", "critique": "critical", "error": "high", "erreur": "high",
                "warning": "medium", "avertissement": "medium", "information": "info", "informational": "info"
            }
            for x in data:
                raw_level = str(x.get("LevelDisplayName") or "info").strip().lower()
                raw_time = str(x.get("TimeCreatedUtc") or "").strip()
                try:
                    timestamp = datetime.fromisoformat(raw_time.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()
                except (ValueError, TypeError):
                    timestamp = datetime.now(timezone.utc).isoformat()
                event_id = x.get("Id")
                logs.append({
                    "timestamp": timestamp, "source": str(x.get("ProviderName") or "Windows System")[:160],
                    "provider": str(x.get("ProviderName") or "Windows System")[:160],
                    "channel": str(x.get("Channel") or "System")[:100],
                    "machine": str(x.get("Machine") or socket.gethostname())[:255],
                    "event_id": int(event_id) if str(event_id or "").isdigit() else None,
                    "record_id": int(x.get("RecordId") or 0) or None,
                    "severity": severity_map.get(raw_level, raw_level[:24]),
                    "message": f"EventID={event_id} {x.get('Message', '')}"[:4000]
                })
        except (ValueError, TypeError, AttributeError):
            pass
    elif shutil.which("journalctl"):
        raw = run(["journalctl", "--since", "3 minutes ago", "-n", "80", "--no-pager", "-o", "json"], 15)
        for line in raw.splitlines()[-80:]:
            try:
                item = json.loads(line)
                stamp = item.get("__REALTIME_TIMESTAMP")
                timestamp = datetime.fromtimestamp(int(stamp) / 1000000, timezone.utc).isoformat() if stamp else datetime.now(timezone.utc).isoformat()
                logs.append({"timestamp": timestamp, "source": "journald",
                             "severity": str(item.get("PRIORITY") or "info"),
                             "message": str(item.get("MESSAGE") or "")[:4000]})
            except (ValueError, TypeError):
                continue
    return logs

def detect_virtualization():
    """Best-effort guest VM detection; does not query or control the hypervisor."""
    system = platform.system()
    vendor = ""
    model = ""
    hypervisor = ""
    if system == "Windows":
        ps = "(Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model | ConvertTo-Json -Compress)"
        raw = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], 10)
        try:
            info = json.loads(raw or "{}")
            vendor = str(info.get("Manufacturer") or "")
            model = str(info.get("Model") or "")
        except (ValueError, AttributeError):
            pass
    elif system == "Linux":
        for path in ("/sys/class/dmi/id/sys_vendor", "/sys/class/dmi/id/product_name"):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    value = f.read().strip()
            except OSError:
                value = ""
            if path.endswith("sys_vendor"):
                vendor = value
            else:
                model = value
        if shutil.which("systemd-detect-virt"):
            hypervisor = run(["systemd-detect-virt"], 5).strip()
            if hypervisor == "none":
                hypervisor = ""
    identity = (vendor + " " + model + " " + hypervisor).lower()
    indicators = ("vmware", "virtualbox", "virtual machine", "kvm", "qemu",
                  "xen", "hyper-v", "hyperv", "parallels", "bhyve", "amazon ec2",
                  "google compute engine", "google cloud", "openstack")
    is_vm = bool(hypervisor) or any(term in identity for term in indicators)
    if hypervisor:
        provider = hypervisor
    elif "vmware" in identity:
        provider = "VMware"
    elif "virtualbox" in identity:
        provider = "VirtualBox"
    elif "hyper-v" in identity or "hyperv" in identity or "virtual machine" in identity:
        provider = "Hyper-V / Microsoft Virtual Machine"
    elif "kvm" in identity or "qemu" in identity:
        provider = "KVM / QEMU"
    elif "xen" in identity:
        provider = "Xen"
    elif "parallels" in identity:
        provider = "Parallels"
    elif "bhyve" in identity:
        provider = "bhyve"
    elif "amazon ec2" in identity:
        provider = "Amazon EC2"
    elif "openstack" in identity:
        provider = "OpenStack"
    else:
        provider = "unknown" if is_vm else None
    return {"is_virtual_machine": is_vm, "provider": provider,
            "manufacturer": vendor[:160], "model": model[:160],
            "detection_method": "guest_os_heuristic", "hypervisor_api_connected": False}


def collect_network_connections():
    """Collect connection metadata only; never captures packet payloads or message contents."""
    items=[]
    try: connections=psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError): connections=[]
    for c in connections[:500]:
        try:
            local_ip=c.laddr.ip if c.laddr else ""
            remote_ip=c.raddr.ip if c.raddr else ""
            pname=""
            if c.pid:
                try: pname=psutil.Process(c.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied): pass
            items.append({"protocol":"tcp" if c.type==socket.SOCK_STREAM else "udp",
                "local_address":local_ip,"local_port":c.laddr.port if c.laddr else 0,
                "remote_address":remote_ip,"remote_port":c.raddr.port if c.raddr else 0,
                "status":str(c.status or "NONE"),"pid":c.pid or 0,"process_name":pname[:255],
                "observed_at":datetime.now(timezone.utc).isoformat()})
        except (AttributeError, OSError, ValueError): continue
    return items

def collect_processes():
    """Collect a bounded process inventory without command-line arguments or user data."""
    items=[]
    for p in psutil.process_iter(["pid","name","exe","create_time"]):
        if len(items)>=500: break
        try:
            info=p.info
            items.append({"pid":int(info.get("pid") or 0),"name":str(info.get("name") or "")[:255],
                "executable":str(info.get("exe") or "")[:1000],
                "started_at":datetime.fromtimestamp(info["create_time"],timezone.utc).isoformat()
                    if info.get("create_time") else ""})
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError, ValueError): continue
    return items

def collect():
    vm=psutil.virtual_memory(); disk=psutil.disk_usage(os.path.abspath(os.sep))
    software = software_inventory()
    software_limit = 500 if platform.system() == "Windows" else 1500
    return {"hostname":socket.gethostname(),"platform":platform.system(),"platform_release":platform.release(),
      "platform_version":platform.version(),"architecture":platform.machine(),"processor":platform.processor(),
      "cpu_percent":psutil.cpu_percent(interval=1),"memory_percent":vm.percent,"disk_percent":disk.percent,
      "ip_addresses":[{"interface":x["interface"],"address":x["address"]} for x in local_interfaces()],
      "interfaces":local_interfaces(),"network_discoveries":discover_connected_networks(),
      "os_installation":os_installation_info(),"software":software,"software_inventory_complete":len(software)<software_limit,"logs":collect_logs(),
      "endpoint_protection":endpoint_protection(),"listening_ports":collect_listening_ports(),
      "network_connections":collect_network_connections(),"processes":collect_processes(),
      "virtualization":detect_virtualization(),"agent_version":"0.3.0","collected_at":datetime.now(timezone.utc).isoformat()}
def post(url,payload,token=None):
    req=urllib.request.Request(url,data=json.dumps(payload).encode(),headers={"Content-Type":"application/json",**({"Authorization":"Bearer "+token} if token else {})},method="POST")
    with urllib.request.urlopen(req,timeout=45) as r: return json.loads(r.read().decode())
def default_token_file():
    if platform.system()=="Windows":
        root=os.environ.get("PROGRAMDATA",r"C:\\ProgramData")
        return os.path.join(root,"CongoSecVision","agent-token.json")
    return "/var/lib/congo-sec-vision/agent-token.json"
def load_agent_token(path):
    try:
        with open(path,"r",encoding="utf-8") as f: return json.load(f).get("agent_token")
    except (OSError,ValueError,AttributeError): return None
def save_agent_token(path,token):
    os.makedirs(os.path.dirname(os.path.abspath(path)),exist_ok=True)
    temp=path+".tmp"
    with open(temp,"w",encoding="utf-8") as f: json.dump({"agent_token":token},f)
    os.replace(temp,path)
    if platform.system()!="Windows":
        os.chmod(path,0o600)
def main():
    p=argparse.ArgumentParser(description="Congo Sec Vision endpoint monitoring agent")
    p.add_argument("--server",required=True)
    p.add_argument("--enrollment-token",default=os.environ.get("CSV_ENROLLMENT_TOKEN"))
    p.add_argument("--token-file",default=default_token_file())
    p.add_argument("--interval",type=int,default=60)
    a=p.parse_args()
    base=a.server.rstrip("/"); token=load_agent_token(a.token_file)
    from urllib.parse import urlparse
    parsed=urlparse(base)
    if parsed.scheme != "https" and parsed.hostname not in ("localhost","127.0.0.1","::1"):
        raise SystemExit("HTTPS obligatoire pour tout serveur distant ; HTTP est autorisé uniquement en laboratoire local.")
    if not token and not a.enrollment_token:
        raise SystemExit("Premier enrôlement : fournir --enrollment-token ou CSV_ENROLLMENT_TOKEN.")
    while True:
        try:
            data=collect()
            if not token:
                result=post(base+"/api/agents/enroll",data,a.enrollment_token)
                token=result["agent_token"];save_agent_token(a.token_file,token)
                print("Enrolled asset",result["asset_id"],flush=True)
            else:
                try:
                    result=post(base+"/api/agents/heartbeat",data,token)
                    sync=result.get("supabase_sync") or {}
                    print("Heartbeat",data["hostname"],"logs",result.get("logs_received",0),
                          "Supabase SOC",sync.get("status","unknown"),flush=True)
                except urllib.error.HTTPError as e:
                    if e.code==401 and a.enrollment_token:
                        token=None
                        try: os.remove(a.token_file)
                        except OSError: pass
                        print("Agent token rejected; will re-enroll on next cycle.",flush=True)
                    else: raise
        except Exception as e: print("Agent error:",e,flush=True)
        time.sleep(max(30,a.interval))
if __name__=="__main__": main()
