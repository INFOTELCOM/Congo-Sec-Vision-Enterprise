import argparse, json, os, platform, socket, time, urllib.request, subprocess, shutil
from datetime import datetime, timezone
import psutil

def run(cmd, timeout=12):
    try: return subprocess.run(cmd,capture_output=True,text=True,timeout=timeout,errors="replace").stdout
    except Exception: return ""
def local_interfaces():
    result=[]
    for name, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if getattr(a.family,"name","")=="AF_INET" and not a.address.startswith("127."):
                result.append({"interface":name,"address":a.address,"netmask":a.netmask})
    return result
def software_inventory():
    items=[]
    if platform.system()=="Windows":
        script="Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Where-Object DisplayName | Select-Object -First 300 DisplayName,DisplayVersion,Publisher | ConvertTo-Json -Compress"
        raw=run(["powershell","-NoProfile","-NonInteractive","-Command",script],20)
        try:
            data=json.loads(raw or "[]")
            if isinstance(data,dict): data=[data]
            for x in data: items.append({"name":x.get("DisplayName",""),"version":x.get("DisplayVersion",""),"vendor":x.get("Publisher","")})
        except Exception: pass
    elif shutil.which("dpkg-query"):
        raw=run(["dpkg-query","-W","-f=${binary:Package}\\t${Version}\\t${Maintainer}\\n"],20)
        for line in raw.splitlines()[:1000]:
            p=line.split("\t")
            if len(p)>=2: items.append({"name":p[0],"version":p[1],"vendor":p[2] if len(p)>2 else ""})
    elif shutil.which("rpm"):
        raw=run(["rpm","-qa","--qf","%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{VENDOR}\\n"],20)
        for line in raw.splitlines()[:1000]:
            p=line.split("\t")
            if len(p)>=2: items.append({"name":p[0],"version":p[1],"vendor":p[2] if len(p)>2 else ""})
    return items
def collect_logs():
    logs=[]
    if platform.system()=="Windows":
        ps="Get-WinEvent -FilterHashtable @{LogName='System';StartTime=(Get-Date).AddMinutes(-2)} -MaxEvents 40 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message | ConvertTo-Json -Compress"
        raw=run(["powershell","-NoProfile","-NonInteractive","-Command",ps],18)
        try:
            data=json.loads(raw or "[]")
            if isinstance(data,dict): data=[data]
            for x in data:
                logs.append({"timestamp":str(x.get("TimeCreated") or ""),"source":x.get("ProviderName","Windows System"),
                             "severity":str(x.get("LevelDisplayName","info")).lower(),"message":f"EventID={x.get('Id')} {x.get('Message','')}"})
        except Exception: pass
    elif shutil.which("journalctl"):
        raw=run(["journalctl","--since","2 minutes ago","-n","60","--no-pager","-o","short-iso"],15)
        for line in raw.splitlines()[-60:]:
            logs.append({"source":"journald","severity":"info","message":line})
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
                  "google", "openstack")
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


def collect():
    vm=psutil.virtual_memory(); disk=psutil.disk_usage(os.path.abspath(os.sep))
    return {"hostname":socket.gethostname(),"platform":platform.system(),"platform_release":platform.release(),
      "platform_version":platform.version(),"architecture":platform.machine(),"processor":platform.processor(),
      "cpu_percent":psutil.cpu_percent(interval=1),"memory_percent":vm.percent,"disk_percent":disk.percent,
      "ip_addresses":[{"interface":x["interface"],"address":x["address"]} for x in local_interfaces()],
      "interfaces":local_interfaces(),"software":software_inventory(),"logs":collect_logs(),
      "virtualization":detect_virtualization(),"agent_version":"0.2.0","collected_at":datetime.now(timezone.utc).isoformat()}
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
                    print("Heartbeat",data["hostname"],"logs",result.get("logs_received",0),flush=True)
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
