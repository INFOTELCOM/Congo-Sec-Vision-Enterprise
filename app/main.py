import os, json, secrets, hashlib, sqlite3, urllib.parse, urllib.request, urllib.error, subprocess, re, ipaddress, time, asyncio, contextvars, threading
from datetime import datetime, timezone, timedelta
from fastapi import FastAPI, Header, HTTPException, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from app.ai_engine import analyze_logs, cve_remediation_advice
from app.cve_engine import (scan_product, search_nvd_catalog, get_nvd_cve, get_nvd_cve_history, search_nvd_cpes, search_nvd_cpe_matches)
from app.authz import get_user_roles
from app.hypervisors import HypervisorError, configured_providers, inventory as collect_hypervisor_inventory
from app.hypervisor_lab import lab_inventory as get_hypervisor_lab_inventory
from app.network_discovery import discover_network, validate_network
from app.opencve import OpenCVEError, check_connection as check_opencve_connection, search_cves as search_opencve_cves, get_cve as get_opencve_cve, get_cve_changes as get_opencve_changes
from app.soc_storage import supabase_public_request, supabase_public_configured

DB = os.getenv("DATABASE_PATH", "congo_sec_vision.db")
SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_PUBLISHABLE_KEY = os.getenv("SUPABASE_PUBLISHABLE_KEY", "")
_internal_task = contextvars.ContextVar("csv_internal_task", default=False)
ENROLL = os.getenv("AGENT_ENROLLMENT_TOKEN", "")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
OPENCVE_API_TOKEN = os.getenv("OPENCVE_API_TOKEN", "").strip()
VBOX_COLLECTOR_TOKEN = os.getenv("CSV_VBOX_COLLECTOR_TOKEN", "").strip()
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "").rstrip("/")
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_MODEL = os.getenv("LLM_MODEL", "")

def now(): return datetime.now(timezone.utc).isoformat()
def conn():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row
    return c

def init():
    with conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS assets(id TEXT PRIMARY KEY, hostname TEXT NOT NULL, platform TEXT,
          ip_addresses TEXT, inventory TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS agent_tokens(token TEXT PRIMARY KEY, asset_id TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id TEXT, severity TEXT,
          category TEXT, message TEXT, created_at TEXT NOT NULL, raw TEXT);
        CREATE TABLE IF NOT EXISTS vulnerabilities(id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id TEXT,
          cve_id TEXT, severity TEXT, title TEXT, status TEXT DEFAULT 'open', source TEXT, created_at TEXT NOT NULL,
          UNIQUE(asset_id,cve_id));
        CREATE TABLE IF NOT EXISTS cve_history(
          id INTEGER PRIMARY KEY AUTOINCREMENT, vulnerability_id INTEGER NOT NULL, cve_id TEXT NOT NULL,
          event_type TEXT NOT NULL, details TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS cve_subscriptions(
          id INTEGER PRIMARY KEY AUTOINCREMENT, vendor TEXT NOT NULL DEFAULT '', product TEXT NOT NULL DEFAULT '',
          asset_id TEXT DEFAULT '', active INTEGER NOT NULL DEFAULT 1, created_by TEXT NOT NULL,
          created_at TEXT NOT NULL, UNIQUE(vendor,product,asset_id));
        CREATE TABLE IF NOT EXISTS cve_notifications(
          id INTEGER PRIMARY KEY AUTOINCREMENT, subscription_id INTEGER NOT NULL, vulnerability_id INTEGER NOT NULL,
          cve_id TEXT NOT NULL, event_type TEXT NOT NULL, title TEXT NOT NULL DEFAULT '',
          severity TEXT NOT NULL DEFAULT 'unknown', created_at TEXT NOT NULL, read_at TEXT,
          UNIQUE(subscription_id,vulnerability_id,event_type));
        CREATE TABLE IF NOT EXISTS software(id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id TEXT,
          name TEXT, version TEXT, vendor TEXT, collected_at TEXT);
        CREATE TABLE IF NOT EXISTS log_findings(id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id TEXT,
          severity TEXT, rule_id TEXT, title TEXT, details TEXT, created_at TEXT);
        CREATE TABLE IF NOT EXISTS network_connections(
          id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id TEXT NOT NULL, protocol TEXT NOT NULL,
          local_address TEXT, local_port INTEGER, remote_address TEXT, remote_port INTEGER,
          status TEXT, pid INTEGER, process_name TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
          observations INTEGER NOT NULL DEFAULT 1,
          UNIQUE(asset_id,protocol,local_address,local_port,remote_address,remote_port,status,pid));
        CREATE INDEX IF NOT EXISTS idx_network_connections_last_seen ON network_connections(last_seen);
        CREATE TABLE IF NOT EXISTS process_observations(
          id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id TEXT NOT NULL, pid INTEGER NOT NULL,
          name TEXT NOT NULL, executable TEXT DEFAULT '', started_at TEXT DEFAULT '',
          first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
          UNIQUE(asset_id,pid,name,started_at));
        CREATE INDEX IF NOT EXISTS idx_process_observations_last_seen ON process_observations(last_seen);
        CREATE TABLE IF NOT EXISTS incidents(
          id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, description TEXT DEFAULT '',
          severity TEXT NOT NULL DEFAULT 'medium', status TEXT NOT NULL DEFAULT 'open',
          assignee TEXT DEFAULT '', source TEXT DEFAULT 'manual', asset_id TEXT,
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL, closed_at TEXT);
        CREATE TABLE IF NOT EXISTS audit_logs(
          id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, action TEXT NOT NULL,
          target TEXT DEFAULT '', details TEXT DEFAULT '', created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS team_members(
          id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
          display_name TEXT NOT NULL, role TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS approvals(
          id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, description TEXT NOT NULL,
          target TEXT DEFAULT '', action_type TEXT DEFAULT 'manual', status TEXT NOT NULL DEFAULT 'pending',
          requested_by TEXT NOT NULL, reviewed_by TEXT DEFAULT '', created_at TEXT NOT NULL, reviewed_at TEXT);
        CREATE TABLE IF NOT EXISTS workflows(
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT DEFAULT '',
          trigger_type TEXT NOT NULL DEFAULT 'manual', enabled INTEGER NOT NULL DEFAULT 0,
          requires_approval INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS ai_agents(
          id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id TEXT UNIQUE NOT NULL,
          name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
          created_at TEXT NOT NULL, last_analysis_at TEXT, last_report_id INTEGER,
          FOREIGN KEY(asset_id) REFERENCES assets(id));
        CREATE TABLE IF NOT EXISTS ai_reports(
          id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id TEXT NOT NULL,
          report_type TEXT NOT NULL, summary TEXT NOT NULL, findings_json TEXT NOT NULL,
          events_reviewed INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL,
          FOREIGN KEY(asset_id) REFERENCES assets(id));
        """)
        # Existing installations stored raw agent tokens. Migrate them once to SHA-256 digests.
        for token_row in c.execute("SELECT token FROM agent_tokens").fetchall():
            stored_token = str(token_row["token"] or "")
            if stored_token and not re.fullmatch(r"[0-9a-f]{64}", stored_token):
                c.execute("UPDATE agent_tokens SET token=? WHERE token=?",
                          (hashlib.sha256(stored_token.encode("utf-8")).hexdigest(), stored_token))
        cols={r["name"] for r in c.execute("PRAGMA table_info(events)").fetchall()}
        if "raw" not in cols: c.execute("ALTER TABLE events ADD COLUMN raw TEXT")
        vuln_cols={r["name"] for r in c.execute("PRAGMA table_info(vulnerabilities)").fetchall()}
        for col, ddl in {
            "software_name":"TEXT DEFAULT ''","software_version":"TEXT DEFAULT ''","vendor":"TEXT DEFAULT ''",
            "match_confidence":"TEXT DEFAULT 'candidate'","cve_url":"TEXT DEFAULT ''",
            "cvss_score":"REAL","cvss_version":"TEXT DEFAULT ''","cvss_vector":"TEXT DEFAULT ''",
            "cwe_ids":"TEXT DEFAULT '[]'","cpe_matches":"TEXT DEFAULT '[]'","references_json":"TEXT DEFAULT '[]'",
            "epss_score":"REAL","epss_percentile":"REAL","known_exploited":"INTEGER NOT NULL DEFAULT 0",
            "published_at":"TEXT DEFAULT ''","last_modified_at":"TEXT DEFAULT ''","vuln_status":"TEXT DEFAULT ''",
            "sources_json":"TEXT DEFAULT '[]'","ssvc_json":"TEXT DEFAULT '[]'","affected_json":"TEXT DEFAULT '[]'","assigned_to":"TEXT DEFAULT ''","tags_json":"TEXT DEFAULT '[]'"
        }.items():
            if col not in vuln_cols: c.execute("ALTER TABLE vulnerabilities ADD COLUMN "+col+" "+ddl)
        c.execute("CREATE TABLE IF NOT EXISTS system_settings(key TEXT PRIMARY KEY,value TEXT NOT NULL,updated_at TEXT NOT NULL)")
        c.execute("""CREATE TABLE IF NOT EXISTS network_discoveries(
          id INTEGER PRIMARY KEY AUTOINCREMENT, cidr TEXT NOT NULL, ip_address TEXT NOT NULL,
          hostname TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'reachable',
          source TEXT NOT NULL DEFAULT 'icmp', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
          UNIQUE(cidr,ip_address))""")
        c.execute("""CREATE TABLE IF NOT EXISTS hypervisor_host_inventory(
          provider TEXT NOT NULL, vm_id TEXT NOT NULL, name TEXT NOT NULL,
          state TEXT NOT NULL DEFAULT 'unknown', metadata TEXT NOT NULL DEFAULT '{}',
          last_seen TEXT NOT NULL, updated_by TEXT NOT NULL DEFAULT 'host-collector',
          PRIMARY KEY(provider,vm_id))""")
if not SUPABASE_URL or not SUPABASE_PUBLISHABLE_KEY or not ENROLL:
    raise RuntimeError("SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY and AGENT_ENROLLMENT_TOKEN must be set; see .env.example")
init()

app = FastAPI(title="Congo Sec Vision API", version="0.3.1")
_default_origins = ["https://infotelcom.github.io"]
_allowed_origins = [
    x.strip()
    for x in os.getenv("ALLOWED_ORIGINS", ",".join(_default_origins)).split(",")
    if x.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)
app.mount("/static", StaticFiles(directory="app/static"), name="static")

def bearer(value):
    if not value or not value.startswith("Bearer "): return None
    return value[7:]
def require_roles(auth, allowed_roles):
    if _internal_task.get():
        return "system"
    token = bearer(auth)
    if not token:
        raise HTTPException(401, "Supabase session required")
    req = urllib.request.Request(
        SUPABASE_URL + "/auth/v1/user",
        headers={"apikey": SUPABASE_PUBLISHABLE_KEY, "Authorization": "Bearer " + token},
        method="GET"
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            user = json.loads(response.read())
    except Exception:
        raise HTTPException(401, "Invalid or expired Supabase session")
    roles = get_user_roles(user)
    if not roles.intersection(set(allowed_roles)):
        raise HTTPException(403, "Insufficient Supabase app_metadata role")
    return str(user.get("email") or user.get("id") or "user")


def require_admin(auth):
    return require_roles(auth, {"admin"})


def require_read(auth):
    return require_roles(auth, {"admin", "analyst", "viewer", "incident_responder"})


def require_analyst(auth):
    return require_roles(auth, {"admin", "analyst"})


def require_incident_responder(auth):
    return require_roles(auth, {"admin", "analyst", "incident_responder"})

def run_internal_ai(asset_id):
    marker = _internal_task.set(True)
    try:
        analyze_asset_ai(asset_id, None)
    finally:
        _internal_task.reset(marker)
def audit(action, target="", details="", actor="admin"):
    with conn() as c:
        c.execute("INSERT INTO audit_logs(actor,action,target,details,created_at) VALUES(?,?,?,?,?)",
                  (actor, action[:120], str(target)[:255], str(details)[:2000], now()))

def require_agent(auth):
    token=bearer(auth)
    if not token: raise HTTPException(401,"Agent token required")
    token_hash=hashlib.sha256(token.encode("utf-8")).hexdigest()
    with conn() as c: row=c.execute("SELECT asset_id FROM agent_tokens WHERE token=?",(token_hash,)).fetchone()
    if not row: raise HTTPException(401,"Unknown agent token")
    return row["asset_id"]
def asset_inventory(data, asset_id=None):
    hostname=str(data.get("hostname") or "unknown")[:255]
    platform=str(data.get("platform") or "unknown")[:80]
    ips=json.dumps(data.get("ip_addresses",[])); stamp=now()
    with conn() as c:
        if asset_id:
            c.execute("UPDATE assets SET hostname=?,platform=?,ip_addresses=?,inventory=?,last_seen=? WHERE id=?",
                      (hostname,platform,ips,json.dumps(data),stamp,asset_id))
        else:
            asset_id=secrets.token_hex(12)
            c.execute("INSERT INTO assets VALUES(?,?,?,?,?,?,?)",(asset_id,hostname,platform,ips,json.dumps(data),stamp,stamp))
            c.execute("INSERT INTO events(asset_id,severity,category,message,created_at) VALUES(?,?,?,?,?)",
                      (asset_id,"info","asset",f"Agent enrolled: {hostname}",stamp))
        c.execute("DELETE FROM software WHERE asset_id=?",(asset_id,))
        for s in data.get("software",[])[:2000]:
            c.execute("INSERT INTO software(asset_id,name,version,vendor,collected_at) VALUES(?,?,?,?,?)",
                      (asset_id,str(s.get("name",""))[:255],str(s.get("version",""))[:100],
                       str(s.get("vendor",""))[:255],stamp))
        # Agent observations are accepted only for valid private CIDRs and addresses inside them.
        observations = data.get("network_discoveries", [])
        if isinstance(observations, list):
            for item in observations[:256]:
                if not isinstance(item, dict):
                    continue
                try:
                    network = validate_network(str(item.get("cidr", "")))
                    address = ipaddress.ip_address(str(item.get("ip_address", "")))
                    if address not in network:
                        continue
                except ValueError:
                    continue
                c.execute("""INSERT INTO network_discoveries(cidr,ip_address,hostname,status,source,first_seen,last_seen)
                  VALUES(?,?,?,?,?,?,?) ON CONFLICT(cidr,ip_address) DO UPDATE SET
                  hostname=CASE WHEN excluded.hostname<>'' THEN excluded.hostname ELSE network_discoveries.hostname END,
                  status='reachable',source='agent-icmp',last_seen=excluded.last_seen""",
                  (str(network), str(address), str(item.get("hostname", ""))[:255],
                   "reachable", "agent-icmp", stamp, stamp))
    return asset_id

def asset_json(a, online=None):
    inv=json.loads(a["inventory"])
    return {"id":a["id"],"hostname":a["hostname"],"platform":a["platform"],
      "ip_addresses":json.loads(a["ip_addresses"]),"first_seen":a["first_seen"],"last_seen":a["last_seen"],
      "online":online,"cpu_percent":inv.get("cpu_percent"),"memory_percent":inv.get("memory_percent"),
      "disk_percent":inv.get("disk_percent"),"agent_version":inv.get("agent_version"),
      "virtualization":inv.get("virtualization",{"is_virtual_machine":False,"provider":None}),
      "interfaces":inv.get("interfaces",[])}


def sync_asset_to_supabase(asset_id, data):
    """Mirror the authenticated endpoint identity into public.assets before SOC child rows."""
    if not supabase_public_configured():
        return {"status":"not-configured","message":"SUPABASE_SERVICE_ROLE_KEY is not configured on the API server."}
    stamp=now()
    with conn() as db:
        asset_row=db.execute("SELECT first_seen FROM assets WHERE id=?",(asset_id,)).fetchone()
    first_seen=asset_row["first_seen"] if asset_row else stamp
    payload={
        "id":asset_id,
        "hostname":str(data.get("hostname") or "unknown")[:255],
        "platform":str(data.get("platform") or "unknown")[:80],
        "ip_addresses":data.get("ip_addresses",[]),
        "inventory":{k:data.get(k) for k in ("cpu_percent","memory_percent","disk_percent","virtualization","interfaces","agent_version","platform_release","architecture","processor","collected_at") if k in data},
        "first_seen":first_seen,
        "last_seen":stamp,
    }
    try:
        supabase_public_request("assets?on_conflict=id","POST",payload)
        return {"status":"ok","asset":"saved"}
    except Exception as exc:
        return {"status":"error","stage":"asset","message":str(exc)[:500]}


def sync_endpoint_telemetry(asset_id, data):
    """Persist endpoint inventory, protection state, detections and network observations in Supabase."""
    if not supabase_public_configured():
        return {"status": "not-configured", "message": "SUPABASE_SERVICE_ROLE_KEY is required on the API server."}
    stamp = now()

    def clean_ip(value):
        try:
            return str(ipaddress.ip_address(str(value or "").strip()))
        except ValueError:
            return None

    def clean_timestamp(value):
        value = str(value or "").strip()
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).isoformat()
        except ValueError:
            return None

    def send_batches(resource, rows, size=200):
        for offset in range(0, len(rows), size):
            supabase_public_request(resource, "POST", rows[offset:offset + size])

    network = []
    for item in (data.get("network_connections") or [])[:500]:
        if not isinstance(item, dict):
            continue
        protocol = str(item.get("protocol") or "other").lower()
        if protocol not in {"tcp", "udp", "icmp", "other"}:
            protocol = "other"
        try:
            local_port = max(0, min(65535, int(item.get("local_port") or 0)))
            remote_port = max(0, min(65535, int(item.get("remote_port") or 0)))
            pid = max(0, int(item.get("pid") or 0))
        except (TypeError, ValueError):
            continue
        network.append({
            "asset_id": asset_id, "protocol": protocol,
            "local_address": clean_ip(item.get("local_address")), "local_port": local_port,
            "remote_address": clean_ip(item.get("remote_address")), "remote_port": remote_port,
            "state": str(item.get("status") or "unknown")[:32], "pid": pid,
            "process_name": str(item.get("process_name") or "")[:255],
            "first_seen": stamp, "last_seen": stamp, "observations": 1,
        })

    processes = []
    alerts = []
    suspicious = ("mimikatz", "lazagne", "keylogger", "njrat", "darkcomet", "remcos",
                  "asyncrat", "nanocore", "quasar", "xworm", "meterpreter", "cobaltstrike")
    for item in (data.get("processes") or [])[:500]:
        if not isinstance(item, dict):
            continue
        try:
            pid = max(0, int(item.get("pid") or 0))
        except (TypeError, ValueError):
            continue
        name = str(item.get("name") or "unknown")[:255]
        executable = str(item.get("executable") or "")[:1000]
        started = clean_timestamp(item.get("started_at"))
        processes.append({
            "asset_id": asset_id, "pid": pid, "name": name, "executable": executable,
            "started_at": started, "first_seen": stamp, "last_seen": stamp,
            "signature_status": str(item.get("signature_status") or "unknown")[:32],
            "reputation": str(item.get("reputation") or "unknown")[:32],
            "sha256": str(item.get("sha256") or "")[:64] or None,
        })
        matched = [term for term in suspicious if term in (name + " " + executable).lower()]
        if matched:
            dedupe = "proc-review:" + asset_id + ":" + name.lower()
            alerts.append({
                "asset_id": asset_id, "rule_id": "PROC-REVIEW-001", "dedupe_key": dedupe,
                "title": "Processus nécessitant une vérification",
                "description": "Un nom ou chemin correspond à un indicateur à examiner. Ce signal ne confirme pas un malware ; vérifier la signature, le hash, la réputation et le contexte.",
                "severity": "medium", "confidence": 0.45, "status": "new", "category": "endpoint",
                "evidence": {"pid": pid, "name": name, "executable": executable, "matched_terms": matched},
                "first_seen": stamp, "last_seen": stamp, "occurrence_count": 1,
                "created_at": stamp, "updated_at": stamp,
            })

    software = []
    for item in (data.get("software") or [])[:1500]:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()[:255]
        if not name:
            continue
        version = str(item.get("version") or "")[:100]
        vendor = str(item.get("vendor") or "")[:255]
        location = str(item.get("install_location") or "")[:1000]
        fingerprint = hashlib.sha256("|".join((asset_id, name.lower(), version, vendor.lower(), location)).encode("utf-8")).hexdigest()
        installed = str(item.get("installed_at") or "").strip()
        if len(installed) == 10:
            installed = installed + "T00:00:00+00:00"
        software.append({
            "asset_id": asset_id, "name": name, "version": version, "vendor": vendor,
            "collected_at": stamp, "installed_at": clean_timestamp(installed),
            "install_location": location, "install_scope": str(item.get("install_scope") or "")[:40],
            "package_id": str(item.get("package_id") or "")[:255],
            "software_fingerprint": fingerprint, "last_seen": stamp,
        })

    protection = data.get("endpoint_protection") or {}
    protection_row = None
    if isinstance(protection, dict):
        provider = str(protection.get("provider") or "unknown")[:160]
        protection_row = {
            "asset_id": asset_id, "provider": provider,
            "product_version": str(protection.get("product_version") or "")[:160],
            "antivirus_enabled": protection.get("antivirus_enabled"),
            "antispyware_enabled": protection.get("antispyware_enabled"),
            "real_time_enabled": protection.get("real_time_enabled"),
            "behavior_monitoring_enabled": protection.get("behavior_monitoring_enabled"),
            "definitions_version": str(protection.get("definitions_version") or "")[:120],
            "definitions_updated_at": clean_timestamp(protection.get("definitions_updated_at")),
            "last_scan_at": clean_timestamp(protection.get("last_scan_at")),
            "last_scan_type": str(protection.get("last_scan_type") or "")[:40],
            "last_scan_status": str(protection.get("last_scan_status") or "unknown")[:40],
            "health_status": str(protection.get("health_status") or "unknown")[:40],
            "raw_details": {k: v for k, v in protection.items() if k not in {"detections"}},
            "observed_at": stamp,
        }

    detections = []
    for item in (protection.get("detections") if isinstance(protection, dict) else []) or []:
        if not isinstance(item, dict):
            continue
        threat_name = str(item.get("ThreatName") or item.get("threat_name") or "Unclassified detection")[:255]
        resources = item.get("Resources") or item.get("resources") or []
        if not isinstance(resources, list):
            resources = [str(resources)]
        file_path = str(resources[0] if resources else item.get("file_path") or "")[:1000]
        detected = clean_timestamp(item.get("InitialDetectionTime") or item.get("detected_at")) or stamp
        threat_id = str(item.get("ThreatID") or item.get("threat_id") or "")
        key_source = "|".join((asset_id, threat_id, threat_name, file_path, detected))
        dedupe_key = hashlib.sha256(key_source.encode("utf-8")).hexdigest()
        detections.append({
            "asset_id": asset_id, "detection_source": str(protection.get("provider") or "endpoint-antivirus")[:160],
            "threat_name": threat_name, "threat_type": "spyware" if any(x in threat_name.lower() for x in ("spy", "keylog", "steal")) else "malware",
            "severity": "high", "confidence": 0.85, "file_path": file_path,
            "sha256": None, "action_taken": "action_succeeded" if item.get("ActionSuccess") else "none",
            "status": "open", "detected_at": detected,
            "evidence": {"threat_id": threat_id, "resources": resources[:10], "raw": item},
            "dedupe_key": dedupe_key,
        })

    listeners = []
    service_names = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",
                     135:"MS-RPC",139:"NetBIOS",143:"IMAP",443:"HTTPS",445:"SMB",3389:"RDP",
                     5432:"PostgreSQL",3306:"MySQL",5985:"WinRM-HTTP",5986:"WinRM-HTTPS",
                     8080:"HTTP-Alt",8443:"HTTPS-Alt"}
    for item in (data.get("listening_ports") or [])[:1000]:
        if not isinstance(item, dict):
            continue
        address = clean_ip(item.get("ip_address"))
        try:
            port = int(item.get("port"))
        except (TypeError, ValueError):
            continue
        protocol = str(item.get("protocol") or "tcp").lower()
        if not address or not 1 <= port <= 65535 or protocol not in {"tcp", "udp"}:
            continue
        listeners.append({
            "asset_id": asset_id, "ip_address": address, "protocol": protocol, "port": port,
            "state": str(item.get("state") or "LISTEN")[:32],
            "service_name": str(item.get("service_name") or service_names.get(port, "unknown"))[:120],
            "product": str(item.get("product") or "")[:160], "version": str(item.get("version") or "")[:160],
            "confidence": 0.8, "source": "endpoint-listener-enumeration",
            "first_seen": stamp, "last_seen": stamp,
        })

    devices = []
    for item in (data.get("network_discoveries") or [])[:256]:
        if not isinstance(item, dict):
            continue
        address = clean_ip(item.get("ip_address"))
        cidr = str(item.get("cidr") or "")
        try:
            network_obj = validate_network(cidr)
            if not address or ipaddress.ip_address(address) not in network_obj:
                continue
        except ValueError:
            continue
        devices.append({
            "ip_address": address, "network_cidr": str(network_obj),
            "hostname": str(item.get("hostname") or "")[:255],
            "mac_address": str(item.get("mac_address") or "")[:64],
            "vendor": str(item.get("vendor") or "")[:160],
            "device_type": str(item.get("device_type") or "unknown")[:80],
            "os_guess": str(item.get("os_guess") or "")[:160],
            "status": "active", "discovery_method": "agent-icmp",
            "confidence": 0.65, "authorized_scope": True,
            "first_seen": stamp, "last_seen": stamp, "last_scan_at": stamp,
            "metadata": {"source_asset_id": asset_id},
        })

    try:
        if network:
            send_batches("soc_network_connections?on_conflict=asset_id,protocol,local_address,local_port,remote_address,remote_port,state,pid", network)
        if processes:
            send_batches("soc_process_observations?on_conflict=asset_id,pid,name,started_at", processes)
        if software:
            send_batches("software?on_conflict=asset_id,software_fingerprint", software)
        if protection_row:
            supabase_public_request("soc_endpoint_protection?on_conflict=asset_id,provider", "POST", protection_row)
        if detections:
            send_batches("soc_malware_detections?on_conflict=dedupe_key", detections)
        if listeners:
            send_batches("soc_listening_ports?on_conflict=ip_address,protocol,port", listeners)
        if devices:
            send_batches("soc_network_devices?on_conflict=network_cidr,ip_address", devices)
        if alerts:
            send_batches("soc_security_alerts?on_conflict=dedupe_key", alerts)
        return {"status": "ok", "network_connections": len(network), "processes": len(processes),
                "software": len(software), "listening_ports": len(listeners), "network_devices": len(devices),
                "antivirus_status": bool(protection_row), "malware_detections": len(detections),
                "indicative_alerts": len(alerts)}
    except Exception as exc:
        return {"status": "error", "stage": "endpoint-telemetry", "message": str(exc)[:500],
                "network_connections_prepared": len(network), "processes_prepared": len(processes),
                "software_prepared": len(software), "ports_prepared": len(listeners)}


@app.get("/")
def index(): return FileResponse("app/static/index.html")

@app.get("/config.js")
def public_web_config(): return FileResponse("app/static/config.js", media_type="application/javascript")
@app.get("/health")
@app.get("/api/health")
def health(): return {"status":"ok","service":"Congo Sec Vision API","version":"0.3.1","time":now()}

@app.get("/api/health/ready")
def readiness():
    database_ok = False
    last_sync = None
    try:
        with conn() as c:
            c.execute("SELECT 1")
            row = c.execute("SELECT value FROM system_settings WHERE key='last_cve_sync'").fetchone()
            last_sync = row["value"] if row else None
            database_ok = True
    except Exception:
        database_ok = False
    task = getattr(app.state, "cve_task", None)
    worker_running = bool(task is not None and not task.done())
    checks = {
        "database": "ok" if database_ok else "error",
        "supabase_soc_storage": "configured" if supabase_public_configured() else "missing_service_role_key",
        "cve_worker": "running" if worker_running else "not-running",
        "last_cve_sync_attempt": last_sync,
        "cve_sync_interval_minutes": max(
            5,
            int(os.getenv("CVE_SYNC_INTERVAL_MINUTES",
                          str(max(5, int(float(os.getenv("CVE_SYNC_INTERVAL_HOURS", "0.25")) * 60)))))
        ),
    }
    return {"status": "ready" if database_ok and worker_running else "degraded", "checks": checks}
@app.post("/api/auth/check")
def auth_check(authorization: str|None=Header(default=None)):
    require_read(authorization); return {"authenticated":True}
@app.post("/api/agents/enroll")
async def enroll(request:Request,background_tasks: BackgroundTasks,authorization:str|None=Header(default=None)):
    if not secrets.compare_digest(bearer(authorization) or "", ENROLL): raise HTTPException(403,"Enrollment not authorized")
    initial_data=await request.json()
    aid=asset_inventory(initial_data)
    supabase_sync=sync_asset_to_supabase(aid, initial_data)
    if supabase_sync.get("status")=="ok":
        supabase_sync=sync_endpoint_telemetry(aid, initial_data)
    token=secrets.token_urlsafe(36)
    with conn() as c:
        c.execute("INSERT INTO agent_tokens VALUES(?,?)",(hashlib.sha256(token.encode("utf-8")).hexdigest(),aid))
        c.execute("INSERT OR IGNORE INTO ai_agents(asset_id,name,status,created_at) VALUES(?,?,?,?)",
                  (aid,"CSVA-AI-"+aid[:8],"active",now()))
    background_tasks.add_task(run_internal_ai, aid)
    audit("agent.enroll", aid, "Nouvel agent enrôlé")
    return {"asset_id":aid,"agent_token":token,"ai_agent_assigned":True,"supabase_sync":supabase_sync}
@app.post("/api/agents/heartbeat")
async def heartbeat(request:Request,background_tasks: BackgroundTasks,authorization:str|None=Header(default=None)):
    aid=require_agent(authorization); data=await request.json(); asset_inventory(data,aid)
    supabase_sync=sync_asset_to_supabase(aid, data)
    with conn() as c:
        c.execute("INSERT OR IGNORE INTO ai_agents(asset_id,name,status,created_at) VALUES(?,?,?,?)",
                  (aid,"CSVA-AI-"+aid[:8],"active",now()))
        ai_row=c.execute("SELECT last_analysis_at FROM ai_agents WHERE asset_id=?",(aid,)).fetchone()
    last=ai_row["last_analysis_at"] if ai_row else None
    due=(not last) or (last < (datetime.now(timezone.utc)-timedelta(minutes=15)).isoformat())
    if due: background_tasks.add_task(run_internal_ai, aid)
    for entry in data.get("logs",[])[:250]:
        ingest_log(aid,entry)
    ingest_endpoint_telemetry(aid, data)
    if supabase_sync.get("status")=="ok":
        supabase_sync=sync_endpoint_telemetry(aid, data)
    return {"accepted":True,"asset_id":aid,"received_at":now(),"logs_received":min(len(data.get("logs",[])),250),"ai_analysis_scheduled":due,"supabase_sync":supabase_sync}

def ingest_endpoint_telemetry(asset_id, data):
    """Persist endpoint connection/process metadata received over the authenticated agent channel."""
    stamp=now()
    suspicious=("mimikatz","lazagne","keylogger","njrat","darkcomet","remcos",
                "asyncrat","nanocore","quasar","xworm","meterpreter","cobaltstrike")
    with conn() as c:
        for item in data.get("network_connections",[])[:500]:
            if not isinstance(item,dict): continue
            proto=str(item.get("protocol") or "unknown")[:8].lower()
            local_ip=str(item.get("local_address") or "")[:64]
            remote_ip=str(item.get("remote_address") or "")[:64]
            try:
                local_port=max(0,min(65535,int(item.get("local_port") or 0)))
                remote_port=max(0,min(65535,int(item.get("remote_port") or 0)))
                pid=max(0,int(item.get("pid") or 0))
            except (TypeError,ValueError): continue
            status=str(item.get("status") or "UNKNOWN")[:32]
            pname=str(item.get("process_name") or "")[:255]
            c.execute("""INSERT INTO network_connections(asset_id,protocol,local_address,local_port,
              remote_address,remote_port,status,pid,process_name,first_seen,last_seen,observations)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,1)
              ON CONFLICT(asset_id,protocol,local_address,local_port,remote_address,remote_port,status,pid)
              DO UPDATE SET last_seen=excluded.last_seen,process_name=excluded.process_name,
              observations=network_connections.observations+1""",
              (asset_id,proto,local_ip,local_port,remote_ip,remote_port,status,pid,pname,stamp,stamp))
        for item in data.get("processes",[])[:500]:
            if not isinstance(item,dict): continue
            try: pid=max(0,int(item.get("pid") or 0))
            except (TypeError,ValueError): continue
            name=str(item.get("name") or "unknown")[:255]
            exe=str(item.get("executable") or "")[:1000]
            started=str(item.get("started_at") or "")[:64]
            c.execute("""INSERT OR IGNORE INTO process_observations
              (asset_id,pid,name,executable,started_at,first_seen,last_seen) VALUES(?,?,?,?,?,?,?)""",
              (asset_id,pid,name,exe,started,stamp,stamp))
            inserted=c.rowcount
            if not inserted:
                c.execute("""UPDATE process_observations SET last_seen=?,executable=?
                  WHERE asset_id=? AND pid=? AND name=? AND started_at=?""",
                  (stamp,exe,asset_id,pid,name,started))
            elif any(term in (name+" "+exe).lower() for term in suspicious):
                c.execute("""INSERT INTO log_findings(asset_id,severity,rule_id,title,details,created_at)
                  VALUES(?,?,?,?,?,?)""",
                  (asset_id,"medium","PROC-REVIEW-001","Processus nécessitant une vérification",
                   "Un nom de processus correspond à un indicateur logiciel à examiner. Ce signal ne confirme pas un malware : vérifier le chemin, la signature, le hash et le contexte.",stamp))
                c.execute("""INSERT INTO events(asset_id,severity,category,message,created_at,raw)
                  VALUES(?,?,?,?,?,?)""",
                  (asset_id,"warning","process-review",f"Processus à examiner : {name} (PID {pid})",stamp,
                   json.dumps({"pid":pid,"name":name,"executable":exe})[:8000]))

def ingest_log(asset_id, entry):
    message=str(entry.get("message",""))[:4000]
    source=str(entry.get("source","endpoint"))[:100]
    severity=str(entry.get("severity","info")).lower()
    stamp=str(entry.get("timestamp") or now())
    with conn() as c:
        c.execute("INSERT INTO events(asset_id,severity,category,message,created_at,raw) VALUES(?,?,?,?,?,?)",
                  (asset_id,severity,"endpoint-log",message,stamp,json.dumps(entry)[:8000]))
    detect_log_patterns(asset_id,message,source)

def detect_log_patterns(asset_id,message,source):
    m=message.lower(); findings=[]
    # Windows Security auditing (actual Event IDs are retained in the source message).
    if "eventid=4625" in m or "failed password" in m or "authentication failure" in m or "invalid user" in m:
        findings.append(("medium","AUTH-001","Échec d'authentification","Échec de connexion observé ; corréler le compte, l'adresse source et la fréquence."))
    if "eventid=4740" in m:
        findings.append(("high","AUTH-002","Verrouillage de compte AD","Un compte a été verrouillé ; vérifier les postes sources et les tentatives répétées."))
    if any(x in m for x in ["eventid=4720","eventid=4728","eventid=4732","eventid=4756"]):
        findings.append(("high","AD-001","Modification sensible Active Directory","Création de compte ou ajout à un groupe ; confirmer l'auteur et le changement attendu."))
    if "eventid=1102" in m:
        findings.append(("critical","AUDIT-001","Journal d'audit Windows effacé","L'effacement du journal Security a été signalé ; préserver les preuves et investiguer."))
    if any(x in m for x in ["mimikatz","sekurlsa","credential dumping","lsass memory"]):
        findings.append(("critical","CRED-001","Indice possible de vol d'identifiants","Motif associé à l'accès aux identifiants détecté ; confirmer avec la télémétrie EDR."))
    if any(x in m for x in ["powershell -enc","encodedcommand","downloadstring("]):
        findings.append(("high","EXEC-001","Commande PowerShell encodée","Commande potentiellement suspecte ; examiner la ligne de commande et le processus parent."))
    if any(x in m for x in ["sudo:","user not in sudoers","privilege escalation"]):
        findings.append(("low","PRIV-001","Événement de privilège Linux","Événement relatif à sudo ou aux privilèges détecté."))
    with conn() as c:
        for sev,rid,title,details in findings:
            c.execute("INSERT INTO log_findings(asset_id,severity,rule_id,title,details,created_at) VALUES(?,?,?,?,?,?)",
                      (asset_id,sev,rid,title,details+" · source "+source,now()))

@app.get("/api/overview")
def overview(authorization:str|None=Header(default=None)):
    require_read(authorization); cutoff=(datetime.now(timezone.utc)-timedelta(minutes=3)).isoformat()
    with conn() as c:
        assets=c.execute("SELECT * FROM assets ORDER BY last_seen DESC").fetchall()
        events=c.execute("SELECT * FROM events ORDER BY id DESC LIMIT 8").fetchall()
        vulns=c.execute("SELECT * FROM vulnerabilities WHERE status IN ('open','needs-validation')").fetchall()
        findings=c.execute("SELECT COUNT(*) n FROM log_findings WHERE created_at >= ?",((datetime.now(timezone.utc)-timedelta(days=1)).isoformat(),)).fetchone()["n"]
    online=[a for a in assets if a["last_seen"]>=cutoff]
    return {"assets_total":len(assets),"assets_online":len(online),"assets_offline":len(assets)-len(online),
      "open_vulnerabilities":len(vulns),"critical_vulnerabilities":sum(v["severity"]=="critical" for v in vulns),
      "log_findings_24h":findings,"recent_events":[dict(e) for e in events],
      "assets":[asset_json(a,a["last_seen"]>=cutoff) for a in assets]}
@app.get("/api/assets")
def assets(authorization:str|None=Header(default=None)):
    require_read(authorization)
    with conn() as c: rows=c.execute("SELECT * FROM assets ORDER BY last_seen DESC").fetchall()
    cutoff=(datetime.now(timezone.utc)-timedelta(minutes=3)).isoformat()
    return [asset_json(a,a["last_seen"]>=cutoff) for a in rows]
@app.get("/api/events")
def events(authorization:str|None=Header(default=None)):
    require_read(authorization)
    with conn() as c: rows=c.execute("SELECT * FROM events ORDER BY id DESC LIMIT 200").fetchall()
    return [dict(r) for r in rows]

@app.get("/api/surveillance/telemetry")
def surveillance_telemetry(authorization:str|None=Header(default=None)):
    require_read(authorization)
    with conn() as c:
        connections=c.execute("""SELECT n.*,a.hostname FROM network_connections n
          LEFT JOIN assets a ON a.id=n.asset_id ORDER BY n.last_seen DESC LIMIT 500""").fetchall()
        processes=c.execute("""SELECT p.*,a.hostname FROM process_observations p
          LEFT JOIN assets a ON a.id=p.asset_id ORDER BY p.last_seen DESC LIMIT 500""").fetchall()
        software=c.execute("""SELECT s.*,a.hostname FROM software s
          LEFT JOIN assets a ON a.id=s.asset_id ORDER BY s.collected_at DESC,s.name LIMIT 1000""").fetchall()
        totals=c.execute("""SELECT COUNT(*) AS total,COUNT(DISTINCT asset_id) AS assets,
          SUM(CASE WHEN status='ESTABLISHED' THEN 1 ELSE 0 END) AS established
          FROM network_connections WHERE last_seen>=?""",
          ((datetime.now(timezone.utc)-timedelta(minutes=10)).isoformat(),)).fetchone()
    storage="sqlite-fallback"
    if supabase_public_configured():
        try:
            connections=supabase_public_request("soc_network_connections?select=*&order=last_seen.desc&limit=500","GET")
            processes=supabase_public_request("soc_process_observations?select=*&order=last_seen.desc&limit=500","GET")
            with conn() as c:
                hostnames={r["id"]:r["hostname"] for r in c.execute("SELECT id,hostname FROM assets").fetchall()}
            connections=[{**r,"hostname":hostnames.get(r.get("asset_id"),"")} for r in connections]
            processes=[{**r,"hostname":hostnames.get(r.get("asset_id"),"")} for r in processes]
            storage="supabase"
        except Exception as exc:
            raise HTTPException(503,"Lecture télémétrie Supabase impossible : "+str(exc)[:300]) from None
    return {"connections":[dict(x) for x in connections],"processes":[dict(x) for x in processes],
      "software":[dict(x) for x in software],
      "summary":{"connections_last_10m":int(totals["total"] or 0),
      "machines_observed":int(totals["assets"] or 0),"established_last_10m":int(totals["established"] or 0)},
      "collection":"endpoint connection metadata and process inventory",
      "storage":storage,"payload_capture":False,"timestamp":now()}
@app.get("/api/surveillance/alerts")
def surveillance_alerts(authorization:str|None=Header(default=None)):
    require_read(authorization)
    if not supabase_public_configured():
        raise HTTPException(503,"SUPABASE_SERVICE_ROLE_KEY doit être configurée côté API.")
    try:
        return supabase_public_request("soc_security_alerts?select=*&order=updated_at.desc&limit=500","GET")
    except Exception as exc:
        raise HTTPException(503,"Lecture des alertes Supabase impossible : "+str(exc)[:300]) from None

@app.get("/api/vulnerabilities")
def vulnerabilities(severity: str|None=None, vendor: str|None=None, product: str|None=None,
                    cwe: str|None=None, status: str|None=None, kev: bool|None=None,
                    min_cvss: float|None=None, min_epss: float|None=None, search: str|None=None,
                    authorization:str|None=Header(default=None)):
    require_read(authorization)
    clauses=[]; params=[]
    if severity: clauses.append("lower(severity)=?"); params.append(severity.lower())
    if vendor: clauses.append("lower(vendor) LIKE ?"); params.append("%"+vendor.lower()+"%")
    if product: clauses.append("lower(software_name) LIKE ?"); params.append("%"+product.lower()+"%")
    if cwe: clauses.append("cwe_ids LIKE ?"); params.append("%"+cwe.upper()+"%")
    if status: clauses.append("lower(status)=?"); params.append(status.lower())
    if kev is not None: clauses.append("known_exploited=?"); params.append(1 if kev else 0)
    if min_cvss is not None: clauses.append("cvss_score>=?"); params.append(min_cvss)
    if min_epss is not None: clauses.append("epss_score>=?"); params.append(min_epss)
    if search:
        clauses.append("(cve_id LIKE ? OR title LIKE ? OR software_name LIKE ? OR vendor LIKE ?)")
        params.extend(["%"+search+"%"]*4)
    sql="SELECT * FROM vulnerabilities"+(" WHERE "+" AND ".join(clauses) if clauses else "")+" ORDER BY known_exploited DESC, cvss_score DESC, created_at DESC LIMIT 2000"
    with conn() as c: rows=c.execute(sql,params).fetchall()
    result=[]
    for row in rows:
        item=dict(row)
        for field in ("cwe_ids","cpe_matches","references_json","sources_json","ssvc_json","affected_json","tags_json"):
            try: item[field.removesuffix("_json") if field.endswith("_json") else field]=json.loads(item.get(field) or "[]")
            except (TypeError,ValueError): item[field.removesuffix("_json") if field.endswith("_json") else field]=[]
        result.append(item)
    return result

@app.patch("/api/vulnerabilities/{vulnerability_id}")
async def update_vulnerability(vulnerability_id: int, request: Request, authorization:str|None=Header(default=None)):
    actor=require_analyst(authorization); data=await request.json()
    allowed={"open","needs-validation","under-analysis","risk-accepted","fixed","false-positive"}
    changes={}
    if "status" in data:
        status=str(data["status"]).lower()
        if status not in allowed: raise HTTPException(400,"Invalid vulnerability status")
        changes["status"]=status
    if "assigned_to" in data: changes["assigned_to"]=str(data["assigned_to"] or "")[:180]
    if "tags" in data:
        tags=data["tags"]
        if not isinstance(tags,list) or len(tags)>30: raise HTTPException(400,"tags must be an array of at most 30 items")
        changes["tags_json"]=json.dumps(sorted({str(x).strip()[:40] for x in tags if str(x).strip()}),ensure_ascii=False)
    if not changes: raise HTTPException(400,"No supported fields")
    with conn() as c:
        row=c.execute("SELECT cve_id FROM vulnerabilities WHERE id=?",(vulnerability_id,)).fetchone()
        if not row: raise HTTPException(404,"Vulnerability not found")
        c.execute("UPDATE vulnerabilities SET "+", ".join(k+"=?" for k in changes)+" WHERE id=?",
                  (*changes.values(),vulnerability_id))
        c.execute("INSERT INTO cve_history(vulnerability_id,cve_id,event_type,details,created_at) VALUES(?,?,?,?,?)",
                  (vulnerability_id,row["cve_id"],"analyst-update",json.dumps(changes,ensure_ascii=False),now()))
    audit("cve.update",vulnerability_id,json.dumps(changes,ensure_ascii=False),actor)
    return {"updated":True,"id":vulnerability_id}

@app.get("/api/cve/history")
def cve_history(cve_id: str|None=None, authorization:str|None=Header(default=None)):
    require_read(authorization)
    with conn() as c:
        if cve_id:
            rows=c.execute("SELECT * FROM cve_history WHERE cve_id=? ORDER BY id DESC LIMIT 500",(cve_id,)).fetchall()
        else:
            rows=c.execute("SELECT * FROM cve_history ORDER BY id DESC LIMIT 500").fetchall()
    return [dict(r) for r in rows]

@app.get("/api/cve/subscriptions")
def list_cve_subscriptions(authorization:str|None=Header(default=None)):
    require_read(authorization)
    with conn() as c: rows=c.execute("SELECT * FROM cve_subscriptions ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]

@app.post("/api/cve/subscriptions")
async def create_cve_subscription(request: Request, authorization:str|None=Header(default=None)):
    actor=require_analyst(authorization); data=await request.json()
    vendor=str(data.get("vendor") or "").strip()[:255]
    product=str(data.get("product") or "").strip()[:255]
    asset_id=str(data.get("asset_id") or "").strip()[:80]
    if not vendor and not product: raise HTTPException(400,"Vendor or product is required")
    try:
        with conn() as c:
            cur=c.execute("INSERT INTO cve_subscriptions(vendor,product,asset_id,created_by,created_at) VALUES(?,?,?,?,?)",
                          (vendor,product,asset_id,actor,now()))
    except sqlite3.IntegrityError:
        raise HTTPException(409,"Subscription already exists")
    audit("cve.subscription.create",cur.lastrowid,vendor+" "+product,actor)
    return {"id":cur.lastrowid,"created":True}

@app.delete("/api/cve/subscriptions/{subscription_id}")
def delete_cve_subscription(subscription_id:int, authorization:str|None=Header(default=None)):
    actor=require_analyst(authorization)
    with conn() as c:
        cur=c.execute("DELETE FROM cve_subscriptions WHERE id=?",(subscription_id,))
    if not cur.rowcount: raise HTTPException(404,"Subscription not found")
    audit("cve.subscription.delete",subscription_id,"",actor)
    return {"deleted":True}

@app.get("/api/cve/notifications")
def list_cve_notifications(unread_only: bool=False, authorization:str|None=Header(default=None)):
    require_read(authorization)
    sql="SELECT * FROM cve_notifications"+(" WHERE read_at IS NULL" if unread_only else "")+" ORDER BY id DESC LIMIT 500"
    with conn() as c: rows=c.execute(sql).fetchall()
    return [dict(r) for r in rows]

@app.patch("/api/cve/notifications/{notification_id}")
def mark_cve_notification_read(notification_id:int, authorization:str|None=Header(default=None)):
    actor=require_read(authorization)
    with conn() as c:
        cur=c.execute("UPDATE cve_notifications SET read_at=? WHERE id=?",(now(),notification_id))
    if not cur.rowcount: raise HTTPException(404,"Notification not found")
    audit("cve.notification.read",notification_id,"",actor)
    return {"read":True}
@app.get("/api/software")
def software(authorization:str|None=Header(default=None)):
    require_read(authorization)
    with conn() as c:
        rows=c.execute("SELECT s.*,a.hostname FROM software s LEFT JOIN assets a ON a.id=s.asset_id ORDER BY s.name").fetchall()
    return [dict(r) for r in rows]

def _run_cve_sync_locked(limit=25):
    with conn() as c:
        settings=c.execute("SELECT value FROM system_settings WHERE key='cve_scan_offset'").fetchone()
        offset=int(settings['value']) if settings else 0
        products=c.execute("SELECT DISTINCT name,version,vendor,asset_id FROM software WHERE name!='' ORDER BY name LIMIT ? OFFSET ?",(max(1,min(int(limit),100)),offset)).fetchall()
    checked=0; added=0; refreshed=0; matched=0; errors=[]
    for idx,p in enumerate(products):
        if idx:
            configured_interval=os.getenv("CVE_SYNC_PRODUCT_INTERVAL_SECONDS", "").strip()
            default_interval="0.7" if NVD_API_KEY else "6.1"
            time.sleep(max(0.0,float(configured_interval or default_interval)))
        try:
            records=scan_product(p['name'],p['version'],p['vendor'],NVD_API_KEY)
            checked+=1
            for v in records:
                with conn() as c:
                    old=c.execute('SELECT * FROM vulnerabilities WHERE asset_id=? AND cve_id=?',(p['asset_id'],v['cve_id'])).fetchone()
                    stamp=now()
                    values=(v['severity'],v['title'],p['name'],p['version'],p['vendor'],v['match_confidence'],v['cve_url'],
                      v.get('cvss_score'),v.get('cvss_version',''),v.get('cvss_vector',''),
                      json.dumps(v.get('cwe_ids',[])),json.dumps(v.get('cpe_matches',[])),
                      json.dumps(v.get('references',[])),v.get('epss_score'),v.get('epss_percentile'),
                      1 if v.get('known_exploited') else 0,v.get('published',''),v.get('last_modified',''),
                      v.get('vuln_status',''),json.dumps(v.get('sources',[])),
                      json.dumps(v.get('ssvc',[])),json.dumps(v.get('affected',[])))
                    if old:
                        c.execute("""UPDATE vulnerabilities SET severity=?,title=?,software_name=?,software_version=?,vendor=?,
                          match_confidence=?,cve_url=?,cvss_score=?,cvss_version=?,cvss_vector=?,cwe_ids=?,cpe_matches=?,
                          references_json=?,epss_score=?,epss_percentile=?,known_exploited=?,published_at=?,last_modified_at=?,
                          vuln_status=?,sources_json=?,ssvc_json=?,affected_json=? WHERE id=?""",values+(old['id'],)); refreshed+=1
                        changed = (
                          old['severity'] != v['severity'] or old['title'] != v['title'] or
                          old['match_confidence'] != v['match_confidence'] or
                          old['cvss_score'] != v.get('cvss_score') or
                          old['epss_score'] != v.get('epss_score') or
                          bool(old['known_exploited']) != bool(v.get('known_exploited')) or
                          old['ssvc_json'] != json.dumps(v.get('ssvc',[])) or
                          old['affected_json'] != json.dumps(v.get('affected',[]))
                        )
                        if changed:
                            c.execute("INSERT INTO cve_history(vulnerability_id,cve_id,event_type,details,created_at) VALUES(?,?,?,?,?)",
                              (old['id'],v['cve_id'],'source-change',json.dumps({'cvss_score':v.get('cvss_score'),'epss_score':v.get('epss_score'),'known_exploited':v.get('known_exploited')}),stamp))
                    else:
                        cur=c.execute("""INSERT INTO vulnerabilities(asset_id,cve_id,severity,title,status,source,created_at,
                          software_name,software_version,vendor,match_confidence,cve_url,cvss_score,cvss_version,cvss_vector,
                          cwe_ids,cpe_matches,references_json,epss_score,epss_percentile,known_exploited,published_at,
                          last_modified_at,vuln_status,sources_json,ssvc_json,affected_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                          (p['asset_id'],v['cve_id'],v['severity'],v['title'],'needs-validation','NVD CVE API',stamp,
                           p['name'],p['version'],p['vendor'],v['match_confidence'],v['cve_url'],*values[7:]))
                        c.execute("INSERT INTO cve_history(vulnerability_id,cve_id,event_type,details,created_at) VALUES(?,?,?,?,?)",
                          (cur.lastrowid,v['cve_id'],'first-seen',json.dumps({'match_confidence':v['match_confidence'],'cvss_score':v.get('cvss_score')}),stamp))
                        subscriptions=c.execute("""SELECT * FROM cve_subscriptions WHERE active=1
                          AND (vendor='' OR lower(?) LIKE '%'||lower(vendor)||'%' OR lower(vendor) LIKE '%'||lower(?)||'%')
                          AND (product='' OR lower(?) LIKE '%'||lower(product)||'%' OR lower(product) LIKE '%'||lower(?)||'%')
                          AND (asset_id='' OR asset_id=?)""",
                          (p['vendor'] or '',p['vendor'] or '',p['name'] or '',p['name'] or '',p['asset_id'] or '')).fetchall()
                        for sub in subscriptions:
                            c.execute("""INSERT OR IGNORE INTO cve_notifications(subscription_id,vulnerability_id,cve_id,event_type,title,severity,created_at)
                              VALUES(?,?,?,?,?,?,?)""",
                              (sub['id'],cur.lastrowid,v['cve_id'],'new-cve',v['title'][:500],v['severity'],stamp))
                        added+=1
                if v['match_confidence']=='version-range-match': matched+=1
        except Exception as exc: errors.append({'software':p['name'],'error':str(exc)[:220]})
    with conn() as c:
        total=c.execute("SELECT COUNT(*) n FROM (SELECT DISTINCT name,version,vendor,asset_id FROM software WHERE name!='')").fetchone()['n']
        next_offset=0 if offset+len(products)>=total else offset+len(products)
        c.execute("INSERT INTO system_settings(key,value,updated_at) VALUES('cve_scan_offset',?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",(str(next_offset),now()))
        c.execute("INSERT INTO system_settings(key,value,updated_at) VALUES('last_cve_sync',?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",(now(),now()))
    return {'software_checked':checked,'software_total':total,'candidate_records_added':added,'records_refreshed':refreshed,
      'version_range_matches':matched,'errors':errors,'last_sync':now(),
      'warning':'Une correspondance CPE/version reste un candidat à valider, pas une preuve d’exposition. Vérifier l’édition, les correctifs rétroportés et l’avis éditeur.'}

_CVE_SYNC_LOCK = threading.Lock()

def run_cve_sync(limit=25):
    """Prevent API-triggered and scheduled scans from racing over the same cursor."""
    if not _CVE_SYNC_LOCK.acquire(blocking=False):
        return {"busy": True, "message": "Une synchronisation CVE est déjà en cours."}
    try:
        return _run_cve_sync_locked(limit)
    finally:
        _CVE_SYNC_LOCK.release()

@app.post('/api/cve/sync')
def cve_sync(authorization:str|None=Header(default=None)):
    require_analyst(authorization)
    result=run_cve_sync(int(os.getenv('CVE_SYNC_BATCH_SIZE','25')))
    if result.get("busy"):
        raise HTTPException(409, result["message"])
    audit('cve.sync','NVD',json.dumps({k:result[k] for k in ('software_checked','candidate_records_added','records_refreshed','version_range_matches')}))
    return result

async def periodic_cve_worker():
    legacy_minutes = max(5, int(float(os.getenv("CVE_SYNC_INTERVAL_HOURS", "0.25")) * 60))
    interval_minutes = max(5, int(os.getenv("CVE_SYNC_INTERVAL_MINUTES", str(legacy_minutes))))
    interval = interval_minutes * 60
    await asyncio.sleep(30)
    while True:
        try: await asyncio.to_thread(run_cve_sync,int(os.getenv('CVE_SYNC_BATCH_SIZE','25')))
        except Exception as exc: audit('cve.sync.error','NVD',str(exc)[:500])
        await asyncio.sleep(interval)

@app.on_event('startup')
async def start_periodic_cve_worker(): app.state.cve_task=asyncio.create_task(periodic_cve_worker())

@app.on_event('shutdown')
async def stop_periodic_cve_worker():
    task=getattr(app.state,'cve_task',None)
    if task:
        task.cancel()
        try: await task
        except asyncio.CancelledError: pass

@app.post("/api/network/discovery")
async def run_network_discovery(request: Request, authorization: str | None = Header(default=None)):
    actor = require_analyst(authorization)
    data = await request.json()
    cidr = str(data.get("cidr", "")).strip()
    try:
        network = validate_network(cidr)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    try:
        results = await asyncio.to_thread(discover_network, str(network))
    except RuntimeError as exc:
        raise HTTPException(503, str(exc)) from None
    stamp = now()
    with conn() as db:
        for item in results:
            db.execute("""INSERT INTO network_discoveries(cidr,ip_address,hostname,status,source,first_seen,last_seen)
              VALUES(?,?,?,?,?,?,?) ON CONFLICT(cidr,ip_address) DO UPDATE SET
              hostname=excluded.hostname,status=excluded.status,source=excluded.source,last_seen=excluded.last_seen""",
              (str(network), item["ip_address"], item.get("hostname", ""), "reachable", "manual-icmp", stamp, stamp))
    audit("network.discovery", str(network), json.dumps({"hosts_reachable": len(results)}), actor)
    return {
        "cidr": str(network),
        "hosts_scanned": len(list(network.hosts())),
        "hosts_reachable": len(results),
        "hosts": results,
        "limitation": "Découverte ICMP ponctuelle uniquement. Les hôtes qui bloquent le ping peuvent être absents. Aucun agent n'est installé et aucun équipement n'est enrôlé automatiquement.",
    }


@app.get("/api/network/discovery")
def list_network_discoveries(authorization: str | None = Header(default=None)):
    require_read(authorization)
    with conn() as db:
        rows = db.execute("SELECT * FROM network_discoveries ORDER BY last_seen DESC LIMIT 1000").fetchall()
    return [dict(row) for row in rows]


@app.get("/api/topology")
def topology(authorization:str|None=Header(default=None)):
    require_read(authorization)
    with conn() as c: rows=c.execute("SELECT * FROM assets").fetchall()
    nodes=[]; edges=[]; networks={}
    for a in rows:
        inv=json.loads(a["inventory"]); nodes.append({"id":a["id"],"label":a["hostname"],"kind":"asset","platform":a["platform"]})
        for iface in inv.get("interfaces",[]):
            addr=iface.get("address"); mask=iface.get("netmask")
            if not addr or not mask: continue
            try:
                net=str(ipaddress.ip_interface(f"{addr}/{mask}").network)
                networks.setdefault(net,[]).append(a["id"])
            except ValueError: pass
    for net,ids in networks.items():
        if len(ids)>1:
            for i in range(len(ids)-1): edges.append({"source":ids[i],"target":ids[i+1],"label":net,"type":"shared-subnet"})
    return {"nodes":nodes,"edges":edges,"method":"agent interface/subnet correlation","limitation":"Not a packet-level discovery or switch/router topology. Add SNMP, NetFlow or authorized network sensors for physical/logical links."}

@app.get("/api/ai/findings")
def ai_findings(authorization:str|None=Header(default=None)):
    require_read(authorization)
    with conn() as c: rows=c.execute("SELECT * FROM log_findings ORDER BY id DESC LIMIT 250").fetchall()
    return [dict(r) for r in rows]
@app.post("/api/ai/analyze")
def ai_analyze(authorization:str|None=Header(default=None)):
    require_analyst(authorization)
    with conn() as c:
        findings=c.execute("SELECT * FROM log_findings ORDER BY id DESC LIMIT 100").fetchall()
        events=c.execute("SELECT e.*,a.hostname FROM events e LEFT JOIN assets a ON a.id=e.asset_id WHERE e.category='endpoint-log' ORDER BY e.id DESC LIMIT 150").fetchall()
        assets=c.execute("SELECT hostname,platform,last_seen FROM assets ORDER BY last_seen DESC").fetchall()
    counts={k:sum(r["severity"]==k for r in findings) for k in ("critical","high","medium","low")}
    local={"findings":len(findings),**counts,"events_reviewed":len(events),"assets_reporting":len(assets),
      "evidence_window":"150 derniers événements endpoint et 100 derniers constats persistés",
      "recommendation":"Prioriser les constats critiques/élevés, vérifier les événements source sur les hôtes concernés et confirmer toute activité avec les journaux natifs. Une règle locale est un signal à investiguer, pas une preuve de compromission."}
    evidence=[{"hostname":r["hostname"],"severity":r["severity"],"category":r["category"],"message":r["message"],"created_at":r["created_at"]} for r in events[:60]]
    if not (LLM_BASE_URL and LLM_MODEL):
        return {"mode":"local-rules","result":local,"evidence":evidence[:20],"message":"Analyse locale active. Pour activer l'analyse IA avancée, configure LLM_BASE_URL, LLM_MODEL et la clé API du fournisseur dans .env, puis redémarre le service."}
    prompt=("Tu es analyste SOC. Analyse uniquement les éléments fournis. N'invente aucun fait, distingue signal et preuve, indique les limites des journaux, regroupe les événements par hôte, classe les priorités et propose des vérifications défensives non destructives. Réponds en français avec Résumé, Observations sourcées, Hypothèses à vérifier, Actions recommandées.\nDONNEES="+json.dumps({"findings":[dict(r) for r in findings[:60]],"events":evidence},ensure_ascii=False))
    payload=json.dumps({"model":LLM_MODEL,"messages":[{"role":"user","content":prompt}],"temperature":0.1}).encode()
    headers={"Content-Type":"application/json"}
    if LLM_API_KEY: headers["Authorization"]="Bearer "+LLM_API_KEY
    req=urllib.request.Request(LLM_BASE_URL+"/chat/completions",data=payload,headers=headers,method="POST")
    try:
        with urllib.request.urlopen(req,timeout=60) as resp: out=json.loads(resp.read())
        return {"mode":"llm","result":out.get("choices",[{}])[0].get("message",{}).get("content",""),"local_summary":local,"evidence_count":len(evidence)}
    except Exception as e:
        return {"mode":"local-rules","result":local,"evidence":evidence[:20],"llm_error":str(e)[:250]}

@app.post("/api/diagnostics/inventory")
def inventory_diagnostic(authorization:str|None=Header(default=None)):
    require_analyst(authorization)
    with conn() as c:
        rows=c.execute("SELECT * FROM assets").fetchall()
        for a in rows:
            inv=json.loads(a["inventory"])
            for key,label in [("disk_percent","Disk usage >= 90%"),("memory_percent","Memory usage >= 90%")]:
                if isinstance(inv.get(key),(int,float)) and inv[key]>=90:
                    c.execute("INSERT INTO events(asset_id,severity,category,message,created_at) VALUES(?,?,?,?,?)",
                              (a["id"],"warning","diagnostic",label,now()))
    return {"checked_assets":len(rows),"message":"Inventory checks completed from endpoint telemetry."}
@app.post("/api/events")
async def create_event(request:Request,authorization:str|None=Header(default=None)):
    require_analyst(authorization); d=await request.json()
    with conn() as c:
        c.execute("INSERT INTO events(asset_id,severity,category,message,created_at) VALUES(?,?,?,?,?)",
                  (d.get("asset_id"),d.get("severity","info"),d.get("category","manual"),d.get("message",""),now()))
    audit("event.create", d.get("asset_id",""), d.get("message",""))
    return {"created":True}
@app.get("/api/config")
def config(authorization: str | None = Header(default=None)):
    require_read(authorization)
    return {"product":"Congo Sec Vision","version":"0.4.0","mode":"laboratory","cve_provider":"NVD + OpenCVE","cve_automatic_sync":True,"nvd_api_key_configured":bool(NVD_API_KEY),"opencve_configured":bool(OPENCVE_API_TOKEN),"cve_sync_interval_hours":int(os.getenv("CVE_SYNC_INTERVAL_HOURS","1")),"cve_sync_interval_minutes":max(5,int(os.getenv("CVE_SYNC_INTERVAL_MINUTES",str(max(5,int(float(os.getenv("CVE_SYNC_INTERVAL_HOURS","0.25"))*60)))))),"llm_configured":bool(LLM_BASE_URL and LLM_MODEL),"llm_model":LLM_MODEL or None,"ai_mode":"LLM configured" if LLM_BASE_URL and LLM_MODEL else "local-rules"}


# --- SOC Enterprise modules: incident lifecycle, audit, team, approvals, exports ---
@app.get("/api/incidents")
def list_incidents(authorization: str|None=Header(default=None)):
    require_read(authorization)
    with conn() as c: rows=c.execute("SELECT * FROM incidents ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, updated_at DESC").fetchall()
    return [dict(r) for r in rows]

@app.post("/api/incidents")
async def create_incident(request: Request, authorization: str|None=Header(default=None)):
    require_incident_responder(authorization); d=await request.json()
    title=str(d.get("title","")).strip()
    if not title: raise HTTPException(400,"Incident title required")
    severity=str(d.get("severity","medium")).lower()
    if severity not in ("critical","high","medium","low"): raise HTTPException(400,"Invalid severity")
    stamp=now()
    with conn() as c:
        cur=c.execute("INSERT INTO incidents(title,description,severity,status,assignee,source,asset_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
          (title,str(d.get("description",""))[:5000],severity,"open",str(d.get("assignee",""))[:120],
           str(d.get("source","manual"))[:120],d.get("asset_id"),stamp,stamp))
        iid=cur.lastrowid
    audit("incident.create",iid,title)
    return {"id":iid,"created":True}

@app.patch("/api/incidents/{incident_id}")
async def update_incident(incident_id:int, request:Request, authorization: str|None=Header(default=None)):
    require_incident_responder(authorization); d=await request.json()
    allowed={"status","severity","assignee","description","title"}
    changes={k:v for k,v in d.items() if k in allowed}
    if not changes: raise HTTPException(400,"No supported fields")
    if "status" in changes and changes["status"] not in ("open","investigating","contained","resolved","closed"): raise HTTPException(400,"Invalid status")
    if "severity" in changes and changes["severity"] not in ("critical","high","medium","low"): raise HTTPException(400,"Invalid severity")
    changes["updated_at"]=now()
    if changes.get("status") in ("resolved","closed"): changes["closed_at"]=now()
    sql=", ".join(f"{k}=?" for k in changes)
    with conn() as c:
        cur=c.execute(f"UPDATE incidents SET {sql} WHERE id=?",(*changes.values(),incident_id))
        if not cur.rowcount: raise HTTPException(404,"Incident not found")
    audit("incident.update",incident_id,json.dumps(changes,ensure_ascii=False))
    return {"updated":True,"id":incident_id}

@app.post("/api/incidents/from-findings")
def incidents_from_findings(authorization: str|None=Header(default=None)):
    require_incident_responder(authorization); created=0
    with conn() as c:
        rows=c.execute("""SELECT f.* FROM log_findings f WHERE NOT EXISTS
          (SELECT 1 FROM incidents i WHERE i.source='finding:'||f.id) ORDER BY f.id DESC LIMIT 100""").fetchall()
        for f in rows:
            c.execute("INSERT INTO incidents(title,description,severity,status,source,asset_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
              (f["title"],f["details"],f["severity"],"open","finding:"+str(f["id"]),f["asset_id"],now(),now()))
            created+=1
    if created: audit("incident.correlate", "log_findings", f"{created} incidents créés")
    return {"created":created}

@app.get("/api/audit")
def get_audit(authorization: str|None=Header(default=None)):
    require_admin(authorization)
    with conn() as c: rows=c.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 500").fetchall()
    return [dict(r) for r in rows]

@app.get("/api/team")
def get_team(authorization: str|None=Header(default=None)):
    require_admin(authorization)
    with conn() as c: rows=c.execute("SELECT id,username,display_name,role,active,created_at FROM team_members ORDER BY id").fetchall()
    return [dict(r) for r in rows]

@app.post("/api/team")
async def add_team_member(request:Request, authorization: str|None=Header(default=None)):
    require_admin(authorization); d=await request.json()
    username=str(d.get("username","")).strip().lower(); display=str(d.get("display_name","")).strip()
    role=str(d.get("role","analyst"))
    if not username or not display: raise HTTPException(400,"Username and display name required")
    if role not in ("admin","analyst","viewer","incident_responder"): raise HTTPException(400,"Invalid role")
    try:
        with conn() as c: cur=c.execute("INSERT INTO team_members(username,display_name,role,created_at) VALUES(?,?,?,?)",(username,display,role,now()))
    except sqlite3.IntegrityError: raise HTTPException(409,"Username already exists")
    audit("team.member.create",username,role)
    return {"id":cur.lastrowid,"created":True}

@app.get("/api/approvals")
def get_approvals(authorization: str|None=Header(default=None)):
    require_incident_responder(authorization)
    with conn() as c: rows=c.execute("SELECT * FROM approvals ORDER BY id DESC LIMIT 300").fetchall()
    return [dict(r) for r in rows]

@app.post("/api/approvals")
async def create_approval(request:Request, authorization: str|None=Header(default=None)):
    require_incident_responder(authorization); d=await request.json()
    title=str(d.get("title","")).strip(); description=str(d.get("description","")).strip()
    if not title or not description: raise HTTPException(400,"Title and description required")
    with conn() as c:
        cur=c.execute("INSERT INTO approvals(title,description,target,action_type,status,requested_by,created_at) VALUES(?,?,?,?,?,?,?)",
          (title,description[:4000],str(d.get("target",""))[:255],str(d.get("action_type","manual"))[:80],"pending","admin",now()))
    audit("approval.request",cur.lastrowid,title)
    return {"id":cur.lastrowid,"status":"pending"}

@app.post("/api/approvals/{approval_id}/review")
async def review_approval(approval_id:int, request:Request, authorization: str|None=Header(default=None)):
    require_admin(authorization); d=await request.json(); decision=d.get("decision")
    if decision not in ("approved","rejected"): raise HTTPException(400,"Decision must be approved or rejected")
    with conn() as c:
        cur=c.execute("UPDATE approvals SET status=?,reviewed_by='admin',reviewed_at=? WHERE id=? AND status='pending'",
                      (decision,now(),approval_id))
        if not cur.rowcount: raise HTTPException(404,"Pending approval not found")
    audit("approval."+decision,approval_id,str(d.get("comment","")))
    return {"reviewed":True,"status":decision,"execution":"not-run"}

@app.get("/api/reports/export.csv")
def export_csv(authorization: str|None=Header(default=None)):
    require_analyst(authorization)
    import csv, io
    with conn() as c: rows=c.execute("SELECT hostname,platform,ip_addresses,first_seen,last_seen FROM assets ORDER BY hostname").fetchall()
    buf=io.StringIO(); writer=csv.writer(buf); writer.writerow(["hostname","platform","ip_addresses","first_seen","last_seen"])
    for r in rows: writer.writerow([r["hostname"],r["platform"],r["ip_addresses"],r["first_seen"],r["last_seen"]])
    audit("report.export.csv","assets",f"{len(rows)} actifs exportés")
    from fastapi.responses import Response
    return Response(buf.getvalue(),media_type="text/csv; charset=utf-8",headers={"Content-Disposition":"attachment; filename=congo-sec-vision-assets.csv"})

@app.get("/api/workflows")
def get_workflows(authorization: str|None=Header(default=None)):
    require_admin(authorization)
    with conn() as c: rows=c.execute("SELECT * FROM workflows ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]

@app.post("/api/workflows")
async def create_workflow(request:Request, authorization: str|None=Header(default=None)):
    require_admin(authorization); d=await request.json()
    name=str(d.get("name","")).strip()
    if not name: raise HTTPException(400,"Workflow name required")
    with conn() as c:
        cur=c.execute("INSERT INTO workflows(name,description,trigger_type,enabled,requires_approval,created_at) VALUES(?,?,?,?,?,?)",
          (name,str(d.get("description",""))[:2000],str(d.get("trigger_type","manual")),0,1,now()))
    audit("workflow.create",cur.lastrowid,name)
    return {"id":cur.lastrowid,"enabled":False,"requires_approval":True}


@app.get("/api/ai/agents")
def list_ai_agents(authorization: str|None=Header(default=None)):
    require_read(authorization)
    with conn() as c:
        rows=c.execute("""SELECT g.*,a.hostname,a.platform,a.last_seen
          FROM ai_agents g JOIN assets a ON a.id=g.asset_id ORDER BY a.hostname""").fetchall()
    return [dict(r) for r in rows]

@app.post("/api/ai/agents/{asset_id}/analyze")
def analyze_asset_ai(asset_id: str, authorization: str|None=Header(default=None)):
    require_analyst(authorization)
    with conn() as c:
        asset=c.execute("SELECT * FROM assets WHERE id=?",(asset_id,)).fetchone()
        if not asset: raise HTTPException(404,"Asset not found")
        c.execute("INSERT OR IGNORE INTO ai_agents(asset_id,name,status,created_at) VALUES(?,?,?,?)",
                  (asset_id,"CSVA-AI-"+asset_id[:8],"active",now()))
        raw_events=c.execute("SELECT * FROM events WHERE asset_id=? ORDER BY created_at DESC LIMIT 500",(asset_id,)).fetchall()
        software_rows=c.execute("SELECT name,version,vendor FROM software WHERE asset_id=? ORDER BY name",(asset_id,)).fetchall()
        vuln_rows=c.execute("SELECT * FROM vulnerabilities WHERE asset_id=? ORDER BY created_at DESC LIMIT 100",(asset_id,)).fetchall()
    log_inputs=[{"message":e["message"],"source":e["category"] or "endpoint","created_at":e["created_at"]} for e in raw_events]
    report=analyze_logs(log_inputs)
    cve_advice=[{"cve_id":v["cve_id"],"severity":v["severity"],"title":v["title"],
       "software_name":v["software_name"],"software_version":v["software_version"],"vendor":v["vendor"],
       "match_confidence":v["match_confidence"],"cve_url":v["cve_url"],
       **cve_remediation_advice(v["cve_id"],v["severity"],v.get("software_name",""),v.get("software_version",""),v["title"])} for v in vuln_rows]
    llm_result=None
    if LLM_BASE_URL and LLM_MODEL and (log_inputs or software_rows or vuln_rows):
        prompt=("Tu es un analyste SOC défensif. Analyse exclusivement les preuves fournies. N'invente pas de CVE, "
          "de version corrigée ou de compromission. Distingue faits et hypothèses. Propose des mesures non destructives. "
          "Réponds en français. Données: "+json.dumps({"host":asset["hostname"],"log_report":report,
          "software":[dict(x) for x in software_rows[:100]],"cve_candidates":cve_advice[:30]},ensure_ascii=False)[:24000])
        payload=json.dumps({"model":LLM_MODEL,"messages":[{"role":"user","content":prompt}],"temperature":0.1}).encode()
        headers={"Content-Type":"application/json"}
        if LLM_API_KEY: headers["Authorization"]="Bearer "+LLM_API_KEY
        req=urllib.request.Request(LLM_BASE_URL+"/chat/completions",data=payload,headers=headers,method="POST")
        try:
            with urllib.request.urlopen(req,timeout=45) as response:
                llm_result=json.loads(response.read()).get("choices",[{}])[0].get("message",{}).get("content")
        except Exception as exc: llm_result={"status":"fallback","reason":str(exc)[:180]}
    summary={"host":asset["hostname"],"platform":asset["platform"],"logs":report,
      "software_inventory_count":len(software_rows),"software_inventory":[dict(x) for x in software_rows],
      "timeline":sorted([{"timestamp":e["created_at"],"source":e["category"],"severity":e["severity"],"message":e["message"]} for e in raw_events],key=lambda x:x["timestamp"] or ""),
      "cve_candidates_count":len(vuln_rows),
      "cve_remediation_advice":cve_advice,"llm_analysis":llm_result,
      "mode":"llm+rules" if llm_result else "local-rules",
      "warning":"Les CVE issues d'une recherche par nom restent des candidates. Confirmer CPE, version affectée et avis éditeur."}
    stamp=now()
    with conn() as c:
        cur=c.execute("INSERT INTO ai_reports(asset_id,report_type,summary,findings_json,events_reviewed,created_at) VALUES(?,?,?,?,?,?)",
          (asset_id,"endpoint-analysis",json.dumps(summary,ensure_ascii=False),json.dumps(report["findings"],ensure_ascii=False),len(log_inputs),stamp))
        report_id=cur.lastrowid
        c.execute("UPDATE ai_agents SET last_analysis_at=?,last_report_id=?,status='active' WHERE asset_id=?",
                  (stamp,report_id,asset_id))
    audit("ai.asset.analyze",asset_id,f"report={report_id}; logs={len(log_inputs)}")
    return {"report_id":report_id,**summary}

@app.get("/api/ai/agents/{asset_id}/reports")
def list_asset_ai_reports(asset_id: str, authorization: str|None=Header(default=None)):
    require_read(authorization)
    with conn() as c:
        rows=c.execute("SELECT id,report_type,summary,events_reviewed,created_at FROM ai_reports WHERE asset_id=? ORDER BY id DESC LIMIT 30",(asset_id,)).fetchall()
    return [dict(x) for x in rows]

@app.get("/api/reports/logs")
def logs_report(authorization: str|None=Header(default=None)):
    require_read(authorization)
    with conn() as c:
        assets=c.execute("SELECT id,hostname,platform,last_seen FROM assets ORDER BY hostname").fetchall()
        events=c.execute("""SELECT e.*,a.hostname FROM events e LEFT JOIN assets a ON a.id=e.asset_id
          WHERE e.category='endpoint-log' OR e.category='endpoint' ORDER BY e.created_at DESC LIMIT 1000""").fetchall()
        findings=c.execute("SELECT f.*,a.hostname FROM log_findings f LEFT JOIN assets a ON a.id=f.asset_id ORDER BY f.created_at DESC LIMIT 500").fetchall()
    return {"generated_at":now(),"machines_total":len(assets),"machines":[dict(a) for a in assets],
      "events_reviewed":len(events),"events":[dict(e) for e in events[:250]],
      "findings_total":len(findings),"findings":[dict(f) for f in findings[:250]],
      "summary":{"critical":sum(f["severity"]=="critical" for f in findings),"high":sum(f["severity"]=="high" for f in findings),
        "medium":sum(f["severity"]=="medium" for f in findings),"low":sum(f["severity"]=="low" for f in findings)},
      "limitations":["Rapport limité aux journaux remontés par les agents et conservés dans la base.",
        "Les alertes sont des signaux à vérifier, pas une preuve automatique d'incident."]}


def supabase_soc_request(resource, method, authorization, payload=None):
    """Call the existing Supabase Data API as the signed-in user (never service_role)."""
    token = bearer(authorization)
    if not token:
        raise HTTPException(401, "Supabase session required")
    url = SUPABASE_URL + "/rest/v1/" + resource
    headers = {
        "apikey": SUPABASE_PUBLISHABLE_KEY,
        "Authorization": "Bearer " + token,
        "Accept": "application/json",
    }
    if method == "GET":
        headers["Accept-Profile"] = "soc"
    else:
        headers["Content-Profile"] = "soc"
        headers["Content-Type"] = "application/json"
        headers["Prefer"] = "resolution=merge-duplicates,return=representation"
    body = None if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise HTTPException(exc.code, "Supabase a refusé l'accès aux données SOC (session ou rôle)") from None
        if exc.code in (404, 406, 415):
            raise HTTPException(503, "Le schéma soc doit être exposé dans Supabase API Settings et la migration doit être appliquée") from None
        raise HTTPException(502, f"Erreur Data API Supabase (HTTP {exc.code})") from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise HTTPException(503, "Supabase Data API est momentanément inaccessible") from None
    if not raw:
        return []
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HTTPException(502, "Réponse invalide de Supabase Data API") from None


def persist_cve_intelligence(authorization, cve_id, **updates):
    """Persist merged NVD/OpenCVE intelligence in Supabase under the caller's SOC role."""
    normalized = str(cve_id or "").strip().upper()
    if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", normalized):
        raise HTTPException(400, "Identifiant CVE invalide.")
    query_id = urllib.parse.quote(normalized, safe="")
    existing = supabase_soc_request(
        "cve_intelligence?select=cve_id,nvd_payload,opencve_payload,opencve_history,sources,nvd_fetched_at,opencve_fetched_at,history_fetched_at,created_at&cve_id=eq." + query_id,
        "GET", authorization,
    )
    previous = existing[0] if isinstance(existing, list) and existing else {}
    stamp = now()
    payload = {
        "cve_id": normalized,
        "nvd_payload": previous.get("nvd_payload") or {},
        "opencve_payload": previous.get("opencve_payload") or {},
        "opencve_history": previous.get("opencve_history") or [],
        "sources": previous.get("sources") or [],
        "nvd_fetched_at": previous.get("nvd_fetched_at"),
        "opencve_fetched_at": previous.get("opencve_fetched_at"),
        "history_fetched_at": previous.get("history_fetched_at"),
        "created_at": previous.get("created_at") or stamp,
        "updated_at": stamp,
    }
    merged_sources = set(payload.get("sources") or [])
    merged_sources.update(updates.get("sources") or [])
    payload.update(updates)
    payload["sources"] = sorted(merged_sources)
    return supabase_soc_request(
        "cve_intelligence?on_conflict=cve_id", "POST", authorization, payload
    )


@app.get("/api/nvd/status")
def nvd_status(authorization: str | None = Header(default=None)):
    require_read(authorization)
    return {
        "configured": True,
        "source": "NVD CVE API 2.0",
        "api_key_configured": bool(NVD_API_KEY),
        "rate_limit_mode": "api-key" if NVD_API_KEY else "conservative",
        "features": ["CVE search", "CVE details", "CVE change history", "CPE dictionary", "CPE match criteria"],
    }


@app.get("/api/nvd/cves")
def nvd_search(
    q: str = "", cve_id: str = "", cpe_name: str = "", vuln_status: str = "",
    has_kev: bool | None = None, page: int = 1, page_size: int = 50,
    authorization: str | None = Header(default=None),
):
    require_read(authorization)
    try:
        return search_nvd_catalog(
            keyword=q, cve_id=cve_id, cpe_name=cpe_name, vuln_status=vuln_status,
            has_kev=has_kev, page=page, page_size=page_size, api_key=NVD_API_KEY,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    except urllib.error.HTTPError as exc:
        raise HTTPException(503, f"NVD a répondu HTTP {exc.code}; vérifie la limite de requêtes ou la clé API.") from None
    except (urllib.error.URLError, TimeoutError):
        raise HTTPException(503, "NVD est momentanément inaccessible depuis le serveur.") from None
    except Exception:
        raise HTTPException(502, "Réponse NVD invalide ou inattendue.") from None


@app.get("/api/nvd/cves/{cve_id}/history")
def nvd_history(
    cve_id: str, page: int = 1, page_size: int = 20,
    authorization: str | None = Header(default=None),
):
    require_read(authorization)
    try:
        return get_nvd_cve_history(cve_id, page=page, page_size=page_size, api_key=NVD_API_KEY)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    except urllib.error.HTTPError as exc:
        raise HTTPException(503, f"NVD History a répondu HTTP {exc.code}.") from None
    except (urllib.error.URLError, TimeoutError):
        raise HTTPException(503, "NVD History est momentanément inaccessible.") from None
    except Exception:
        raise HTTPException(502, "Réponse NVD History invalide ou inattendue.") from None


@app.get("/api/nvd/cves/{cve_id}")
def nvd_detail(cve_id: str, authorization: str | None = Header(default=None)):
    require_read(authorization)
    try:
        return get_nvd_cve(cve_id, api_key=NVD_API_KEY)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from None
    except urllib.error.HTTPError as exc:
        raise HTTPException(503, f"NVD a répondu HTTP {exc.code}.") from None
    except (urllib.error.URLError, TimeoutError):
        raise HTTPException(503, "NVD est momentanément inaccessible.") from None
    except Exception:
        raise HTTPException(502, "Réponse NVD invalide ou inattendue.") from None


@app.get("/api/nvd/cpes")
def nvd_cpe_search(
    q: str, page: int = 1, page_size: int = 50,
    authorization: str | None = Header(default=None),
):
    require_read(authorization)
    try:
        return search_nvd_cpes(q, page=page, page_size=page_size, api_key=NVD_API_KEY)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    except urllib.error.HTTPError as exc:
        raise HTTPException(503, f"NVD CPE a répondu HTTP {exc.code}.") from None
    except (urllib.error.URLError, TimeoutError):
        raise HTTPException(503, "Le dictionnaire NVD CPE est momentanément inaccessible.") from None
    except Exception:
        raise HTTPException(502, "Réponse NVD CPE invalide ou inattendue.") from None


@app.get("/api/nvd/cpe-matches")
def nvd_cpe_match_search(
    q: str, page: int = 1, page_size: int = 50,
    authorization: str | None = Header(default=None),
):
    require_read(authorization)
    try:
        return search_nvd_cpe_matches(q, page=page, page_size=page_size, api_key=NVD_API_KEY)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    except urllib.error.HTTPError as exc:
        raise HTTPException(503, f"NVD CPE Match a répondu HTTP {exc.code}.") from None
    except (urllib.error.URLError, TimeoutError):
        raise HTTPException(503, "Le catalogue NVD CPE Match est momentanément inaccessible.") from None
    except Exception:
        raise HTTPException(502, "Réponse NVD CPE Match invalide ou inattendue.") from None


@app.get("/api/cve/intelligence/{cve_id}")
def combined_cve_intelligence(cve_id: str, authorization: str | None = Header(default=None)):
    """Combine NVD and OpenCVE, then persist successful source payloads in Supabase."""
    require_read(authorization)
    try:
        nvd = get_nvd_cve(cve_id, api_key=NVD_API_KEY)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from None
    except urllib.error.HTTPError as exc:
        raise HTTPException(503, f"NVD a répondu HTTP {exc.code}.") from None
    except (urllib.error.URLError, TimeoutError):
        raise HTTPException(503, "NVD est momentanément inaccessible.") from None
    result = {"cve_id": cve_id.upper(), "nvd": nvd, "opencve": None, "opencve_history": None,
              "opencve_status": "not-configured", "opencve_message": "", "persistence_status": "pending"}
    updates = {"nvd_payload": nvd, "nvd_fetched_at": now(), "sources": ["NVD"]}
    if OPENCVE_API_TOKEN:
        try:
            result["opencve"] = get_opencve_cve(cve_id)
            result["opencve_history"] = get_opencve_changes(cve_id, page=1, page_size=10)
            result["opencve_status"] = "available"
            updates.update({
                "opencve_payload": result["opencve"],
                "opencve_history": {"page": 1, "page_size": 10, "data": result["opencve_history"]},
                "opencve_fetched_at": now(),
                "history_fetched_at": now(),
                "sources": ["NVD", "OpenCVE"],
            })
        except OpenCVEError as exc:
            result["opencve_status"] = "unavailable"
            result["opencve_message"] = str(exc)
    try:
        persist_cve_intelligence(authorization, cve_id, **updates)
        result["persistence_status"] = "saved"
    except HTTPException as exc:
        result["persistence_status"] = "failed"
        result["persistence_message"] = exc.detail
    return result


@app.get("/api/opencve/status")
def opencve_status(authorization: str | None = Header(default=None)):
    require_read(authorization)
    if not OPENCVE_API_TOKEN:
        return {"configured": False, "connected": False, "message": "Jeton OPENCVE_API_TOKEN absent du serveur."}
    try:
        return check_opencve_connection()
    except OpenCVEError as exc:
        return {"configured": True, "connected": False, "message": str(exc)}


@app.get("/api/opencve/cves")
def opencve_catalog(q: str = "", page: int = 1, page_size: int = 50,
                    authorization: str | None = Header(default=None)):
    require_read(authorization)
    try:
        payload = search_opencve_cves(q, page, page_size)
        rows = payload.get("results", []) if isinstance(payload, dict) else []
        saved = 0
        for item in rows[:100]:
            if not isinstance(item, dict):
                continue
            candidate_id = str(item.get("id") or item.get("cve_id") or "").upper()
            if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", candidate_id):
                continue
            try:
                persist_cve_intelligence(
                    authorization, candidate_id, opencve_payload=item,
                    opencve_fetched_at=now(), sources=["OpenCVE"],
                )
                saved += 1
            except HTTPException:
                continue
        if isinstance(payload, dict):
            payload["supabase_saved"] = saved
        return payload
    except OpenCVEError as exc:
        raise HTTPException(503, str(exc)) from None


@app.get("/api/opencve/cves/{cve_id}/changes")
def opencve_cve_changes(cve_id: str, page: int = 1, page_size: int = 20,
                        authorization: str | None = Header(default=None)):
    require_read(authorization)
    try:
        payload = get_opencve_changes(cve_id, page, page_size)
        persist_cve_intelligence(
            authorization, cve_id,
            opencve_history={"page": page, "page_size": page_size, "data": payload},
            history_fetched_at=now(), sources=["OpenCVE"],
        )
        return payload
    except OpenCVEError as exc:
        raise HTTPException(503, str(exc)) from None


@app.get("/api/opencve/cves/{cve_id}")
def opencve_cve_detail(cve_id: str, authorization: str | None = Header(default=None)):
    require_read(authorization)
    try:
        payload = get_opencve_cve(cve_id)
        persist_cve_intelligence(
            authorization, cve_id, opencve_payload=payload,
            opencve_fetched_at=now(), sources=["OpenCVE"],
        )
        return payload
    except OpenCVEError as exc:
        raise HTTPException(503, str(exc)) from None


@app.post("/api/hypervisors/virtualbox/ingest")
async def ingest_virtualbox_host_inventory(
    request: Request,
    x_collector_token: str | None = Header(default=None, alias="X-Collector-Token"),
):
    """Accept read-only VBoxManage inventory from the Windows host collector."""
    if not VBOX_COLLECTOR_TOKEN:
        raise HTTPException(503, "CSV_VBOX_COLLECTOR_TOKEN n'est pas configuré côté serveur.")
    if not x_collector_token or not secrets.compare_digest(x_collector_token, VBOX_COLLECTOR_TOKEN):
        raise HTTPException(401, "Jeton du collecteur VirtualBox invalide.")
    data = await request.json()
    machines = data.get("machines") if isinstance(data, dict) else None
    if not isinstance(machines, list) or len(machines) > 2000:
        raise HTTPException(400, "Le corps doit contenir une liste machines de 0 à 2000 éléments.")
    stamp = now()
    received = 0
    with conn() as db:
        for machine in machines:
            if not isinstance(machine, dict):
                continue
            vm_id = str(machine.get("id") or "").strip()[:255]
            name = str(machine.get("name") or vm_id).strip()[:255]
            if not vm_id or not name:
                continue
            metadata = machine.get("metadata") if isinstance(machine.get("metadata"), dict) else {}
            db.execute("""INSERT INTO hypervisor_host_inventory(provider,vm_id,name,state,metadata,last_seen,updated_by)
              VALUES('virtualbox',?,?,?,?,?,'windows-vboxmanage')
              ON CONFLICT(provider,vm_id) DO UPDATE SET name=excluded.name,state=excluded.state,
              metadata=excluded.metadata,last_seen=excluded.last_seen,updated_by=excluded.updated_by""",
              (vm_id, name, str(machine.get("state") or "unknown")[:80],
               json.dumps(metadata, ensure_ascii=False)[:12000], stamp))
            received += 1
    audit("hypervisor.virtualbox.host_ingest", "virtualbox", f"{received} machine(s) reçue(s)", "windows-vboxmanage")
    return {"received": received, "provider": "virtualbox", "read_only": True, "timestamp": stamp}


@app.get("/api/hypervisors/providers")
def hypervisor_providers(authorization: str | None = Header(default=None)):
    require_read(authorization)
    return configured_providers()


@app.get("/api/hypervisors/inventory")
def list_hypervisor_inventory(authorization: str | None = Header(default=None)):
    require_read(authorization)
    remote = supabase_soc_request(
        "hypervisor_inventory?select=provider,vm_id,name,state,metadata,last_seen,updated_by"
        "&order=provider.asc,name.asc&limit=1000",
        "GET", authorization,
    )
    known = {(str(row.get("provider")), str(row.get("vm_id"))) for row in remote if isinstance(row, dict)}
    with conn() as db:
        local = db.execute(
            "SELECT provider,vm_id,name,state,metadata,last_seen,updated_by FROM hypervisor_host_inventory "
            "ORDER BY name LIMIT 2000"
        ).fetchall()
    for row in local:
        key = (row["provider"], row["vm_id"])
        if key in known:
            continue
        item = dict(row)
        try:
            item["metadata"] = json.loads(item.get("metadata") or "{}")
        except (TypeError, ValueError):
            item["metadata"] = {}
        item["source"] = "host-collector"
        remote.append(item)
    return remote


@app.post("/api/hypervisors/sync")
def sync_hypervisor_inventory(authorization: str | None = Header(default=None)):
    actor = require_analyst(authorization)
    outcomes = []
    for provider in configured_providers():
        name = provider["provider"]
        if not provider["configured"]:
            outcomes.append({"provider": name, "status": "not-configured", "saved": 0})
            continue
        try:
            if name == "virtualbox" and provider.get("host_collector"):
                with conn() as db:
                    local_rows = db.execute(
                        "SELECT vm_id,name,state,metadata FROM hypervisor_host_inventory "
                        "WHERE provider='virtualbox' ORDER BY name LIMIT 2000"
                    ).fetchall()
                machines = []
                for row in local_rows:
                    try:
                        metadata = json.loads(row["metadata"] or "{}")
                    except (TypeError, ValueError):
                        metadata = {}
                    machines.append({"id": row["vm_id"], "name": row["name"],
                                     "state": row["state"], "metadata": metadata})
                if not machines:
                    outcomes.append({"provider": name, "status": "no-data", "saved": 0,
                                     "message": "Collecteur hôte configuré, mais aucun inventaire n'a encore été reçu."})
                    continue
            else:
                machines = collect_hypervisor_inventory(name)
            stamp = now()
            records = []
            for machine in machines[:2000]:
                vm_id = str(machine.get("id") or "").strip()
                if not vm_id:
                    continue
                records.append({
                    "provider": name,
                    "vm_id": vm_id[:255],
                    "name": str(machine.get("name") or vm_id)[:255],
                    "state": str(machine.get("state") or "unknown")[:80],
                    "metadata": machine.get("metadata") if isinstance(machine.get("metadata"), dict) else {},
                    "last_seen": stamp,
                    "updated_by": actor[:255],
                })
            saved = supabase_soc_request(
                "hypervisor_inventory?on_conflict=provider,vm_id",
                "POST", authorization, records,
            ) if records else []
            outcomes.append({"provider": name, "status": "ok", "discovered": len(records),
                             "saved": len(saved) if isinstance(saved, list) else len(records)})
        except (HypervisorError, HTTPException) as exc:
            detail = exc.detail if isinstance(exc, HTTPException) else str(exc)
            outcomes.append({"provider": name, "status": "error", "saved": 0, "message": str(detail)[:240]})
    audit("hypervisor.inventory.sync", "all-providers", json.dumps(outcomes, ensure_ascii=False), actor)
    return {"results": outcomes, "read_only": True, "timestamp": now()}

@app.get("/api/hypervisors/lab/inventory")
def hypervisor_lab_inventory(authorization: str | None = Header(default=None)):
    """Synthetic inventory is isolated from the live Supabase inventory."""
    require_read(authorization)
    return get_hypervisor_lab_inventory()


@app.post("/api/hypervisors/providers/check")
def check_hypervisor_providers(authorization: str | None = Header(default=None)):
    """Probe configured providers with inventory-only requests; never persists results."""
    actor = require_analyst(authorization)
    outcomes = []
    for provider in configured_providers():
        name = provider["provider"]
        if not provider["configured"]:
            outcomes.append({"provider": name, "status": "not-configured", "machines": 0})
            continue
        try:
            if name == "virtualbox" and provider.get("host_collector"):
                with conn() as db:
                    rows = db.execute(
                        "SELECT COUNT(*) AS count, MAX(last_seen) AS last_seen FROM hypervisor_host_inventory "
                        "WHERE provider='virtualbox'"
                    ).fetchone()
                outcomes.append({
                    "provider": name,
                    "status": "reachable" if rows["count"] else "no-data",
                    "machines": int(rows["count"] or 0),
                    "last_seen": rows["last_seen"],
                    "message": "" if rows["count"] else "En attente de la première remontée du collecteur Windows.",
                    "read_only": True,
                })
                continue
            machines = collect_hypervisor_inventory(name)
            outcomes.append({"provider": name, "status": "reachable", "machines": len(machines),
                             "read_only": True})
        except HypervisorError as exc:
            outcomes.append({"provider": name, "status": "error", "machines": 0,
                             "message": str(exc)[:200]})
    audit("hypervisor.providers.check", "all-providers", json.dumps(outcomes, ensure_ascii=False), actor)
    return {"results": outcomes, "read_only": True, "persisted": False, "timestamp": now()}


@app.get("/api/security/status")
def security_status(authorization: str|None=Header(default=None)):
    require_admin(authorization)
    return {"authentication":"Supabase Auth session validated server-side","database":"Supabase PostgreSQL for SOC endpoint telemetry and hypervisor inventory; SQLite retained for legacy modules pending migration","tls":"HTTPS reverse-proxy required for deployment","mfa":"not-enforced; Supabase MFA/AAL2 integration pending","rbac":"server-enforced app_metadata roles: admin, analyst, viewer, incident_responder","rate_limiting":"not-configured","remediation":"approval-only; no remote execution","agent_tokens":"SHA-256 digests at rest; rotation workflow pending","agent_enrollment":"shared bootstrap token; protect and rotate before production","mode":"laboratory","soc_telemetry_supabase":supabase_public_configured(),"production_ready":False}
