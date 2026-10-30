import os, json, secrets, sqlite3, urllib.parse, urllib.request, urllib.error, subprocess, re, ipaddress, time
from datetime import datetime, timezone, timedelta
from fastapi import FastAPI, Header, HTTPException, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from app.ai_engine import analyze_logs, cve_remediation_advice

DB = os.getenv("DATABASE_PATH", "congo_sec_vision.db")
ADMIN = os.getenv("ADMIN_TOKEN", "")
ENROLL = os.getenv("AGENT_ENROLLMENT_TOKEN", "")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
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
        CREATE TABLE IF NOT EXISTS software(id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id TEXT,
          name TEXT, version TEXT, vendor TEXT, collected_at TEXT);
        CREATE TABLE IF NOT EXISTS log_findings(id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id TEXT,
          severity TEXT, rule_id TEXT, title TEXT, details TEXT, created_at TEXT);
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
        cols={r["name"] for r in c.execute("PRAGMA table_info(events)").fetchall()}
        if "raw" not in cols: c.execute("ALTER TABLE events ADD COLUMN raw TEXT")
if not ADMIN or not ENROLL:
    raise RuntimeError("ADMIN_TOKEN and AGENT_ENROLLMENT_TOKEN must be set; see .env.example")
if ADMIN == ENROLL:
    raise RuntimeError("ADMIN_TOKEN and AGENT_ENROLLMENT_TOKEN must be different")
init()

app = FastAPI(title="Congo Sec Vision API", version="0.3.1")
_allowed_origins = [x.strip() for x in os.getenv("ALLOWED_ORIGINS", "").split(",") if x.strip()]
if _allowed_origins:
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
def require_admin(auth):
    if bearer(auth) != ADMIN: raise HTTPException(401, "Invalid administrator token")
def audit(action, target="", details="", actor="admin"):
    with conn() as c:
        c.execute("INSERT INTO audit_logs(actor,action,target,details,created_at) VALUES(?,?,?,?,?)",
                  (actor, action[:120], str(target)[:255], str(details)[:2000], now()))

def require_agent(auth):
    token=bearer(auth)
    if not token: raise HTTPException(401,"Agent token required")
    with conn() as c: row=c.execute("SELECT asset_id FROM agent_tokens WHERE token=?",(token,)).fetchone()
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
    return asset_id

def asset_json(a, online=None):
    inv=json.loads(a["inventory"])
    return {"id":a["id"],"hostname":a["hostname"],"platform":a["platform"],
      "ip_addresses":json.loads(a["ip_addresses"]),"first_seen":a["first_seen"],"last_seen":a["last_seen"],
      "online":online,"cpu_percent":inv.get("cpu_percent"),"memory_percent":inv.get("memory_percent"),
      "disk_percent":inv.get("disk_percent"),"agent_version":inv.get("agent_version"),
      "interfaces":inv.get("interfaces",[])}

@app.get("/")
def index(): return FileResponse("app/static/index.html")
@app.get("/api/health")
def health(): return {"status":"ok","service":"Congo Sec Vision API","version":"0.3.1","time":now()}
@app.post("/api/auth/check")
def auth_check(authorization: str|None=Header(default=None)):
    require_admin(authorization); return {"authenticated":True}
@app.post("/api/agents/enroll")
async def enroll(request:Request,authorization:str|None=Header(default=None)):
    if bearer(authorization)!=ENROLL: raise HTTPException(403,"Enrollment not authorized")
    aid=asset_inventory(await request.json()); token=secrets.token_urlsafe(36)
    with conn() as c:
        c.execute("INSERT INTO agent_tokens VALUES(?,?)",(token,aid))
        c.execute("INSERT OR IGNORE INTO ai_agents(asset_id,name,status,created_at) VALUES(?,?,?,?)",
                  (aid,"CSVA-AI-"+aid[:8],"active",now()))
    background_tasks.add_task(analyze_asset_ai, aid, "Bearer "+ADMIN)
    audit("agent.enroll", aid, "Nouvel agent enrôlé")
    return {"asset_id":aid,"agent_token":token,"ai_agent_assigned":True}
@app.post("/api/agents/heartbeat")
async def heartbeat(request:Request,background_tasks: BackgroundTasks,authorization:str|None=Header(default=None)):
    aid=require_agent(authorization); data=await request.json(); asset_inventory(data,aid)
    with conn() as c:
        c.execute("INSERT OR IGNORE INTO ai_agents(asset_id,name,status,created_at) VALUES(?,?,?,?)",
                  (aid,"CSVA-AI-"+aid[:8],"active",now()))
        ai_row=c.execute("SELECT last_analysis_at FROM ai_agents WHERE asset_id=?",(aid,)).fetchone()
    last=ai_row["last_analysis_at"] if ai_row else None
    due=(not last) or (last < (datetime.now(timezone.utc)-timedelta(minutes=15)).isoformat())
    if due: background_tasks.add_task(analyze_asset_ai, aid, "Bearer "+ADMIN)
    for entry in data.get("logs",[])[:250]:
        ingest_log(aid,entry)
    return {"accepted":True,"asset_id":aid,"received_at":now(),"logs_received":min(len(data.get("logs",[])),250),"ai_analysis_scheduled":due}

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
    require_admin(authorization); cutoff=(datetime.now(timezone.utc)-timedelta(minutes=3)).isoformat()
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
    require_admin(authorization)
    with conn() as c: rows=c.execute("SELECT * FROM assets ORDER BY last_seen DESC").fetchall()
    cutoff=(datetime.now(timezone.utc)-timedelta(minutes=3)).isoformat()
    return [asset_json(a,a["last_seen"]>=cutoff) for a in rows]
@app.get("/api/events")
def events(authorization:str|None=Header(default=None)):
    require_admin(authorization)
    with conn() as c: rows=c.execute("SELECT * FROM events ORDER BY id DESC LIMIT 200").fetchall()
    return [dict(r) for r in rows]
@app.get("/api/vulnerabilities")
def vulnerabilities(authorization:str|None=Header(default=None)):
    require_admin(authorization)
    with conn() as c: rows=c.execute("SELECT * FROM vulnerabilities ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]
@app.get("/api/software")
def software(authorization:str|None=Header(default=None)):
    require_admin(authorization)
    with conn() as c:
        rows=c.execute("SELECT s.*,a.hostname FROM software s LEFT JOIN assets a ON a.id=s.asset_id ORDER BY s.name").fetchall()
    return [dict(r) for r in rows]

def nvd_search(keyword):
    params=urllib.parse.urlencode({"keywordSearch":keyword,"resultsPerPage":20})
    url="https://services.nvd.nist.gov/rest/json/cves/2.0?"+params
    req=urllib.request.Request(url,headers={"User-Agent":"CongoSecVision/0.2"})
    if NVD_API_KEY: req.add_header("apiKey",NVD_API_KEY)
    with urllib.request.urlopen(req,timeout=25) as r: return json.loads(r.read())
@app.post("/api/cve/sync")
def cve_sync(authorization:str|None=Header(default=None)):
    require_admin(authorization)
    with conn() as c: products=c.execute("SELECT DISTINCT name,version,asset_id FROM software WHERE name!='' LIMIT 5").fetchall()
    checked=0; added=0; errors=[]
    for idx,p in enumerate(products):
        if idx:
            time.sleep(0.7 if NVD_API_KEY else 6.0)
        # NVD keyword matching is a candidate-discovery step, not proof of applicability.
        query=str(p["name"])[:100]
        try:
            result=nvd_search(query); checked+=1
            for item in result.get("vulnerabilities",[]):
                cv=item.get("cve",{}); cve_id=cv.get("id","")
                desc=next((d.get("value","") for d in cv.get("descriptions",[]) if d.get("lang")=="en"),"")
                metrics=cv.get("metrics",{}); sev="unknown"
                for metric in metrics.get("cvssMetricV31",[])+metrics.get("cvssMetricV30",[]):
                    sev=metric.get("cvssData",{}).get("baseSeverity","unknown").lower(); break
                title=(desc[:220] or "NVD candidate match")
                with conn() as c:
                    before=c.total_changes
                    c.execute("INSERT OR IGNORE INTO vulnerabilities(asset_id,cve_id,severity,title,status,source,created_at) VALUES(?,?,?,?,?,?,?)",
                              (p["asset_id"],cve_id,sev,title,"needs-validation","NVD CVE API",now()))
                    if c.total_changes>before: added+=1
        except Exception as e: errors.append({"software":query,"error":str(e)[:220]})
    with conn() as c: remaining=max(0,c.execute("SELECT COUNT(DISTINCT name) n FROM software WHERE name!=''").fetchone()["n"]-checked)
    return {"software_checked":checked,"candidate_records_added":added,"remaining_software_estimate":remaining,"errors":errors,
            "warning":"NVD keyword matches are candidates only. Validate CPE, affected version ranges and vendor advisories before declaring a host vulnerable."}

@app.get("/api/topology")
def topology(authorization:str|None=Header(default=None)):
    require_admin(authorization)
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
    require_admin(authorization)
    with conn() as c: rows=c.execute("SELECT * FROM log_findings ORDER BY id DESC LIMIT 250").fetchall()
    return [dict(r) for r in rows]
@app.post("/api/ai/analyze")
def ai_analyze(authorization:str|None=Header(default=None)):
    require_admin(authorization)
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
    require_admin(authorization)
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
    require_admin(authorization); d=await request.json()
    with conn() as c:
        c.execute("INSERT INTO events(asset_id,severity,category,message,created_at) VALUES(?,?,?,?,?)",
                  (d.get("asset_id"),d.get("severity","info"),d.get("category","manual"),d.get("message",""),now()))
    audit("event.create", d.get("asset_id",""), d.get("message",""))
    return {"created":True}
@app.get("/api/config")
def config(): return {"product":"Congo Sec Vision","version":"0.3.1","mode":"laboratory","cve_provider":"NVD","ai_mode":"LLM configured" if LLM_BASE_URL and LLM_MODEL else "local-rules"}


# --- SOC Enterprise modules: incident lifecycle, audit, team, approvals, exports ---
@app.get("/api/incidents")
def list_incidents(authorization: str|None=Header(default=None)):
    require_admin(authorization)
    with conn() as c: rows=c.execute("SELECT * FROM incidents ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, updated_at DESC").fetchall()
    return [dict(r) for r in rows]

@app.post("/api/incidents")
async def create_incident(request: Request, authorization: str|None=Header(default=None)):
    require_admin(authorization); d=await request.json()
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
    require_admin(authorization); d=await request.json()
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
    require_admin(authorization); created=0
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
    require_admin(authorization)
    with conn() as c: rows=c.execute("SELECT * FROM approvals ORDER BY id DESC LIMIT 300").fetchall()
    return [dict(r) for r in rows]

@app.post("/api/approvals")
async def create_approval(request:Request, authorization: str|None=Header(default=None)):
    require_admin(authorization); d=await request.json()
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
    require_admin(authorization)
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
    require_admin(authorization)
    with conn() as c:
        rows=c.execute("""SELECT g.*,a.hostname,a.platform,a.last_seen
          FROM ai_agents g JOIN assets a ON a.id=g.asset_id ORDER BY a.hostname""").fetchall()
    return [dict(r) for r in rows]

@app.post("/api/ai/agents/{asset_id}/analyze")
def analyze_asset_ai(asset_id: str, authorization: str|None=Header(default=None)):
    require_admin(authorization)
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
       **cve_remediation_advice(v["cve_id"],v["severity"],"", "",v["title"])} for v in vuln_rows]
    llm_result=None
    if LLM_BASE_URL and LLM_MODEL and log_inputs:
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
      "software_inventory_count":len(software_rows),"cve_candidates_count":len(vuln_rows),
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
    require_admin(authorization)
    with conn() as c:
        rows=c.execute("SELECT id,report_type,summary,events_reviewed,created_at FROM ai_reports WHERE asset_id=? ORDER BY id DESC LIMIT 30",(asset_id,)).fetchall()
    return [dict(x) for x in rows]

@app.get("/api/reports/logs")
def logs_report(authorization: str|None=Header(default=None)):
    require_admin(authorization)
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

@app.get("/api/security/status")
def security_status(authorization: str|None=Header(default=None)):
    require_admin(authorization)
    return {"authentication":"admin bearer token","database":"sqlite persistent","tls":"terminaison reverse-proxy requise en déploiement","mfa":"not-configured","rbac":"team roles metadata; per-user authentication not enabled","remediation":"approval-only; no remote execution","agent_enrollment":"shared bootstrap token; rotate and protect","mode":"laboratory"}
