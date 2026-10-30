"""NVD synchronization and conservative CPE/version applicability checks."""
import json, os, re, time, urllib.parse, urllib.request
from datetime import datetime, timezone

def _nums(v):
    found=re.findall(r"\\d+",str(v or ""))
    return tuple(int(x) for x in found[:8])

def _applies(cve, name, vendor, version):
    hay=(str(name)+" "+str(vendor)).lower().replace("_"," ")
    ver=_nums(version); uncertain=False
    for cfg in cve.get("configurations",[]):
        for node in cfg.get("nodes",[]):
            for item in node.get("cpeMatch",[]):
                if not item.get("vulnerable",False): continue
                parts=str(item.get("criteria","")).lower().split(":")
                if len(parts)<6: continue
                tokens=[x.replace("_"," ") for x in parts[3:5] if x not in ("*","-")]
                if not tokens or not any(t in hay or t.replace(" ","") in hay.replace(" ","") for t in tokens): continue
                if not ver: uncertain=True; continue
                cpever=parts[5]
                if cpever not in ("*","-") and _nums(cpever) and ver!=_nums(cpever): continue
                lower=item.get("versionStartIncluding") or item.get("versionStartExcluding")
                upper=item.get("versionEndIncluding") or item.get("versionEndExcluding")
                if lower and _nums(lower) and ver<_nums(lower): continue
                if upper and _nums(upper) and (ver>_nums(upper) or (ver==_nums(upper) and item.get("versionEndExcluding"))): continue
                return "version-range-match"
    return "candidate"

def search_nvd(keyword, api_key="", published_after=None):
    params={"keywordSearch":keyword,"resultsPerPage":100}
    if published_after:
        params["pubStartDate"]=published_after
        params["pubEndDate"]=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
    url="https://services.nvd.nist.gov/rest/json/cves/2.0?"+urllib.parse.urlencode(params)
    req=urllib.request.Request(url,headers={"User-Agent":"CongoSecVision/1.0"})
    if api_key: req.add_header("apiKey",api_key)
    with urllib.request.urlopen(req,timeout=30) as response: return json.loads(response.read())

def scan_product(name, version, vendor, api_key="", published_after=None):
    keyword=" ".join(x for x in (str(vendor or "").strip(),str(name or "").strip()) if x)[:140]
    payload=search_nvd(keyword,api_key,published_after)
    output=[]
    for wrapper in payload.get("vulnerabilities",[]):
        cve=wrapper.get("cve",{}); cve_id=cve.get("id","")
        if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}",cve_id): continue
        desc=next((d.get("value","") for d in cve.get("descriptions",[]) if d.get("lang")=="en"),"")
        severity="unknown"
        for key in ("cvssMetricV40","cvssMetricV31","cvssMetricV30","cvssMetricV2"):
            metrics=cve.get("metrics",{}).get(key,[])
            if metrics:
                severity=str(metrics[0].get("cvssData",{}).get("baseSeverity") or "unknown").lower(); break
        output.append({"cve_id":cve_id,"severity":severity,"title":desc[:500],
          "match_confidence":_applies(cve,name,vendor,version),
          "cve_url":"https://nvd.nist.gov/vuln/detail/"+cve_id})
    return output