"""Defensive CVE intelligence engine.

NVD is the primary vulnerability source. CPE applicability is evaluated conservatively:
a match is evidence for analyst review, never proof that a host is exploitable.
Optional EPSS and CISA KEV enrichments are best-effort and never block NVD ingestion.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
USER_AGENT = "CongoSecVision/1.0 (+defensive vulnerability management)"
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}


def _request_json(url: str, api_key: str = "", timeout: int = 30, attempts: int = 4) -> dict[str, Any]:
    """GET JSON with bounded retries for rate limits and transient upstream failures."""
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key
    last_error: Exception | None = None
    for attempt in range(max(1, attempts)):
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code not in (403, 429, 500, 502, 503, 504) or attempt + 1 >= attempts:
                raise
            retry_after = exc.headers.get("Retry-After", "")
            try:
                delay = min(60.0, max(1.0, float(retry_after)))
            except (TypeError, ValueError):
                delay = min(30.0, 2.0 ** attempt)
            time.sleep(delay)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt + 1 >= attempts:
                raise
            time.sleep(min(15.0, 2.0 ** attempt))
    if last_error:
        raise last_error
    raise RuntimeError("Upstream request failed")


def _norm(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def _version_parts(value: Any) -> tuple[tuple[int, Any], ...]:
    """Tokenize versions without treating 1.10 as older than 1.9."""
    text = str(value or "").strip().lower()
    if not text or text in ("*", "-", "unknown", "n/a"):
        return ()
    tokens = re.findall(r"\d+|[a-z]+", text)
    return tuple((0, int(x)) if x.isdigit() else (1, x) for x in tokens)


def _version_compare(left: Any, right: Any) -> int | None:
    a, b = _version_parts(left), _version_parts(right)
    if not a or not b:
        return None
    # Pad numeric components so 2.1 and 2.1.0 compare equally.
    size = max(len(a), len(b))
    a = a + ((0, 0),) * (size - len(a))
    b = b + ((0, 0),) * (size - len(b))
    return (a > b) - (a < b)


def _cpe_product_match(criteria: str, name: str, vendor: str) -> bool:
    parts = criteria.split(":")
    if len(parts) < 6 or parts[0:2] != ["cpe", "2.3"]:
        return False
    cpe_vendor, cpe_product = parts[3], parts[4]
    if cpe_vendor in ("*", "-") or cpe_product in ("*", "-"):
        return False
    wanted_vendor, wanted_product = _norm(cpe_vendor), _norm(cpe_product)
    actual_vendor, actual_name = _norm(vendor), _norm(name)
    # Product names may be distributed with a vendor prefix or suffix.
    vendor_ok = not actual_vendor or wanted_vendor in actual_vendor or actual_vendor in wanted_vendor
    product_ok = wanted_product == actual_name or wanted_product in actual_name or actual_name in wanted_product
    return vendor_ok and product_ok


def _match_one(item: dict[str, Any], name: str, vendor: str, version: str) -> str | None:
    if not item.get("vulnerable", False):
        return None
    criteria = str(item.get("criteria") or item.get("cpe23Uri") or "")
    if not _cpe_product_match(criteria, name, vendor):
        return None
    parts = criteria.split(":")
    cpe_version = parts[5] if len(parts) > 5 else "*"
    if cpe_version not in ("*", "-"):
        comparison = _version_compare(version, cpe_version)
        if comparison is None or comparison != 0:
            return None
    checks = (
        ("versionStartIncluding", lambda c: c >= 0),
        ("versionStartExcluding", lambda c: c > 0),
        ("versionEndIncluding", lambda c: c <= 0),
        ("versionEndExcluding", lambda c: c < 0),
    )
    for field, predicate in checks:
        boundary = item.get(field)
        if boundary:
            comparison = _version_compare(version, boundary)
            if comparison is None or not predicate(comparison):
                return None
    return "version-range-match"


def _evaluate_node(node: dict[str, Any], name: str, vendor: str, version: str) -> bool:
    """Evaluate NVD recursive AND/OR nodes; unsupported/unknown expressions fail closed."""
    results: list[bool] = []
    for item in node.get("cpeMatch", []) or []:
        results.append(_match_one(item, name, vendor, version) is not None)
    for child in node.get("children", []) or []:
        results.append(_evaluate_node(child, name, vendor, version))
    if not results:
        return False
    operator = str(node.get("operator") or "OR").upper()
    matched = all(results) if operator == "AND" else any(results)
    return not matched if node.get("negate") else matched


def _applies(cve: dict[str, Any], name: str, vendor: str, version: str) -> str:
    """Return conservative applicability confidence; never label a candidate confirmed."""
    if not name or not version:
        return "candidate"
    configurations = cve.get("configurations") or []
    for config in configurations:
        nodes = config.get("nodes") or []
        if any(_evaluate_node(node, name, vendor, version) for node in nodes):
            return "version-range-match"
    return "candidate"


def _severity(cve: dict[str, Any]) -> tuple[str, float | None, str, dict[str, Any]]:
    metrics = cve.get("metrics") or {}
    for key, version in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"),
                         ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        rows = metrics.get(key) or []
        if not rows:
            continue
        metric = rows[0]
        data = metric.get("cvssData") or {}
        score = data.get("baseScore")
        severity = str(data.get("baseSeverity") or metric.get("baseSeverity") or "unknown").lower()
        if severity not in SEVERITY_ORDER:
            severity = "unknown"
        return severity, float(score) if score is not None else None, version, data
    return "unknown", None, "", {}


def _extract_weaknesses(cve: dict[str, Any]) -> list[str]:
    found: set[str] = set()
    for item in cve.get("weaknesses") or []:
        for desc in item.get("description") or []:
            value = str(desc.get("value") or "")
            if re.fullmatch(r"CWE-\d+", value):
                found.add(value)
    return sorted(found)


def _extract_references(cve: dict[str, Any]) -> list[dict[str, Any]]:
    refs = []
    for item in cve.get("references") or []:
        url = str(item.get("url") or "")
        if not url.startswith(("https://", "http://")):
            continue
        refs.append({"url": url, "source": item.get("source") or "",
                     "tags": item.get("tags") or []})
    return refs[:100]


def _extract_cpe(cve: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    def walk(nodes: list[dict[str, Any]]) -> None:
        for node in nodes or []:
            for item in node.get("cpeMatch") or []:
                rows.append({
                    "criteria": item.get("criteria") or item.get("cpe23Uri") or "",
                    "vulnerable": bool(item.get("vulnerable")),
                    "matchCriteriaId": item.get("matchCriteriaId"),
                    "versionStartIncluding": item.get("versionStartIncluding"),
                    "versionStartExcluding": item.get("versionStartExcluding"),
                    "versionEndIncluding": item.get("versionEndIncluding"),
                    "versionEndExcluding": item.get("versionEndExcluding"),
                    "operator": node.get("operator", "OR"),
                    "negate": bool(node.get("negate", False)),
                })
            walk(node.get("children") or [])
    for config in cve.get("configurations") or []:
        walk(config.get("nodes") or [])
    return rows[:500]


def _epss_for(cve_ids: list[str]) -> dict[str, dict[str, Any]]:
    if not cve_ids:
        return {}
    params = urllib.parse.urlencode({"cve": ",".join(cve_ids[:100])})
    payload = _request_json(EPSS_URL + "?" + params, timeout=15, attempts=2)
    return {str(x.get("cve")): {"score": float(x["epss"]), "percentile": float(x["percentile"])}
            for x in payload.get("data", []) if x.get("cve") and x.get("epss") is not None}


@lru_cache(maxsize=1)
def _kev_catalog_cached(day: str) -> frozenset[str]:
    payload = _request_json(CISA_KEV_URL, timeout=20, attempts=2)
    return frozenset(str(x.get("cveID")) for x in payload.get("vulnerabilities", []) if x.get("cveID"))


def _kev_ids() -> frozenset[str]:
    return _kev_catalog_cached(datetime.now(timezone.utc).date().isoformat())


def search_nvd(keyword: str, api_key: str = "", published_after: str | None = None,
               results_per_page: int = 2000, max_pages: int = 50) -> dict[str, Any]:
    """Retrieve all matching NVD pages up to a safe configurable cap."""
    page_size = max(1, min(int(results_per_page), 2000))
    collected: list[dict[str, Any]] = []
    start = 0
    total = None
    pages = 0
    while pages < max(1, min(int(max_pages), 100)):
        params: dict[str, Any] = {"keywordSearch": keyword, "resultsPerPage": page_size, "startIndex": start}
        if published_after:
            params["pubStartDate"] = published_after
            params["pubEndDate"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
        url = NVD_CVE_URL + "?" + urllib.parse.urlencode(params)
        payload = _request_json(url, api_key=api_key)
        batch = payload.get("vulnerabilities") or []
        collected.extend(batch)
        total = int(payload.get("totalResults", len(collected)))
        pages += 1
        start += len(batch)
        if not batch or start >= total:
            break
        # NVD rate limits unauthenticated clients more aggressively.
        time.sleep(float(os.getenv("NVD_REQUEST_INTERVAL_SECONDS", "6.1" if not api_key else "0.7")))
    return {"vulnerabilities": collected, "totalResults": total or 0,
            "pagesFetched": pages, "truncated": bool(total is not None and len(collected) < total)}


def scan_product(name: str, version: str, vendor: str, api_key: str = "",
                 published_after: str | None = None) -> list[dict[str, Any]]:
    keyword = " ".join(x for x in (str(vendor or "").strip(), str(name or "").strip()) if x)[:140]
    if not keyword:
        return []
    payload = search_nvd(keyword, api_key, published_after)
    raw_cves = [x.get("cve", {}) for x in payload.get("vulnerabilities", [])]
    ids = [str(x.get("id")) for x in raw_cves if re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", str(x.get("id") or ""))]
    epss: dict[str, dict[str, Any]] = {}
    kev: frozenset[str] = frozenset()
    try:
        epss = _epss_for(ids)
    except Exception:
        pass
    try:
        kev = _kev_ids()
    except Exception:
        pass
    output = []
    for cve in raw_cves:
        cve_id = str(cve.get("id") or "")
        if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", cve_id):
            continue
        desc = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        severity, score, cvss_version, cvss_vector = _severity(cve)
        output.append({
            "cve_id": cve_id, "severity": severity, "cvss_score": score,
            "cvss_version": cvss_version, "cvss_vector": cvss_vector.get("vectorString", ""),
            "title": desc[:2000], "published": cve.get("published"),
            "last_modified": cve.get("lastModified"), "vuln_status": cve.get("vulnStatus"),
            "match_confidence": _applies(cve, name, vendor, version),
            "cwe_ids": _extract_weaknesses(cve), "cpe_matches": _extract_cpe(cve),
            "references": _extract_references(cve),
            "epss_score": (epss.get(cve_id) or {}).get("score"),
            "epss_percentile": (epss.get(cve_id) or {}).get("percentile"),
            "known_exploited": cve_id in kev,
            "cve_url": "https://nvd.nist.gov/vuln/detail/" + cve_id,
            "sources": ["NVD", "FIRST EPSS"] if cve_id in epss else ["NVD"],
        })
    return output
