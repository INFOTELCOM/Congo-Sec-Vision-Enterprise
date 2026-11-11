"""Minimal, server-side OpenCVE API v2 client (organization token only)."""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

DEFAULT_BASE_URL = "https://app.opencve.io/api/v2"
USER_AGENT = "CongoSecVision/1.0 (+defensive vulnerability management)"
CVE_ID_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")


class OpenCVEError(RuntimeError):
    """Sanitized OpenCVE API failure; never includes request headers or tokens."""


def api_base_url() -> str:
    return os.getenv("OPENCVE_API_BASE_URL", DEFAULT_BASE_URL).strip().rstrip("/")


def api_token() -> str:
    return os.getenv("OPENCVE_API_TOKEN", "").strip()


def _request_json(path: str, *, params: dict[str, Any] | None = None,
                  timeout: int = 20) -> dict[str, Any]:
    token = api_token()
    if not token:
        raise OpenCVEError("OpenCVE API token is not configured on the server")
    query = urllib.parse.urlencode({k: v for k, v in (params or {}).items() if v is not None})
    url = api_base_url() + "/" + path.lstrip("/")
    if query:
        url += "?" + query
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        messages = {
            401: "OpenCVE a refusé le jeton API (absent, invalide ou révoqué).",
            403: "Le jeton OpenCVE ne possède pas le droit de lecture requis.",
            404: "Ressource OpenCVE introuvable.",
            429: "Limite de requêtes OpenCVE atteinte. Réessaie plus tard.",
        }
        raise OpenCVEError(messages.get(exc.code, f"OpenCVE a répondu HTTP {exc.code}.")) from None
    except urllib.error.URLError:
        raise OpenCVEError("OpenCVE est inaccessible depuis le serveur.") from None
    except TimeoutError:
        raise OpenCVEError("La requête OpenCVE a dépassé le délai autorisé.") from None
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise OpenCVEError("OpenCVE a renvoyé une réponse JSON invalide.") from None
    if not isinstance(payload, dict):
        raise OpenCVEError("Format de réponse OpenCVE inattendu.")
    return payload


def check_connection() -> dict[str, Any]:
    if not api_token():
        return {"configured": False, "connected": False, "base_url": api_base_url()}
    payload = _request_json("cves", params={"page": 1, "page_size": 1})
    return {
        "configured": True,
        "connected": True,
        "base_url": api_base_url(),
        "catalog_count": payload.get("count"),
    }


def search_cves(query: str = "", page: int = 1, page_size: int = 50) -> dict[str, Any]:
    page = max(1, min(int(page), 10000))
    page_size = max(1, min(int(page_size), 100))
    query = str(query or "").strip()
    if len(query) > 500:
        raise OpenCVEError("La requête OpenCVE est limitée à 500 caractères.")
    return _request_json("cves", params={"q": query or None, "page": page, "page_size": page_size})


def get_cve(cve_id: str) -> dict[str, Any]:
    cve_id = str(cve_id or "").upper()
    if not CVE_ID_RE.fullmatch(cve_id):
        raise OpenCVEError("Identifiant CVE invalide.")
    return _request_json("cves/" + urllib.parse.quote(cve_id, safe=""),
                         params={"include": "nvd_cpe_configurations,references"})


def get_cve_changes(cve_id: str, page: int = 1, page_size: int = 20) -> dict[str, Any]:
    cve_id = str(cve_id or "").upper()
    if not CVE_ID_RE.fullmatch(cve_id):
        raise OpenCVEError("Identifiant CVE invalide.")
    page = max(1, min(int(page), 10000))
    page_size = max(1, min(int(page_size), 100))
    return _request_json(
        "cves/" + urllib.parse.quote(cve_id, safe="") + "/changes",
        params={"page": page, "page_size": page_size},
    )
