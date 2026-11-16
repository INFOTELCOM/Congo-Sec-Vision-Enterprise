"""Server-only Supabase Data API access for authenticated agent telemetry.

The service-role secret is read only from the backend environment. It must never
be sent to the browser or included in an agent package.
"""
import json
import os
import urllib.error
import urllib.parse
import urllib.request


def supabase_public_configured() -> bool:
    return bool(os.getenv("SUPABASE_URL", "").strip() and
                os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip())


def supabase_public_request(resource: str, method: str = "GET", payload=None):
    base = os.getenv("SUPABASE_URL", "").rstrip("/")
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    if not base or not key:
        raise RuntimeError("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required for SOC persistence")
    if method not in {"GET", "POST", "PATCH"}:
        raise ValueError("Unsupported Supabase method")
    url = base + "/rest/v1/" + resource.lstrip("/")
    headers = {
        "apikey": key,
        "Authorization": "Bearer " + key,
        "Accept": "application/json",
        "Accept-Profile": "public",
    }
    body = None
    if method != "GET":
        headers["Content-Type"] = "application/json"
        headers["Content-Profile"] = "public"
        headers["Prefer"] = "resolution=merge-duplicates,return=representation"
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read(1200).decode("utf-8", "replace")
        raise RuntimeError(f"Supabase Data API HTTP {exc.code}: {detail}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"Supabase Data API unavailable: {exc}") from None
    if not raw:
        return []
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RuntimeError("Invalid JSON response from Supabase Data API") from None
