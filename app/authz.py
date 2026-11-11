"""Server-side authorization helpers for Supabase user payloads."""

def is_admin_user(user: dict) -> bool:
    """Trust only Supabase app_metadata, never user-editable user_metadata."""
    metadata = user.get("app_metadata") or {}
    if not isinstance(metadata, dict):
        return False
    role = str(metadata.get("role") or "").strip().lower()
    roles = metadata.get("roles") or []
    if not isinstance(roles, (list, tuple, set)):
        roles = []
    return role in {"admin", "owner"} or any(
        str(item).strip().lower() in {"admin", "owner"} for item in roles
    )
