"""Server-side role extraction from Supabase-controlled app_metadata."""

VALID_ROLES = frozenset({"admin", "analyst", "viewer", "incident_responder"})


def get_user_roles(user: dict) -> frozenset[str]:
    """Return only recognized roles from server-controlled Supabase app_metadata."""
    metadata = user.get("app_metadata") or {}
    if not isinstance(metadata, dict):
        return frozenset()

    raw_roles = []
    role = metadata.get("role")
    if isinstance(role, str):
        raw_roles.append(role)
    roles = metadata.get("roles") or []
    if isinstance(roles, (list, tuple, set)):
        raw_roles.extend(item for item in roles if isinstance(item, str))

    normalized = set()
    for item in raw_roles:
        value = item.strip().lower().replace("-", "_").replace(" ", "_")
        if value == "owner":
            value = "admin"
        if value in VALID_ROLES:
            normalized.add(value)
    return frozenset(normalized)


def has_any_role(user: dict, allowed_roles) -> bool:
    """Check an explicit allow-list; never trust user-editable user_metadata."""
    return bool(get_user_roles(user).intersection(set(allowed_roles)))


def is_admin_user(user: dict) -> bool:
    """Compatibility helper for code that requires a privileged administrator."""
    return has_any_role(user, {"admin"})
