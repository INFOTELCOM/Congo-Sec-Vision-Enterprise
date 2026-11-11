# Hypervisor inventory connectors

This change introduces an isolated, read-only connector layer. It does not yet add UI controls or mutate the SOC database. The existing API, dashboard, agent, and SQLite persistence remain untouched.

## Supported inventory paths

| Provider | Inventory mechanism | Required placement |
|---|---|---|
| VMware vSphere | vSphere REST API (/api/session, /api/vcenter/vm) | API host can reach vCenter |
| Proxmox VE | Proxmox REST API (/api2/json/cluster/resources?type=vm) | API host can reach Proxmox |
| VirtualBox | Local VBoxManage list vms --long | API process runs on VirtualBox host |
| Hyper-V | PowerShell inventory over WinRM HTTPS | API host can reach Windows Hyper-V host on TCP 5986 |

VirtualBox is not treated as a generic REST API: its connector uses the host-side VBoxManage CLI. Hyper-V uses WinRM with HTTPS; do not expose WinRM to the public Internet.

## Server-side environment variables

Configure only the providers actually used. Never place credentials in the browser, dashboard configuration, Git, or chat.

### VMware
- CSV_VMWARE_URL — vCenter base URL, for example https://vcenter.example.org
- CSV_VMWARE_USERNAME
- CSV_VMWARE_PASSWORD
- CSV_VMWARE_VERIFY_TLS=true (default; keep certificate validation enabled)

Use a dedicated vCenter account with inventory-read privileges only.

### Proxmox
- CSV_PROXMOX_URL — base URL, for example https://pve.example.org:8006
- CSV_PROXMOX_TOKEN_ID — API token identity, for example csv-readonly@pve!inventory
- CSV_PROXMOX_TOKEN_SECRET
- CSV_PROXMOX_VERIFY_TLS=true (default)

Create a dedicated Proxmox role/token with only permissions required to view cluster and VM inventory.

### VirtualBox
- CSV_VBOXMANAGE_PATH=VBoxManage (default) or an absolute path to VBoxManage.
- The API service must run on the VirtualBox host and under an OS account allowed to query the local VirtualBox service.

### Hyper-V
- CSV_HYPERV_HOST — host name or explicit WinRM HTTPS endpoint
- CSV_HYPERV_USERNAME
- CSV_HYPERV_PASSWORD
- CSV_HYPERV_TRANSPORT=ntlm (default; use the organization's approved authentication method)

Enable and firewall WinRM HTTPS deliberately. Use a certificate trusted by the API host. The Hyper-V connector requires the pinned pywinrm package.

## Safety boundaries

- Inventory reads only VM metadata and resource/state fields.
- No start, stop, restart, snapshot, delete, console, migration, or VM configuration operation is implemented.
- TLS certificate validation is enabled by default.
- Credentials are read from process environment and are never returned by connector status.
- Provider errors are sanitized to avoid returning response bodies or credentials.
- Each provider is independent: an unavailable provider should not prevent querying another provider.
- Do not connect a provider to production until a dedicated read-only service account and network ACL are configured.

## Current integration boundary

The connector library and unit tests are added on a dedicated feature branch. API routes, RBAC checks, persistence in the existing Supabase soc schema, dashboard integration, and production deployment are intentionally deferred until the existing authentication PRs are reconciled and tested. This prevents a new endpoint from inheriting the current main branch's session-only authorization behavior.
