# Hypervisor inventory connectors

The read-only connectors are wired to authenticated FastAPI routes and the Hypervisors dashboard page. Inventory snapshots are upserted into the existing Supabase project in soc.hypervisor_inventory. The legacy endpoint/CVE/incident modules still use SQLite and are not silently migrated by this feature.

## Supported inventory paths

| Provider | Inventory mechanism | Required placement |
|---|---|---|
| VMware vSphere | vSphere REST API (/api/session, /api/vcenter/vm) | API host can reach vCenter |
| Proxmox VE | Proxmox REST API (/api2/json/cluster/resources?type=vm) | API host can reach Proxmox |
| VirtualBox | Local VBoxManage list vms --long | API process runs on VirtualBox host |
| Hyper-V | PowerShell inventory over WinRM HTTPS | API host can reach Windows Hyper-V host on TCP 5986 |

VirtualBox is not treated as a generic REST API: its connector uses the VBoxManage CLI on the same operating-system host as the API process. The current Docker image does not install VBoxManage and a container cannot execute a host-installed binary just because it exists on the Docker host. Therefore VirtualBox inventory is not available in the standard Docker deployment yet; do not mount host binaries or the VirtualBox kernel device as an ad-hoc workaround. It requires a separately designed and authenticated host-side collector, or running the API natively on the VirtualBox host. Hyper-V uses WinRM with HTTPS; do not expose WinRM to the public Internet.

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

## API and Supabase integration

- GET /api/hypervisors/providers reports non-sensitive connector configuration status.
- GET /api/hypervisors/inventory reads the SOC inventory through the existing user's Supabase JWT.
- POST /api/hypervisors/sync requires admin or analyst and upserts discovered VM metadata.
- The backend uses the publishable key plus the caller's JWT; it does not use service_role.
- Apply the versioned migration in supabase/migrations and add soc to Supabase Dashboard → Project Settings → API → Exposed schemas. The SQL migration grants schema usage and table privileges, but Supabase's Data API will not route custom schemas until soc is exposed.
- RLS policies restrict inventory reads to recognized SOC roles and writes to admin/analyst.

## Integration boundary

The connector library, API routes, dashboard, tests, and additive Supabase migration are included. No live hypervisor has been connected yet because provider endpoints and read-only credentials must be configured on the API host. The complete historical SQLite-to-PostgreSQL migration is not included: each legacy data domain needs an export, schema mapping, reconciliation, backup, and rollback plan. Production deployment is not performed from this feature branch.
