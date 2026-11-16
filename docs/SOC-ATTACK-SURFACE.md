# SOC Attack Surface — endpoint and network monitoring

The Threats & Events page combines endpoint telemetry with an explicitly authorized private-LAN scan.

## Endpoint agent telemetry

Agent version 0.3.0 reports:
- OS installation date only when the operating system provides a usable source (Windows WMI; Linux installer-file birth time when available).
- Installed software name, version, publisher, install date where available, install scope and install location.
- Running processes and local TCP listening / UDP-bound sockets.
- Microsoft Defender status, real-time protection, antispyware, signature date and Defender detection history on Windows.
- ClamAV presence/version on Linux. Presence is not reported as a completed malware scan.
- Windows event provider, channel, event ID, record ID, UTC timestamp and Unicode message.

The agent does not run a full malware scan on every heartbeat. Malware detections shown in the SOC are sourced from the endpoint protection product's own detection history. Other antivirus products require a vendor-specific connector for authoritative scan results.

## Network discovery and port scan

Endpoint discovery and the manual scan are limited to private, non-loopback, non-link-local networks of at most 256 addresses. The scan checks a fixed list of common TCP ports; it does not exploit services, brute-force credentials or capture packet payloads. UDP is not scanned by this feature.

A device is included when it responds to ICMP or exposes one of the checked TCP ports. Devices that block both may remain undiscovered. Service versions are displayed only when a recognizable banner is returned; otherwise the version remains unknown.

## CVE correlation

- Installed-software CVE candidates are produced by the existing NVD/CPE sync process.
- Network service CVE candidates are queried only when a service banner yields a product and version.
- CVSS, EPSS and CISA KEV metadata are retained when available.
- Every match remains a candidate / needs-validation until an analyst verifies product edition, affected version range, vendor backports and actual exposure. An open port alone is not a vulnerability.

## Supabase persistence

The schema stores network devices, listening ports, endpoint protection observations, malware detections, scan runs, software installation metadata and CVE-to-IP/port associations. New tables use RLS and role-based read/write policies. The API writes through the server-side service-role key; that key must never be embedded in the browser or agent.

## API routes

- `GET /api/surveillance/attack-surface`
- `POST /api/network/attack-surface-scan` with JSON body `{"cidr":"192.168.1.0/24"}`

The POST route requires an analyst-capable session and a configured server-side `SUPABASE_SERVICE_ROLE_KEY`.
