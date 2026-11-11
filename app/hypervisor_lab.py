"""Explicit, read-only synthetic inventory for hypervisor integration testing."""
from __future__ import annotations
import os
from copy import deepcopy
from datetime import datetime, timezone

def lab_mode_enabled() -> bool:
    return os.getenv("CSV_HYPERVISOR_LAB_MODE", "false").strip().lower() in {"1", "true", "yes", "on"}

def lab_inventory() -> dict:
    """Return clearly labelled synthetic records; never contacts or writes to a provider."""
    if not lab_mode_enabled():
        return {"enabled": False, "mode": "disabled", "simulated": True, "read_only": True, "count": 0, "machines": []}
    stamp = datetime.now(timezone.utc).isoformat()
    machines = [
        {"provider":"vmware","vm_id":"lab-vmware-001","name":"CSV-LAB-DC01","state":"poweredOn","metadata":{"cpu_count":4,"memory_size_MiB":8192,"guest_OS":"Windows Server 2022","host":"esxi-lab-01"}},
        {"provider":"vmware","vm_id":"lab-vmware-002","name":"CSV-LAB-SOC01","state":"poweredOn","metadata":{"cpu_count":8,"memory_size_MiB":16384,"guest_OS":"Ubuntu 24.04","host":"esxi-lab-01"}},
        {"provider":"proxmox","vm_id":"lab-proxmox-101","name":"CSV-LAB-WEB01","state":"running","metadata":{"node":"pve-lab-01","vm_type":"qemu","cpu":2,"memory_bytes":4294967296}},
        {"provider":"proxmox","vm_id":"lab-proxmox-102","name":"CSV-LAB-DB01","state":"stopped","metadata":{"node":"pve-lab-02","vm_type":"qemu","cpu":4,"memory_bytes":8589934592}},
        {"provider":"virtualbox","vm_id":"lab-vbox-201","name":"CSV-LAB-KALI","state":"running","metadata":{"guest_os":"Debian 64-bit","memory_mb":4096,"cpu_count":2,"host":"workstation-lab"}},
        {"provider":"virtualbox","vm_id":"lab-vbox-202","name":"CSV-LAB-WIN11","state":"powered off","metadata":{"guest_os":"Windows 11 64-bit","memory_mb":8192,"cpu_count":4,"host":"workstation-lab"}},
        {"provider":"hyperv","vm_id":"lab-hyperv-301","name":"CSV-LAB-AD01","state":"Running","metadata":{"cpu_usage":3,"memory_assigned_bytes":8589934592,"version":"10.0","host":"hyperv-lab-01"}},
        {"provider":"hyperv","vm_id":"lab-hyperv-302","name":"CSV-LAB-APP01","state":"Off","metadata":{"cpu_usage":0,"memory_assigned_bytes":4294967296,"version":"10.0","host":"hyperv-lab-01"}},
    ]
    rows = []
    for machine in machines:
        rows.append({**deepcopy(machine), "last_seen": stamp, "source": "simulation",
                     "simulated": True, "read_only": True})
    return {"enabled": True, "mode": "simulation", "simulated": True, "read_only": True,
            "count": len(rows), "timestamp": stamp, "notice": "Données fictives de laboratoire — aucune connexion hyperviseur réelle.",
            "providers": ["vmware", "proxmox", "virtualbox", "hyperv"], "machines": rows}
