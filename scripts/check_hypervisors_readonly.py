"""Run real, read-only inventory probes for configured hypervisor providers.

Usage inside the API container:
    docker compose exec -T api python scripts/check_hypervisors_readonly.py

The script never prints hostnames, VM names, credentials, tokens, or inventory
metadata. It only reports provider status and the number of discovered VMs.
"""
from __future__ import annotations

import sys

from app.hypervisors import HypervisorError, configured_providers, inventory


def main() -> int:
    providers = configured_providers()
    failures = 0
    configured = 0

    for provider in providers:
        name = provider["provider"]
        if not provider["configured"]:
            print(f"{name}: NON CONFIGURE (ignore)")
            continue

        configured += 1
        try:
            rows = inventory(name)
        except HypervisorError as exc:
            failures += 1
            print(f"{name}: ECHEC - {exc}")
        except Exception:
            failures += 1
            print(f"{name}: ECHEC - erreur inattendue (details masques)")
        else:
            if not all(row.get("read_only") is True for row in rows):
                failures += 1
                print(f"{name}: ECHEC - resultat sans garantie read-only")
            else:
                print(f"{name}: OK - {len(rows)} machine(s), lecture seule")

    print(f"Resume: {configured} fournisseur(s) configure(s), {failures} echec(s)")
    if configured == 0:
        print("Aucun connecteur configure: ce resultat ne valide aucune connexion reelle.")
        return 2
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
