"""
Entry point for the ims-remediation AAP bootstrap job.

Runs once (as a Kubernetes PostSync Job managed by ArgoCD) to create
the IMS Remediation job template in AAP Controller via its REST API.
Mirrors the bootstrap pattern used by services/shared/aap.py in
IMS-Anomaly-Remediation.
"""
from __future__ import annotations

import json
import sys

import aap


def main() -> None:
    print("=== IMS Remediation AAP Bootstrap ===")

    print("\n[1/2] Checking AAP Controller status...")
    status = aap.controller_status()
    print(json.dumps(status, indent=2))

    if status.get("bootstrapped"):
        print("\n[✓] AAP resources already configured — nothing to do.")
        return

    print("\n[2/2] Bootstrapping AAP resources...")
    result = aap.bootstrap_resources()
    print(json.dumps(result, indent=2))

    print("\n[✓] Bootstrap complete.")
    for t in result.get("templates", []):
        print(f"    • {t['name']}  (id={t['job_template_id']}, playbook={t['playbook']})")


if __name__ == "__main__":
    try:
        main()
    except aap.AAPBootstrapError as exc:
        print(f"\n[✗] Bootstrap failed: {exc}", file=sys.stderr)
        sys.exit(1)
