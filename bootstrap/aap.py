from __future__ import annotations

import base64
import os
import time
from pathlib import Path
from typing import Any, Dict

import requests


class AAPBootstrapError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Template definitions
# ---------------------------------------------------------------------------

TEMPLATE_DEFINITIONS: Dict[str, Dict[str, str]] = {
    "ims_remediation": {
        "job_template_name": "IMS Remediation - Lightspeed Playbook Generator",
        "playbook": "automation/ansible/playbooks/ims-remediation.yaml",
        "description": (
            "Calls the Ansible Lightspeed API with a given lightspeed_prompt "
            "and returns a generated playbook. Triggered via Kafka EDA events."
        ),
    },
}

TERMINAL_JOB_STATUSES = {"successful", "failed", "error", "canceled"}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def bootstrap_resources() -> Dict[str, Any]:
    """Create or update all AAP resources required by ims-remediation."""
    organization_id = _require_object_id("/api/v2/organizations/", _organization_name(), "organization")
    inventory_id    = _ensure_inventory(organization_id)
    project_id      = _ensure_project(organization_id)
    _sync_project(project_id)

    templates = []
    for key, definition in TEMPLATE_DEFINITIONS.items():
        template_id = _ensure_job_template(
            organization_id=organization_id,
            inventory_id=inventory_id,
            project_id=project_id,
            key=key,
            playbook=definition["playbook"],
            description=definition["description"],
        )
        templates.append(
            {
                "key": key,
                "name": _job_template_name(key),
                "job_template_id": template_id,
                "playbook": definition["playbook"],
            }
        )

    return {
        "configured": True,
        "organization": _organization_name(),
        "inventory_name": _inventory_name(),
        "inventory_id": inventory_id,
        "project_name": _project_name(),
        "project_id": project_id,
        "templates": templates,
    }


def controller_status() -> Dict[str, Any]:
    """Return the live status of AAP resources for ims-remediation."""
    try:
        ping            = _request("GET", "/api/v2/ping/")
        project_payload = _request("GET", "/api/v2/projects/",      params={"name": _project_name(),    "page_size": 200})
        template_payload = _request("GET", "/api/v2/job_templates/", params={"page_size": 200})

        project_exists = any(
            str(item.get("name") or "") == _project_name()
            for item in project_payload.get("results", [])
        )
        existing = {
            str(item.get("name") or ""): int(item.get("id") or 0)
            for item in template_payload.get("results", [])
        }
        templates = [
            {
                "key": key,
                "name": _job_template_name(key),
                "playbook": d["playbook"],
                "template_exists": bool(existing.get(_job_template_name(key))),
                "job_template_id": existing.get(_job_template_name(key)),
            }
            for key, d in TEMPLATE_DEFINITIONS.items()
        ]
        return {
            "configured": True,
            "live_configured": True,
            "version": ping.get("version"),
            "controller_url": _controller_url(),
            "project_name": _project_name(),
            "project_exists": project_exists,
            "bootstrapped": project_exists and all(t["template_exists"] for t in templates),
            "templates": templates,
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "configured": True,
            "live_configured": False,
            "error": str(exc),
            "controller_url": _controller_url(),
        }


# ---------------------------------------------------------------------------
# Environment helpers
# ---------------------------------------------------------------------------

def _controller_url() -> str:
    return (
        os.getenv("AAP_CONTROLLER_URL", "").strip()
        or "http://aap-controller-service.aap.svc.cluster.local"
    ).rstrip("/")


def _controller_username() -> str:
    return os.getenv("AAP_CONTROLLER_USERNAME", "admin").strip() or "admin"


def _controller_password() -> str:
    explicit = os.getenv("AAP_CONTROLLER_PASSWORD", "").strip()
    if explicit:
        return explicit
    namespace = os.getenv("AAP_CONTROLLER_PASSWORD_SECRET_NAMESPACE", "aap").strip() or "aap"
    name      = os.getenv("AAP_CONTROLLER_PASSWORD_SECRET_NAME", "aap-controller-admin-password").strip() or "aap-controller-admin-password"
    key       = os.getenv("AAP_CONTROLLER_PASSWORD_SECRET_KEY", "password").strip() or "password"
    return _read_kubernetes_secret_key(namespace, name, key)


def _controller_verify() -> bool | str:
    val = os.getenv("AAP_CONTROLLER_VERIFY_SSL", "").strip().lower()
    if val in {"false", "0", "no"}:
        return False
    ca_path = os.getenv("AAP_CONTROLLER_CA_PATH", "").strip()
    return ca_path if ca_path else True


def _organization_name() -> str:
    return os.getenv("AAP_ORGANIZATION", "Default").strip() or "Default"


def _inventory_name() -> str:
    return os.getenv("AAP_INVENTORY_NAME", "IMS Remediation Inventory").strip() or "IMS Remediation Inventory"


def _project_name() -> str:
    return os.getenv("AAP_PROJECT_NAME", "IMS Remediation").strip() or "IMS Remediation"


def _project_scm_url() -> str:
    return (
        os.getenv("AAP_PROJECT_SCM_URL", "").strip()
        or "https://github.com/<your-org>/ims-remediation.git"
    )


def _project_branch() -> str:
    return os.getenv("AAP_PROJECT_BRANCH", "main").strip() or "main"


def _job_template_name(key: str) -> str:
    definition = TEMPLATE_DEFINITIONS.get(key) or {}
    env_name = f"AAP_JOB_TEMPLATE_{key.upper()}"
    return os.getenv(env_name, definition.get("job_template_name", key)).strip() or key


# ---------------------------------------------------------------------------
# Ensure helpers  (create-or-patch, mirrors existing aap.py pattern)
# ---------------------------------------------------------------------------

def _ensure_inventory(organization_id: int) -> int:
    name    = _inventory_name()
    payload = _request("GET", "/api/v2/inventories/", params={"name": name, "page_size": 200})
    inv     = next((i for i in payload.get("results", []) if str(i.get("name") or "") == name), None)
    desired = {
        "name": name,
        "organization": organization_id,
        "description": "Local execution inventory for IMS Remediation Lightspeed playbook jobs.",
    }
    if inv is None:
        inv = _request("POST", "/api/v2/inventories/", expected_status=(200, 201), json=desired)
    _ensure_inventory_host(int(inv["id"]))
    return int(inv["id"])


def _ensure_inventory_host(inventory_id: int) -> None:
    host_name = "localhost"
    payload   = _request("GET", f"/api/v2/inventories/{inventory_id}/hosts/", params={"name": host_name, "page_size": 200})
    if any(str(i.get("name") or "") == host_name for i in payload.get("results", [])):
        return
    _request(
        "POST",
        f"/api/v2/inventories/{inventory_id}/hosts/",
        expected_status=(200, 201),
        json={
            "name": host_name,
            "description": "Local execution target inside the AAP execution environment.",
            "variables": "ansible_connection: local\nansible_python_interpreter: /usr/bin/python3\n",
        },
    )


def _ensure_project(organization_id: int) -> int:
    name    = _project_name()
    payload = _request("GET", "/api/v2/projects/", params={"name": name, "page_size": 200})
    project = next((i for i in payload.get("results", []) if str(i.get("name") or "") == name), None)
    desired: Dict[str, Any] = {
        "name": name,
        "organization": organization_id,
        "description": "IMS Remediation automation sourced from the ims-remediation GitHub repository.",
        "scm_type": "git",
        "scm_url": _project_scm_url(),
        "scm_branch": _project_branch(),
        "scm_update_on_launch": True,
        "allow_override": False,
    }
    if project is None:
        project = _request("POST", "/api/v2/projects/", expected_status=(200, 201), json=desired)
        return int(project["id"])
    patch: Dict[str, Any] = {}
    for field in ("scm_url", "scm_branch", "scm_update_on_launch", "allow_override", "description"):
        if project.get(field) != desired[field]:
            patch[field] = desired[field]
    if patch:
        _request("PATCH", f"/api/v2/projects/{project['id']}/", json=patch)
    return int(project["id"])


def _sync_project(project_id: int) -> None:
    payload   = _request("POST", f"/api/v2/projects/{project_id}/update/", expected_status=(200, 202), json={})
    update_id = int(payload.get("project_update") or payload.get("id") or 0)
    if update_id <= 0:
        return
    deadline = time.time() + float(os.getenv("AAP_PROJECT_SYNC_TIMEOUT_SECONDS", "120"))
    while time.time() < deadline:
        update = _request("GET", f"/api/v2/project_updates/{update_id}/")
        status = str(update.get("status") or "").strip().lower()
        if status == "successful":
            return
        if status in {"failed", "error", "canceled"}:
            raise AAPBootstrapError(
                f"AAP project sync failed for '{_project_name()}': {update.get('result_traceback') or status}"
            )
        time.sleep(4)
    raise AAPBootstrapError(f"AAP project sync timed out for '{_project_name()}'.")


def _ensure_job_template(
    organization_id: int,
    inventory_id: int,
    project_id: int,
    key: str,
    playbook: str,
    description: str,
) -> int:
    name    = _job_template_name(key)
    payload = _request("GET", "/api/v2/job_templates/", params={"name": name, "page_size": 200})
    template = next((i for i in payload.get("results", []) if str(i.get("name") or "") == name), None)
    desired: Dict[str, Any] = {
        "name": name,
        "description": description,
        "job_type": "run",
        "inventory": inventory_id,
        "project": project_id,
        "organization": organization_id,
        "playbook": playbook,
        "ask_variables_on_launch": True,
        "verbosity": 1,
        # Default extra_vars — overridden at launch time by EDA via lightspeed_prompt
        "extra_vars": (
            "input_lightspeed_url: https://c.ai.ansible.redhat.com/api/v0/ai/generations/\n"
            "lightspeed_wca_token: \"\"\n"
            "lightspeed_prompt: \"\"\n"
        ),
    }
    if template is None:
        template = _request("POST", "/api/v2/job_templates/", expected_status=(200, 201), json=desired)
        return int(template["id"])
    patch: Dict[str, Any] = {}
    for field in ("description", "inventory", "project", "organization", "playbook",
                  "ask_variables_on_launch", "verbosity", "extra_vars"):
        if template.get(field) != desired[field]:
            patch[field] = desired[field]
    if patch:
        _request("PATCH", f"/api/v2/job_templates/{template['id']}/", json=patch)
    return int(template["id"])


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _require_object_id(path: str, name: str, label: str) -> int:
    payload = _request("GET", path, params={"name": name, "page_size": 200})
    for item in payload.get("results", []):
        if str(item.get("name") or "") == name:
            return int(item["id"])
    raise AAPBootstrapError(f"AAP {label} '{name}' was not found.")


def _request(
    method: str,
    path: str,
    expected_status: tuple[int, ...] = (200,),
    **kwargs: Any,
) -> Dict[str, Any]:
    url = f"{_controller_url()}{path}"
    response = requests.request(
        method,
        url,
        auth=(_controller_username(), _controller_password()),
        verify=_controller_verify(),
        timeout=float(os.getenv("AAP_CONTROLLER_TIMEOUT_SECONDS", "30")),
        headers={"Content-Type": "application/json", **kwargs.pop("headers", {})},
        **kwargs,
    )
    if response.status_code not in expected_status:
        raise AAPBootstrapError(
            f"AAP request failed {method} {path}: {response.status_code} {response.text[:400]}"
        )
    if not response.text.strip():
        return {}
    try:
        return response.json()
    except ValueError as exc:
        raise AAPBootstrapError(f"AAP returned non-JSON for {method} {path}.") from exc


def _read_kubernetes_secret_key(namespace: str, name: str, key: str) -> str:
    token   = Path("/var/run/secrets/kubernetes.io/serviceaccount/token").read_text(encoding="utf-8").strip()
    ca_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    host    = os.getenv("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
    port    = os.getenv("KUBERNETES_SERVICE_PORT_HTTPS", "443")
    response = requests.get(
        f"https://{host}:{port}/api/v1/namespaces/{namespace}/secrets/{name}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        verify=ca_path,
        timeout=15,
    )
    if response.status_code not in (200,):
        raise AAPBootstrapError(f"Could not read Kubernetes secret {namespace}/{name}: {response.status_code}")
    data    = response.json().get("data") or {}
    encoded = str(data.get(key) or "").strip()
    if not encoded:
        raise AAPBootstrapError(f"Kubernetes secret {namespace}/{name} has no key '{key}'.")
    return base64.b64decode(encoded).decode("utf-8").strip()
