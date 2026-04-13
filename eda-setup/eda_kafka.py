from __future__ import annotations

import base64
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List

import requests


class EDAKafkaError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Policy definitions
# Add new Kafka-based policies here. Each entry needs:
#   name        - human-readable activation name in EDA
#   rulebook    - path to the YAML file relative to the repo root
#   description - shown in EDA UI
#   event_types - informational, used by policy_catalog()
#   cases       - informational, used by policy_catalog()
#   extra_vars  - (optional) dict injected as extra_var on the EDA activation;
#                 template name should live in the rulebook YAML itself via
#                 "{{ workflow_template_name | default('...') }}"
# ---------------------------------------------------------------------------
POLICY_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "web_app_issue": {
        "name": "ANI Remediation",
        "rulebook": "rulebooks/web-app-issue.yml",
        "description": "Monitor Apache logs via Kafka and trigger AI workflow on shutdown events.",
        "event_types": ["kafka"],
        "cases": ["apache_shutdown"],
        "extra_vars": {},
    },
}


def enabled() -> bool:
    return os.getenv("EDA_KAFKA_ENABLED", "true").strip().lower() == "true"


def policy_catalog() -> List[Dict[str, Any]]:
    return [
        {
            "policy_key": key,
            "name": str(defn["name"]),
            "rulebook": str(defn["rulebook"]),
            "description": str(defn["description"]),
            "event_types": list(defn.get("event_types", [])),
            "cases": list(defn.get("cases", [])),
            "trigger_modes": ["event_driven"],
        }
        for key, defn in POLICY_DEFINITIONS.items()
    ]


def bootstrap_resources() -> Dict[str, Any]:
    if not enabled():
        return {"configured": False, "mode": "disabled", "policies": []}

    organization_id = _organization_id()
    project_id = _ensure_project(organization_id)
    _sync_project(project_id)
    decision_environment_id = _ensure_decision_environment(organization_id)
    awx_token_id = _ensure_awx_token_id()
    rulebooks = _rulebooks_by_name(project_id)

    policies: List[Dict[str, Any]] = []
    for policy_key, definition in POLICY_DEFINITIONS.items():
        rulebook_filename = _rulebook_name(policy_key)
        rulebook = rulebooks.get(rulebook_filename)
        if not rulebook:
            raise EDAKafkaError(
                f"Rulebook '{rulebook_filename}' was not found in EDA project '{_project_name()}' after sync."
            )
        activation = _ensure_activation(
            policy_key=policy_key,
            organization_id=organization_id,
            decision_environment_id=decision_environment_id,
            rulebook_id=int(rulebook["id"]),
            awx_token_id=awx_token_id,
        )
        policies.append(
            {
                "policy_key": policy_key,
                "name": str(activation.get("name") or definition["name"]),
                "activation_id": int(activation.get("id") or 0),
                "rulebook": rulebook_filename,
                "status": str(activation.get("status") or "unknown"),
            }
        )

    return {
        "configured": True,
        "mode": "eda-kafka",
        "organization": _organization_name(),
        "project_name": _project_name(),
        "project_id": project_id,
        "decision_environment_name": _decision_environment_name(),
        "decision_environment_id": decision_environment_id,
        "eda_url": _api_url(),
        "policies": policies,
    }


def status() -> Dict[str, Any]:
    if not enabled():
        return {"configured": False, "mode": "disabled", "live_configured": False, "policies": []}
    try:
        _request("GET", "/api/eda/v1/status/")
        organization_id = _organization_id()
        project = _find_named_item("/api/eda/v1/projects/", _project_name())
        decision_environment = _find_named_item("/api/eda/v1/decision-environments/", _decision_environment_name())
        policies = _policy_status()
        return {
            "configured": True,
            "mode": "eda-kafka",
            "live_configured": True,
            "eda_url": _api_url(),
            "organization": _organization_name(),
            "organization_id": organization_id,
            "project_name": _project_name(),
            "project_exists": project is not None,
            "project_import_state": str((project or {}).get("import_state") or ""),
            "decision_environment_name": _decision_environment_name(),
            "decision_environment_exists": decision_environment is not None,
            "bootstrapped": bool(project)
            and bool(decision_environment)
            and all(
                item.get("activation_exists") and item.get("enabled")
                for item in policies
            ),
            "policies": policies,
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "configured": True,
            "mode": "eda-kafka",
            "live_configured": False,
            "error": str(exc),
            "eda_url": _api_url(),
            "organization": _organization_name(),
            "project_name": _project_name(),
            "decision_environment_name": _decision_environment_name(),
            "policies": policy_catalog(),
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _ensure_activation(
    policy_key: str,
    organization_id: int,
    decision_environment_id: int,
    rulebook_id: int,
    awx_token_id: int,
) -> Dict[str, Any]:
    definition = POLICY_DEFINITIONS[policy_key]
    extra_vars = dict(definition.get("extra_vars") or {})

    desired = {
        "name": definition["name"],
        "description": definition["description"],
        "is_enabled": True,
        "decision_environment_id": decision_environment_id,
        "rulebook_id": rulebook_id,
        "organization_id": organization_id,
        "restart_policy": "always",
        "log_level": "info",
        "awx_token_id": awx_token_id,
        "extra_var": json.dumps(extra_vars) if extra_vars else "{}",
    }

    existing = _find_named_item("/api/eda/v1/activations/", definition["name"])
    if existing is None:
        return _request("POST", "/api/eda/v1/activations/", expected_status=(200, 201), json=desired)

    patch: Dict[str, Any] = {}
    decision_environment = existing.get("decision_environment") if isinstance(existing.get("decision_environment"), dict) else {}
    rulebook = existing.get("rulebook") if isinstance(existing.get("rulebook"), dict) else {}
    organization = existing.get("organization") if isinstance(existing.get("organization"), dict) else {}
    comparisons = {
        "description": existing.get("description"),
        "decision_environment_id": decision_environment.get("id"),
        "rulebook_id": rulebook.get("id"),
        "organization_id": organization.get("id"),
        "restart_policy": existing.get("restart_policy"),
        "log_level": existing.get("log_level"),
        "awx_token_id": existing.get("awx_token_id"),
        "extra_var": existing.get("extra_var"),
    }
    for field, current in comparisons.items():
        if current != desired[field]:
            patch[field] = desired[field]
    if patch:
        activation_id = int(existing["id"])
        if bool(existing.get("is_enabled")):
            _request("POST", f"/api/eda/v1/activations/{activation_id}/disable/", expected_status=(200, 201, 202))
            _wait_for_activation_stopped(activation_id)
        return _replace_activation(activation_id, str(definition["name"]), desired)
    if desired["is_enabled"] and not bool(existing.get("is_enabled")):
        _request("POST", f"/api/eda/v1/activations/{existing['id']}/enable/", expected_status=(200, 201, 202))
    return _request("GET", f"/api/eda/v1/activations/{existing['id']}/")


def _policy_status() -> List[Dict[str, Any]]:
    payload = _request("GET", "/api/eda/v1/activations/", params={"page_size": 200})
    activations = {
        str(item.get("name") or ""): item
        for item in payload.get("results", [])
        if isinstance(item, dict)
    }
    policies: List[Dict[str, Any]] = []
    for item in policy_catalog():
        activation = activations.get(str(item["name"]))
        activation_id = int(activation.get("id") or 0) if activation else 0
        policies.append(
            item | {
                "activation_exists": activation is not None,
                "activation_id": activation_id or None,
                "enabled": bool(activation.get("is_enabled")) if activation else False,
                "status": str(activation.get("status") or ("ready" if activation else "missing")),
            }
        )
    return policies


def _ensure_project(organization_id: int) -> int:
    desired = {
        "name": _project_name(),
        "description": "Kafka event-driven policies sourced from the cluster Git repository.",
        "organization_id": organization_id,
        "url": _project_url(),
        "verify_ssl": False if _project_url().startswith("http://") else True,
        "scm_type": "git",
        "scm_branch": _project_branch(),
    }
    existing = _find_named_item("/api/eda/v1/projects/", _project_name())
    if existing is None:
        project = _request("POST", "/api/eda/v1/projects/", expected_status=(200, 201), json=desired)
        return int(project["id"])
    patch: Dict[str, Any] = {}
    for field in ("description", "organization_id", "url", "verify_ssl", "scm_type", "scm_branch"):
        if existing.get(field) != desired[field]:
            patch[field] = desired[field]
    if patch:
        _request("PATCH", f"/api/eda/v1/projects/{existing['id']}/", expected_status=(200,), json=patch)
    return int(existing["id"])


def _sync_project(project_id: int) -> None:
    _request("POST", f"/api/eda/v1/projects/{project_id}/sync/", expected_status=(200, 201, 202, 409))
    deadline = time.time() + float(os.getenv("EDA_PROJECT_SYNC_TIMEOUT_SECONDS", "120"))
    last_state = "unknown"
    last_error = ""
    while time.time() < deadline:
        project = _request("GET", f"/api/eda/v1/projects/{project_id}/")
        if _rulebooks_by_name(project_id):
            return
        import_state = str(project.get("import_state") or "").strip().lower()
        import_error = str(project.get("import_error") or "").strip()
        last_state = import_state or "unknown"
        last_error = import_error
        if import_state in {"completed", "successful", "ready"}:
            if import_error:
                raise EDAKafkaError(f"EDA project import completed with errors for '{_project_name()}': {import_error}")
            return
        if import_state in {"failed", "error"}:
            raise EDAKafkaError(f"EDA project import failed for '{_project_name()}': {import_error or import_state}")
        time.sleep(4)
    if last_error:
        raise EDAKafkaError(f"EDA project sync timed out for '{_project_name()}' while waiting for rulebooks: {last_error}")
    raise EDAKafkaError(f"EDA project sync timed out for '{_project_name()}' with state '{last_state}'.")


def _ensure_decision_environment(organization_id: int) -> int:
    desired = {
        "name": _decision_environment_name(),
        "description": "Decision environment for Kafka event-driven policies.",
        "image_url": _decision_environment_image(),
        "organization_id": organization_id,
    }
    existing = _find_named_item("/api/eda/v1/decision-environments/", _decision_environment_name())
    if existing is None:
        environment = _request("POST", "/api/eda/v1/decision-environments/", expected_status=(200, 201), json=desired)
        return int(environment["id"])
    patch: Dict[str, Any] = {}
    for field in ("description", "image_url", "organization_id"):
        if existing.get(field) != desired[field]:
            patch[field] = desired[field]
    if patch:
        _request("PATCH", f"/api/eda/v1/decision-environments/{existing['id']}/", expected_status=(200,), json=patch)
    return int(existing["id"])


def _rulebooks_by_name(project_id: int) -> Dict[str, Dict[str, Any]]:
    payload = _request("GET", "/api/eda/v1/rulebooks/", params={"page_size": 200})
    return {
        str(item.get("name") or ""): item
        for item in payload.get("results", [])
        if isinstance(item, dict)
        and int(item.get("project_id") or 0) == project_id
        and str(item.get("name") or "")
    }


def _rulebook_name(policy_key: str) -> str:
    return str(POLICY_DEFINITIONS[policy_key]["rulebook"]).rsplit("/", 1)[-1]


def _wait_for_activation_stopped(activation_id: int) -> None:
    deadline = time.time() + float(os.getenv("EDA_ACTIVATION_STOP_TIMEOUT_SECONDS", "90"))
    while time.time() < deadline:
        activation = _request("GET", f"/api/eda/v1/activations/{activation_id}/")
        if not bool(activation.get("is_enabled")) and str(activation.get("status") or "").lower() in {"stopped", "disabled"}:
            return
        time.sleep(3)
    raise EDAKafkaError(f"EDA activation {activation_id} did not stop within the configured timeout.")


def _replace_activation(activation_id: int, activation_name: str, desired: Dict[str, Any]) -> Dict[str, Any]:
    _request("DELETE", f"/api/eda/v1/activations/{activation_id}/", expected_status=(200, 202, 204))
    deadline = time.time() + float(os.getenv("EDA_ACTIVATION_RECREATE_TIMEOUT_SECONDS", "90"))
    while time.time() < deadline:
        if _find_named_item("/api/eda/v1/activations/", activation_name) is None:
            return _request("POST", "/api/eda/v1/activations/", expected_status=(200, 201), json=desired)
        time.sleep(3)
    raise EDAKafkaError(f"EDA activation '{activation_name}' was not deleted before recreate timed out.")


def _ensure_awx_token_id() -> int:
    name = _controller_token_name()
    payload = _request("GET", "/api/eda/v1/users/me/awx-tokens/", params={"page_size": 200})
    for item in payload.get("results", []):
        if isinstance(item, dict) and str(item.get("name") or "") == name:
            return int(item["id"])

    controller_user = _controller_request("GET", "/api/v2/me/")
    results = controller_user.get("results") if isinstance(controller_user.get("results"), list) else []
    if not results:
        raise EDAKafkaError("AAP controller did not return the current user needed to create an EDA controller token.")
    controller_user_id = int(results[0]["id"])

    existing_tokens = _controller_request("GET", f"/api/v2/users/{controller_user_id}/personal_tokens/", params={"page_size": 200})
    for item in existing_tokens.get("results", []):
        if isinstance(item, dict) and str(item.get("description") or "") == name:
            _controller_request("DELETE", f"/api/v2/tokens/{item['id']}/", expected_status=(204,))

    created_token = _controller_request(
        "POST",
        f"/api/v2/users/{controller_user_id}/personal_tokens/",
        expected_status=(200, 201),
        json={"description": name, "application": None, "scope": "write"},
    )
    token_value = str(created_token.get("token") or "").strip()
    if not token_value:
        raise EDAKafkaError("AAP controller did not return a token value for Event-Driven Ansible.")

    created_awx_token = _request(
        "POST",
        "/api/eda/v1/users/me/awx-tokens/",
        expected_status=(200, 201),
        json={"name": name, "description": "Controller token used by EDA for Kafka-triggered workflow templates.", "token": token_value},
    )
    return int(created_awx_token["id"])


# ---------------------------------------------------------------------------
# Config helpers — use EDA_KAFKA_* env vars where project-specific,
# fall back to shared EDA_* vars for credentials and API URL.
# ---------------------------------------------------------------------------

def _api_url() -> str:
    return (os.getenv("EDA_API_URL", "").strip() or "http://aap-eda-api.aap.svc.cluster.local:8000").rstrip("/")


def _username() -> str:
    return os.getenv("EDA_USERNAME", "admin").strip() or "admin"


def _password() -> str:
    explicit = os.getenv("EDA_PASSWORD", "").strip()
    if explicit:
        return explicit
    namespace = os.getenv("EDA_PASSWORD_SECRET_NAMESPACE", "aap").strip() or "aap"
    name = os.getenv("EDA_PASSWORD_SECRET_NAME", "aap-eda-admin-password").strip() or "aap-eda-admin-password"
    key = os.getenv("EDA_PASSWORD_SECRET_KEY", "password").strip() or "password"
    return _read_kubernetes_secret_key(namespace, name, key)


def _api_verify() -> bool | str:
    verify_ssl = os.getenv("EDA_VERIFY_SSL", "").strip().lower()
    if verify_ssl in {"false", "0", "no"}:
        return False
    ca_path = os.getenv("EDA_CA_PATH", "").strip()
    if ca_path:
        return ca_path
    return True


def _organization_name() -> str:
    return os.getenv("EDA_ORGANIZATION", "Default").strip() or "Default"


def _organization_id() -> int:
    explicit = os.getenv("EDA_ORGANIZATION_ID", "").strip()
    if explicit.isdigit():
        return int(explicit)
    payload = _request("GET", "/api/eda/v1/organizations/", params={"name": _organization_name(), "page_size": 200})
    for item in payload.get("results", []):
        if str(item.get("name") or "") == _organization_name():
            return int(item["id"])
    raise EDAKafkaError(f"EDA organization '{_organization_name()}' was not found.")


def _project_name() -> str:
    return os.getenv("EDA_KAFKA_PROJECT_NAME", "IMS Kafka Event Policies").strip() or "IMS Kafka Event Policies"


def _project_url() -> str:
    return (
        os.getenv("EDA_PROJECT_URL", "").strip()
        or "http://gitea-http.gitea.svc.cluster.local:3000/gitadmin/IMS-Anomaly-Detection-with-Red-Hat-OpenShift-AI.git"
    )


def _project_branch() -> str:
    return os.getenv("EDA_PROJECT_BRANCH", "main").strip() or "main"


def _decision_environment_name() -> str:
    return os.getenv("EDA_KAFKA_DECISION_ENVIRONMENT_NAME", "IMS Kafka Decisions").strip() or "IMS Kafka Decisions"


def _decision_environment_image() -> str:
    return (
        os.getenv("EDA_DECISION_ENVIRONMENT_IMAGE", "").strip()
        or "registry.redhat.io/ansible-automation-platform-26/de-minimal-rhel9:latest"
    )


def _controller_url() -> str:
    return (os.getenv("AAP_CONTROLLER_URL", "").strip() or "http://aap-controller-service.aap.svc.cluster.local").rstrip("/")


def _controller_username() -> str:
    return os.getenv("AAP_CONTROLLER_USERNAME", "admin").strip() or "admin"


def _controller_password() -> str:
    explicit = os.getenv("AAP_CONTROLLER_PASSWORD", "").strip()
    if explicit:
        return explicit
    namespace = os.getenv("AAP_CONTROLLER_PASSWORD_SECRET_NAMESPACE", "aap").strip() or "aap"
    name = os.getenv("AAP_CONTROLLER_PASSWORD_SECRET_NAME", "aap-controller-admin-password").strip() or "aap-controller-admin-password"
    key = os.getenv("AAP_CONTROLLER_PASSWORD_SECRET_KEY", "password").strip() or "password"
    return _read_kubernetes_secret_key(namespace, name, key)


def _controller_verify() -> bool | str:
    if _controller_url().startswith("http://"):
        return False
    verify_ssl = os.getenv("AAP_CONTROLLER_VERIFY_SSL", "").strip().lower()
    if verify_ssl in {"false", "0", "no"}:
        return False
    ca_path = os.getenv("AAP_CONTROLLER_CA_PATH", "").strip()
    if ca_path:
        return ca_path
    return True


def _controller_token_name() -> str:
    return os.getenv("EDA_KAFKA_CONTROLLER_TOKEN_NAME", "IMS EDA Kafka Controller Token").strip() or "IMS EDA Kafka Controller Token"


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _request(
    method: str,
    path: str,
    expected_status: tuple[int, ...] = (200,),
    **kwargs: Any,
) -> Dict[str, Any]:
    response = requests.request(
        method,
        f"{_api_url()}{path}",
        auth=(_username(), _password()),
        verify=_api_verify(),
        timeout=float(os.getenv("EDA_API_TIMEOUT_SECONDS", "30")),
        headers={"Content-Type": "application/json", **kwargs.pop("headers", {})},
        **kwargs,
    )
    if response.status_code not in expected_status:
        raise EDAKafkaError(f"EDA request failed for {method} {path}: {response.status_code} {response.text[:400]}")
    if not response.text.strip():
        return {}
    try:
        return response.json()
    except ValueError as exc:
        raise EDAKafkaError(f"EDA returned non-JSON content for {method} {path}.") from exc


def _controller_request(
    method: str,
    path: str,
    expected_status: tuple[int, ...] = (200,),
    **kwargs: Any,
) -> Dict[str, Any]:
    response = requests.request(
        method,
        f"{_controller_url()}{path}",
        auth=(_controller_username(), _controller_password()),
        verify=_controller_verify(),
        timeout=float(os.getenv("AAP_CONTROLLER_TIMEOUT_SECONDS", "30")),
        headers={"Content-Type": "application/json", **kwargs.pop("headers", {})},
        **kwargs,
    )
    if response.status_code not in expected_status:
        raise EDAKafkaError(f"Controller request failed for {method} {path}: {response.status_code} {response.text[:400]}")
    if not response.text.strip():
        return {}
    try:
        return response.json()
    except ValueError as exc:
        raise EDAKafkaError(f"Controller returned non-JSON content for {method} {path}.") from exc


def _find_named_item(path: str, name: str) -> Dict[str, Any] | None:
    payload = _request("GET", path, params={"name": name, "page_size": 200})
    for item in payload.get("results", []):
        if isinstance(item, dict) and str(item.get("name") or "") == name:
            return item
    return None


def _read_kubernetes_secret_key(namespace: str, name: str, key: str) -> str:
    token = Path("/var/run/secrets/kubernetes.io/serviceaccount/token").read_text(encoding="utf-8").strip()
    ca_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    host = os.getenv("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc").strip() or "kubernetes.default.svc"
    port = os.getenv("KUBERNETES_SERVICE_PORT_HTTPS", "443").strip() or "443"
    response = requests.get(
        f"https://{host}:{port}/api/v1/namespaces/{namespace}/secrets/{name}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        verify=ca_path,
        timeout=float(os.getenv("EDA_KUBERNETES_TIMEOUT_SECONDS", "15")),
    )
    if response.status_code != 200:
        raise EDAKafkaError(f"Kubernetes secret {namespace}/{name} could not be read: {response.status_code}")
    data = response.json().get("data") or {}
    encoded = str(data.get(key) or "").strip()
    if not encoded:
        raise EDAKafkaError(f"Kubernetes secret {namespace}/{name} does not contain key '{key}'.")
    return base64.b64decode(encoded).decode("utf-8").strip()
