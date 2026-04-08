# ims-remediation

GitOps content repository for the **IMS Remediation** ArgoCD application.

Managed by ArgoCD from the `IMS-Anomaly-Remediation` repo — do not apply these manifests manually.

## Repository layout

```
k8s/base/remediation/          # Kubernetes manifests (synced by ArgoCD)
  kustomization.yaml
  kafka-topic.yaml              # KafkaTopic: ims-remediation-events
  aap-credentials-secret.yaml  # Secret: AAP Controller credentials
  aap-template-configmap.yaml  # ConfigMap: bootstrap playbook
  aap-template-bootstrap-job.yaml  # PostSync Job: creates AAP template + EDA activation

rulebooks/
  kafka-remediation-trigger.yml  # EDA rulebook — listens on Kafka, fires AAP template

automation/ansible/playbooks/
  ims-remediation.yaml           # Calls Ansible Lightspeed API with lightspeed_prompt
```

## How it works

1. A Kafka message lands on `ims-remediation-events` with `{ "lightspeed_prompt": "..." }`.
2. The EDA rulebook picks it up and launches the `ims-remediation` AAP job template.
3. The job template calls the Ansible Lightspeed API and returns a generated playbook via `set_stats`.

## Setup

1. Push this repo to GitHub.
2. Update the `repoURL` placeholder in `IMS-Anomaly-Remediation/deploy/argocd/ims-remediation-application.yaml`.
3. Populate real credentials in `aap-credentials-secret.yaml` (or use SealedSecrets / Vault).
4. Set `lightspeed_wca_token` in the EDA activation variables via the AAP UI.
