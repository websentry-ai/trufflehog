# Kubernetes deployment (EKS / ArgoCD)

Deploys the `cmd/analyzer` HTTP service to Unbound's EKS clusters via ArgoCD,
mirroring the layout of the other websentry-ai service repos
(`k8s/chart` + per-env overlays at `k8s/<env>/values.yaml`).

```
k8s/
├── chart/                 # Helm chart (templated objects)
│   ├── Chart.yaml
│   ├── values.yaml        # base defaults
│   └── templates/         # deployment, service, externalsecret, ingress, hpa, servicemonitor
├── dev/values.yaml        # dev overlay      (secrets: dev/trufflehog)
├── staging/values.yaml    # staging overlay  (secrets: staging/trufflehog)
└── prod/values.yaml       # prod overlay     (secrets: prod/trufflehog)
```

## What gets deployed

The `cmd/analyzer` service (see `cmd/analyzer/main.go`):

- `POST /analyze` — Bearer-auth (`TRUFFLEHOG_API_KEY`), scans the request body for secrets.
- `GET /health` — unauthenticated, used by k8s probes.

Listens on `:8080`. Stateless and **internal-only** — reached over cluster DNS at
`trufflehog-<env>.<env>.svc.cluster.local:8080`. No public ingress by default.

## Image

Built and pushed by `.github/workflows/deploy-eks.yml` to
`228304386839.dkr.ecr.us-west-2.amazonaws.com/k8s/trufflehog`:

- push to `main` → `:<sha>` + `:dev`, then rollout `dev`
- `workflow_dispatch` (env=staging|prod) → `:<sha>` + `:<env>`; staging rolls out, prod is print-only.

## Secret (required — service exits without it)

`TRUFFLEHOG_API_KEY` is pulled from AWS Secrets Manager by External Secrets
Operator (`ClusterSecretStore: aws-secrets-manager`) via `dataFrom.extract`, so
the SM value **must be a JSON object**, not a plaintext string:

```json
{ "TRUFFLEHOG_API_KEY": "<random-bearer-token>" }
```

Paths: `dev/trufflehog`, `staging/trufflehog`, `prod/trufflehog`. The same token
must be configured on whatever calls `/analyze`.

The ArgoCD `Application` manifests live in `websentry-ai/unbound-infra` at
`argocd-apps/<env>/trufflehog.yaml`.
