# Kubernetes Deployment

Aegis ships a Helm chart ([`deploy/helm/aegis`](deploy/helm/aegis)) that deploys
the full stack — API, orchestrator, scanner, web, plus in-chart PostgreSQL and
Redis — with autoscaling, network policies, hardened pod security, secrets
management, and observability hooks.

Verified with `helm lint` (0 failures) and `helm template` (renders 28 objects:
4 Deployments, 2 StatefulSets, 5 Services, 3 HPAs + PodDisruptionBudgets,
Ingress, migrate Job, 5 NetworkPolicies, Secret/ExternalSecret, ServiceMonitor,
PrometheusRule).

## Quick start

```bash
helm install aegis deploy/helm/aegis \
  --namespace aegis --create-namespace \
  --set image.tag=2.0 \
  --set config.dashboardURL=https://aegis.example.com \
  --set ingress.host=aegis.example.com \
  --set secrets.existingSecret=aegis-secrets   # create this first (see Secrets)
```

Migrations run automatically as a `pre-install`/`pre-upgrade` hook (the migrate
Job, weight −5) before any app pod starts.

## Values highlights

| Key | Purpose |
| --- | --- |
| `image.tag`, `global.imageRegistry` | image coordinates |
| `<svc>.autoscaling.*` | HPA min/max/target CPU (api, orchestrator, scanner) |
| `<svc>.resources` | requests/limits (scanner gets the most: 4 CPU / 4Gi) |
| `ingress.provider` | `nginx` \| `traefik` \| `alb` \| `gce` |
| `networkPolicy.enabled` | default-deny + explicit allows |
| `secrets.*`, `externalSecrets.*` | secret sourcing (see below) |
| `postgres.enabled`, `redis.enabled` | in-chart datastores (off → use managed) |
| `observability.*` | ServiceMonitor + PrometheusRule (needs prom-operator) |
| `podSecurityContext`, `containerSecurityContext` | applied to every workload |

## Pod security (6e)

Every workload runs `runAsNonRoot` (uid 10001), `allowPrivilegeEscalation:false`,
`capabilities.drop:[ALL]`, `seccompProfile:RuntimeDefault`, and
`readOnlyRootFilesystem:true`. The orchestrator and scanner override
`readOnlyRootFilesystem:false` (they clone repos / write engine temp files) but
keep every other restriction, with scratch on `emptyDir` volumes.

## Secrets management (6f)

Three mutually exclusive options:

1. **Existing Secret (default, recommended)** — create it out of band:
   ```bash
   kubectl -n aegis create secret generic aegis-secrets \
     --from-literal=JWT_ACCESS_SECRET=$(openssl rand -hex 32) \
     --from-literal=JWT_REFRESH_SECRET=$(openssl rand -hex 32) \
     --from-literal=TOKEN_ENCRYPTION_KEY=$(openssl rand -hex 32) \
     --from-literal=POSTGRES_PASSWORD=$(openssl rand -hex 16)
   ```
2. **External Secrets Operator** — `--set externalSecrets.enabled=true` pulls
   from AWS Secrets Manager / Vault / GCP SM via a `ClusterSecretStore`.
3. **Chart-rendered (dev only)** — `--set secrets.create=true` with
   `secrets.values.*`. Never use in production.

## Ingress per provider (6c)

`--set ingress.provider=<p>` sets the class + provider annotations:

- **nginx** — `ingressClassName: nginx`, 50m body size, ssl-redirect.
- **traefik** — `websecure` entrypoint.
- **alb** (AWS Load Balancer Controller) — internet-facing, IP target, 80/443
  listeners, ssl-redirect.
- **gce** (GKE) — GCE ingress class, HTTP disabled.

`/api/v1` and `/scim/v2` route to the API service; everything else to web.

## Autoscaling (6b)

HPAs on api (2–8), orchestrator (2–12), scanner (3–20) target CPU utilization,
each paired with a PodDisruptionBudget (`minAvailable: 1`) so scale-in and node
drains never take a tier fully offline.

## Backup & restore (6h)

**PostgreSQL** (the source of truth — all findings/scans/orgs):

```bash
# Backup
kubectl -n aegis exec aegis-aegis-postgres-0 -- \
  pg_dump -U aegis -Fc aegis > aegis-$(date +%F).dump
# Restore (into a fresh/empty DB)
kubectl -n aegis exec -i aegis-aegis-postgres-0 -- \
  pg_restore -U aegis -d aegis --clean --if-exists < aegis-2026-01-01.dump
```

Recommended: a `CronJob` running `pg_dump` to object storage (S3/GCS), plus
volume snapshots of the PVC via your CSI driver. Redis is a cache/queue
(append-only file on its PVC) — losing it drops in-flight scan jobs only, which
re-queue; it does not need point-in-time backup. For production, prefer a
**managed Postgres** (RDS/Cloud SQL) with automated backups and set
`postgres.enabled=false` + point `DATABASE_URL` at it.

## Upgrades & rollback (6i)

```bash
helm upgrade aegis deploy/helm/aegis --set image.tag=2.1   # migrate hook runs first
helm history aegis
helm rollback aegis <REVISION>          # reverts manifests
```

Migrations are additive/backward-compatible so a rolled-back app version keeps
working against the newer schema. For a breaking schema change, take a backup
first (above) and gate the rollout. `helm rollback` reverts Kubernetes objects;
it does **not** run down-migrations — restore from backup if a schema revert is
required.

## Cluster targets (6j)

**Minikube (local validation):**
```bash
minikube start --cpus 4 --memory 8192
minikube addons enable ingress                    # nginx
eval $(minikube docker-env)                        # build images into the VM
docker compose build                               # or push tagged images
helm install aegis deploy/helm/aegis -n aegis --create-namespace \
  --set image.pullPolicy=Never --set secrets.create=true \
  --set ingress.host=aegis.local
echo "$(minikube ip) aegis.local" | sudo tee -a /etc/hosts
```

**Managed clusters** — same chart, provider-specific values:

| Cluster | Ingress | Storage class | Secrets |
| --- | --- | --- | --- |
| **EKS** | `ingress.provider=alb` (LB Controller) | `gp3` | ESO → Secrets Manager |
| **GKE** | `ingress.provider=gce` | `standard-rwo` | ESO → Secret Manager |
| **AKS** | `ingress.provider=nginx` | `managed-csi` | ESO → Key Vault |

Set `global.storageClass`, `global.imageRegistry`, and `postgres.enabled=false`
(with a managed DB `DATABASE_URL`) for production on any of the three.

## Observability (6g)

With prometheus-operator installed, `--set observability.serviceMonitor.enabled=true`
and `observability.prometheusRule.enabled=true` add scraping + alerts (API down,
scan failure rate > 20%, queue backlog > 100). A starter Grafana dashboard JSON
lives beside the chart for import.
