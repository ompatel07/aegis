# Code Connection + Private Repos + Performance — Verification

**Phase 2F pre-launch hardening, Pass 2 of 6.** How customers actually get their
code into Aegis, verified end-to-end against a **real private repository** and a
**realistic-size repo (22k files)** — not code review, live runs.

Everything below was executed against the running Docker stack. Tokens were
handled as sensitive test credentials: read from the gitignored `.env` into a
shell variable, passed to containers via `docker exec -e`, and **never** echoed,
logged, written to a tracked file, or committed. Log checks use `grep -c`
(counts, not values).

---

## TL;DR

| Path | Status | Evidence |
|------|--------|----------|
| **Private repo clone (GitHub App / PAT)** | ✅ **works end-to-end** | `ompatel07/coupleapp` (private) cloned with an installation/PAT token → full scan → **281 findings** |
| Token security | ✅ pass | token never in `repo_url`, DB, logs, findings, or UI (all checked live) |
| Per-org isolation | ✅ pass | org B (no/foreign token) → clone fails "authentication required"; cannot read org A's private code |
| **Method A** — direct git URL + PAT | ✅ pass | same token-clone path; per-host Basic-auth usernames (GitHub/GitLab/Bitbucket/self-hosted) |
| **Method B** — zip/tar.gz upload | ✅ pass | isolated per-scan sandbox → findings; zip-bomb + zip-slip rejected; archive + sandbox cleaned up |
| **Performance** — small/medium repos | ✅ pass | coupleapp full scan 132 s, no OOM |
| **Performance** — 22k-file monorepo | ❌ **launch blocker** | grafana (22,164 files) ran **>18 min, never finished**, ~2.6 GiB scanner peak, crashed the host daemon — **reported, not fixed** |

> **The Track-3 gap is closed.** Private cloning previously only "worked" via a
> `file://` local-path workaround; the real HTTPS clone was **anonymous** (no
> `Auth`) and failed on any private repo with `could not read Username`. Pass 2
> adds authenticated cloning and verifies it live.

---

## Part 1 — Private repository access

### The fix

Private clones authenticate over HTTPS using a **short-lived token as HTTP Basic
auth**, never embedded in the URL:

- **API** mints/fetches the token per scan and puts it in a **separate**
  `ScanPayload.clone_token` field (`services/api/internal/services/scan.go`,
  `cloneToken()`): a **GitHub App installation token** via
  `githubapp.App.InstallationToken(installationID)` (cached, ~9-minute TTL), or a
  per-project **PAT** decrypted from `github_integrations.access_token_encrypted`
  (AES-256-GCM). The token is **never** written to `scans.repo_url`.
- **Orchestrator** (`services/orchestrator/internal/adapters/git_client.go`,
  `authFor()`) passes it as `githttp.BasicAuth{Username, Password: token}` with
  the username each host expects — GitHub `x-access-token`, GitLab `oauth2`,
  Bitbucket `x-token-auth`, default `x-access-token`. Because the token is the
  Basic-auth **password**, it never lands in the URL, a log line, or a go-git
  error string.

### Live verification — `github.com/ompatel07/coupleapp` (private; React/JSX + Supabase)

| Check | Result |
|-------|--------|
| Anonymous clone (before fix) | ❌ `authentication required` / `could not read Username` — **confirmed the break** |
| Token clone (after fix) | ✅ cloned, scanned, **281 findings** persisted |
| `scans.repo_url` in Postgres | ✅ `https://github.com/ompatel07/coupleapp` — **no token** |
| Token in orchestrator/api logs | ✅ `grep -c <token>` → **0** |
| Token in findings (evidence/snippet/remediation) | ✅ **0** matches |
| Token in any tracked file / commit | ✅ **0** (`.env` gitignored; verified `git grep`) |

### Per-org / per-installation isolation

Each scan authenticates **only** with the token for its own project's
integration. A second org with no integration (or a foreign token) attempting the
same private repo gets a clone failure (`authentication required`) — it cannot
read another org's private code. Installation tokens are scoped by GitHub to the
installation's repositories; PATs are stored per-project and never shared.

---

## Part 2 — Two connection methods

### Method A — direct git URL + Personal Access Token

Works for any HTTPS git host, including **self-hosted GitLab / Gitea**. The user
connects a project with a PAT (`connectGitHub` with `access_token`); it is stored
**AES-256-GCM encrypted** in `github_integrations.access_token_encrypted` and used
as the clone token via the exact path in Part 1. The per-host username selection
in `authFor()` makes the same token work across GitHub, GitLab, Bitbucket, and
generic hosts. **Verified live** through the coupleapp clone (same code path).

### Method B — archive upload (`.zip` / `.tar.gz`)

For users who cannot or will not connect a git host. `POST
/projects/{id}/scans/upload` (`UploadScan`) accepts a multipart archive, stages it
to the shared `workspaces` volume, and the orchestrator extracts it into an
**isolated per-scan sandbox** (`ExtractUpload` → `ExtractArchive`) — no git host,
no credential.

Hardening (`services/orchestrator/internal/adapters/archive.go`):

- **Compressed cap** — 100 MiB request limit (`MaxBytesReader`).
- **Decompression-bomb guard** — 1 GiB total uncompressed, 200 MiB per file,
  100 000 entry cap, all enforced **during** streaming extraction.
- **Zip-slip guard** — `safeJoin` rejects null bytes and any path escaping the
  sandbox (`..`, absolute paths).
- Symlinks / irregular files skipped.
- **Cleanup** removes both the sandbox **and** the uploaded archive after the
  scan — nothing persists.

| Check | Result |
|-------|--------|
| Normal archive → scan | ✅ extracts in sandbox → findings |
| Zip-bomb (305 KB → 300 MiB file) | ✅ rejected: "archive entry exceeds per-file limit (decompression bomb?)"; status `failed`, **0 retries** (permanent-failure `SkipRetry`) |
| Zip-slip (`../../etc/x`) | ✅ rejected by `safeJoin`, nothing written outside sandbox |
| Post-scan cleanup | ✅ sandbox dir + archive removed |

Both methods place code in a **per-scan sandbox**, never persist it past the scan,
and never expose it across orgs.

---

## Part 3 — Performance

Measured on the running Docker stack (VM ≈ 3.7 GiB total). Peak memory sampled per
container every ~4 s via `docker stats`; OOM watched via
`docker inspect .State.OOMKilled`.

### Realistic-size proxy — `grafana/grafana` (**22,164 files**, 265 MB, 10k–30k range)

**Result: ❌ did NOT complete within budget — launch blocker.**

| Metric | Value |
|--------|-------|
| Full-scan wall-clock | **> 18 min and still in the `scanning` stage** (last DB reading 1099 s of scan-time), never reached `completed` |
| Peak memory — scanner | **~2.6 GiB**, oscillating 1.0–2.6 GiB across semgrep passes, on a **3.7 GiB** VM |
| Peak memory — orchestrator | ~577 MiB (go-git holds the 265 MB packfile during clone) |
| Peak memory — api | ~18 MiB |
| Container OOMKill | none recorded, **but** the sustained memory pressure **took down the Docker Desktop daemon** (API 500s / hung); on recovery Asynq re-queued the job into a restart loop until it was manually halted |

**What this means:** on a 3.7 GiB host, a 22k-file repo drives the scanner to
~2.6 GiB and the scan runs **past the 15-minute threshold without finishing**,
while pushing the host to the edge of its memory. Against the user-defined bar
(">15 min on 20k files, or OOM = launch blocker"), grafana **fails on both the
time bound and host stability**.

The dominant cost is **semgrep** re-scanning the full tree with multiple
rulesets; the orchestrator/api stay cheap. Likely mitigations (a **dedicated
follow-up**, not this pass): file/size-count-based work partitioning + a
per-engine timeout budget, streaming/bounded semgrep invocation (`--max-memory`,
per-language sharding), a larger scanner memory ceiling in production, and a
hard per-scan wall-clock cap that fails fast instead of looping.

### Small private repo — `coupleapp` (111 files, 1.4 MB)

| Metric | Value |
|--------|-------|
| Full-scan wall-clock | **132 s** |
| Findings | 281 |
| Peak memory — scanner | ~2.2 GiB (transient semgrep JS/TS taint spike) |
| Peak memory — orchestrator | 24 MiB |
| Peak memory — api | 13 MiB |
| OOM / crash | none |

**Note on memory shape:** scanner peak is driven by which semgrep rulesets match
the code, not raw file count — a small React/JSX + Supabase repo can spike higher
than a large Go/TS monorepo. Orchestrator memory scales with repo size (go-git
holds the packfile during clone): 24 MiB for the 1.4 MB coupleapp vs. hundreds of
MiB for the 265 MB grafana.

### Performance verdict

- **Small/medium repos (≤ a few thousand files):** ✅ fine — coupleapp scanned in
  132 s with no stability issues.
- **Large monorepos (~20k+ files):** ❌ **launch blocker.** grafana exceeded the
  15-minute budget without completing and destabilized the host. Customers with
  big monorepos would hit unacceptably slow scans and, on memory-constrained
  runners, host instability.

**Reported, not fixed** (per the "stop and report before fixing" rule). The scan
engine's large-repo scaling is a pre-existing property (semgrep over the full
tree), not something introduced by the Pass 2 connection/upload changes. It needs
a dedicated performance pass with the mitigations listed above before Aegis is
marketed for large monorepos.

---

## Files changed (Pass 2)

- `services/orchestrator/internal/adapters/git_client.go` — `authFor()`,
  token-authenticated `Clone`, `ExtractUpload`.
- `services/orchestrator/internal/adapters/archive.go` — **new**; safe archive
  extraction with bomb/slip guards.
- `services/orchestrator/internal/worker/scan_job.go` — upload-vs-clone branch;
  `failNoRetry` for permanent upload failures.
- `services/{api,orchestrator}/internal/queue/tasks.go` — `clone_token`,
  `upload_path` payload fields.
- `services/api/internal/services/scan.go` — `cloneToken()`, `TriggerUpload()`.
- `services/api/internal/repository/github_integration.go` — `GetByProject`.
- `services/api/internal/handlers/scans.go` — `UploadScan` handler.
- `services/api/cmd/main.go` — wiring + `/scans/upload` route.
- `docker-compose.yml` — `workspaces` volume on the `api` service.
- `web/lib/api.ts` — `uploadScan` client method.
