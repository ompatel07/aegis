# Enterprise SSO & Provisioning (SAML · OIDC · SCIM)

Aegis supports enterprise single sign-on over **OIDC** and **SAML 2.0**, with
**SCIM 2.0** for automated user provisioning/deprovisioning. Connections are
per-organization; users are routed to their IdP by email domain.

## Concepts

- **Connection** — one org's IdP configuration (`oidc` or `saml`). Owns an
  optional `email_domain` used for auto-routing.
- **JIT provisioning** — on first successful login the user is created (no local
  password) and added to the connection's organization with `default_role`.
- **Domain routing** — the login page calls `GET /api/v1/auth/sso/discover?email=…`;
  if the domain matches an enabled connection it redirects the user to that IdP.
- **SCIM token** — a per-org bearer credential the IdP uses to push user
  lifecycle events; provisioning maps directly to org membership, so
  deprovisioning revokes access immediately.

Secrets (OIDC client secret) are stored **AES-256-GCM encrypted** at rest; SCIM
tokens are stored only as SHA-256 hashes and shown once at creation.

## Administering connections (admin UI)

Organization owners can manage everything below from the app —
**Settings → Single Sign-On** (`/settings/sso`) — without hand-rolling API calls:
create/edit/enable/delete OIDC & SAML connections, copy the SP metadata/ACS URLs
for a SAML connection, and mint or **revoke** SCIM tokens (the secret is shown
once). The page is owner-gated and org-scoped; the raw API below is equivalent for
scripting. (Frontend: `web/app/(dashboard)/settings/sso/page.tsx`.)

## OIDC (Okta, Auth0, Azure AD, Google Workspace)

The flow is standard Authorization Code + **PKCE** with a server-side `state` and
`nonce` (10-minute TTL in Redis); the `id_token` signature, audience, and nonce
are all verified.

1. In your IdP create an OIDC app. Set the redirect URI to:
   ```
   https://<your-aegis-host>/api/v1/auth/sso/oidc/callback
   ```
2. Create the connection (org owner):
   ```http
   POST /api/v1/sso/connections
   {
     "organization_id": "<org-uuid>",
     "protocol": "oidc",
     "display_name": "Acme Okta",
     "enabled": true,
     "email_domain": "acme.com",
     "oidc_issuer": "https://acme.okta.com",
     "oidc_client_id": "0oa...",
     "oidc_client_secret": "…",
     "oidc_scopes": "openid email profile",
     "default_role": "member",
     "jit_provisioning": true
   }
   ```
   `oidc_issuer` is the IdP's discovery base (`/.well-known/openid-configuration`
   is fetched automatically). Provider-specific issuers: Okta
   `https://<tenant>.okta.com`, Auth0 `https://<tenant>.auth0.com/`, Azure AD
   `https://login.microsoftonline.com/<tenant-id>/v2.0`, Google
   `https://accounts.google.com`.
3. Users at `acme.com` are now routed to Okta automatically.

## SAML 2.0

SP-initiated redirect binding; the IdP posts a **signed** assertion to the ACS,
whose signature is validated against the IdP's certificate and bound to the
originating `AuthnRequest` ID (replay protection).

1. Create the connection with `protocol: "saml"` and:
   `saml_idp_entity_id`, `saml_idp_sso_url`, `saml_idp_certificate` (PEM).
2. Give your IdP the SP metadata:
   ```
   GET /api/v1/auth/sso/<connection-id>/saml/metadata
   ```
   - **ACS URL**: `https://<host>/api/v1/auth/sso/saml/acs`
   - **SP Entity ID**: the metadata URL above
3. Map the IdP's email/name assertion attributes (defaults: `email`, `name`;
   common SAML claim URIs are also recognized).

## SCIM 2.0 provisioning

1. Mint a token (org owner) — copy it, it is shown once:
   ```http
   POST /api/v1/sso/scim-tokens   { "organization_id": "<org>", "display_name": "Okta SCIM" }
   → { "id": "...", "token": "scim_…", "scim_base_url": "/scim/v2" }
   ```
2. In your IdP's provisioning config set:
   - **Base URL**: `https://<host>/scim/v2`
   - **Auth**: HTTP Header, `Authorization: Bearer scim_…`
3. Supported operations on `/scim/v2/Users`:

   | Method | Effect |
   | --- | --- |
   | `POST /Users` | Provision → create/link user + add to org |
   | `GET /Users?filter=userName eq "x"` | Lookup (org-scoped) |
   | `GET /Users/{id}` | Read |
   | `PATCH /Users/{id}` (`active:false`) | Deprovision → remove from org |
   | `DELETE /Users/{id}` | Deprovision |

## Verification status

Verified **live** end-to-end against the running stack (migration 000021 applied):

| Check | Result |
| --- | --- |
| Create OIDC connection; client secret encrypted at rest (never echoed) | ✅ |
| **Edit connection** (`PUT`) — rename + enable, secret omitted → preserved | ✅ |
| **Revoke SCIM token** (`DELETE`) — token flips to disabled | ✅ |
| Owner-gating — revoke against a non-owned org → **403** | ✅ |
| Domain routing — `discover?email=…@domain` → the right connection | ✅ |
| Unknown domain → 404 | ✅ |
| Mint SCIM token (shown once) | ✅ |
| SCIM request without token → 401 | ✅ |
| SCIM `POST /Users` provisions + joins the org | ✅ |
| SCIM `GET /Users?filter=userName eq` finds the user | ✅ |
| SCIM `PATCH active:false` deprovisions (removed from org) | ✅ |

The **OIDC/SAML browser login flow itself** (redirect → IdP → callback/ACS) is
implemented and compiles, but exercising it requires a real or mock IdP; that is
deferred to a live environment (Okta/Azure/Auth0/Google onboarding). The code
paths — PKCE/state/nonce, id_token verification, SAML assertion validation, and
JIT provisioning — are covered by review + the live connection/SCIM tests above.

## Security notes

- OIDC: PKCE + `state` (CSRF) + `nonce` (replay) + id_token signature/audience.
- SAML: assertion signature verified against the pinned IdP cert; response bound
  to the AuthnRequest ID; single-use RelayState.
- Secrets encrypted at rest (client secret) or hashed (SCIM token).
- SSO users have no password — they cannot fall back to password login.
- Connection administration is restricted to organization **owners**.
