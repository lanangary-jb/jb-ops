# JB Ops Bridge

A secured, token-gated REST endpoint for **authorized**, programmatic inspection and controlled
changes to a WordPress site's database and routing state — without SSH or direct DB access.
Intended for trusted, first-party site-management automation.

## Security posture

- **No anonymous access.** Every request requires a valid bearer credential.
- **Signed access tokens.** When an Ed25519 public key is configured (`H_OPS_SIGNING_PUBKEY`), the
  bridge accepts only short-lived, **daily-rotating** tokens signed by the matching private key. A
  public key can *verify* a token but never *forge* one, so it is safe to ship; the private key is
  never stored in this repository or on any site. If no key is configured, the bridge stays **inert**
  unless explicitly enabled with a per-site token in the WordPress admin.
- **Structured operations only.** No raw SQL and no code evaluation — callers invoke a fixed,
  allowlisted set of operations.
- **Reversible writes.** Changes are previewed (dry-run) first and require a one-time confirmation
  token to apply; each applied change returns a single-use revert token.
- **Redaction.** Values that look like secrets/credentials are redacted before leaving the site.
- **Audited.** Every call is recorded to an audit table.
- **Admin UI lockdown.** Settings/activity pages are visible only to logged-in administrators on
  allowed email domains (filterable via `jb_ops_allowed_email_domains`).

## Configuration

- `H_OPS_SIGNING_PUBKEY` — base64 Ed25519 public key for the signed-token path. Leave empty (`''`)
  to disable it and use the manual enable + per-site token model in **wp-admin → JB Ops → Settings**.
- The endpoint is namespaced under `wp-json/h-ops/v1/` and exposes a self-describing operation list
  to authenticated clients.

## Requirements

WordPress 5.x+, PHP 7.2+ (libsodium required for signed tokens).

## License

Proprietary — internal use.
