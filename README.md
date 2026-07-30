# JB Site Health

A **read-only** WordPress endpoint that supplies the six Digital Support Plan data points which
cannot be observed from outside a site. One request, one signed token, no per-site configuration.

> **This repository is public.** The fleet private key is deliberately **not** committed here, and
> is not committed anywhere else either — it lives only in the caller's environment. Only the public
> keys ship with the plugin, and a public key cannot forge a token. See [Auth](#auth).

## Why this exists

The support-plan report runs ~29 checks. 23 already work externally (SSL/TLS, HTTP headers, email
DNS, indexability, uptime). Six do not, and today they render to the client as `Unknown` or land in
the "Needs access to check" block:

| Report row | Source |
|---|---|
| WordPress version | `$wp_version` |
| PHP version | `phpversion()` |
| Plugin update status | `get_plugin_updates()` |
| `DISALLOW_FILE_EDIT` | constant |
| PHP execution in uploads | `uploads/.htaccess` + `.user.ini` |
| Brute-force attempt count | Solid Security / Wordfence tables |

## Why not just extend jb-ops

jb-ops can answer some of this, but it carries 80+ operations including `write_file`, `export_db`,
`update_option` and `activate_plugin`, with writes enabled. Shipping that to every client site
purely to feed a monthly read-only report is far more privilege than the job needs.

This plugin is **read-only by construction** — there is no code path that writes to the database,
the filesystem, or the options table. It therefore carries its **own keypair**, deliberately
separate from `jb-ops-access/`: if this fleet-wide key ever leaks, the worst case is information
disclosure, not site takeover.

It also installs on the sites that have no jb-ops bridge at all, without granting them write access.

## Why not the SSH connector

The support-plan skill can also read a site over SSH, via the per-repo `PROD_SSH_HOST` /
`PROD_SSH_USER` / `PROD_SSH_WEBROOT` variables. That route works, but it must be configured once per
repository — which is why most sites report `Unknown`: those variables were never set. It also needs
`wp-cli` present on the host.

| Check | SSH connector | This plugin |
|---|---|---|
| WP core version | yes | yes |
| PHP version | **CLI PHP** | **web PHP** |
| Plugin updates | names only | grouped by owner |
| `DISALLOW_FILE_EDIT` | yes | yes |
| `DISALLOW_FILE_MODS` | no | yes |
| Theme updates | no | yes |
| Brute-force logs | no | yes |
| Uploads PHP execution | guess | evidence + reason |
| Setup per site | 4–6 env vars + key | none |
| Non-WordPress apps | yes | no |

The skill tries SSH **first** and falls back to this plugin, so sites already wired up are
unaffected.

## Install

No per-site configuration is needed by any route.

### Composer (preferred — Bedrock)

Add the repository once, then require it:

```jsonc
"repositories": [
  { "type": "git", "url": "https://github.com/lanangary-jb/juicebox-site-health.git" }
]
```

```bash
composer require lanangary-jb/juicebox-site-health:dev-main
```

The package is `type: wordpress-muplugin`, so Bedrock's existing installer path
(`www/app/mu-plugins/{$name}/`) puts it at `www/app/mu-plugins/juicebox-site-health/`. Subdirectory
mu-plugins are loaded by `bedrock-autoloader.php`, which every Juicebox Bedrock repo already ships —
so it activates itself with no stub and no admin step. Same pattern as `lanangary-jb/jb-ops`.

> **Migrating from the flat file:** if `mu-plugins/jb-site-health.php` is already deployed, delete it
> in the same commit that adds the Composer requirement. The plugin guards against the duplicate
> class, so a site that briefly has both will not fatal — but it should not stay that way.

### Manual

- **Flat mu-plugin.** Copy `jb-site-health.php` into `wp-content/mu-plugins/` (or
  `www/app/mu-plugins/` on Bedrock). It auto-activates and needs no loader stub.
- **Normal plugin.** Clone into `plugins/` and activate.

> On Bedrock repos note that `.gitignore` typically ignores `mu-plugins/*/` (subdirectories only),
> so a flat `.php` file **is** tracked. Commit it deliberately or deploy it out of band.

## Use

The token minter is **not** in this repository — it is the caller, in the private
`digital-support-plan` skill, which carries the private half of the keypair and signs a fresh
token on every run. Nothing needs configuring at either end. To mint one by hand for debugging:

```bash
TOKEN=$(python3 scripts/digital_support_plan.py --mint-token)
curl -H "Authorization: Bearer $TOKEN" https://<site>/wp-json/jb-health/v1/report
```

Add `?refresh=1` to force WordPress to re-run its update checks before answering. That costs
several seconds of latency; without it the response reports `checked_at` so the caller can judge
staleness itself.

If a host strips `Authorization` (some LiteSpeed/cPanel stacks do), send `X-JB-Health-Token`
instead — the plugin accepts either.

## Auth

Same proven scheme as the jb-ops bridge, with its own key and its own signing context:

```
jb1.<UTCdate Ymd>.<base64url Ed25519 signature of "jb-health-v1:<date>">
```

The plugin embeds only the **public** keys, which can verify a token but never forge one. That is
what makes this repository safe to keep public: everything in it is already readable by anyone, and
none of it can be turned into a valid request. The date must be within ±1 day UTC, so a captured
token expires on its own after roughly a day. Anything malformed, expired, or unsigned gets an
identical `401 Unauthorised` — the response never reveals which.

The private half is the fleet credential and is **not in this repository**. It exists in exactly one
place: the private skills repo, inside the caller that signs with it. There is no second copy, no
vault, and nothing to keep in sync.

That is a deliberate trade rather than an oversight. A committed credential is in git history
permanently and is readable by everyone with access to that repo — accepted because the alternative
(a secret somebody has to set per environment) is exactly the configuration step that left this
report showing `Unknown` on almost every site, and because this plugin is read-only, so the worst
case is disclosure rather than takeover. **Rotating is the revocation** — deleting the constant is
not. See [Rotating](#rotating).

### Rotating

`JB_HEALTH_SIGNING_PUBKEYS` is a **list**, and every key in it is accepted. Without that, rotation
would mean changing the key on ~40 sites in the same instant. Instead:

1. Generate a new pair.
2. Add the new public key to the list here. Both keys now verify — deploy the fleet at whatever pace suits.
3. Once every site carries it, switch the caller to the new private key.
4. Drop the retired public key on the next routine deploy.

No coordinated cutover, no window where a site is unreachable. A site can also override the list
in `wp-config.php` to opt out of the fleet credential entirely.

**Rotated 30 Jul 2026 in `1.2.0`** after a review flagged the key in the caller's source. The team
chose to keep it in source — see [Auth](#auth) — so the rotation stands on its own: the fleet was a
single staging site at the time, so this went straight to the new key rather than running the staged
path above. The retired public key is gone from the list, so the old private key — which remains in
the skills repo's git history and cannot be removed from it — now verifies against nothing. Any site
still on `1.1.0` will reject current tokens until it redeploys.

## The one rule: never guess

The report is client-facing, so a wrong value is worse than an honest "don't know". Every field
that cannot be determined returns `null` alongside a `reason`. Nothing infers or falls back to a
plausible default.

The clearest case is `uploads_php_execution`. Only `.htaccess` and `.user.ini` are inspectable from
PHP. On nginx the rule usually lives in a server config this code cannot read — so it returns
`null` plus the server name, rather than reporting "not blocked" and turning a config we simply
cannot see into a client-facing FAIL.

Likewise `brute_force` returns `null` with a reason when no supported security plugin is present —
never `0`, which would read as "no attacks" rather than "not measured".

## Response shape

```jsonc
{
  "ok": true, "schema_version": 1, "plugin_version": "1.2.0",
  "generated_at": "2026-07-28T03:33:49+00:00",
  "site":      { "siteurl": "…", "home": "…", "is_multisite": false, "server_software": "nginx/1.25.4" },
  "wordpress": { "version": "6.9.4", "latest": "7.0.2", "update_available": true, "checked_at": 1785121264 },
  "php":       { "version": "8.2.29", "major_minor": "8.2", "sapi": "fpm-fcgi" },
  "plugins":   { "active_count": 33, "update_count": 20,
                 "updates": [ { "name": "Gravity Forms", "slug": "gravityforms",
                                "current": "2.9.24", "new": "2.10.5" } ] },
  "themes":    { "update_count": 0, "updates": [] },
  "hardening": { "disallow_file_edit": { "defined": true, "value": true },
                 "uploads_php_execution": { "blocked": null, "reason": "…" },
                 "blog_public": true, "debug_display": false },
  "brute_force": { "source": "solid-security", "window_days": 30,
                   "lockouts": 0, "failed_logins": 0 }
}
```

Compare `site.home` against the domain you asked about before trusting the numbers — that is what
stops a staging box quietly answering for production. The support-plan skill's SSH connector does
the same thing via `siteurl`, flagging `ENV MISMATCH`.

## A note on PHP version accuracy

This reports the PHP the **site actually runs on**, because it executes inside WordPress. The SSH
connector cannot: WP-CLI reports the *CLI* PHP, which on cPanel MultiPHP is frequently a different
build from the one serving the domain (termihc live is `ea-php82`). The easier integration is also
the more accurate one.

## Verified

Tested against `easystarthomes.test` on 28 Jul 2026: no token → 401, malformed token → 401, valid
token → 200 with all six data points populated. WordPress 6.9.4 (7.0.2 available), PHP 8.2.29,
20 plugin updates, `DISALLOW_FILE_EDIT` true, uploads honestly `null` on nginx, brute-force via
Solid Security.

Deployed to `termihc.com.au` staging on 28 Jul 2026. The support-plan report resolved all four
`Unknown` rows: WordPress 7.0.2, PHP 8.3.24 (`fpm-fcgi`), `DISALLOW_FILE_EDIT=1`, brute-force 0 via
Solid Security — and the "Needs access to check" block dropped from 6 entries to 3, all of which are
uptime figures Loop already sources from Better Stack.
