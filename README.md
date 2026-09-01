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

The clearest case is `uploads_php_execution`, which answers `true` or `null` and **never `false`**.
Reading files can prove a rule exists; it can never prove one does not, because the rule may equally
live in an Apache/LiteSpeed vhost block, an nginx server block, a WAF or a php-fpm pool — none of
which PHP can read.

Two readable places are inspected. A rule in `uploads/.htaccess` or `uploads/.user.ini` is scoped to
that directory, so any deny-ish directive counts. Every `.htaccess` from there up to the document
root is also read, but a rule there must name the uploads path **and** a script extension **and**
actually deny (`[F]`, `Require … denied`, `SetHandler`, `php_flag`, `RemoveHandler`, `403`) on the
same line — comments are skipped, because an intent described is not an intent enforced. The
`inspected` array reports exactly which files were read, relative to the document root.

Ancestor `.htaccess` matching landed in 1.3.0. Before it, a site hardened at the document root — the
common Juicebox shape, e.g. `RewriteRule ^app/uploads/.*\.(?:php|…)$ - [F,L,NC]` — was reported as
`false`/"Not blocked" in client-facing reports while being fully protected.

The authoritative negative is an HTTP request for a `.php` under uploads, which the support-plan
skill performs. That tests behaviour rather than inferring it, and it works on sites without this
plugin — so a genuinely open site is still caught, by the check that can actually prove it.

Likewise `brute_force` returns `null` with a reason when no supported security plugin is present —
never `0`, which would read as "no attacks" rather than "not measured".

## Response shape

```jsonc
{
  "ok": true, "schema_version": 1, "plugin_version": "1.5.0",
  "generated_at": "2026-07-28T03:33:49+00:00",
  "site":      { "siteurl": "…", "home": "…", "is_multisite": false, "server_software": "nginx/1.25.4" },
  "wordpress": { "version": "6.9.4", "latest": "7.0.2", "update_available": true, "checked_at": 1785121264 },
  "php":       { "version": "8.2.29", "major_minor": "8.2", "sapi": "fpm-fcgi" },
  "plugins":   { "active_count": 33, "update_count": 20,
                 "updates": [ { "name": "Gravity Forms", "slug": "gravityforms",
                                "current": "2.9.24", "new": "2.10.5" } ] },
  "themes":    { "update_count": 0, "updates": [] },
  "hardening": { "disallow_file_edit": { "defined": true, "value": true },
                 // `blocked` is true or null, never false. `evidence` accompanies true,
                 // `reason` accompanies null; `inspected` lists the files actually read,
                 // relative to the document root.
                 "uploads_php_execution": { "blocked": true, "evidence": ".htaccess denies PHP under app/uploads",
                                            "reason": null, "inspected": [".htaccess"] },
                 "blog_public": true, "debug_display": false },
  "brute_force": { "source": "solid-security", "window_days": 30,
                   "lockouts": 0, "failed_logins": 0 },
  "forms":     { "engine": "gravityforms", "engine_version": "2.10.0",
                 "recaptcha_v3_sitewide": true,
                 "mailer": { "plugin": "wp-mail-smtp", "active": true, "mailer": "sendgrid",
                             "wp_env": "production", "reason": null },
                 "count": 4,
                 "items": [ { "id": 1, "title": "Contact Form", "active": true,
                              // two independent gates, never collapsed into one flag
                              "captcha": { "field": false, "field_type": null, "recaptcha_v3": false },
                              "notifications": [ { "name": "Admin Notification", "active": true,
                                                   "event": "form_submission", "to_type": "email",
                                                   "to": "hello@example.com" } ],
                              "entries_total": 60, "entries_30d": 4, "entries_prev_30d": 3,
                              "last_entry": "2026-08-31T01:34:44+00:00" } ] }
}
```

## Forms (added 1.4.0)

Forms are the thing that breaks quietly after a WordPress, PHP or plugin update: the page still
renders, the visitor still sees "thanks", and the first we hear of it is a client asking why nobody
called them back. None of that is visible from outside the site, which makes it exactly this
plugin's job.

**This section observes; it does not judge.** Nothing here submits a form, sends mail, or decides
that a form is "broken" — it reports configuration and entry volume and lets the caller compare
across months. Two signals carry most of the value:

| Signal | What it means |
|---|---|
| `notifications[].active` false, or a stale `to` | A delivery failure that has **already happened** |
| `entries_30d` collapsed against `entries_prev_30d` | The fingerprint of a form that started failing silently |
| `mailer.active` false on a production site | Every form on the site is falling back to PHP `mail()` |

Three traps this encodes, all of which produce a confidently wrong answer if you get them backwards:

- **The v3 setting is inverted.** A form carries `gravityformsrecaptcha.disable-recaptchav3` only
  when someone opted it *out*. No key means v3 is **active**. So `recaptcha_v3` is true when site
  keys are configured *and* the form has no opt-out — which is how two otherwise identical forms end
  up with one gated and one not.
- **A missing `isActive` on a notification means active**, not off. Gravity Forms omits the key
  entirely until someone toggles it.
- **`to` is reported verbatim**, merge tags and all (`{admin_email}`, or a field id when the form
  routes to an address the visitor typed). Resolving it would mean guessing.

`entries_*` counts exclude trashed and spam rows, so a spam wave cannot mask a form that stopped
receiving genuine submissions. All forms are counted in a single grouped query rather than three per
form, so a site with forty forms does not turn the health check into a slow page.

`wp_env` sits beside `mailer.active` deliberately: the Bedrock template ships a mu-plugin that
deactivates SMTP plugins outside production **by design**, so `active: false` on a staging box is
correct behaviour rather than a fault. Without that context the field reads as a false alarm.

Gravity Forms only for now — it is what the fleet runs. Any other form plugin returns a `reason`
rather than a misleading empty list.

Compare `site.home` against the domain you asked about before trusting the numbers — that is what
stops a staging box quietly answering for production. The support-plan skill's SSH connector does
the same thing via `siteurl`, flagging `ENV MISMATCH`.

## Entry lookup (added 1.5.0)

```
GET /wp-json/jb-health/v1/forms/entry?form=<id>&stamp=<run reference>[&hours=24]
```

The `forms` section says how forms are **configured**. This says what happened to **one specific
submission**.

`form-check` submits every form on a site and then has to prove two things the browser cannot show
it: that the entry was actually stored, and that WordPress actually handed the notification to a
mail server. On a local site it reads the database. On staging, live, or a Loop runner it has
neither a database nor `wp-cli` — so it asks here instead. Same token, same 401, same
`Cache-Control: no-store, private`.

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://<site>/wp-json/jb-health/v1/forms/entry?form=1&stamp=JBFC-B0D5AB38-F1"
```

```jsonc
{
  "ok": true, "schema_version": 1, "plugin_version": "1.5.0",
  "generated_at": "2026-09-01T05:25:57+00:00",
  "site":   { "siteurl": "…", "home": "…", "is_multisite": false, "server_software": "nginx/1.25.4" },
  "query":  { "form": 1, "stamp": "JBFC-B0D5AB38-F1", "hours": 24 },
  "engine": "gravityforms",
  "found":  true,
  // `status` is reported, never filtered on — see below.
  "entry":  { "id": 106, "form_id": 1, "status": "active",
              "created_at": "2026-09-01T05:25:37+00:00", "matched_field": "5" },
  "notifications": {
    "checked": true, "reason": null, "success": 2, "errors": 0,
    "items": [ { "sub_type": "success",
                 "message": "WordPress successfully passed the notification email to the sending server.",
                 "created_at": "2026-09-01T05:25:41+00:00" } ] },
  "reason": null
}
```

**200 whether or not the entry is there.** "No entry carrying that stamp" is a result of the check,
not a transport failure, and folding it into a 404 would make it indistinguishable from this route
being absent on a site still running 1.4.0 — which is a completely different conclusion. `found:
false` always arrives with a `reason`, and so does `notifications.checked: false`:

```jsonc
{ "engine": "gravityforms", "found": false, "entry": null,
  "notifications": { "checked": false, "reason": "no entry carrying that stamp on form 1 in the last 24h",
                     "success": 0, "errors": 0, "items": [] },
  "reason": "no entry carrying that stamp on form 1 in the last 24h" }
```

The counters are never absent and never guessed: `success: 0` beside `checked: false` means *not
measured*, exactly as `brute_force` refuses to report `0` for "no security plugin installed".

### The stamp format is the security model

`stamp` must match `^JBFC-[A-F0-9]{8}(-F[0-9]{1,6})?$` — the run reference `form-check` writes into a
name/text/textarea field before it submits (`JBFC-XXXXXXXX`, suffixed `-F<form id>` for the per-form
variant). Anything else is rejected with a 400 before a query is built.

That strictness is the entire point. A `?q=<anything>` version of this endpoint would be "search
every entry on this site for string X", which turns a read-only reporting key into a PII exfiltration
tool wearing a health-check badge. A caller can only ask about a reference it wrote itself.

Three properties follow from the same reasoning:

- **The response never contains field values.** Only ids, the entry status, timestamps, the
  `meta_key` of the field the stamp was found in, and Gravity Forms' own notification note text. No
  names, no email addresses, no IPs, no message bodies. The note text is GF's own system message —
  on an error it can carry the SMTP failure string, which is operational data rather than personal
  data, and it is capped at 500 characters.
- **401 comes before 400.** WordPress does not do this by itself: `WP_REST_Server::dispatch()`
  validates arguments and hands the resulting error to `respond_to_request()`, which then skips the
  `permission_callback` because a response already exists. Left alone, a stranger sending a malformed
  stamp would get a descriptive 400 while the same stranger sending a well-formed one got a 401 —
  the difference being a free oracle for the argument format, handed out before any credential was
  examined. A `rest_request_before_callbacks` filter puts the 401 back in front, on this plugin's
  routes only. An authorised caller still gets the descriptive 400: WordPress's own
  `rest_invalid_param`, carrying `jb_health_bad_stamp` / `jb_health_bad_form` /
  `jb_health_bad_hours` in `data.details`.
- **`hours` (1–168, default 24) bounds the scan.** `meta_value` carries no index a leading-wildcard
  `LIKE` can use, so the `date_created` window is what does the narrowing — an unbounded search
  across an entry meta table with years of rows in it is a denial of service dressed as a query
  string.

### What the notification block proves — and what it does not

Gravity Forms writes one note per notification attempt from
`GFFormsModel::add_notification_note()`, **present since GF 2.4.14**, into `{prefix}gf_entry_notes`
with `note_type = 'notification'` and a `sub_type` of `success` or `error`. The success text is GF's
own "WordPress successfully passed the notification email to the sending server"; the error text
carries the reason (an invalid TO address, or whatever PHPMailer's `ErrorInfo` said).

| It proves | It does not prove |
|---|---|
| The entry was stored, and with what `status` | That the email reached an inbox |
| WordPress handed the mail to the sending server | That the sending server delivered it |
| Which notifications errored, and why | Anything on a site older than GF 2.4.14 |

So `success` means **accepted**, not **delivered**: SPF/DKIM failures, a full mailbox and spam
filing all happen downstream of the last thing this can see. It is still the difference between "the
form quietly mails nobody" and "the mail left the building" — and `form-check` checks a real inbox
as well wherever it can reach one.

Two honest limits on top of that:

- **Absence of a note is not proof of failure.** GF writes the note only when `wp_mail()` returned a
  plain `true` or `false`; a `WP_Error` from a filtering plugin produces no note at all. And on a
  schema older than GF 2.3 the notes table has no `sub_type` column, which is reported as
  `checked: false` with a reason rather than counted as zero.
- **The entry status is reported, never filtered on.** A test submission that landed in `spam` or
  `trash` is a **finding** — the form works, but the entry is being thrown away. This is the one
  place the plugin deliberately parts company with the `forms` section, which excludes trash and
  spam because it is counting genuine volume.

Gravity Forms only, exactly like `forms`: any other form plugin returns `engine: null` and a reason
rather than a misleading `found: false`.

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
