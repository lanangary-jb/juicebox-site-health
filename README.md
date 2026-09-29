# JB Site Health

A WordPress endpoint that supplies the six Digital Support Plan data points which cannot be
observed from outside a site, and (from 1.8.0) the PHP errors the site has been throwing. One
request, one signed token, no per-site configuration.

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
purely to feed a monthly report is far more privilege than the job needs.

This plugin **never changes the site**: no posts, users, settings, files or code. The only rows it
writes are its own. That means the SendGrid delivery ledger (1.7.0, accepted only under SendGrid's
signature), the PHP error log (1.8.0, recorded by the site as errors happen and pruned to its
retention window when read), and one option recording the error tables' schema version. No caller
chooses what is written. It therefore carries its **own keypair**, deliberately separate from
`jb-ops-access/`: if this fleet-wide key ever leaks, the worst case is information disclosure, not
site takeover.

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
report showing `Unknown` on almost every site, and because nothing a token unlocks here can change
the site, so the worst case is disclosure rather than takeover. **Rotating is the revocation** — deleting the constant is
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

### Loop's per-request token (jb2, added 1.8.0)

Loop calls with its own token, signed per request instead of per day:

```
jb2.<base64url claims JSON>.<base64url Ed25519 signature of "jb-health-v2:" + claims segment>
```

The signature is checked before the claims are decoded. The claims must then say `v: 2`,
`iss: "loop"`, carry integer `iat`/`exp` at most 300 seconds apart (60 seconds of clock skew either
way), a `jti` of 16 to 64 URL-safe characters, and an `aud` naming this site. The audience is
compared against the hosts of both `home_url()` and `site_url()`, lowercased, without port, one
trailing dot or one leading `www.`, and never against the request's `Host` header.

Each token is scoped per route, so a token minted to read errors cannot read form entries:

| Route | Scope |
|---|---|
| `/report` | `report:read` |
| `/errors` | `errors:read` |
| `/forms/entry` | `forms:read` |

Loop's public keys live in `JB_HEALTH_LOOP_PUBKEYS`, a list for rotation exactly like
`JB_HEALTH_SIGNING_PUBKEYS`. It ships empty: no jb2 token verifies until Loop's production key is
added at release. jb1 is unchanged and keeps working on every route. Failures get the same generic
`401 Unauthorised` either way. Send the token in both `Authorization: Bearer` and
`X-JB-Health-Token`, with a browser-like `User-Agent`.

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
                             "wp_env": "production", "reason": null,
                             // what SendGrid said about the last 30 days of this site's mail (1.7.0)
                             "delivery_30d": { "webhook_configured": true, "checked": true, "reason": null,
                                               "delivered": 41, "bounced": 1, "dropped": 0, "deferred": 2,
                                               "last_event_at": "2026-09-02T04:01:16+00:00",
                                               "last_bounce": { "to": "o***@example.com", "event": "bounce",
                                                                "reason": "reason: 550 5.1.1 The email account that you tried to reach does not exist",
                                                                "at": "2026-08-30T09:12:41+00:00" } } },
                 "count": 4,
                 "items": [ { "id": 1, "title": "Contact Form", "active": true,
                              // two independent gates, never collapsed into one flag
                              "captcha": { "field": false, "field_type": null, "recaptcha_v3": false },
                              "notifications": [ { "name": "Admin Notification", "active": true,
                                                   "event": "form_submission", "to_type": "email",
                                                   "to": "hello@example.com" } ],
                              "entries_total": 60, "entries_30d": 4, "entries_prev_30d": 3,
                              "last_entry": "2026-08-31T01:34:44+00:00",
                              // the site's own email log for this form (1.6.0)
                              "notifications_30d": { "checked": true, "reason": null,
                                                     "sent": 8, "failed": 1,
                                                     "prev_30d": { "sent": 6, "failed": 0 },
                                                     "last_sent_at": "2026-08-31T01:34:46+00:00",
                                                     "last_failed_at": "2026-08-12T09:02:11+00:00",
                                                     "last_error": "WordPress was unable to send the notification email." } } ] },
  // the site's own PHP error log (1.8.0); nulls + reason when capture is off
  "errors":    { "capture_enabled": true, "reason": null, "fatal_30d": 2, "warning_30d": 311,
                 "groups_active_24h": 4, "last_fatal_at": "2026-09-26T22:14:03Z",
                 "top": [ /* up to five groups, fatals first, same shape as /errors minus `days` */ ] }
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

## Notification log (added 1.6.0)

Every form item carries `notifications_30d`: what Gravity Forms itself recorded about the
notifications it tried to send for that form in the last 30 days. This is the site's own email log,
and it answers the question the entry counts cannot — *are this form's real submissions being
emailed?* — without submitting anything.

Gravity Forms writes one entry note per notification attempt (`GFFormsModel::add_notification_note()`,
GF ≥ 2.4.14): `sub_type` `success` when `wp_mail()` handed the message to the sending server, `error`
with the underlying reason when it did not. The plugin counts those per form in one grouped query
(joined to the entry table for the form id), with the 30 days before as a second window so a collapse
is visible rather than just a zero, and returns the most recent error text per form because it usually
*is* the diagnosis — an invalid TO address, an SMTP refusal. That text is GF's own system message,
never visitor input, and is capped at 500 characters.

| Field | Meaning |
|---|---|
| `checked` | `false` with a `reason` when the log could not be read (no notes table, or a pre-2.3 schema without `sub_type`). A zero that means "not measured" is exactly what this plugin refuses to emit. |
| `sent` / `failed` | Notifications accepted by / refused by the sending server, last 30 days |
| `prev_30d` | The same two counts for the 30 days before |
| `last_sent_at` / `last_failed_at` | Most recent of each (UTC, ISO 8601) |
| `last_error` | Text of the most recent failure in the window, or `null` |

Two things to read correctly:

- **Accepted is not delivered.** `success` means the sending server took the message. A bounce, a
  full mailbox or a spam folder downstream are invisible here. It is still the difference between
  "the form quietly mails nobody" and "the mail left the building", and it is what the fleet
  agreed to treat as proof of sending.
- **Entry status is not filtered.** A note exists only because a send was attempted, and a later
  trash or spam flag on the entry does not un-send the mail — so `sent` can exceed `entries_30d`
  on a site where test entries are trashed after the fact.

This is what lets a captcha-gated form — one no unattended check can submit — still be reported
on: `sent > 0, failed = 0` over 30 days is evidence from real people's submissions, `failed > 0`
carries its own reason, and `0 / 0` honestly means there was nothing to judge by.

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

## Delivery events (added 1.7.0)

The notification log says the site handed a message to its mail server. That is
the ceiling of what a WordPress site can know on its own. One step further — did
the **recipient's** mail server accept it — is something only the sending provider
knows, and SendGrid tells anyone who asks through its Event Webhook. 1.7.0 collects
those events per site and reads them back in two places.

**Receiving:** `POST /wp-json/jb-health/v1/mail-events`. SendGrid posts batches of
events here; the request is verified with SendGrid's *Signed Event Webhook* scheme
(ECDSA P-256 / SHA-256 over `timestamp + body`) against the subuser's verification
key, and nothing is parsed before that holds. Unsigned or badly signed → 401; a site
with no key configured → 403, so a misdirected webhook shows up as errors in
SendGrid's own activity feed instead of vanishing. Stored per event: recipient,
event type, provider timestamp, the provider's reason. Never a subject, never a
body. The table keeps seven days and is created on first use.

**Setup, once per site (per SendGrid subuser):**

1. SendGrid → Settings → Mail Settings → Event Webhook → HTTP POST URL
   `https://<site>/wp-json/jb-health/v1/mail-events`. Tick at least *Delivered,
   Bounced, Dropped, Deferred, Processed*. Enable *Signed Event Webhook* and copy
   the **Verification Key**.
2. Give the site that key as `JB_HEALTH_SENDGRID_PUBKEY` — the constant, the
   environment (Bedrock `.env`, i.e. the `PROD_JB_HEALTH_SENDGRID_PUBKEY` repo
   variable on the deploy pipeline), or the `jb_health_sendgrid_pubkey` option
   (`wp option update …`). Checked in that order; empty means the feature is off
   and every delivery answer says so.
3. Send anything. `forms.mailer.delivery_30d` in `/report` turns from
   `checked: false, reason: "no delivery events received yet"` into counts.

**Reading, per entry:** `/forms/entry` gains `delivery`:

```jsonc
"delivery": { "configured": true, "checked": true, "reason": null,
              "summary": "delivered",           // bounced · dropped · partial · deferred · processed · pending · unknown
              "window": { "before_s": 0, "after_s": 1800, "from": "2026-09-02T04:01:13+00:00" },
              "recipients": [ { "to": "hello@example.com", "status": "delivered",
                                "events": [ { "event": "processed", "at": "…", "reason": null },
                                            { "event": "delivered", "at": "…", "reason": "response: 250 2.0.0 OK" } ] } ] }
```

Events carry the recipient, not the entry, so the match is *an event for one of
this form's active submission-notification recipients, from the moment Gravity
Forms logged the send for this entry to thirty minutes after*. Recipients are
resolved from the notification config with merge tags expanded (`{admin_email}`,
a field the visitor typed); routing-type notifications are skipped, not guessed.
**There is deliberately no look-back**: a delivery cannot precede its send, and any
tolerance lets an earlier message to the same address stand in for this one — that
exact false pass showed up in testing with two runs twelve seconds apart. Two
submissions to the same recipient inside one half hour can still share an event;
the form check submits once per form per run, so that is a documented corner.

**Reading, site-wide:** `forms.mailer.delivery_30d` — delivered / bounced / dropped
/ deferred counts for the last 30 days, the last event time, and the most recent
bounce with a masked address (`j***@example.com`) and the provider's reason. The
number that says "the client actually receives what this site sends", and the
line that names a dead address.

**What it proves, and what it does not.** `delivered` = the recipient's mail server
took the message. A spam folder is on the far side of that and invisible to every
tool that does not read the recipient's inbox. Bounces and drops, on the other
hand, are exactly the failures the notification log cannot see, with the reason.

## PHP errors (added 1.8.0)

A site can look fine from the outside while a plugin throws a warning on every page or a checkout
step fatals for one customer in ten. 1.8.0 records what PHP itself reports, on the site, and hands
it to Loop.

**What is recorded.** Every fatal (including uncaught exceptions and out-of-memory), plus warnings
by default. Each error becomes a group, keyed by a fingerprint of level, type, relative file, line
and the message's first line with numbers and quoted values blanked. So `Undefined array key "a"`
and `…"b"` from the same line are one group, with a running `count`, a `first_seen`/`last_seen`,
the request type it last came from (`web`, `admin`, `ajax`, `rest`, `cron` or `cli`), the path it
last happened on, and the component that owns the file (`plugin:<slug>`, `mu-plugin:<name>`,
`theme:<slug>`, `core`, `dropin:<file>`, `vendor:<vendor/pkg>` or `other`). Daily counts per group
sit beside it.

**What it costs a request.** The handler only buffers. A repeat of the same error costs an array
lookup, so a warning fired 10,000 times in one loop is one row with `count: 10000`, written at the
end of the request in two statements. At most 25 distinct errors are itemised per request; the rest
are counted in one overflow group per level. `@`-suppressed errors are skipped. Nothing is written
while WordPress installs or upgrades, while it sandboxes a plugin activation, or when the fatal is
the database or object cache itself. A write that fails is dropped, never retried.

**What never leaves the site.** Messages and paths are redacted before they are stored. Absolute
paths become relative to the site (or `…/basename`), stack traces keep five frames and lose their
arguments (that is where a password passed to a login function would show up), and query strings,
emails (masked as `j***@example.com`), `'user'@'host'` pairs, `password=`/`token=`/`key=`-style
values, long hex or base64 tokens and IP addresses are replaced. Messages are capped at 1,000
characters.

**Reading it.** `GET /wp-json/jb-health/v1/errors`, same auth as `/report`:

| Parameter | Meaning |
|---|---|
| `since` | ISO 8601 or unix seconds. Default: the last 24 hours |
| `limit` | 1 to 500, default 100. `truncated: true` when more matched |
| `level` | Optional: `fatal`, `warning`, `notice` or `deprecated` |

```jsonc
{ "ok": true, "schema_version": 1, "plugin_version": "1.8.0", "generated_at": "2026-09-27T03:00:00Z",
  "site": { "home": "…", "siteurl": "…" },
  "capture": { "enabled": true, "levels": ["fatal", "warning"], "reason": null },
  "window": { "since": "2026-09-26T03:00:00Z", "until": "2026-09-27T03:00:00Z" },
  "truncated": false,
  "groups": [ { "fingerprint": "…40 hex…", "level": "warning", "type": "E_WARNING",
                "message": "Undefined array key \"proofs\"",
                "file": "app/plugins/wp-real-time-social-proof/wprtsp.php", "line": 770,
                "component": "plugin:wp-real-time-social-proof", "context": "web", "last_path": "/",
                "first_seen": "…Z", "last_seen": "…Z", "count": 123,
                "days": [ ["2026-09-26", 14], ["2026-09-27", 3] ] } ],
  "daily": [ { "day": "2026-08-29", "fatal": 0, "warning": 3 } /* 30 rows, oldest first, zero-filled */ ] }
```

`days` covers the query window (from the `since` date). `daily` is always 30 rows, site-wide, with
`notice`/`deprecated` keys only when those levels are recorded. A malformed `since` from a caller
without a valid token gets the usual 401, not a 400. `/report` carries a summary of the same data as
`errors`.

**Settings**, all optional, in `wp-config.php`:

| Constant | Default | Effect |
|---|---|---|
| `JB_HEALTH_CAPTURE_ERRORS` | on | `false` switches capture off. `/errors` then answers `capture.enabled: false` with a reason |
| `JB_HEALTH_ERROR_LEVELS` | `E_WARNING \| E_USER_WARNING` | Which non-fatal levels are recorded. Fatals always are. On PHP 8 deprecations run to hundreds per request, which is why they are off by default |
| `JB_HEALTH_LOOP_PUBKEYS` | empty | Loop's jb2 public keys (see [Auth](#loops-per-request-token-jb2-added-180)) |

**Storage and retention.** Two tables, `{prefix}jb_health_errors` and `{prefix}jb_health_error_days`,
created on `plugins_loaded` when the recorded `jb_health_db_version` option is behind the plugin
(so an in-place deploy needs no activation step). A failed create is retried hourly, not on every
page. If the tables vanish (a database pulled from another environment), the next write or read
notices and they are rebuilt on the following request. Whenever the log is read, day rows older than
35 days and groups unseen for 30 days are removed, and only the 500 most recently seen groups are
kept. There is no cron to depend on.

**Honest limits.**

- Query Monitor replaces the error handler and never passes errors on. The plugin takes the top
  spot back at the end of `plugins_loaded`, with Query Monitor chained behind it. A handler that
  displaces it later than that (on `init`, say) hides errors raised after that point.
- WordPress's fatal error page runs before any plugin's shutdown code and ends the request, so the
  fatal is recorded from the `wp_php_error_message` filter. A site with a custom
  `wp-content/php-error.php` drop-in that exits skips that filter, and its fatals are not recorded.
- An `E_USER_ERROR` that another handler swallows never becomes a fatal, so it is not recorded.
- An out-of-memory fatal is recorded from a 32 KB reserve released at shutdown. It worked in testing
  (64 MB limit, 20 KB allocation), but a request that dies deep inside WordPress's own fatal handler
  can still take the recording down with it.

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

1.8.0 was tested against `globalin25.test` (Bedrock, WordPress 7.1, PHP 8.4 web / 8.2 CLI, MySQL
9.4) on 27 Sep 2026 with the jb2 test vector key. Warnings and fatals were recorded from page views,
the REST API, wp-admin, admin-ajax, wp-cron and WP-CLI, each with the right context. A loop of
10,000 warnings produced one row with `count: 10000` and no measurable slowdown. Suppressed errors
produced nothing. Uncaught exceptions, out-of-memory and post-output fatals were all recorded, and
WordPress's error page still answered 500. Stored rows held no absolute paths, emails, IPs, query
strings or stack-frame arguments. jb2 answered 200 for a valid token (including a `www.` audience)
and 401 for expired, over-long, wrong-audience, wrong-context, wrong-key, tampered and
under-scoped tokens. jb1 was unchanged. Query Monitor was not active on that site, so its
displacement was simulated with a non-chaining handler rather than tested with Query Monitor itself.
