# gcpx

Per-command Google Cloud identity selection. One static binary, no runtime, no daemon.

```bash
gcpx exec work    -- bq query --use_legacy_sql=false 'select 1'
gcpx exec client-dev -- dbt run
```

Nothing is ever globally activated. Each invocation builds its own environment and hands it to one child process, so two jobs running as two identities cannot see or corrupt each other.

## Why

The AWS and Kubernetes ecosystems solved this years ago with `aws-vault exec` and `kubie exec`. GCP never got the equivalent. The available tools all manage *one active identity at a time* by mutating global files, which breaks the moment two things run at once.

Three specific problems this fixes:

**Interactive reauth policies.** Google Workspace session-control policies force `gcloud auth login` credentials to be re-approved through a browser, sometimes daily. Application Default Credentials are a separate credential system that those policies do not touch, and `CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE` makes the CLI use them. gcpx sets that variable per command.

**Credential files cannot describe themselves.** An ADC file has no `scopes` field, and gcloud writes its `account` field empty. Given five of them, nothing on disk tells you which is which. gcpx keeps a metadata sidecar per identity and verifies it against live token introspection.

**Bare logins silently strip scopes.** `gcloud auth application-default login` with no `--scopes` overwrites the well-known credential file with a minimal grant, quietly removing Drive access that something else depended on. Tools do this to you unprompted; `dbt-bigquery` shells out to exactly that command. gcpx mints inside a throwaway config directory, so your credentials are never in the blast radius.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/luutuankiet/gcpx/main/scripts/install.sh | sh
```

Installs to `${XDG_BIN_HOME:-$HOME/.local/bin}`. Pin a version by passing a tag, or set `GCPX_VERSION`. Linux and macOS, amd64 and arm64. Requires the Google Cloud SDK on PATH for `login` and `rescope` only; everything else is self-contained.

## Quick start

```bash
gcpx adopt --scan                  # what credentials are already on this host?
gcpx adopt --alias work --file ~/.config/gcloud/application_default_credentials.json
gcpx login --preset dbt            # or mint a fresh one
gcpx ls                            # who do I have, and what is broken?
gcpx exec work -- bq query 'select 1'
```

## Commands

| | |
|---|---|
| `exec <alias> [-p PROJECT] -- <cmd...>` | run a command as that identity |
| `env <alias> [--json\|--export]` | print the environment instead of running |
| `ls [--json] [--wide] [--all]` | identities, states, next actions |
| `doctor [alias\|--all] [--json]` | live probe, plus which credential source wins on this host |
| `refresh [alias\|--all] [--quiet]` | warm tokens, update cached state |
| `login [--alias] [--preset] [--scopes] [--project] [--sdk-client]` | mint through the browser |
| `rescope <alias> --add drive [--sdk-client]` | re-mint with wider scopes, alias preserved |
| `set <alias> [--project P] [--quota-project P]` | edit defaults without re-consenting |
| `adopt --alias A --file PATH` | import a credential that already exists |
| `archive <alias>` / `rm <alias>` | retire, or delete |
| `export <alias>` / `import --bundle F` | move an identity to another host, sealed |
| `push <alias> [--to h1,h2]` | re-sync this credential to the other hosts that hold it |
| `fleet [ls\|discover\|self\|add\|rm]` | peers that mirror these identities |
| `schedule install\|uninstall\|status` | background refresh via crontab |
| `self-update [--check]` | replace this binary with the latest release |

## Status at a glance

```
ALIAS       EMAIL              PROJECT          SCOPES                STATE      NEXT ACTION
work        you@example.com    acme-analytics   bq,cloud-platform,+3  ACTIVE     -
client-dev  ops@example.com    client-staging   cloud-platform,drive  ACTIVE     -
client-ro   -                  client-staging   cloud-platform,+1     SCOPE-GAP  gcpx rescope client-ro --add drive
old-hire    -                  -                -                     EXPIRED    gcpx login --alias old-hire
```

Three deliberate choices in that table:

- **The remediation is a literal command**, never a description of one. That is what makes the output equally useful to a person and to an agent.
- **States are plain ASCII words**, not emoji. Column alignment counts bytes, not display cells, and these get grepped.
- **Exit codes carry the verdict** so nothing has to parse text: `0` ok, `1` error, `2` scope-gap, `3` expired.

Every verdict comes from one live refresh-grant attempt. Reading the file proves nothing: it carries no expiry, no scopes, and no way to know the token was revoked an hour ago.

## Scopes

Short names or full URLs, either works:

```bash
gcpx login --preset dbt
gcpx login --scopes drive,sheets,bigquery
gcpx rescope work --add drive
```

Presets: `base`, `dbt`, `sheets`, `full` — see `gcpx help scopes`.

Every mint force-includes `openid`, `userinfo.email` and `cloud-platform`. The first two are what let token introspection return an email address, which is the only way a credential can identify itself; the third is required by gcloud.

`--scopes` **replaces** rather than appends. That is how credentials end up mysteriously missing Drive.

**`drive.file` is not a substitute for `drive`.** It grants access only to files this OAuth client itself created, so it fails on a pre-existing Sheet while still looking like "a Drive scope" is present. gcpx flags it explicitly.

Scopes are frozen at consent time. There is no API to widen an existing grant, so `rescope` re-mints — the command is named for what it actually does.

## Two OAuth clients, and why Drive fails

`gcloud auth login` and `gcloud auth application-default login` do not use the same OAuth client. Nothing in either command's output says so, and the two credential files look identical apart from one opaque numeric id. That difference decides three things:

| | SDK client (`gcloud auth login`) | Auth-library client (`application-default login`) |
|---|---|---|
| Scope control | fixed set, no `--scopes` flag | any scopes you ask for |
| Quota project | not required | **required** for Drive, Sheets and other non-Cloud APIs |
| Drive consent | usually allowlisted | some Workspace tenants block it outright |

Two credentials can therefore carry byte-identical scope lists and still behave differently. gcpx covers both halves:

```bash
# Tenant blocks the default flow's Drive consent screen.
gcpx login --alias work --sdk-client

# Drive answers 403 with wording about permissions; the real cause is a
# missing quota project. No re-consent needed.
gcpx set work --quota-project auto
```

`login` stamps the quota project automatically when the credential needs one, so this is mostly a repair path for identities minted before that existed. When a mint asks for Drive and Google grants everything except Drive, gcpx names that as a tenant-side block and offers the SDK route rather than leaving a scope list to squint at.

`doctor` reports which client minted each identity, what quota project is attached, and a live Drive call with the failing layer named:

```
  work
    client   auth-library
    quota    NOT SET - Drive and Sheets will refuse this credential. Fix: gcpx set work --quota-project auto
```

## Moving an identity between hosts

Mint once, distribute the file. Refresh tokens are portable, and Google caps them at 100 per account per OAuth client, silently invalidating the oldest past that — so minting separately on every host burns slots for no benefit.

Learn the peers once, then one command keeps them in step:

```bash
gcpx fleet discover              # probe ~/.ssh/config for hosts running gcpx
gcpx fleet self box-a            # what the others call this machine
gcpx push work                   # stream the live credential to each peer
```

There is no coordinating node and no shared registry. Each machine keeps its own list of who it can reach and what the others call it, which is the only state a peer-to-peer copy needs. `discover` builds that list from the ssh config the operator already maintains; `self` exists because an ssh destination is a human's name for a box and almost never matches the box's own hostname — without it a host cannot tell which entry in the list is itself.

`push` streams an unsealed bundle over ssh stdin. Nothing is written to disk on either end and no passphrase appears on a remote command line, where any local `ps` would read it — ssh is already the encrypted channel, so a second layer would only move the secret somewhere worse.

For a channel gcpx does not control — a paste buffer, a chat window, an agent transcript — use the sealed file instead:

```bash
gcpx export work --out work.gcpx     # on the host that minted
gcpx import --bundle work.gcpx       # on each target
```

Bundles are encrypted with AES-256-GCM under a PBKDF2 passphrase by default. This is not ceremony: what crosses the wire is a live OAuth refresh token. `--plaintext` exists and warns loudly.

### Why push exists

Consent is granted per account and OAuth client, never per machine. Approving a new scope set **replaces** the grant, and every other host still holding the previous refresh token is left with a receipt for an authorization that no longer exists. Those hosts cannot detect this: the file is intact, the daemon keeps running, and calls simply start failing as if the account had been revoked.

This is why `login`, `rescope` and `adopt` end by naming the hosts they just invalidated and offering to push. Steady-state sharing is safe — any number of machines can refresh the same token concurrently, indefinitely — so the only moment that needs a human is the moment the grant changes.

## Background refresh

```bash
gcpx schedule install     # */30 * * * * gcpx refresh --all --quiet
```

crontab rather than a systemd user timer, because user units are killed on logout unless `loginctl enable-linger` has been run, and that needs root.

**Refreshing does not make a credential immortal.** It cannot outlast a revocation or an admin policy change. What it buys you is real but narrower: it resets the six-month inactivity clock, keeps a warm access token, and surfaces a dead credential within one interval instead of when a job trips over it.

## For agents

`gcpx ls --json` emits email, description, tags, default project and known projects per identity — enough to pick the right credential from an instruction like "use the analytics workspace against the staging project" without guessing at file paths. Combine with exit codes and `gcpx doctor --json`.

## Storage

```
$XDG_DATA_HOME/gcpx/identities/<alias>.json       metadata
$XDG_DATA_HOME/gcpx/identities/<alias>.adc.json   credential, 0600
$XDG_DATA_HOME/gcpx/archive/                      retired, kept for audit
$XDG_DATA_HOME/gcpx/cfg/<alias>/                  per-identity gcloud config
$XDG_STATE_HOME/gcpx/refresh.log
```

One file pair per identity, no central registry: two agents on two identities never contend, and a bad write can only damage one identity. Writes go through a tempfile and rename within the same directory.

`GCPX_HOME` overrides the store location, which is what makes throwaway sandboxes possible.

## Lifecycle

```
active ──stale──> refresh ──> active
   │
   ├──> scope-gap ──rescope (re-mint)──> active
   ├──> expired ────login  (re-mint)──> active
   └──> archived (alias freed, credential kept for audit)
```

The alias never changes and files are never renamed with timestamps, so every reference to `work` keeps working across re-mints. An expiring credential keeps its alias and flips its state; archiving moves the pair aside and frees the alias.

## Building

```bash
make build && make test
```

Go 1.25, zero external dependencies.

## License

MIT
